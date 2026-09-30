//! The remote admin surface's transport: TLS 1.3, mutually
//! authenticated.
//!
//! The server presents its own certificate and requires one from the
//! client that chains to the configured CA. There is no plaintext
//! fallback and no TLS 1.2: the crate is built without it. Session
//! resumption is off, so every connection presents a certificate and
//! the identity checked is always the one verified on that connection.
//!
//! The handshake runs on its own thread, bounded in time and in number,
//! so a peer that connects and stalls holds a handshake slot, never the
//! admin loop. Only an established connection and its verified identity
//! reach the loop.

use crate::admin_access::check_identity;
use anyhow::{anyhow, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

/// Handshakes in progress at once. Past this an accepted connection is
/// closed at once rather than given a thread: stalled peers cannot grow
/// the process without bound.
pub const TLS_HANDSHAKES_MAX: usize = 16;
/// How long a peer has to finish its handshake.
const HANDSHAKE_WITHIN: Duration = Duration::from_secs(10);

/// Build the server's TLS configuration from PEM files.
pub fn server_config(
    cert: &std::path::Path,
    key: &std::path::Path,
    client_ca: &std::path::Path,
) -> Result<Arc<ServerConfig>> {
    let read =
        |p: &std::path::Path| std::fs::read(p).map_err(|e| anyhow!("reading {}: {e}", p.display()));
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&read(cert)?)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("{}: {e:?}", cert.display()))?;
    if chain.is_empty() {
        return Err(anyhow!("{}: no certificate", cert.display()));
    }
    let key = PrivateKeyDer::from_pem_slice(&read(key)?)
        .map_err(|e| anyhow!("{}: {e:?}", key.display()))?;
    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(&read(client_ca)?) {
        let ca = ca.map_err(|e| anyhow!("{}: {e:?}", client_ca.display()))?;
        roots
            .add(ca)
            .map_err(|e| anyhow!("{}: {e}", client_ca.display()))?;
    }
    if roots.is_empty() {
        return Err(anyhow!("{}: no CA certificate", client_ca.display()));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| anyhow!("client CA: {e}"))?;
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("{e}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| anyhow!("server certificate: {e}"))?;
    cfg.send_tls13_tickets = 0;
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Arc::new(cfg))
}

/// An established, verified TLS connection.
pub struct TlsLink {
    tls: ServerConnection,
    sock: TcpStream,
}

/// Accept connections on `listener` forever, handshaking each on its
/// own thread and handing established ones, with their identity, to
/// `out`.
pub fn serve_handshakes(
    listener: TcpListener,
    cfg: Arc<ServerConfig>,
    out: Sender<(TlsLink, String)>,
) {
    let in_flight = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(sock) = conn else { continue };
        if in_flight.fetch_add(1, Ordering::SeqCst) >= TLS_HANDSHAKES_MAX {
            in_flight.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (cfg, out, in_flight) = (cfg.clone(), out.clone(), in_flight.clone());
        std::thread::spawn(move || {
            let peer = sock.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            match handshake(sock, cfg) {
                Ok((link, id)) => {
                    eprintln!("[loam-server] admin tls {peer}: {id}");
                    let _ = out.send((link, id));
                }
                Err(e) => eprintln!("[loam-server] admin tls {peer} refused: {e}"),
            }
            in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn handshake(mut sock: TcpStream, cfg: Arc<ServerConfig>) -> Result<(TlsLink, String)> {
    sock.set_nodelay(true).ok();
    sock.set_read_timeout(Some(HANDSHAKE_WITHIN))?;
    sock.set_write_timeout(Some(HANDSHAKE_WITHIN))?;
    let mut tls = ServerConnection::new(cfg)?;
    while tls.is_handshaking() {
        if let Err(e) = tls.complete_io(&mut sock) {
            // The alert rustls queued says why; the peer may read it.
            let _ = tls.write_tls(&mut sock);
            return Err(anyhow!("{e}"));
        }
    }
    let id = identity(&tls)?;
    sock.set_read_timeout(None)?;
    sock.set_nonblocking(true)?;
    Ok((TlsLink { tls, sock }, id))
}

/// The verified leaf certificate's identity: its first URI SAN, else
/// its first DNS SAN, else its subject CommonName.
///
/// Subject alternative names first because that is where a
/// certificate's names are meant to live; the CommonName is the
/// fallback a certificate minted without SANs still carries. URI before
/// DNS because a device identity is a URI (a SPIFFE-style id), and a
/// certificate carrying both uses DNS for its network names.
fn identity(tls: &ServerConnection) -> Result<String> {
    let leaf = tls
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| anyhow!("no client certificate"))?;
    let cert = webpki::EndEntityCert::try_from(leaf).map_err(|e| anyhow!("{e}"))?;
    let id = cert
        .valid_uri_names()
        .next()
        .or_else(|| cert.valid_dns_names().next())
        .or_else(|| common_name(cert.subject()))
        .ok_or_else(|| anyhow!("client certificate names no identity"))?
        .to_string();
    check_identity(&id)?;
    Ok(id)
}

/// One DER element: its tag, its contents, and what follows it.
fn der_next(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 2 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// The first CommonName in a DER Name's contents (RDNSequence).
fn common_name(subject: &[u8]) -> Option<&str> {
    const SET: u8 = 0x31;
    const SEQUENCE: u8 = 0x30;
    const OID: u8 = 0x06;
    const CN: [u8; 3] = [0x55, 0x04, 0x03];
    let mut rdns = subject;
    while !rdns.is_empty() {
        let (tag, set, rest) = der_next(rdns)?;
        rdns = rest;
        if tag != SET {
            return None;
        }
        let mut atvs = set;
        while !atvs.is_empty() {
            let (tag, atv, rest) = der_next(atvs)?;
            atvs = rest;
            if tag != SEQUENCE {
                return None;
            }
            let (tag, oid, value) = der_next(atv)?;
            if tag == OID && oid == CN {
                let (vtag, v, _) = der_next(value)?;
                // UTF8String, PrintableString, IA5String.
                return match vtag {
                    0x0C | 0x13 | 0x16 => std::str::from_utf8(v).ok(),
                    _ => None,
                };
            }
        }
    }
    None
}

impl TlsLink {
    /// Move whatever plaintext has arrived into `out` without blocking,
    /// stopping once `out` holds `limit` bytes. `Ok(false)` once the
    /// peer has closed.
    pub fn read_into(&mut self, out: &mut Vec<u8>, limit: usize) -> std::io::Result<bool> {
        let mut open = true;
        let mut chunk = [0u8; 16 * 1024];
        loop {
            // Drain plaintext first: rustls refuses more ciphertext
            // while its plaintext buffer is full.
            loop {
                match self.tls.reader().read(&mut chunk) {
                    Ok(0) => return Ok(false),
                    Ok(n) => out.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            if !open {
                return Ok(false);
            }
            if out.len() >= limit {
                return Ok(true);
            }
            match self.tls.read_tls(&mut self.sock) {
                Ok(0) => open = false,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(true),
                Err(e) => return Err(e),
            }
            if let Err(e) = self.tls.process_new_packets() {
                let _ = self.flush();
                return Err(std::io::Error::other(e));
            }
        }
    }

    /// Send `bytes` whole. The socket is blocking for the duration: a
    /// reply is either delivered or the connection is dropped, never
    /// left half-sent in a buffer the loop may not come back to.
    pub fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let mut at = 0;
        while at < bytes.len() {
            let n = self.tls.writer().write(&bytes[at..])?;
            at += n;
            self.flush()?;
            if n == 0 && at < bytes.len() {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.set_nonblocking(false)?;
        let r = (|| {
            while self.tls.wants_write() {
                self.tls.write_tls(&mut self.sock)?;
            }
            Ok(())
        })();
        self.sock.set_nonblocking(true)?;
        r
    }
}
