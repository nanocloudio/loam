//! Client for loam's admin surface: the protocol `loam-server`
//! serves on its unix socket (`--socket`) and, to a remote caller,
//! over mutually authenticated TLS 1.3 (`--admin-listen`). One
//! struct, blocking calls, one dependency (rustls) — the crate a
//! volume backend (nanocloud's CsiPlugin), a tool, or a test links
//! instead of re-implementing the wire.
//!
//! The wire itself is the same `#[path]`-included
//! `modules/common/mechanics/loam_admin_wire.rs` the PIC modules compile —
//! there is exactly one encoding in the tree. Requests carry a
//! client-chosen correlation id; replies echo it. This client
//! runs one request at a time per connection, so cids are a
//! monotonic counter and replies are read until the frame's own
//! decode reports completion (every ack decode returns
//! `Truncated` on a partial buffer).

#[allow(
    dead_code,
    unused_imports,
    reason = "shared fluxor SDK include; each includer uses a subset"
)]
pub(crate) mod sha256_impl {
    include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
}
use sha256_impl::Sha256;

#[path = "../../../modules/common/mechanics/loam_limits.rs"]
mod limits;

#[path = "../../../modules/common/mechanics/loam_manifest_wire.rs"]
pub mod manifest_wire;

#[path = "../../../modules/common/mechanics/loam_admin_wire.rs"]
pub mod admin_wire;

#[path = "../../../modules/common/mechanics/loam_volume_map_wire.rs"]
pub mod map_wire;

mod volume;
pub use volume::{random_holder, Volume, VolumeWriter, PAGE_CACHE_PAGES, STAGED_EXTENTS_MAX};

use admin_wire as wire;

/// Namespace kinds, as `loam_wire` numbers them.
pub const KIND_FILE: u8 = 0;
pub const KIND_VOLUME: u8 = 3;
use admin_wire::WireError;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Chunk size for streamed writes and ranged reads. Below the
/// body plane's single-shot MAX_BODY (60 KiB) with frame headroom.
pub const IO_CHUNK: usize = 48 * 1024;

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    /// A manifest could not be encoded or decoded.
    Manifest(String),
    /// The server requires authentication and this connection has
    /// not provided it, or the token was wrong. The server closes
    /// the connection either way, so recovery is to reconnect —
    /// not to retry on this one.
    Unauthenticated,
    /// The server answered, but with a NAK status.
    Nak(u8),
    /// A reply that doesn't decode as the expected ack.
    Protocol(WireError),
    /// A reply whose correlation id isn't the request's.
    CorrelationMismatch {
        expected: u32,
        observed: u32,
    },
    /// TLS configuration the client could not build: a PEM that does
    /// not parse, a key that does not match, a bad server name.
    Tls(String),
    /// A volume that cannot be used as asked: a geometry no map can
    /// describe, a path bound to something that is not a volume, a map
    /// page that does not decode, or a writer ended by an earlier
    /// refusal.
    Volume(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::Manifest(m) => write!(f, "manifest: {m}"),
            ClientError::Unauthenticated => write!(
                f,
                "not authenticated — the server requires --admin-token; \
                 call authenticate() first, and reconnect after a failure"
            ),
            ClientError::Nak(s) if *s == wire::STATUS_FORBIDDEN => write!(
                f,
                "forbidden (status 0x{s:02x}): this identity holds no grant for the op"
            ),
            ClientError::Nak(s) => write!(f, "server nak (status 0x{s:02x})"),
            ClientError::Protocol(e) => write!(f, "protocol: {e:?}"),
            ClientError::CorrelationMismatch { expected, observed } => {
                write!(f, "correlation mismatch: sent {expected}, got {observed}")
            }
            ClientError::Tls(m) => write!(f, "tls: {m}"),
            ClientError::Volume(m) => write!(f, "volume: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<WireError> for ClientError {
    fn from(e: WireError) -> Self {
        ClientError::Protocol(e)
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// What the admin wire is carried over.
///
/// An enum rather than a `Box<dyn Read + Write>`: there are exactly
/// two transports, the dispatch is on the hot path of every frame,
/// and a concrete type keeps the error surface honest — a unix
/// socket and a TLS session fail in different ways and the caller can
/// tell which it has.
enum Transport {
    Unix(UnixStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Unix(s) => s.read(buf),
            Transport::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Unix(s) => s.write(buf),
            Transport::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Unix(s) => s.flush(),
            Transport::Tls(s) => s.flush(),
        }
    }
}

/// Parse every certificate in a PEM buffer.
fn pem_certs(pem: &[u8], what: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ClientError::Tls(format!("{what}: {e:?}")))?;
    if certs.is_empty() {
        return Err(ClientError::Tls(format!("{what}: no certificate")));
    }
    Ok(certs)
}

/// A blocking connection to a loam-server admin surface.
pub struct LoamClient {
    conn: Transport,
    next_cid: u32,
}

impl LoamClient {
    /// Connect to the unix admin socket at `path`.
    pub fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let conn = UnixStream::connect(path)?;
        conn.set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok(LoamClient {
            conn: Transport::Unix(conn),
            next_cid: 1,
        })
    }

    /// Connect to a remote admin surface over TLS 1.3.
    ///
    /// The server is verified against `ca_pem` under `server_name` (a
    /// DNS name or IP address its certificate carries); this client
    /// presents `client_cert_pem` / `client_key_pem`, whose name is the
    /// identity the server checks every request against its grants.
    /// All PEM arguments are file contents, not paths.
    ///
    /// A certificate the server does not accept fails the first
    /// request, not this call: in TLS 1.3 the client finishes its
    /// handshake before the server has judged the client's
    /// certificate.
    ///
    /// Lease holders need no special handling here: the server binds
    /// whatever holder this connection names to its identity, so two
    /// identities can never share one, and the holders a caller picks
    /// still tell its own writers apart.
    pub fn connect_tls(
        addr: impl std::net::ToSocketAddrs,
        server_name: &str,
        ca_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
    ) -> Result<Self> {
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        for ca in pem_certs(ca_pem, "CA")? {
            roots
                .add(ca)
                .map_err(|e| ClientError::Tls(format!("CA: {e}")))?;
        }
        let chain = pem_certs(client_cert_pem, "client certificate")?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(client_key_pem)
            .map_err(|e| ClientError::Tls(format!("client key: {e:?}")))?;
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| ClientError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .map_err(|e| ClientError::Tls(format!("client certificate: {e}")))?;
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| ClientError::Tls(format!("server name {server_name:?}: {e}")))?;
        let mut tls = rustls::ClientConnection::new(std::sync::Arc::new(cfg), name)
            .map_err(|e| ClientError::Tls(e.to_string()))?;
        let mut sock = TcpStream::connect(addr)?;
        sock.set_read_timeout(Some(Duration::from_secs(30)))?;
        sock.set_nodelay(true).ok();
        while tls.is_handshaking() {
            tls.complete_io(&mut sock)?;
        }
        Ok(LoamClient {
            conn: Transport::Tls(Box::new(rustls::StreamOwned::new(tls, sock))),
            next_cid: 1,
        })
    }

    /// Present `token` to the server. On a unix socket, must succeed
    /// before any other call when the server was started with
    /// `--admin-token`. A TLS connection authenticated in its handshake,
    /// and the server refuses a token on one.
    ///
    /// A server that requires auth closes the connection on a wrong
    /// token rather than letting it be guessed again, so a failure
    /// here means reconnecting, not retrying.
    pub fn authenticate(&mut self, token: &[u8]) -> Result<()> {
        let cid = self.cid();
        let mut buf = vec![0u8; 8 + token.len()];
        let n = wire::encode_admin_auth(&mut buf, cid, token)?;
        let status = self.round_trip(&buf[..n], wire::decode_admin_auth_ack, cid)?;
        if status == wire::STATUS_OK {
            Ok(())
        } else {
            Err(ClientError::Unauthenticated)
        }
    }

    fn cid(&mut self) -> u32 {
        let c = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        c
    }

    /// Send `frame`, then read until `decode` accepts the reply.
    /// `decode` returns the reply's correlation id plus the value.
    fn round_trip<T>(
        &mut self,
        frame: &[u8],
        decode: impl Fn(&[u8]) -> std::result::Result<(u32, T), WireError>,
        expected_cid: u32,
    ) -> Result<T> {
        self.conn.write_all(frame)?;
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 64 * 1024];
        loop {
            match decode(&buf) {
                Ok((cid, v)) => {
                    if cid != expected_cid {
                        return Err(ClientError::CorrelationMismatch {
                            expected: expected_cid,
                            observed: cid,
                        });
                    }
                    return Ok(v);
                }
                Err(WireError::Truncated) => {}
                Err(e) => return Err(ClientError::Protocol(e)),
            }
            let n = match self.conn.read(&mut chunk) {
                Ok(n) => n,
                // A signal landing in the wait is not the peer's answer:
                // a socket with a read timeout is not restarted, and
                // giving up here would abandon a reply already on its
                // way.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Err(ClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-reply",
                )));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Write `body` to `(namespace_root, path)` at `revision`.
    /// Single-shot for small bodies, digest-first streamed past
    /// IO_CHUNK. Returns the content digest (sha256).
    pub fn put_file(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        revision: u64,
        body: &[u8],
    ) -> Result<[u8; 32]> {
        if body.len() <= IO_CHUNK {
            let cid = self.cid();
            let mut buf = vec![0u8; body.len() + namespace_root.len() + path.len() + 64];
            let n = admin_wire::encode_admin_put_file(
                &mut buf,
                cid,
                namespace_root,
                path,
                0,
                revision,
                body,
            )
            .map_err(ClientError::Protocol)?;
            let (status, digest) = self.round_trip(
                &buf[..n],
                |b| {
                    admin_wire::decode_admin_put_file_ack(b)
                        .map(|(cid, status, d)| (cid, (status, d.map(|d| d.to_vec()))))
                },
                cid,
            )?;
            return match (status, digest) {
                (admin_wire::STATUS_OK, Some(d)) if d.len() == 32 => {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&d);
                    Ok(out)
                }
                (s, _) => Err(ClientError::Nak(s)),
            };
        }

        // Streamed: digest first, then open/chunk/commit.
        let mut h = Sha256::new();
        h.update(body);
        let digest = h.finalize();

        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 128];
        let n = admin_wire::encode_put_file_open(
            &mut buf,
            cid,
            namespace_root,
            path,
            0,
            revision,
            &digest,
            body.len() as u64,
        )
        .map_err(ClientError::Protocol)?;
        let (status, pfid) = self.round_trip(
            &buf[..n],
            |b| admin_wire::decode_put_file_open_ack(b).map(|(c, s, p)| (c, (s, p))),
            cid,
        )?;
        if status != admin_wire::STATUS_OK {
            return Err(ClientError::Nak(status));
        }

        for chunk in body.chunks(IO_CHUNK) {
            let cid = self.cid();
            let mut buf = vec![0u8; chunk.len() + 32];
            let n = admin_wire::encode_put_file_chunk(&mut buf, cid, pfid, chunk)
                .map_err(ClientError::Protocol)?;
            let status = self.round_trip(&buf[..n], admin_wire::decode_put_file_chunk_ack, cid)?;
            if status != admin_wire::STATUS_OK {
                return Err(ClientError::Nak(status));
            }
        }

        let cid = self.cid();
        let mut buf = vec![0u8; 16];
        let n = admin_wire::encode_put_file_commit(&mut buf, cid, pfid)
            .map_err(ClientError::Protocol)?;
        let (status, committed) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_admin_put_file_ack(b)
                    .map(|(c, s, d)| (c, (s, d.map(|d| d.to_vec()))))
            },
            cid,
        )?;
        match (status, committed) {
            (admin_wire::STATUS_OK, Some(d)) if d.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&d);
                Ok(out)
            }
            (s, _) => Err(ClientError::Nak(s)),
        }
    }

    /// Fetch the whole body at `(namespace_root, path)`. `None` if
    /// the path is not bound. Bodies past the single-shot cap are
    /// assembled from ranged reads (the body plane never serves
    /// more than one chunk per frame).
    pub fn get_file(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<Option<Vec<u8>>> {
        let size = match self.stat_file(namespace_root, path)? {
            Some(s) => s,
            None => return Ok(None),
        };
        if size as usize > IO_CHUNK {
            let mut out = Vec::with_capacity(size as usize);
            while (out.len() as u64) < size {
                let want = ((size - out.len() as u64) as usize).min(IO_CHUNK) as u32;
                match self.read_range(namespace_root, path, out.len() as u64, want)? {
                    Some(bytes) if !bytes.is_empty() => out.extend_from_slice(&bytes),
                    _ => {
                        return Err(ClientError::Io(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "ranged read came back short",
                        )))
                    }
                }
            }
            return Ok(Some(out));
        }
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 32];
        let n = admin_wire::encode_admin_get_file(&mut buf, cid, namespace_root, path)
            .map_err(ClientError::Protocol)?;
        let (status, body) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_admin_get_file_ack(b)
                    .map(|(c, s, d)| (c, (s, d.map(|d| d.to_vec()))))
            },
            cid,
        )?;
        match status {
            admin_wire::STATUS_OK => Ok(body),
            admin_wire::STATUS_NOT_FOUND => Ok(None),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// Read `[offset, offset+len)` of the file. `None` if the path
    /// is not bound. `len` is capped at IO_CHUNK per call.
    pub fn read_range(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        offset: u64,
        len: u32,
    ) -> Result<Option<Vec<u8>>> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 64];
        let n = admin_wire::encode_read_file_range(
            &mut buf,
            cid,
            offset,
            len.min(IO_CHUNK as u32),
            namespace_root,
            path,
        )
        .map_err(ClientError::Protocol)?;
        let (status, bytes) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_read_file_range_ack(b)
                    .map(|(c, s, d)| (c, (s, d.map(|d| d.to_vec()))))
            },
            cid,
        )?;
        match status {
            admin_wire::STATUS_OK => Ok(bytes),
            admin_wire::STATUS_NOT_FOUND => Ok(None),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// Size of the file, without transferring the body. `None` if
    /// the path is not bound.
    pub fn stat_file(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<Option<u64>> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 32];
        let n = admin_wire::encode_stat_file(&mut buf, cid, namespace_root, path)
            .map_err(ClientError::Protocol)?;
        let (status, size) = self.round_trip(
            &buf[..n],
            |b| admin_wire::decode_stat_file_ack(b).map(|(c, s, sz)| (c, (s, sz))),
            cid,
        )?;
        match status {
            admin_wire::STATUS_OK => Ok(Some(size)),
            admin_wire::STATUS_NOT_FOUND => Ok(None),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// Unbind `(namespace_root, path)`. Returns whether the binding
    /// existed. The body blob stays (content-addressed, possibly
    /// shared); orphan GC collects it when nothing references it.
    pub fn delete_file(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<bool> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 32];
        let n = admin_wire::encode_admin_delete_file(&mut buf, cid, namespace_root, path)
            .map_err(ClientError::Protocol)?;
        let status = self.round_trip(&buf[..n], admin_wire::decode_admin_delete_file_ack, cid)?;
        match status {
            admin_wire::STATUS_OK => Ok(true),
            admin_wire::STATUS_NOT_FOUND => Ok(false),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// Every bound path under `namespace_root` (cursor paging is
    /// internal).
    pub fn list_files(&mut self, namespace_root: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut cursor = 0u32;
        loop {
            let cid = self.cid();
            let mut buf = vec![0u8; namespace_root.len() + 32];
            let n = admin_wire::encode_admin_list_files(&mut buf, cid, namespace_root, cursor, 16)
                .map_err(ClientError::Protocol)?;
            let (status, next, page) = self.round_trip(
                &buf[..n],
                |b| {
                    let mut page = Vec::new();
                    admin_wire::decode_admin_list_files_ack(b, |p| page.push(p.to_vec()))
                        .map(|(c, s, next, _)| (c, (s, next, page)))
                },
                cid,
            )?;
            if status != admin_wire::STATUS_OK {
                return Err(ClientError::Nak(status));
            }
            out.extend(page);
            if next == 0 {
                break;
            }
            cursor = next;
        }
        Ok(out)
    }
}

// ── Raw body plane ─────────────────────────────────────────────────

impl LoamClient {
    /// Raw content-addressed body write. Returns the digest the
    /// store named it by, which is a fact about the bytes and not a
    /// choice — so two writers storing the same bytes get the same
    /// answer, on any cluster.
    pub fn put_body(&mut self, blob: &[u8]) -> Result<[u8; 32]> {
        let cid = self.cid();
        let mut buf = vec![0u8; blob.len() + 64];
        let n = admin_wire::encode_admin_put_body(&mut buf, cid, blob)
            .map_err(ClientError::Protocol)?;
        let (status, digest) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_admin_put_body_ack(b)
                    .map(|a| (a.correlation_id, (a.status, a.digest.map(|d| d.to_vec()))))
            },
            cid,
        )?;
        if status != admin_wire::STATUS_OK {
            return Err(ClientError::Nak(status));
        }
        let d = digest.ok_or(ClientError::Nak(status))?;
        let mut out = [0u8; 32];
        if d.len() != 32 {
            return Err(ClientError::Nak(status));
        }
        out.copy_from_slice(&d);
        Ok(out)
    }

    /// Raw body read by key/digest. `None` when the blob doesn't
    /// exist anywhere in the fleet.
    pub fn get_body(&mut self, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let cid = self.cid();
        let mut buf = vec![0u8; 64];
        let n =
            admin_wire::encode_admin_get_body(&mut buf, cid, key).map_err(ClientError::Protocol)?;
        let (status, body) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_admin_get_body_ack(b)
                    .map(|(c, s, d)| (c, (s, d.map(|d| d.to_vec()))))
            },
            cid,
        )?;
        match status {
            admin_wire::STATUS_OK => Ok(body),
            admin_wire::STATUS_NOT_FOUND => Ok(None),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// Raw body delete by key/digest. Returns whether it existed.
    pub fn delete_body(&mut self, key: &[u8; 32]) -> Result<bool> {
        let cid = self.cid();
        let mut buf = vec![0u8; 64];
        let n = admin_wire::encode_admin_delete_body(&mut buf, cid, key)
            .map_err(ClientError::Protocol)?;
        let (status, existed) = self.round_trip(
            &buf[..n],
            |b| admin_wire::decode_admin_delete_body_ack(b).map(|(c, s, e)| (c, (s, e))),
            cid,
        )?;
        if status != admin_wire::STATUS_OK {
            return Err(ClientError::Nak(status));
        }
        Ok(existed)
    }
}

// ── Volume writer leases ───────────────────────────────────────────
//
// A lease decides who a volume's writer IS before anyone writes. One
// holder per volume, a TTL the holder renews, and a fence token that
// grows every time the holder changes, so a writer that stalled past
// its lease can be told apart from its successor: the namespace
// refuses a commit whose fence is not the live lease's.
//
// The server judges expiry by its own clock; nothing here sends a
// time. `holder` is an opaque 16-byte identity the caller chooses —
// stable for one attachment, distinct between attachments.

/// A granted writer lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// Grows every time the volume's writer changes, and never
    /// repeats. A holder re-acquiring or renewing its own live lease
    /// keeps it.
    pub fence: u64,
    /// When the lease lapses, in the server's wall-clock milliseconds.
    /// Renew before it, allowing for the round trip.
    pub expires_at_ms: u64,
}

impl LoamClient {
    /// Take the writer lease on `(namespace_root, path)` for `ttl_ms`.
    ///
    /// Granted when nobody holds it, the holder's lease has lapsed, or
    /// `holder` already holds it. Refused `Nak(STATUS_LEASE_HELD)`
    /// while another holder's lease is live, `Nak(STATUS_BUSY)` when
    /// the server's lease table is full (retry), and `Nak(STATUS_NAK)`
    /// for a TTL outside `1..=LEASE_TTL_MAX_MS`.
    pub fn acquire_lease(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        holder: &[u8; admin_wire::LEASE_HOLDER_LEN],
        ttl_ms: u32,
    ) -> Result<Lease> {
        self.lease_op(
            admin_wire::LEASE_ACQUIRE,
            namespace_root,
            path,
            holder,
            ttl_ms,
        )
    }

    /// Extend `holder`'s live lease to `ttl_ms` from now, keeping its
    /// fence. `Nak(STATUS_LEASE_LOST)` when `holder` no longer holds it
    /// — expired, released, or taken over — and the caller must stop
    /// writing.
    pub fn renew_lease(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        holder: &[u8; admin_wire::LEASE_HOLDER_LEN],
        ttl_ms: u32,
    ) -> Result<Lease> {
        self.lease_op(
            admin_wire::LEASE_RENEW,
            namespace_root,
            path,
            holder,
            ttl_ms,
        )
    }

    /// Give up `holder`'s lease so the next writer need not wait out
    /// the TTL. The fence is kept, so the next holder's is higher.
    /// `Nak(STATUS_LEASE_LOST)` when `holder` does not hold it,
    /// including when it was already released.
    pub fn release_lease(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        holder: &[u8; admin_wire::LEASE_HOLDER_LEN],
    ) -> Result<()> {
        self.lease_op(admin_wire::LEASE_RELEASE, namespace_root, path, holder, 0)
            .map(|_| ())
    }

    fn lease_op(
        &mut self,
        mode: u8,
        namespace_root: &[u8],
        path: &[u8],
        holder: &[u8; admin_wire::LEASE_HOLDER_LEN],
        ttl_ms: u32,
    ) -> Result<Lease> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 64];
        let n = admin_wire::encode_admin_lease(
            &mut buf,
            cid,
            mode,
            namespace_root,
            path,
            holder,
            ttl_ms,
        )?;
        let (status, fence, expires_at_ms) = self.round_trip(
            &buf[..n],
            |b| admin_wire::decode_admin_lease_ack(b).map(|(c, s, f, e)| (c, (s, f, e))),
            cid,
        )?;
        if status == admin_wire::STATUS_OK {
            Ok(Lease {
                fence,
                expires_at_ms,
            })
        } else {
            Err(ClientError::Nak(status))
        }
    }
}

// ── Snapshots, clones and portable export ────────────────────────
//
// Content addressing gives these away almost free, and the design
// exploits that rather than building a parallel mechanism:
//
//   snapshot = the same object ids bound under a second root
//   clone    = a snapshot restored into a writable root
//   export   = the manifest blob plus the bodies it names
//
// The consequence worth stating: **the orphan GC has no
// snapshot-specific logic.** It asks "is this object id bound by
// anything?", and a snapshot's bindings are bindings. A volume
// snapshot binds a map root, and the GC already walks the map of every
// VOLUME binding, so a snapshotted volume's pages and extents are kept
// by the same walk that keeps the live one's. A design that instead
// reference-counted bodies would need a durable counter, a crash model
// for it, and a new way to be wrong.
//
// A snapshot costs N bindings, which is what the namespace's hot
// cache over a compacted snapshot file exists to absorb.

impl LoamClient {
    /// Bind `(namespace_root, path)` to an existing `object_id`
    /// without moving any bytes.
    ///
    /// This is the primitive a clone is built from: the body is
    /// already stored under its content digest, so a second name for
    /// it is a metadata write and nothing more.
    pub fn bind(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        object_id: &[u8],
        revision: u64,
    ) -> Result<()> {
        self.bind_as(namespace_root, path, object_id, KIND_FILE, revision)
    }

    /// [`bind`](Self::bind) under an explicit namespace kind. Not for a
    /// volume: the namespace refuses a plain bind that would create,
    /// replace or remove a volume binding, because those changes are
    /// fenced — see [`bind_volume_root`](Self::bind_volume_root).
    pub fn bind_as(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        object_id: &[u8],
        kind: u8,
        revision: u64,
    ) -> Result<()> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + object_id.len() + 64];
        let n = admin_wire::encode_admin_bind(
            &mut buf,
            cid,
            namespace_root,
            path,
            object_id,
            kind,
            revision,
        )?;
        let status = self.round_trip(
            &buf[..n],
            |b| admin_wire::decode_admin_bind_ack(b).map(|a| (a.correlation_id, a.status)),
            cid,
        )?;
        if status == admin_wire::STATUS_OK {
            Ok(())
        } else {
            Err(ClientError::Nak(status))
        }
    }

    /// The content digest of the object bound at `path`, or `None`.
    ///
    /// COST: this reads the body to hash it. The descriptor already
    /// holds the digest and `STAT_FILE` could return it — that is the
    /// obvious optimisation and it is a wire change, deliberately not
    /// bundled into the feature that revealed the need. Snapshotting
    /// a large namespace therefore reads it once.
    pub fn digest_of(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<Option<[u8; 32]>> {
        let Some(body) = self.get_file(namespace_root, path)? else {
            return Ok(None);
        };
        let mut h = Sha256::new();
        h.update(&body);
        Ok(Some(h.finalize()))
    }

    /// Freeze everything under `src_root` as a snapshot bound under
    /// `snap_root`, and return the manifest describing it.
    ///
    /// Every entry is bound, not copied, so the snapshot shares its
    /// bodies with the live namespace — and pins them against the
    /// orphan GC by the ordinary means. The manifest is returned
    /// rather than stored, so the caller decides whether it is worth
    /// keeping; `put_file` it wherever you like, and it becomes an
    /// ordinary content-addressed object with binding, replication
    /// and GC unchanged.
    ///
    /// Each entry keeps its kind. A volume's entry is the digest of the
    /// map root it had committed at that moment, so the snapshot pins
    /// that exact version: later commits to the volume write new
    /// extents and a new root, and never touch the ones pinned here.
    pub fn snapshot_create(&mut self, src_root: &[u8], snap_root: &[u8]) -> Result<Vec<u8>> {
        let keys = self.list_files(src_root)?;
        let mut digests: Vec<(Vec<u8>, [u8; 32], u8)> = Vec::with_capacity(keys.len());
        for key in &keys {
            // A key that vanished between the listing and here is
            // simply not in the snapshot. A snapshot is of a moment,
            // and this is that moment's honest content — better than
            // failing the whole operation over one concurrent delete.
            // A binding that names no content digest has no body a
            // manifest could name, and is not in it either.
            if let Some(b) = self.lookup(src_root, key)? {
                if let Some(d) = digest_of_object_id(&b.object_id) {
                    digests.push((key.clone(), d, b.kind));
                }
            }
        }
        for (key, digest, kind) in &digests {
            self.bind_entry(snap_root, key, digest, *kind)?;
        }
        let refs: Vec<manifest_wire::Entry<'_>> = digests
            .iter()
            .map(|(k, d, kind)| (k.as_slice(), *d, *kind))
            .collect();
        let mut out = vec![0u8; manifest_wire::encoded_len(src_root, &refs)];
        let n = manifest_wire::encode(&mut out, src_root, &refs)
            .map_err(|e| ClientError::Manifest(format!("{e:?}")))?;
        out.truncate(n);
        Ok(out)
    }

    /// Restore a manifest into `dst_root`, binding every entry to the
    /// body it names. With a fresh `dst_root` this is a CLONE: no
    /// bytes move, because the bodies are already there under their
    /// content digests.
    ///
    /// Returns how many entries were bound.
    pub fn snapshot_restore(&mut self, manifest: &[u8], dst_root: &[u8]) -> Result<usize> {
        let mut entries: Vec<(Vec<u8>, [u8; 32], u8)> = Vec::new();
        manifest_wire::for_each(manifest, |key, digest, kind| {
            entries.push((key.to_vec(), *digest, kind));
        })
        .map_err(|e| ClientError::Manifest(format!("{e:?}")))?;
        for (key, digest, kind) in &entries {
            self.bind_entry(dst_root, key, digest, *kind)?;
        }
        Ok(entries.len())
    }

    /// Bind one snapshot entry at revision 1. A volume entry is bound the
    /// only way a volume binding can be: a fenced commit of its root.
    fn bind_entry(&mut self, root: &[u8], key: &[u8], digest: &[u8; 32], kind: u8) -> Result<()> {
        if kind == KIND_VOLUME {
            return self.bind_volume_root(root, key, digest).map(|_| ());
        }
        let oid = object_id_for(digest);
        self.bind_as(root, key, oid.as_bytes(), kind, 1)
    }

    /// Drop every binding under `snap_root`.
    ///
    /// The bodies are NOT deleted here, and that is the point: they
    /// may still be named by the live namespace or another snapshot.
    /// Whatever is left unreferenced is the orphan GC's to reclaim,
    /// by the same rule it already applies to everything else.
    pub fn snapshot_delete(&mut self, snap_root: &[u8]) -> Result<usize> {
        let keys = self.list_files(snap_root)?;
        let mut n = 0;
        for key in &keys {
            let volume = matches!(self.lookup(snap_root, key)?, Some(b) if b.kind == KIND_VOLUME);
            let gone = if volume {
                self.delete_volume(snap_root, key)?
            } else {
                self.delete_file(snap_root, key)?
            };
            if gone {
                n += 1;
            }
        }
        Ok(n)
    }

    /// The digests a destination would need in order to receive this
    /// manifest — every digest it does not already hold.
    ///
    /// This is what makes a portable export cheap: the receiver asks
    /// only for what it lacks, and deduplication across the transfer
    /// is free because the names are content digests on both sides.
    ///
    /// A volume entry names only its map root; the pages and extents
    /// the root reaches are asked about by [`export_snapshot`], which
    /// can read them at the source.
    pub fn manifest_missing_here(&mut self, manifest: &[u8]) -> Result<Vec<[u8; 32]>> {
        let mut want: Vec<[u8; 32]> = Vec::new();
        manifest_wire::for_each(manifest, |_, d, _| want.push(*d))
            .map_err(|e| ClientError::Manifest(format!("{e:?}")))?;
        self.missing_here(want)
    }

    /// Those of `want` this cluster does not hold.
    pub fn missing_here(&mut self, mut want: Vec<[u8; 32]>) -> Result<Vec<[u8; 32]>> {
        want.sort_unstable();
        want.dedup();
        let mut missing = Vec::new();
        for d in want {
            if self.get_body(&d)?.is_none() {
                missing.push(d);
            }
        }
        Ok(missing)
    }

    /// Every body a manifest needs, read here: each entry's digest and,
    /// for a volume entry, every map page and extent its root reaches.
    pub fn manifest_closure(&mut self, manifest: &[u8]) -> Result<Vec<[u8; 32]>> {
        let mut entries: Vec<([u8; 32], u8)> = Vec::new();
        manifest_wire::for_each(manifest, |_, d, kind| entries.push((*d, kind)))
            .map_err(|e| ClientError::Manifest(format!("{e:?}")))?;
        let mut want = Vec::new();
        for (digest, kind) in entries {
            want.push(digest);
            if kind == KIND_VOLUME {
                want.extend(self.volume_bodies(&digest)?);
            }
        }
        want.sort_unstable();
        want.dedup();
        Ok(want)
    }
}

/// Copy a snapshot from `src` to `dst`, transferring only the
/// bodies `dst` lacks, then binding the manifest's entries under
/// `dst_root`.
///
/// It is deliberately a FUNCTION OVER TWO CLIENTS rather than a
/// protocol. The manifest is encryption-agnostic and its digests are
/// over plaintext, so a manifest means the same thing on both sides
/// whatever
/// keys each cluster holds — which is what lets the whole transfer
/// be ordinary reads and writes.
///
/// Deduplication across the transfer is free: the receiver is asked
/// what it lacks, and "lacks" is decided by content digest, so
/// bytes it already holds under any other name are never sent.
///
/// ORDER MATTERS and is the one invariant here. Every body lands
/// BEFORE any binding names it. A binding whose body has not
/// arrived is a dangling name — a reader gets a not-found for
/// something the namespace says exists — and on an interrupted
/// transfer that state would persist. Bodies first means an
/// interrupted export leaves unreferenced blobs, which the orphan
/// sweep reclaims, rather than broken names, which nothing repairs.
///
/// Returns `(bodies_sent, entries_bound)`.
pub fn export_snapshot(
    src: &mut LoamClient,
    dst: &mut LoamClient,
    manifest: &[u8],
    dst_root: &[u8],
) -> Result<(usize, usize)> {
    // 1. Ask the DESTINATION what it lacks. Asking the source would
    //    send everything. The source says what "everything" is: a
    //    volume entry reaches bodies the manifest does not name.
    let wanted = src.manifest_closure(manifest)?;
    let missing = dst.missing_here(wanted)?;

    // 2. Ship exactly those, verifying as we go. A digest the source
    //    cannot produce is a broken manifest, not something to skip
    //    quietly — skipping would produce a snapshot at the
    //    destination that silently contains less than it claims.
    let mut sent = 0usize;
    for digest in &missing {
        let body = src.get_body(digest)?.ok_or_else(|| {
            ClientError::Manifest(format!(
                "source does not hold {}, so this manifest cannot be exported whole",
                hex_digest(digest)
            ))
        })?;
        let landed = dst.put_body(&body)?;
        if &landed != digest {
            // Content addressing makes this checkable for free, and
            // it is worth checking: it catches a corrupted transfer
            // and a store that named the bytes differently.
            return Err(ClientError::Manifest(format!(
                "destination named the body {} where the manifest says {}",
                hex_digest(&landed),
                hex_digest(digest)
            )));
        }
        sent += 1;
    }

    // 3. Only now bind. See ORDER MATTERS above.
    let bound = dst.snapshot_restore(manifest, dst_root)?;
    Ok((sent, bound))
}

fn hex_digest(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The digest the store names `bytes` by: their SHA-256.
pub fn content_digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize()
}

/// The digest a content-derived object id names, or `None` for an id of
/// any other form.
pub fn digest_of_object_id(object_id: &[u8]) -> Option<[u8; 32]> {
    let hex = object_id.strip_prefix(b"sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.chunks(2).enumerate() {
        let s = std::str::from_utf8(pair).ok()?;
        if s.bytes().any(|c| c.is_ascii_uppercase()) {
            return None;
        }
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// The content-derived object id for a digest: `sha256:<64 hex>`.
/// The one form `object_index` treats as enumerable, because it is
/// the one whose lifecycle the storage substrate owns.
pub fn object_id_for(digest: &[u8; 32]) -> String {
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256:");
    for b in digest {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}
