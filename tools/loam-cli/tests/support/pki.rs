//! A throwaway PKI and a TLS admin server to test against.
//!
//! Every run mints its own CA, server and client certificates, so no
//! key material is committed and no test depends on a certificate
//! expiring later than the suite is run.

use crate::support::{announced_addr, spawn_ready, Proc};
use loam_client::LoamClient;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use std::path::{Path, PathBuf};
use std::process::Command;

/// How a client certificate names its holder.
#[allow(dead_code, reason = "each suite mints the names it tests")]
pub enum Name<'a> {
    /// Subject CommonName only, no SAN.
    Cn(&'a str),
    /// A DNS SAN, under a CommonName that differs from it.
    Dns(&'a str),
    /// A URI SAN, beside a DNS SAN and a CommonName that differ from it.
    Uri(&'a str),
}

/// A client's certificate and key, as PEM and as DER (the key as PKCS#8).
pub struct Creds {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    #[allow(dead_code, reason = "only the node-graph suite loads DER")]
    pub cert_der: Vec<u8>,
    #[allow(dead_code, reason = "only the node-graph suite loads DER")]
    pub key_der: Vec<u8>,
}

pub struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl Ca {
    pub fn new(name: &str) -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        Ca { issuer }
    }

    pub fn pem(&self) -> Vec<u8> {
        self.issuer.pem().into_bytes()
    }

    #[allow(dead_code, reason = "only the node-graph suite loads DER")]
    pub fn der(&self) -> Vec<u8> {
        self.issuer.der().to_vec()
    }

    /// A server certificate for `localhost` and 127.0.0.1.
    pub fn server(&self) -> Creds {
        let mut params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "loam-server");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        self.sign(params)
    }

    pub fn client(&self, name: Name<'_>) -> Creds {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        match name {
            Name::Cn(cn) => params.distinguished_name.push(DnType::CommonName, cn),
            Name::Dns(dns) => {
                params
                    .distinguished_name
                    .push(DnType::CommonName, "not-the-identity");
                params
                    .subject_alt_names
                    .push(SanType::DnsName(dns.try_into().unwrap()));
            }
            Name::Uri(uri) => {
                params
                    .distinguished_name
                    .push(DnType::CommonName, "not-the-identity");
                params.subject_alt_names.push(SanType::DnsName(
                    "not-the-identity.example".try_into().unwrap(),
                ));
                params
                    .subject_alt_names
                    .push(SanType::URI(uri.try_into().unwrap()));
            }
        }
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        self.sign(params)
    }

    fn sign(&self, params: CertificateParams) -> Creds {
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Creds {
            cert: cert.pem().into_bytes(),
            key: key.serialize_pem().into_bytes(),
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }
}

/// A running TLS admin server and what a client needs to reach it.
pub struct TlsServer {
    #[allow(
        dead_code,
        reason = "held so the server lives exactly as long as this handle"
    )]
    pub proc: Proc,
    pub addr: String,
    pub ca: Ca,
}

#[allow(dead_code, reason = "each suite uses the calls it needs")]
impl TlsServer {
    /// Connect as a fresh client certificate named `name`.
    pub fn connect(&self, name: Name<'_>) -> LoamClient {
        self.connect_with(&self.ca.client(name))
    }

    pub fn connect_with(&self, creds: &Creds) -> LoamClient {
        LoamClient::connect_tls(
            &self.addr,
            "localhost",
            &self.ca.pem(),
            &creds.cert,
            &creds.key,
        )
        .expect("tls connect")
    }
}

/// Write the server's PKI and `grants` (JSON) under `dir`, returning
/// the four TLS flags with their paths.
pub fn tls_flags(dir: &Path, ca: &Ca, grants: &str) -> Vec<String> {
    let server = ca.server();
    let file = |name: &str, bytes: &[u8]| -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    };
    let flags = [
        ("--admin-tls-cert", file("server.pem", &server.cert)),
        ("--admin-tls-key", file("server.key", &server.key)),
        ("--admin-client-ca", file("client-ca.pem", &ca.pem())),
        ("--admin-grants", file("grants.json", grants.as_bytes())),
    ];
    flags
        .into_iter()
        .flat_map(|(f, p)| [f.to_string(), p.to_str().unwrap().to_string()])
        .collect()
}

/// A server whose only admin surface is TLS, on a port the OS picks,
/// with a fresh CA and `grants`.
pub fn spawn_tls_server(server_bin: &str, dir: &Path, grants: &str) -> TlsServer {
    let ca = Ca::new("loam test ca");
    let mut cmd = Command::new(server_bin);
    cmd.args([
        "--admin-listen",
        "127.0.0.1:0",
        "--ns-wal",
        dir.join("ns.wal").to_str().unwrap(),
        "--obj-wal",
        dir.join("obj.wal").to_str().unwrap(),
        "--fleet",
        &format!("dir:{}", dir.join("bodies").display()),
        "--tick-us",
        "1000",
    ]);
    cmd.args(tls_flags(dir, &ca, grants));
    let (proc, line) = spawn_ready(cmd, "admin surface on tls");
    TlsServer {
        proc,
        addr: announced_addr(&line).to_string(),
        ca,
    }
}

/// A grant file giving `identity` every class on every root.
#[allow(dead_code, reason = "each suite uses the calls it needs")]
pub fn grant_all(identity: &str) -> String {
    format!(
        r#"{{"grants":[{{"identity":"{identity}","roots":["*"],"ops":["read","write","lease","admin"]}}]}}"#
    )
}
