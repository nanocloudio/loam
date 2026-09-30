//! `loam-nbd` against a remote loam-server: the volume backend's shape,
//! over the TLS admin surface under its own certificate and grant.

#[path = "support/pki.rs"]
mod pki;
mod support;

use pki::{spawn_tls_server, Name, TlsServer};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use support::{announced_addr, spawn_ready};

const GRANTS: &str = r#"{
  "grants": [
    { "identity": "nbd-host", "roots": ["vol"], "ops": ["read", "write", "lease"] },
    { "identity": "no-lease", "roots": ["vol"], "ops": ["read", "write"] }
  ]
}"#;

fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_loam-server")
}

/// Write `name`'s certificate, key and the CA under `dir`; return the
/// three client TLS flags.
fn client_flags(srv: &TlsServer, dir: &Path, name: &str) -> Vec<String> {
    let creds = srv.ca.client(Name::Cn(name));
    let file = |f: &str, bytes: &[u8]| -> PathBuf {
        let p = dir.join(f);
        std::fs::write(&p, bytes).unwrap();
        p
    };
    let flags = [
        ("--tls-ca", file(&format!("{name}-ca.pem"), &srv.ca.pem())),
        ("--tls-cert", file(&format!("{name}.pem"), &creds.cert)),
        ("--tls-key", file(&format!("{name}.key"), &creds.key)),
    ];
    flags
        .into_iter()
        .flat_map(|(f, p)| [f.to_string(), p.to_str().unwrap().to_string()])
        .collect()
}

fn nbd(srv: &TlsServer, extra: &[String]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_loam-nbd"));
    // No --tls-server-name: the host part of --admin is the name the
    // server's certificate is checked for, here its IP SAN.
    cmd.args([
        "--admin",
        &srv.addr,
        "--volume",
        "vol:/disk",
        "--listen",
        "127.0.0.1:0",
    ]);
    cmd.args(extra);
    cmd
}

#[test]
fn a_remote_nbd_server_writes_its_volume_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), GRANTS);
    srv.connect(Name::Cn("nbd-host"))
        .create_volume(b"vol", b"/disk", 64 * 1024, 4096)
        .unwrap();

    let flags = client_flags(&srv, dir.path(), "nbd-host");
    let (nbd_proc, line) = spawn_ready(nbd(&srv, &flags), "[loam-nbd] serving");
    let mut s = TcpStream::connect(announced_addr(&line)).unwrap();

    // Newstyle handshake, export by empty name.
    let mut greeting = [0u8; 18];
    s.read_exact(&mut greeting).unwrap();
    s.write_all(&0u32.to_be_bytes()).unwrap();
    s.write_all(&0x49484156454F5054u64.to_be_bytes()).unwrap();
    s.write_all(&1u32.to_be_bytes()).unwrap();
    s.write_all(&0u32.to_be_bytes()).unwrap();
    let mut export = [0u8; 10];
    s.read_exact(&mut export).unwrap();
    assert_eq!(
        u64::from_be_bytes(export[..8].try_into().unwrap()),
        64 * 1024
    );

    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let request = |s: &mut TcpStream, cmd: u16, handle: u64, off: u64, len: u32| {
        s.write_all(&0x25609513u32.to_be_bytes()).unwrap();
        s.write_all(&0u16.to_be_bytes()).unwrap();
        s.write_all(&cmd.to_be_bytes()).unwrap();
        s.write_all(&handle.to_be_bytes()).unwrap();
        s.write_all(&off.to_be_bytes()).unwrap();
        s.write_all(&len.to_be_bytes()).unwrap();
    };
    let reply = |s: &mut TcpStream| -> u32 {
        let mut hdr = [0u8; 16];
        s.read_exact(&mut hdr).unwrap();
        u32::from_be_bytes(hdr[4..8].try_into().unwrap())
    };
    request(&mut s, 1, 7, 4000, payload.len() as u32);
    s.write_all(&payload).unwrap();
    assert_eq!(reply(&mut s), 0, "write");
    request(&mut s, 3, 8, 0, 0);
    assert_eq!(reply(&mut s), 0, "flush commits");
    drop(s);
    // The admin surface serves one connection at a time; the device's
    // must end before the read-back's is served.
    drop(nbd_proc);

    let mut c = srv.connect(Name::Cn("nbd-host"));
    let mut vol = c.open_volume(b"vol", b"/disk").unwrap().unwrap();
    let mut got = vec![0u8; vol.size_bytes as usize];
    c.volume_read(&mut vol, 0, &mut got).unwrap();
    assert!(got[4000..4000 + payload.len()] == payload[..]);
}

#[test]
fn a_remote_nbd_server_needs_tls_credentials_and_a_lease_grant() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), GRANTS);
    srv.connect(Name::Cn("nbd-host"))
        .create_volume(b"vol", b"/disk", 64 * 1024, 4096)
        .unwrap();

    let out = nbd(&srv, &[]).output().unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--admin requires --tls-ca"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let flags = client_flags(&srv, dir.path(), "no-lease");
    let out = nbd(&srv, &flags).output().unwrap();
    assert!(
        !out.status.success(),
        "an identity without the lease class cannot take the writer lease"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("forbidden"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
