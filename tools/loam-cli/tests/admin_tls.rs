//! The remote admin surface: TLS 1.3 with client certificates, a
//! grant per identity, every request checked against it, and lease
//! holders bound to the identity that names them.
//!
//! The server serves every open connection at once: a control plane keeps
//! one while each attached volume's node graph holds its own.

#[path = "support/pki.rs"]
mod pki;
mod support;

use loam_client::{admin_wire as wire, random_holder, ClientError, LoamClient, VolumeWriter};
use pki::{spawn_tls_server, Ca, Name};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_loam-server")
}

fn forbidden<T: std::fmt::Debug>(r: Result<T, ClientError>) {
    match r {
        Err(ClientError::Nak(s)) if s == wire::STATUS_FORBIDDEN => {}
        other => panic!("expected STATUS_FORBIDDEN, got {other:?}"),
    }
}

fn nak<T: std::fmt::Debug>(r: Result<T, ClientError>) -> u8 {
    match r {
        Err(ClientError::Nak(s)) => s,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ── Transport ─────────────────────────────────────────────────────

#[test]
fn a_granted_client_reads_and_writes_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), &pki::grant_all("node-a"));
    let mut c = srv.connect(Name::Cn("node-a"));
    c.put_file(b"vol", b"/remote.txt", 1, b"written from off-box")
        .expect("a granted client can write");
    assert_eq!(
        c.get_file(b"vol", b"/remote.txt").unwrap().as_deref(),
        Some(&b"written from off-box"[..])
    );
    // Past one TLS record, and past the single-shot cap: the streamed
    // path, whose chunks belong to the connection that opened them.
    let large: Vec<u8> = (0..loam_client::IO_CHUNK * 3 + 777)
        .map(|i| (i * 7 % 253) as u8)
        .collect();
    c.put_file(b"vol", b"/big.bin", 1, &large).expect("stream");
    assert_eq!(
        c.get_file(b"vol", b"/big.bin").unwrap(),
        Some(large),
        "a multi-record frame arrives whole"
    );
}

#[test]
fn a_plaintext_client_is_refused_and_nothing_is_served() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), &pki::grant_all("node-a"));

    let mut frame = vec![0u8; 256];
    let n =
        wire::encode_admin_put_file(&mut frame, 1, b"vol", b"/plain.txt", 0, 1, b"clear").unwrap();
    let mut raw = TcpStream::connect(&srv.addr).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    raw.write_all(&frame[..n]).unwrap();
    let mut reply = Vec::new();
    let _ = raw.read_to_end(&mut reply);
    assert!(
        wire::decode_admin_put_file_ack(&reply).is_err(),
        "a plaintext peer gets no admin reply, only the close; got {reply:?}"
    );

    let mut c = srv.connect(Name::Cn("node-a"));
    assert_eq!(
        c.get_file(b"vol", b"/plain.txt").unwrap(),
        None,
        "and its request never reached the store"
    );
}

#[test]
fn a_client_certificate_from_another_ca_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), &pki::grant_all("node-a"));

    // The same name, signed by a CA the server does not trust.
    let rogue = Ca::new("rogue ca").client(Name::Cn("node-a"));
    let attempt = LoamClient::connect_tls(
        &srv.addr,
        "localhost",
        &srv.ca.pem(),
        &rogue.cert,
        &rogue.key,
    )
    .and_then(|mut c| c.put_file(b"vol", b"/rogue.txt", 1, b"x"));
    match attempt {
        Err(ClientError::Io(_)) => {}
        other => panic!("expected the handshake to fail, got {other:?}"),
    }

    let mut c = srv.connect(Name::Cn("node-a"));
    assert_eq!(c.get_file(b"vol", b"/rogue.txt").unwrap(), None);
}

#[test]
fn a_client_refuses_a_server_its_ca_did_not_sign() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), &pki::grant_all("node-a"));
    let creds = srv.ca.client(Name::Cn("node-a"));
    let other = Ca::new("other ca");
    let r = LoamClient::connect_tls(
        &srv.addr,
        "localhost",
        &other.pem(),
        &creds.cert,
        &creds.key,
    );
    assert!(r.is_err(), "the server is verified too");
}

#[test]
fn admin_listen_without_tls_flags_refuses_to_start() {
    // Not "starts and warns": a misconfigured server that runs is an
    // open admin surface. There is no plaintext or --insecure override.
    let dir = tempfile::tempdir().unwrap();
    let base = |extra: &[String]| {
        Command::new(server_bin())
            .args([
                "--admin-listen",
                "127.0.0.1:0",
                "--ns-wal",
                dir.path().join("ns.wal").to_str().unwrap(),
                "--obj-wal",
                dir.path().join("obj.wal").to_str().unwrap(),
                "--fleet",
                &format!("dir:{}", dir.path().join("bodies").display()),
            ])
            .args(extra)
            .output()
            .expect("run loam-server")
    };
    let tok = dir.path().join("token");
    std::fs::write(&tok, "a-token-is-not-tls").unwrap();
    let flags = pki::tls_flags(dir.path(), &Ca::new("ca"), &pki::grant_all("x"));
    let cases: Vec<(&str, Vec<String>)> = vec![
        ("no flags", vec![]),
        (
            "a token instead",
            vec!["--admin-token".into(), tok.to_str().unwrap().into()],
        ),
        ("no grants", flags[..6].to_vec()),
        ("no client CA", [&flags[..4], &flags[6..]].concat()),
    ];
    for (what, extra) in cases {
        let out = base(&extra);
        assert!(
            !out.status.success(),
            "{what}: the server must refuse to start"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("--admin-listen requires --admin-tls-cert"),
            "{what}: the refusal must say why; got: {err}"
        );
    }
}

#[test]
fn a_grant_file_that_does_not_mean_what_it_says_refuses_to_start() {
    let bad = [
        r#"{"grants":[{"identity":"a","roots":["r"],"ops":["read","delete"]}]}"#,
        r#"{"grants":[{"identity":"a","roots":[],"ops":["read"]}]}"#,
        r#"{"grants":[{"identity":"a","roots":["r"],"ops":[]}]}"#,
        r#"{"grants":[{"identity":"a","roots":["r"],"ops":["read"]},{"identity":"a","roots":["s"],"ops":["write"]}]}"#,
        r#"{"grants":[{"identity":"local-operator","roots":["*"],"ops":["admin"]}]}"#,
        r#"{"grants":[{"identity":"a","roots":["r"],"ops":["read"],"expires":"never"}]}"#,
    ];
    for grants in bad {
        let dir = tempfile::tempdir().unwrap();
        let out = Command::new(server_bin())
            .args([
                "--admin-listen",
                "127.0.0.1:0",
                "--ns-wal",
                dir.path().join("ns.wal").to_str().unwrap(),
                "--obj-wal",
                dir.path().join("obj.wal").to_str().unwrap(),
                "--fleet",
                &format!("dir:{}", dir.path().join("bodies").display()),
            ])
            .args(pki::tls_flags(dir.path(), &Ca::new("ca"), grants))
            .output()
            .expect("run loam-server");
        assert!(!out.status.success(), "accepted {grants}");
    }
}

// ── Grants ────────────────────────────────────────────────────────

const GRANTS: &str = r#"{
  "grants": [
    { "identity": "tenant-a-writer", "roots": ["tenant-a"], "ops": ["read", "write"] },
    { "identity": "tenant-a-reader", "roots": ["tenant-a"], "ops": ["read"] },
    { "identity": "spiffe://loam.test/node/7", "roots": ["tenant-b", "tenant-c"], "ops": ["read", "write", "lease"] },
    { "identity": "operator.loam.test", "roots": ["*"], "ops": ["admin"] }
  ]
}"#;

#[test]
fn a_granted_identity_is_confined_to_its_roots_and_classes() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), GRANTS);

    {
        let mut c = srv.connect(Name::Cn("tenant-a-writer"));
        let digest = c
            .put_file(b"tenant-a", b"/doc", 1, b"mine")
            .expect("its own root");
        c.bind(
            b"tenant-a",
            b"/alias",
            loam_client::object_id_for(&digest).as_bytes(),
            1,
        )
        .expect("bind in its own root");
        assert_eq!(
            c.get_file(b"tenant-a", b"/alias").unwrap().as_deref(),
            Some(&b"mine"[..])
        );

        // Another root, by every write op that names one.
        forbidden(c.put_file(b"tenant-b", b"/doc", 1, b"theirs"));
        forbidden(c.bind(
            b"tenant-b",
            b"/x",
            loam_client::object_id_for(&digest).as_bytes(),
            1,
        ));
        forbidden(c.delete_file(b"tenant-b", b"/doc"));
        let big = vec![7u8; loam_client::IO_CHUNK * 2];
        forbidden(c.put_file(b"tenant-b", b"/big", 1, &big));
        // ...and every read.
        forbidden(c.get_file(b"tenant-b", b"/doc"));
        forbidden(c.list_files(b"tenant-b"));
        forbidden(c.lookup(b"tenant-b", b"/doc"));

        // A class it was not granted, on its own root.
        let h = random_holder();
        forbidden(c.acquire_lease(b"tenant-a", b"/vol", &h, 30_000));
        forbidden(c.delete_body(&digest));
        // A token proves nothing more over a verified certificate.
        assert!(matches!(
            c.authenticate(b"anything"),
            Err(ClientError::Unauthenticated)
        ));

        // A content-addressed put needs write on some root; it is an
        // orphan until a granted bind names it.
        let body = c.put_body(b"an extent").expect("rootless write");
        assert_eq!(
            c.get_body(&body).unwrap().as_deref(),
            Some(&b"an extent"[..])
        );

        // Refusals leave the connection usable: the remedy is a grant,
        // not a reconnect.
        assert!(c.stat_file(b"tenant-a", b"/doc").unwrap().is_some());
    }
    {
        let mut c = srv.connect(Name::Cn("tenant-a-reader"));
        assert_eq!(
            c.get_file(b"tenant-a", b"/doc").unwrap().as_deref(),
            Some(&b"mine"[..])
        );
        forbidden(c.put_file(b"tenant-a", b"/doc", 2, b"overwrite"));
        forbidden(c.delete_file(b"tenant-a", b"/doc"));
        forbidden(c.put_body(b"no write class"));
    }
    {
        // A URI SAN is the identity, not the DNS SAN or CN beside it.
        let mut c = srv.connect(Name::Uri("spiffe://loam.test/node/7"));
        c.put_file(b"tenant-c", b"/f", 1, b"c")
            .expect("granted root");
        forbidden(c.get_file(b"tenant-a", b"/doc"));
    }
    {
        // The admin class reaches the raw keyed plane, and nothing else.
        let mut c = srv.connect(Name::Dns("operator.loam.test"));
        let key = [0x42u8; 32];
        assert!(!c.delete_body(&key).expect("admin may delete by key"));
        forbidden(c.get_file(b"tenant-a", b"/doc"));
    }
    {
        let mut c = srv.connect(Name::Cn("nobody-granted-me"));
        forbidden(c.get_file(b"tenant-a", b"/doc"));
        forbidden(c.list_files(b"tenant-a"));
        forbidden(c.get_body(&[0u8; 32]));
    }
}

/// Speak raw frames over TLS, for requests `LoamClient` never sends.
fn raw_tls(
    srv: &pki::TlsServer,
    name: Name<'_>,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    let creds = srv.ca.client(name);
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&srv.ca.pem()) {
        roots.add(c.unwrap()).unwrap();
    }
    let chain: Vec<_> = CertificateDer::pem_slice_iter(&creds.cert)
        .map(|c| c.unwrap())
        .collect();
    let key = PrivateKeyDer::from_pem_slice(&creds.key).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .unwrap();
    let conn = rustls::ClientConnection::new(
        Arc::new(cfg),
        ServerName::try_from("localhost".to_string()).unwrap(),
    )
    .unwrap();
    let sock = TcpStream::connect(&srv.addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    rustls::StreamOwned::new(conn, sock)
}

#[test]
fn an_unknown_op_is_refused_and_the_connection_closed() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), &pki::grant_all("node-a"));
    let mut s = raw_tls(&srv, Name::Cn("node-a"));
    let cid = 9u32;
    let mut frame = vec![0x7Fu8];
    frame.extend_from_slice(&cid.to_le_bytes());
    frame.extend_from_slice(&[0u8; 16]);
    s.write_all(&frame).unwrap();
    let mut ack = [0u8; 6];
    s.read_exact(&mut ack).expect("a refusal before the close");
    assert_eq!(ack[0], 0x7F);
    assert_eq!(u32::from_le_bytes(ack[1..5].try_into().unwrap()), cid);
    assert_eq!(ack[5], wire::STATUS_FORBIDDEN);
    let mut rest = Vec::new();
    let closed = matches!(s.read_to_end(&mut rest), Ok(0) | Err(_));
    assert!(
        closed && rest.is_empty(),
        "the connection is closed after it"
    );
}

#[test]
fn a_stream_belongs_to_the_connection_that_opened_it() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), &pki::grant_all("node-a"));
    let mut s = raw_tls(&srv, Name::Cn("node-a"));
    let mut buf = vec![0u8; 128];
    // A chunk and a commit into a stream this connection never opened.
    let n = wire::encode_put_file_chunk(&mut buf, 5, 0, b"smuggled").unwrap();
    s.write_all(&buf[..n]).unwrap();
    let mut ack = [0u8; 6];
    s.read_exact(&mut ack).unwrap();
    assert_eq!(
        wire::decode_put_file_chunk_ack(&ack).unwrap(),
        (5, wire::STATUS_FORBIDDEN)
    );
    let n = wire::encode_put_file_commit(&mut buf, 6, 0).unwrap();
    s.write_all(&buf[..n]).unwrap();
    s.read_exact(&mut ack).unwrap();
    let (cid, status, _) = wire::decode_admin_put_file_ack(&ack).unwrap();
    assert_eq!((cid, status), (6, wire::STATUS_FORBIDDEN));
}

// ── Lease holders bound to identity ───────────────────────────────

const LEASE_GRANTS: &str = r#"{
  "grants": [
    { "identity": "writer-a", "roots": ["vols"], "ops": ["read", "write", "lease"] },
    { "identity": "writer-b", "roots": ["vols"], "ops": ["read", "write", "lease"] }
  ]
}"#;

#[test]
fn a_lease_is_bound_to_the_identity_that_took_it() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), LEASE_GRANTS);
    let (root, path) = (&b"vols"[..], &b"/disk"[..]);
    let a_creds = srv.ca.client(Name::Cn("writer-a"));
    let holder = [0x5Au8; wire::LEASE_HOLDER_LEN];

    let fence = {
        let mut a = srv.connect_with(&a_creds);
        let vol = a
            .create_volume(root, path, 64 * 1024, 32 * 1024)
            .expect("create");
        let lease = a
            .acquire_lease(root, path, &holder, 60_000)
            .expect("acquire");
        let (status, _) = a
            .volume_record(
                wire::VOLUME_BEGIN,
                root,
                path,
                &holder,
                lease.fence,
                vol.revision,
                b"",
            )
            .unwrap();
        assert_eq!(status, wire::STATUS_OK, "a opens a flush under its lease");
        lease.fence
    };

    {
        // B names A's holder bytes exactly, and is still not A.
        let mut b = srv.connect(Name::Cn("writer-b"));
        assert_eq!(
            nak(b.acquire_lease(root, path, &holder, 60_000)),
            wire::STATUS_LEASE_HELD
        );
        assert_eq!(
            nak(b.renew_lease(root, path, &holder, 60_000)),
            wire::STATUS_LEASE_LOST
        );
        assert_eq!(
            nak(b.release_lease(root, path, &holder)),
            wire::STATUS_LEASE_LOST
        );
        let binding = b.lookup(root, path).unwrap().expect("bound");
        let (status, _) = b
            .volume_record(
                wire::VOLUME_COMMIT,
                root,
                path,
                &holder,
                fence,
                binding.revision,
                &binding.object_id,
            )
            .unwrap();
        assert_eq!(
            status,
            wire::STATUS_LEASE_LOST,
            "b cannot commit under a's lease"
        );
    }

    {
        // A, on a new connection, is still the holder: the binding is
        // to the identity, not the connection.
        let mut a = srv.connect_with(&a_creds);
        let renewed = a
            .renew_lease(root, path, &holder, 60_000)
            .expect("a renews");
        assert_eq!(renewed.fence, fence);
        let (status, _) = a
            .volume_record(wire::VOLUME_ABORT, root, path, &holder, fence, 0, b"")
            .unwrap();
        assert_eq!(status, wire::STATUS_OK);
        a.release_lease(root, path, &holder).expect("a releases");
    }

    {
        let mut b = srv.connect(Name::Cn("writer-b"));
        let lease = b
            .acquire_lease(root, path, &holder, 60_000)
            .expect("b's turn");
        assert!(lease.fence > fence, "a new writer, a new fence");
    }
}

#[test]
fn open_connections_are_served_at_once_and_answered_on_their_own() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), LEASE_GRANTS);
    let (root, path) = (&b"vols"[..], &b"/shared"[..]);
    let creds = srv.ca.client(Name::Cn("writer-a"));
    let holder = [0x3Cu8; wire::LEASE_HOLDER_LEN];

    // The control plane's connection stays open throughout.
    let mut control = srv.connect_with(&creds);
    control
        .create_volume(root, path, 64 * 1024, 32 * 1024)
        .expect("create");
    let lease = control
        .acquire_lease(root, path, &holder, 60_000)
        .expect("acquire");

    // A node graph's connection, opened beside it, is answered: the same
    // holder takes the lease it already holds, under the same fence.
    let mut node = srv.connect_with(&creds);
    let again = node
        .acquire_lease(root, path, &holder, 60_000)
        .expect("a second open connection is served");
    assert_eq!(again.fence, lease.fence);

    // Both keep asking, interleaved, each client counting its own ids
    // from the same start: every answer reaches the connection that asked.
    for _ in 0..3 {
        let a = control
            .renew_lease(root, path, &holder, 60_000)
            .expect("control");
        let b = node.renew_lease(root, path, &holder, 60_000).expect("node");
        assert_eq!((a.fence, b.fence), (lease.fence, lease.fence));
        assert!(control.lookup(root, path).unwrap().is_some());
        assert!(node.lookup(root, path).unwrap().is_some());
    }

    // One closing does not end the other.
    drop(node);
    control
        .release_lease(root, path, &holder)
        .expect("the control plane is still served");
}

#[test]
fn a_volume_is_written_flushed_and_read_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), LEASE_GRANTS);
    let creds = srv.ca.client(Name::Cn("writer-a"));
    let size = 200 * 1024u64;
    let data: Vec<u8> = (0..70_000).map(|i| (i % 241) as u8).collect();
    {
        let mut c = srv.connect_with(&creds);
        let vol = c
            .create_volume(b"vols", b"/db", size, 32 * 1024)
            .expect("create");
        let mut w = VolumeWriter::open(&mut c, vol, random_holder(), 60_000).expect("writer");
        w.write(&mut c, 10_000, &data).expect("stage");
        assert_eq!(w.flush(&mut c).expect("flush"), 2);
        w.release(&mut c).expect("release");
    }
    let mut c = srv.connect_with(&creds);
    let mut vol = c.open_volume(b"vols", b"/db").unwrap().expect("volume");
    let mut got = vec![0u8; size as usize];
    c.volume_read(&mut vol, 0, &mut got).expect("read");
    assert!(got[..10_000].iter().all(|&b| b == 0));
    assert!(got[10_000..10_000 + data.len()] == data[..]);
    assert!(got[10_000 + data.len()..].iter().all(|&b| b == 0));
}

// ── The wire's framing ────────────────────────────────────────────

#[test]
fn every_request_frames_to_the_length_its_encoder_wrote() {
    type Enc = fn(&mut [u8]) -> usize;
    let encoders: Vec<Enc> = vec![
        |b| wire::encode_admin_auth(b, 1, b"token").unwrap(),
        |b| wire::encode_admin_bind(b, 1, b"r", b"/p", b"sha256:x", 0, 3).unwrap(),
        |b| wire::encode_admin_put_body(b, 1, &[5u8; 700]).unwrap(),
        |b| wire::encode_admin_get_body(b, 1, &[3u8; 32]).unwrap(),
        |b| wire::encode_admin_put_file(b, 1, b"r", b"/p", 0, 1, &[5u8; 700]).unwrap(),
        |b| wire::encode_admin_get_file(b, 1, b"r", b"/p").unwrap(),
        |b| wire::encode_admin_delete_file(b, 1, b"r", b"/p").unwrap(),
        |b| wire::encode_admin_list_files(b, 1, b"root", 7, 16).unwrap(),
        |b| wire::encode_put_file_open(b, 1, b"r", b"/p", 0, 1, &[3u8; 32], 99).unwrap(),
        |b| wire::encode_put_file_chunk(b, 1, 2, &[5u8; 700]).unwrap(),
        |b| wire::encode_put_file_commit(b, 1, 2).unwrap(),
        |b| wire::encode_read_file_range(b, 1, 5, 6, b"r", b"/p").unwrap(),
        |b| wire::encode_stat_file(b, 1, b"r", b"/p").unwrap(),
        |b| wire::encode_admin_put_body_keyed(b, 1, &[3u8; 32], &[5u8; 700]).unwrap(),
        |b| wire::encode_admin_delete_body(b, 1, &[3u8; 32]).unwrap(),
        |b| {
            wire::encode_admin_lease(
                b,
                1,
                wire::LEASE_ACQUIRE,
                b"r",
                b"/p",
                &[4u8; wire::LEASE_HOLDER_LEN],
                9,
            )
            .unwrap()
        },
        |b| {
            wire::encode_admin_volume(
                b,
                &wire::DecodedAdminVolume {
                    correlation_id: 1,
                    mode: wire::VOLUME_COMMIT,
                    namespace_root: b"r",
                    path: b"/p",
                    object_id: b"sha256:ab",
                    holder: [4u8; wire::LEASE_HOLDER_LEN],
                    fence: 2,
                    expected: 3,
                },
            )
            .unwrap()
        },
        |b| wire::encode_admin_lookup(b, 1, b"r", b"/p").unwrap(),
    ];
    for enc in encoders {
        let mut buf = vec![0u8; 4096];
        let n = enc(&mut buf);
        let op = buf[0];
        assert_eq!(wire::request_len(&buf[..n]), Ok(n), "op 0x{op:02x}");
        // Followed by more bytes, it still frames to its own length.
        assert_eq!(wire::request_len(&buf[..n + 10]), Ok(n), "op 0x{op:02x}");
        // Every strict prefix of the header is Truncated or already
        // complete enough to measure; never a wrong length.
        for cut in 0..n {
            match wire::request_len(&buf[..cut]) {
                Err(wire::WireError::Truncated) => {}
                Ok(len) => assert_eq!(len, n, "op 0x{op:02x} cut {cut}"),
                Err(e) => panic!("op 0x{op:02x} cut {cut}: {e:?}"),
            }
        }
    }
    assert_eq!(
        wire::request_len(&[0x7F, 0, 0, 0, 0]),
        Err(wire::WireError::BadOpcode { observed: 0x7F })
    );
}
