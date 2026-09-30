//! The `loam-client` crate against a real loam-server: every
//! public call, over the actual unix admin socket. This is the
//! contract a volume backend (nanocloud's CsiPlugin) builds on.

#[path = "support/pki.rs"]
mod pki;
mod support;

use loam_client::{ClientError, LoamClient, IO_CHUNK};
use std::process::Command;
use support::{spawn_ready, Proc};

fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_loam-server")
}

fn spawn_server(socket: &std::path::Path, dir: &std::path::Path) -> Proc {
    let mut cmd = Command::new(server_bin());
    cmd.args([
        "--socket",
        socket.to_str().unwrap(),
        "--ns-wal",
        dir.join("ns.wal").to_str().unwrap(),
        "--obj-wal",
        dir.join("obj.wal").to_str().unwrap(),
        "--fleet",
        &format!("dir:{}", dir.join("bodies").display()),
        "--tick-us",
        "1000",
    ]);
    spawn_ready(cmd, "admin socket on").0
}

#[test]
fn client_covers_the_admin_surface() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let _server = spawn_server(&socket, dir.path());
    let mut c = LoamClient::connect(&socket).expect("connect");

    // Small file: single-shot path.
    let small = b"loam-client small body".to_vec();
    let digest = c.put_file(b"vol", b"/a.txt", 1, &small).expect("put small");
    assert_ne!(digest, [0u8; 32]);

    // Large file: streamed path (3.5 chunks).
    let large: Vec<u8> = (0..IO_CHUNK * 3 + IO_CHUNK / 2)
        .map(|i| (i * 13 % 251) as u8)
        .collect();
    let large_digest = c
        .put_file(b"vol", b"/big.bin", 1, &large)
        .expect("put large");

    // Whole-body get.
    assert_eq!(c.get_file(b"vol", b"/a.txt").expect("get"), Some(small));
    assert_eq!(
        c.get_file(b"vol", b"/big.bin").expect("get large"),
        Some(large.clone())
    );
    assert_eq!(c.get_file(b"vol", b"/absent").expect("get miss"), None);

    // Stat without transfer.
    assert_eq!(
        c.stat_file(b"vol", b"/big.bin").expect("stat"),
        Some(large.len() as u64)
    );
    assert_eq!(c.stat_file(b"vol", b"/absent").expect("stat miss"), None);

    // Ranged read out of the middle.
    let got = c
        .read_range(b"vol", b"/big.bin", 100_000, 4096)
        .expect("range")
        .expect("present");
    assert_eq!(got, &large[100_000..100_000 + 4096]);
    assert_eq!(
        c.read_range(b"vol", b"/absent", 0, 16).expect("range miss"),
        None
    );

    // Listing.
    let mut listed = c.list_files(b"vol").expect("list");
    listed.sort();
    assert_eq!(listed, vec![b"/a.txt".to_vec(), b"/big.bin".to_vec()]);

    // Overwrite needs a higher revision; same revision is refused.
    assert!(matches!(
        c.put_file(b"vol", b"/a.txt", 1, b"dup"),
        Err(ClientError::Nak(_))
    ));
    let redigest = c
        .put_file(b"vol", b"/a.txt", 2, b"replaced")
        .expect("rev 2");
    assert_ne!(redigest, digest);
    assert_eq!(
        c.get_file(b"vol", b"/a.txt").expect("get v2"),
        Some(b"replaced".to_vec())
    );

    // Delete: true, then false, then gone.
    assert!(c.delete_file(b"vol", b"/a.txt").expect("delete"));
    assert!(!c.delete_file(b"vol", b"/a.txt").expect("re-delete"));
    assert_eq!(c.get_file(b"vol", b"/a.txt").expect("get deleted"), None);
    assert_eq!(
        c.list_files(b"vol").expect("list after"),
        vec![b"/big.bin".to_vec()]
    );

    // Same bytes to a fresh path must commit under the same
    // content digest (digest-first contract).
    let again = c
        .put_file(b"vol", b"/big2.bin", 1, &large)
        .expect("put again");
    assert_eq!(
        again, large_digest,
        "content-addressed: same bytes, same digest"
    );
}

// ── Admin authentication ──────────────────────────────────────────
//
// The admin surface can bind, read and delete anything in any
// namespace, so who is on the far end of the connection is the
// boundary that matters. Both halves are checked here — that a
// configured server refuses the unauthenticated, and that it still
// serves the authenticated.

fn spawn_server_with_token(
    socket: &std::path::Path,
    dir: &std::path::Path,
    token_file: &std::path::Path,
) -> Proc {
    let mut cmd = Command::new(server_bin());
    cmd.args([
        "--socket",
        socket.to_str().unwrap(),
        "--ns-wal",
        dir.join("ns.wal").to_str().unwrap(),
        "--obj-wal",
        dir.join("obj.wal").to_str().unwrap(),
        "--fleet",
        &format!("dir:{}", dir.join("bodies").display()),
        "--admin-token",
        token_file.to_str().unwrap(),
        "--tick-us",
        "1000",
    ]);
    spawn_ready(cmd, "admin socket on").0
}

#[test]
fn an_authenticated_client_is_served_normally() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("admin.sock");
    let tokf = dir.path().join("token");
    std::fs::write(&tokf, "s3cr3t-admin-token\n").unwrap();
    let _g = spawn_server_with_token(&sock, dir.path(), &tokf);

    let mut c = LoamClient::connect(&sock).expect("connect");
    c.authenticate(b"s3cr3t-admin-token")
        .expect("the configured token is accepted");

    // Trailing whitespace in the file is trimmed, so the secret is
    // what the operator typed, not what their editor added.
    let digest = c
        .put_file(b"tenant", b"/hello.txt", 1, b"hi")
        .expect("an authenticated client can write");
    assert_eq!(digest.len(), 32);
    assert_eq!(
        c.get_file(b"tenant", b"/hello.txt").unwrap().as_deref(),
        Some(&b"hi"[..]),
        "and read back"
    );
}

#[test]
fn an_unauthenticated_client_is_refused_and_disconnected() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("admin.sock");
    let tokf = dir.path().join("token");
    std::fs::write(&tokf, "s3cr3t-admin-token").unwrap();
    let _g = spawn_server_with_token(&sock, dir.path(), &tokf);

    // Skipping authenticate() entirely: the very first op is refused.
    let mut c = LoamClient::connect(&sock).expect("connect");
    let err = c
        .put_file(b"tenant", b"/nope.txt", 1, b"x")
        .expect_err("an unauthenticated write must not succeed");
    // The server closes the connection rather than answering, so the
    // client sees the close — which is the point: there is no second
    // guess on this connection.
    assert!(
        matches!(err, ClientError::Io(_) | ClientError::Protocol(_)),
        "expected a closed connection, got {err:?}"
    );
}

#[test]
fn a_wrong_token_is_refused_and_the_connection_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("admin.sock");
    let tokf = dir.path().join("token");
    std::fs::write(&tokf, "correct-horse").unwrap();
    let _g = spawn_server_with_token(&sock, dir.path(), &tokf);

    let mut c = LoamClient::connect(&sock).expect("connect");
    let err = c
        .authenticate(b"battery-staple")
        .expect_err("a wrong token must be refused");
    assert!(
        matches!(err, ClientError::Unauthenticated),
        "expected Unauthenticated, got {err:?}"
    );

    // The connection is spent: guessing is bounded to one attempt per
    // connect, so a second try on this socket cannot succeed either.
    assert!(
        c.authenticate(b"correct-horse").is_err(),
        "a refused connection is closed, not left open to guess again"
    );

    // A fresh connection with the right token works, which proves the
    // refusal was about the token and not about the server.
    let mut c2 = LoamClient::connect(&sock).expect("reconnect");
    c2.authenticate(b"correct-horse")
        .expect("the correct token authenticates on a new connection");
}

#[test]
fn an_anonymous_server_still_serves_without_a_token() {
    // No --admin-token: the surface is anonymous. That is a supported
    // shape for a unix socket, whose filesystem permissions are the
    // boundary, and the server says so on stderr rather than leaving
    // it to be discovered.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("admin.sock");
    let _g = spawn_server(&sock, dir.path());
    let mut c = LoamClient::connect(&sock).expect("connect");
    c.put_file(b"tenant", b"/anon.txt", 1, b"ok")
        .expect("an anonymous server serves an unauthenticated client");
}

#[test]
fn the_token_comparison_is_length_safe() {
    // `tokens_match` is the constant-time comparison the server uses.
    // A prefix must not authenticate, an empty token must never
    // match, and equal-length equality must still work.
    use loam_client::admin_wire::tokens_match;
    assert!(tokens_match(b"abc123", b"abc123"));
    assert!(!tokens_match(b"abc", b"abc123"), "a prefix is not a match");
    assert!(!tokens_match(b"abc123", b"abc"), "nor the other way");
    assert!(!tokens_match(b"", b""), "an empty token never matches");
    assert!(!tokens_match(b"", b"abc"));
    assert!(!tokens_match(b"abc124", b"abc123"), "last byte differs");
    assert!(!tokens_match(b"zbc123", b"abc123"), "first byte differs");
}

// ── Snapshots, clones and portable export ─────────────────────────

#[test]
fn a_snapshot_freezes_the_namespace_and_survives_source_changes() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("admin.sock");
    let _g = spawn_server(&sock, dir.path());
    let mut c = LoamClient::connect(&sock).expect("connect");

    c.put_file(b"live", b"/a.txt", 1, b"alpha").unwrap();
    c.put_file(b"live", b"/b.txt", 1, b"bravo").unwrap();

    let manifest = c.snapshot_create(b"live", b"snap1").expect("snapshot");
    let (root, count) = loam_client::manifest_wire::peek(&manifest).unwrap();
    assert_eq!(root, b"live", "the manifest records what it was taken from");
    assert_eq!(count, 2);

    // Move the live namespace on: overwrite one, delete the other.
    c.put_file(b"live", b"/a.txt", 2, b"ALPHA-v2").unwrap();
    assert!(c.delete_file(b"live", b"/b.txt").unwrap());

    // The snapshot is unmoved — it is bindings onto the ORIGINAL
    // content digests, and content-addressed bodies do not change
    // under you.
    assert_eq!(
        c.get_file(b"snap1", b"/a.txt").unwrap().as_deref(),
        Some(&b"alpha"[..]),
        "the snapshot still holds the pre-overwrite bytes"
    );
    assert_eq!(
        c.get_file(b"snap1", b"/b.txt").unwrap().as_deref(),
        Some(&b"bravo"[..]),
        "and the deleted file's body is still reachable through it — \
         which is the whole point of pinning by binding"
    );
    // Meanwhile the live namespace moved.
    assert_eq!(
        c.get_file(b"live", b"/a.txt").unwrap().as_deref(),
        Some(&b"ALPHA-v2"[..])
    );
    assert!(c.get_file(b"live", b"/b.txt").unwrap().is_none());
}

#[test]
fn a_clone_moves_no_bytes_and_is_independently_writable() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("admin.sock");
    let _g = spawn_server(&sock, dir.path());
    let mut c = LoamClient::connect(&sock).expect("connect");

    c.put_file(b"src", b"/one", 1, b"shared-content").unwrap();
    c.put_file(b"src", b"/two", 1, b"also-shared").unwrap();
    let manifest = c.snapshot_create(b"src", b"snapshot").unwrap();

    // Restoring into a fresh root is a clone: metadata only.
    let n = c.snapshot_restore(&manifest, b"clone").expect("restore");
    assert_eq!(n, 2);
    assert_eq!(
        c.get_file(b"clone", b"/one").unwrap().as_deref(),
        Some(&b"shared-content"[..])
    );

    // The clone is its own namespace: writing it does not touch the
    // source, because a bind is a name and the bodies are immutable.
    c.put_file(b"clone", b"/one", 2, b"diverged").unwrap();
    assert_eq!(
        c.get_file(b"clone", b"/one").unwrap().as_deref(),
        Some(&b"diverged"[..])
    );
    assert_eq!(
        c.get_file(b"src", b"/one").unwrap().as_deref(),
        Some(&b"shared-content"[..]),
        "the source is untouched by a write to its clone"
    );
}

#[test]
fn deleting_a_snapshot_drops_its_bindings_only() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("admin.sock");
    let _g = spawn_server(&sock, dir.path());
    let mut c = LoamClient::connect(&sock).expect("connect");

    c.put_file(b"live", b"/keep", 1, b"still-referenced")
        .unwrap();
    let _ = c.snapshot_create(b"live", b"snap").unwrap();
    assert_eq!(c.snapshot_delete(b"snap").unwrap(), 1);

    assert!(
        c.get_file(b"snap", b"/keep").unwrap().is_none(),
        "the snapshot's bindings are gone"
    );
    assert_eq!(
        c.get_file(b"live", b"/keep").unwrap().as_deref(),
        Some(&b"still-referenced"[..]),
        "but the body is untouched — it is still named by the live \
         namespace, and reclaiming it is the orphan GC's business, \
         by the same rule it already applies to everything else"
    );
}

#[test]
fn an_export_asks_only_for_the_digests_the_destination_lacks() {
    // Deduplication across a transfer, for free: the names ARE
    // content digests, so a receiver can answer "which of these do I
    // not have?" without the sender describing anything.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("admin.sock");
    let _g = spawn_server(&sock, dir.path());
    let mut c = LoamClient::connect(&sock).expect("connect");

    c.put_file(b"src", b"/shared", 1, b"both-sides-have-this")
        .unwrap();
    c.put_file(b"src", b"/only-here", 1, b"unique-to-source")
        .unwrap();
    let manifest = c.snapshot_create(b"src", b"snap").unwrap();

    // Everything in the manifest is present locally, so nothing is
    // missing — the degenerate case, and the one that proves the
    // check is real rather than always-true.
    assert!(
        c.manifest_missing_here(&manifest).unwrap().is_empty(),
        "every body the manifest names is present here"
    );

    // A manifest naming a digest nothing stored: exactly one gap.
    let refs: Vec<loam_client::manifest_wire::Entry<'_>> = vec![(
        &b"/absent"[..],
        [0xAB; 32],
        loam_client::manifest_wire::KIND_FILE,
    )];
    let mut synthetic = vec![0u8; loam_client::manifest_wire::encoded_len(b"src", &refs)];
    let n = loam_client::manifest_wire::encode(&mut synthetic, b"src", &refs).unwrap();
    synthetic.truncate(n);
    assert_eq!(
        c.manifest_missing_here(&synthetic).unwrap(),
        vec![[0xAB; 32]],
        "a digest the destination lacks is exactly what it asks for"
    );
}

#[test]
fn a_manifest_round_trips_and_refuses_a_corrupt_one() {
    use loam_client::manifest_wire as mw;
    let refs: Vec<mw::Entry<'_>> = vec![
        (&b"/a"[..], [1u8; 32], mw::KIND_FILE),
        (&b"/nested/b"[..], [2u8; 32], mw::KIND_FILE),
    ];
    let mut buf = vec![0u8; mw::encoded_len(b"root", &refs)];
    let n = mw::encode(&mut buf, b"root", &refs).unwrap();
    assert_eq!(n, buf.len(), "encoded_len is exact, not an estimate");

    let mut seen = Vec::new();
    let count = mw::for_each(&buf, |k, d, _| seen.push((k.to_vec(), *d))).unwrap();
    assert_eq!(count, 2);
    assert_eq!(seen[0].0, b"/a");
    assert_eq!(seen[1].1, [2u8; 32]);
    assert_eq!(
        seen.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        vec![b"/a".to_vec(), b"/nested/b".to_vec()],
        "order is preserved, so two manifests of one snapshot compare byte-for-byte"
    );

    // A truncated manifest is refused, not silently short — the same
    // rule the change stream holds itself to.
    assert!(mw::for_each(&buf[..buf.len() - 4], |_, _, _| {}).is_err());
    let mut bad = buf.clone();
    bad[0] ^= 0xFF;
    assert_eq!(mw::peek(&bad), Err(mw::ManifestError::BadMagic));
}

// ── Portable export between two clusters ──────────────────────────
//
// Two real servers, so the transfer is exercised rather than
// asserted. The manifest is encryption-agnostic and its digests are
// over plaintext, so it means the same thing on both
// sides — which is what lets the whole export be ordinary reads and
// writes rather than a protocol.

/// Two TLS servers, each with its own CA, and a client of each granted
/// everything.
fn two_clusters() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    pki::TlsServer,
    pki::TlsServer,
    LoamClient,
    LoamClient,
) {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();
    let src_srv = pki::spawn_tls_server(server_bin(), src_dir.path(), &pki::grant_all("exporter"));
    let dst_srv = pki::spawn_tls_server(server_bin(), dst_dir.path(), &pki::grant_all("importer"));
    let src = src_srv.connect(pki::Name::Cn("exporter"));
    let dst = dst_srv.connect(pki::Name::Cn("importer"));
    (src_dir, dst_dir, src_srv, dst_srv, src, dst)
}

#[test]
fn a_snapshot_exports_to_a_second_cluster_sending_only_what_it_lacks() {
    // Two clusters, each with its own CA: the remote admin surface is
    // TLS only, so an export between them is authenticated on both
    // ends by construction. There is no plaintext path to take.
    let (_src_dir, _dst_dir, _gs, _gd, mut src, mut dst) = two_clusters();

    // Three objects, two of them with IDENTICAL content — content
    // addressing should make that one body, on both sides.
    src.put_file(b"vol", b"/a.txt", 1, b"alpha").unwrap();
    src.put_file(b"vol", b"/b.txt", 1, b"beta").unwrap();
    src.put_file(b"vol", b"/c.txt", 1, b"alpha").unwrap();

    let manifest = src.snapshot_create(b"vol", b"snap-1").expect("snapshot");
    let (root, count) = loam_client::manifest_wire::peek(&manifest).unwrap();
    assert_eq!(root, b"vol");
    assert_eq!(count, 3, "three keys");

    // The destination holds nothing, so it needs both distinct
    // bodies — two, not three, because /a.txt and /c.txt are one.
    let missing = dst.manifest_missing_here(&manifest).unwrap();
    assert_eq!(
        missing.len(),
        2,
        "duplicate content is one body, so the transfer carries two"
    );

    let (sent, bound) =
        loam_client::export_snapshot(&mut src, &mut dst, &manifest, b"restored").expect("export");
    assert_eq!(sent, 2);
    assert_eq!(bound, 3, "all three keys are bound at the destination");

    for (key, want) in [
        (&b"/a.txt"[..], &b"alpha"[..]),
        (&b"/b.txt"[..], &b"beta"[..]),
        (&b"/c.txt"[..], &b"alpha"[..]),
    ] {
        assert_eq!(
            dst.get_file(b"restored", key).unwrap().as_deref(),
            Some(want),
            "{} did not arrive intact",
            String::from_utf8_lossy(key)
        );
    }
}

#[test]
fn re_exporting_the_same_snapshot_sends_nothing() {
    // The receiver is asked what it LACKS, and lacking is decided by
    // content digest — so a second export is metadata only. That is
    // the property that makes an incremental backup cheap.
    let (_src_dir, _dst_dir, _gs, _gd, mut src, mut dst) = two_clusters();

    src.put_file(b"vol", b"/x", 1, b"payload").unwrap();
    let manifest = src.snapshot_create(b"vol", b"snap").unwrap();

    let (sent1, _) = loam_client::export_snapshot(&mut src, &mut dst, &manifest, b"r1").unwrap();
    assert_eq!(sent1, 1);

    // Same bytes, different destination root: the body is already
    // there under its content digest, so nothing crosses the wire.
    let (sent2, bound2) =
        loam_client::export_snapshot(&mut src, &mut dst, &manifest, b"r2").unwrap();
    assert_eq!(sent2, 0, "the destination already holds these bytes");
    assert_eq!(bound2, 1);
    assert_eq!(
        dst.get_file(b"r2", b"/x").unwrap().as_deref(),
        Some(&b"payload"[..])
    );
}

#[test]
fn an_export_whose_source_lost_a_body_fails_rather_than_arriving_short() {
    // A snapshot at the destination that silently contains less than
    // it claims is worse than a failed export: the failure is
    // visible and retryable, the short snapshot is neither.
    let (_src_dir, _dst_dir, _gs, _gd, mut src, mut dst) = two_clusters();

    src.put_file(b"vol", b"/gone", 1, b"will be removed")
        .unwrap();
    let manifest = src.snapshot_create(b"vol", b"snap").unwrap();

    // Forge a manifest naming a body no source holds. Same shape as
    // a source that lost one.
    let phantom = [0x5au8; 32];
    let refs: Vec<loam_client::manifest_wire::Entry<'_>> = vec![(
        &b"/phantom"[..],
        phantom,
        loam_client::manifest_wire::KIND_FILE,
    )];
    let mut forged = vec![0u8; loam_client::manifest_wire::encoded_len(b"vol", &refs)];
    let n = loam_client::manifest_wire::encode(&mut forged, b"vol", &refs).unwrap();
    forged.truncate(n);

    let err = loam_client::export_snapshot(&mut src, &mut dst, &forged, b"r").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("cannot be exported whole"),
        "the failure must name the problem, got: {msg}"
    );
    assert!(
        dst.get_file(b"r", b"/phantom").unwrap().is_none(),
        "and nothing was bound at the destination"
    );
    let _ = manifest;
}

/// One writer per volume. The lease is decided by the server's clock and
/// its fence grows every time the writer changes — including across a
/// restart, which replays the lease table from the namespace log.
#[test]
fn a_volume_lease_admits_one_writer_and_its_fence_only_grows() {
    use loam_client::admin_wire;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let server = spawn_server(&socket, dir.path());
    // The server serves one admin connection at a time, so one
    // connection plays both writers: the lease is judged by holder id,
    // not by who sent it.
    let mut c = LoamClient::connect(&socket).expect("connect");
    let a = [0xAA; admin_wire::LEASE_HOLDER_LEN];
    let b = [0xBB; admin_wire::LEASE_HOLDER_LEN];
    let (root, path) = (&b"tenant"[..], &b"/vols/leased"[..]);
    let refused = |r: Result<loam_client::Lease, ClientError>| match r {
        Err(ClientError::Nak(s)) => s,
        other => panic!("expected a refusal, got {other:?}"),
    };

    let first = c.acquire_lease(root, path, &a, 60_000).expect("acquire");
    assert_eq!(first.fence, 1, "the first writer holds the first fence");
    assert!(first.expires_at_ms > 0, "expiry is on the server's clock");

    let again = c.acquire_lease(root, path, &a, 60_000).expect("re-acquire");
    assert_eq!(again.fence, first.fence, "the same writer keeps its fence");

    assert_eq!(
        refused(c.acquire_lease(root, path, &b, 60_000)),
        admin_wire::STATUS_LEASE_HELD,
        "a second writer is refused while the lease is live"
    );
    assert_eq!(
        refused(c.renew_lease(root, path, &b, 60_000)),
        admin_wire::STATUS_LEASE_LOST
    );
    assert!(
        matches!(c.release_lease(root, path, &b), Err(ClientError::Nak(s)) if s == admin_wire::STATUS_LEASE_LOST),
        "only the holder can release"
    );

    let renewed = c.renew_lease(root, path, &a, 60_000).expect("renew");
    assert_eq!(renewed.fence, first.fence, "a renew keeps the fence");

    c.release_lease(root, path, &a).expect("release");
    assert!(
        matches!(c.release_lease(root, path, &a), Err(ClientError::Nak(s)) if s == admin_wire::STATUS_LEASE_LOST),
        "a released lease cannot be released again"
    );
    assert_eq!(
        refused(c.renew_lease(root, path, &a, 60_000)),
        admin_wire::STATUS_LEASE_LOST,
        "nor renewed"
    );

    let second = c.acquire_lease(root, path, &b, 60_000).expect("b acquires");
    assert_eq!(second.fence, first.fence + 1, "a new writer, a new fence");

    // A TTL outside 1..=LEASE_TTL_MAX_MS is malformed, not contended.
    assert_eq!(
        refused(c.acquire_lease(root, b"/vols/other", &a, 0)),
        admin_wire::STATUS_NAK
    );
    assert_eq!(
        refused(c.acquire_lease(root, b"/vols/other", &a, 300_001)),
        admin_wire::STATUS_NAK
    );

    // A lapsed lease is anyone's, under a new fence.
    let short = c
        .acquire_lease(root, b"/vols/short", &a, 50)
        .expect("short");
    std::thread::sleep(std::time::Duration::from_millis(120));
    let taken = c
        .acquire_lease(root, b"/vols/short", &b, 60_000)
        .expect("taken over after expiry");
    assert_eq!(taken.fence, short.fence + 1);
    assert_eq!(
        refused(c.renew_lease(root, b"/vols/short", &a, 60_000)),
        admin_wire::STATUS_LEASE_LOST,
        "the lapsed holder learns it lost the lease"
    );

    // ── Restart: the lease table replays from the namespace WAL. ──
    drop(c);
    drop(server);
    let _server = spawn_server(&socket, dir.path());
    let mut c = LoamClient::connect(&socket).expect("reconnect");
    assert_eq!(
        refused(c.acquire_lease(root, path, &a, 60_000)),
        admin_wire::STATUS_LEASE_HELD,
        "b's lease is still live after the restart"
    );
    c.release_lease(root, path, &b).expect("b releases");
    let third = c.acquire_lease(root, path, &a, 60_000).expect("a again");
    assert_eq!(
        third.fence,
        second.fence + 1,
        "the fence continues where it was, never reissued"
    );
}
