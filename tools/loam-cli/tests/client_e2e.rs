//! The `loam-client` crate against a real loam-server: every
//! public call, over the actual unix admin socket. This is the
//! contract a volume backend (nanocloud's CsiPlugin) builds on.

mod support;

use loam_client::{ClientError, LoamClient, IO_CHUNK};
use std::process::Command;
use support::{announced_addr, spawn_ready, Proc};

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

#[test]
fn block_volume_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let server = spawn_server(&socket, dir.path());
    let mut c = LoamClient::connect(&socket).expect("connect");

    // 200 KiB volume, 32 KiB extents (7 extents, short tail).
    let size = 200 * 1024u64;
    let es = 32 * 1024u32;
    let vol = c
        .create_volume(b"tenant", b"/vols/db0", size, es)
        .expect("create");

    // Unwritten volume reads as zeros.
    let mut buf = vec![0xFFu8; 8192];
    c.volume_read(&vol, 50_000, &mut buf).expect("read fresh");
    assert!(buf.iter().all(|&b| b == 0), "unwritten reads zero");

    // Model the volume; write patterns that cross extent
    // boundaries and land mid-extent, verifying RMW.
    let mut model = vec![0u8; size as usize];
    let mut write = |c: &mut LoamClient, off: usize, data: &[u8]| {
        c.volume_write(&vol, off as u64, data).expect("write");
        model[off..off + data.len()].copy_from_slice(data);
    };
    let pat = |seed: u8, len: usize| -> Vec<u8> {
        (0..len)
            .map(|i| ((i as u32 * 7 + seed as u32) % 251) as u8)
            .collect()
    };
    write(&mut c, 0, &pat(1, 1000)); // head of extent 0
    write(&mut c, 30_000, &pat(2, 40_000)); // spans extents 0..2
    write(&mut c, 100_000, &pat(3, 5)); // tiny mid-extent RMW
    write(&mut c, (size - 700) as usize, &pat(4, 700)); // tail extent

    let check = |c: &mut LoamClient, model: &[u8]| {
        // Whole-volume read, compared to the model.
        let mut got = vec![0u8; model.len()];
        c.volume_read(&vol, 0, &mut got).expect("read all");
        assert!(got == model, "volume content matches model");
        // And an unaligned window.
        let mut win = vec![0u8; 60_000];
        c.volume_read(&vol, 25_123, &mut win).expect("read window");
        assert!(win[..] == model[25_123..25_123 + 60_000], "window matches");
    };
    check(&mut c, &model);

    // Out-of-range I/O is refused.
    assert!(c.volume_read(&vol, size - 10, &mut [0u8; 32]).is_err());
    assert!(c.volume_write(&vol, size, b"x").is_err());

    // ── Restart the server: extents + descriptor must persist. ──
    drop(c);
    drop(server);
    let _server = spawn_server(&socket, dir.path());
    let mut c = LoamClient::connect(&socket).expect("reconnect");
    let vol2 = c
        .open_volume(b"tenant", b"/vols/db0")
        .expect("open")
        .expect("descriptor bound");
    assert_eq!(vol2.desc, vol.desc, "descriptor round-trips");
    check(&mut c, &model);

    // Overwrite after restart still works (mutable keyed blobs).
    c.volume_write(&vol, 30_000, &pat(9, 10_000))
        .expect("rewrite");
    let mut got = vec![0u8; 10_000];
    c.volume_read(&vol, 30_000, &mut got).expect("re-read");
    assert_eq!(got, pat(9, 10_000));

    // Delete: extents and the binding go away.
    c.delete_volume(&vol).expect("delete");
    assert!(c
        .open_volume(b"tenant", b"/vols/db0")
        .expect("gone")
        .is_none());
    // First extent's blob is gone from the body plane too.
    let key0 = loam_client::extent_wire::derive_extent_key(&vol.desc.volume_id, 0);
    assert_eq!(c.get_body(&key0).expect("extent gone"), None);
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
    let refs: Vec<(&[u8], [u8; 32])> = vec![(&b"/absent"[..], [0xAB; 32])];
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
    let refs: Vec<(&[u8], [u8; 32])> =
        vec![(&b"/a"[..], [1u8; 32]), (&b"/nested/b"[..], [2u8; 32])];
    let mut buf = vec![0u8; mw::encoded_len(b"root", &refs)];
    let n = mw::encode(&mut buf, b"root", &refs).unwrap();
    assert_eq!(n, buf.len(), "encoded_len is exact, not an estimate");

    let mut seen = Vec::new();
    let count = mw::for_each(&buf, |k, d| seen.push((k.to_vec(), *d))).unwrap();
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
    assert!(mw::for_each(&buf[..buf.len() - 4], |_, _| {}).is_err());
    let mut bad = buf.clone();
    bad[0] ^= 0xFF;
    assert_eq!(mw::peek(&bad), Err(mw::ManifestError::BadMagic));
}

// ── Remote admin over TCP ─────────────────────────────────────────
//
// This is what a volume backend running off the storage node needs.
// The transport and the authentication are one feature: a TCP admin
// surface without a token is refused at startup, so these tests
// always run authenticated.

/// A server whose admin surface is on TCP, at an address the OS picks.
fn spawn_server_tcp(dir: &std::path::Path, token_file: Option<&std::path::Path>) -> (Proc, String) {
    let mut cmd = Command::new(server_bin());
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
    if let Some(t) = token_file {
        cmd.args(["--admin-token", t.to_str().unwrap()]);
    }
    let (proc, line) = spawn_ready(cmd, "admin surface on tcp");
    (proc, announced_addr(&line).to_string())
}

#[test]
fn a_remote_client_works_over_tcp_once_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let tokf = dir.path().join("token");
    std::fs::write(&tokf, "remote-secret").unwrap();
    let (_g, addr) = spawn_server_tcp(dir.path(), Some(&tokf));

    let mut c = LoamClient::connect_tcp(&addr).expect("tcp connect");
    c.authenticate(b"remote-secret").expect("authenticate");
    c.put_file(b"vol", b"/remote.txt", 1, b"written from off-box")
        .expect("a remote authenticated client can write");
    assert_eq!(
        c.get_file(b"vol", b"/remote.txt").unwrap().as_deref(),
        Some(&b"written from off-box"[..])
    );
}

#[test]
fn tcp_admin_without_a_token_refuses_to_start() {
    // Not "starts and warns" — a misconfigured server that runs is
    // an open admin surface. The refusal is at startup so it cannot
    // be missed, and there is deliberately no --insecure override.
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
        .output()
        .expect("run loam-server");
    assert!(!out.status.success(), "the server must refuse to start");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--admin-listen requires --admin-token"),
        "the refusal must say why; got: {err}"
    );
}

// ── Portable export between two clusters ──────────────────────────
//
// Two real servers, so the transfer is exercised rather than
// asserted. The manifest is encryption-agnostic and its digests are
// over plaintext, so it means the same thing on both
// sides — which is what lets the whole export be ordinary reads and
// writes rather than a protocol.

#[test]
fn a_snapshot_exports_to_a_second_cluster_sending_only_what_it_lacks() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();
    // A TCP admin surface REFUSES to start without a token, so
    // an export between two clusters is authenticated on both ends
    // by construction. There is no unauthenticated path to take.
    let stok = src_dir.path().join("tok");
    let dtok = dst_dir.path().join("tok");
    std::fs::write(&stok, "src-secret").unwrap();
    std::fs::write(&dtok, "dst-secret").unwrap();
    let (_gs, src_addr) = spawn_server_tcp(src_dir.path(), Some(&stok));
    let (_gd, dst_addr) = spawn_server_tcp(dst_dir.path(), Some(&dtok));

    let mut src = LoamClient::connect_tcp(&src_addr).expect("src connect");
    src.authenticate(b"src-secret").unwrap();
    let mut dst = LoamClient::connect_tcp(&dst_addr).expect("dst connect");
    dst.authenticate(b"dst-secret").unwrap();

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
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();
    let stok = src_dir.path().join("tok");
    let dtok = dst_dir.path().join("tok");
    std::fs::write(&stok, "s").unwrap();
    std::fs::write(&dtok, "d").unwrap();
    let (_gs, src_addr) = spawn_server_tcp(src_dir.path(), Some(&stok));
    let (_gd, dst_addr) = spawn_server_tcp(dst_dir.path(), Some(&dtok));
    let mut src = LoamClient::connect_tcp(&src_addr).unwrap();
    src.authenticate(b"s").unwrap();
    let mut dst = LoamClient::connect_tcp(&dst_addr).unwrap();
    dst.authenticate(b"d").unwrap();

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
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();
    let stok = src_dir.path().join("tok");
    let dtok = dst_dir.path().join("tok");
    std::fs::write(&stok, "s").unwrap();
    std::fs::write(&dtok, "d").unwrap();
    let (_gs, src_addr) = spawn_server_tcp(src_dir.path(), Some(&stok));
    let (_gd, dst_addr) = spawn_server_tcp(dst_dir.path(), Some(&dtok));
    let mut src = LoamClient::connect_tcp(&src_addr).unwrap();
    src.authenticate(b"s").unwrap();
    let mut dst = LoamClient::connect_tcp(&dst_addr).unwrap();
    dst.authenticate(b"d").unwrap();

    src.put_file(b"vol", b"/gone", 1, b"will be removed")
        .unwrap();
    let manifest = src.snapshot_create(b"vol", b"snap").unwrap();

    // Forge a manifest naming a body no source holds. Same shape as
    // a source that lost one.
    let mut refs: Vec<(&[u8], [u8; 32])> = Vec::new();
    let phantom = [0x5au8; 32];
    refs.push((&b"/phantom"[..], phantom));
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
