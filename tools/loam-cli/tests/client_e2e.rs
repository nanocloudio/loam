//! The `loam-client` crate against a real loam-server: every
//! public call, over the actual unix admin socket. This is the
//! contract a volume backend (nanocloud's CsiPlugin) builds on.

use loam_client::{ClientError, LoamClient, IO_CHUNK};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_loam-server")
}

struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_server(socket: &std::path::Path, dir: &std::path::Path) -> ServerGuard {
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
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    let child = cmd.spawn().expect("spawn loam-server");
    let started = Instant::now();
    while !socket.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "loam-server didn't open its socket within 5s"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(50));
    ServerGuard(child)
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
