//! Block volumes against a real loam-server: copy-on-write maps of
//! content-addressed extents, committed by a fenced, revisioned bind.
//!
//! What these pin is the contract a block device builds on: a flush is
//! the one atomic point — before it nothing is visible, after it all of
//! it is, and a crash in between leaves the previous revision whole;
//! exactly one writer, whose lease fence gates the commit; and an
//! orphan GC that collects superseded versions while never touching a
//! body a committed root, a snapshot, or a flush still in flight
//! reaches.
//!
//! The server serves one admin connection at a time, so where a test
//! needs two writers they share one connection: what the namespace
//! judges is the holder and fence a record carries, not who sent it.

mod support;

use loam_client::{admin_wire, random_holder, ClientError, LoamClient, VolumeWriter};
use std::process::Command;
use std::time::{Duration, Instant};
use support::{spawn_ready, Proc};

fn spawn_server(socket: &std::path::Path, dir: &std::path::Path, gc_interval: u32) -> Proc {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_loam-server"));
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
        "--gc-interval",
        &gc_interval.to_string(),
    ]);
    spawn_ready(cmd, "admin socket on").0
}

fn pat(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u32 * 7 + seed as u32) % 251) as u8)
        .collect()
}

fn nak(r: Result<impl std::fmt::Debug, ClientError>) -> u8 {
    match r {
        Err(ClientError::Nak(s)) => s,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn read_all(c: &mut LoamClient, root: &[u8], path: &[u8]) -> Vec<u8> {
    let mut vol = c.open_volume(root, path).expect("open").expect("bound");
    let mut out = vec![0u8; vol.size_bytes as usize];
    c.volume_read(&mut vol, 0, &mut out).expect("read");
    out
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    loam_client::content_digest(bytes)
}

/// Poll `cond` until it holds or `within` passes.
fn eventually(within: Duration, what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < within, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn writes_become_visible_and_durable_only_at_the_flush() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let server = spawn_server(&socket, dir.path(), 0);
    let mut c = LoamClient::connect(&socket).expect("connect");

    // 200 KiB in 32 KiB extents: 7 extents, a short tail, depth 1.
    let size = 200 * 1024u64;
    let vol = c
        .create_volume(b"tenant", b"/vols/db0", size, 32 * 1024)
        .expect("create");
    assert_eq!((vol.revision, vol.depth), (1, 1));
    assert_eq!(
        nak(c.create_volume(b"tenant", b"/vols/db0", size, 32 * 1024)),
        admin_wire::STATUS_CONFLICT,
        "creation cannot overwrite a volume that exists"
    );
    assert!(
        read_all(&mut c, b"tenant", b"/vols/db0")
            .iter()
            .all(|&b| b == 0),
        "an unwritten volume reads as zeros"
    );

    let mut w = VolumeWriter::open(&mut c, vol, random_holder(), 60_000).expect("writer");
    let mut model = vec![0u8; size as usize];
    let writes: [(usize, Vec<u8>); 4] = [
        (0, pat(1, 1000)),                    // head of extent 0
        (30_000, pat(2, 40_000)),             // spans extents 0..2
        (100_000, pat(3, 5)),                 // tiny mid-extent RMW
        ((size - 700) as usize, pat(4, 700)), // the short tail
    ];
    for (off, data) in &writes {
        w.write(&mut c, *off as u64, data).expect("stage");
        model[*off..*off + data.len()].copy_from_slice(data);
    }
    // The writer reads its own staged writes...
    let mut mine = vec![0u8; size as usize];
    w.read(&mut c, 0, &mut mine)
        .expect("read through the writer");
    assert!(mine == model);
    // ...and nobody else sees any of them.
    assert!(read_all(&mut c, b"tenant", b"/vols/db0")
        .iter()
        .all(|&b| b == 0));

    assert_eq!(
        w.flush(&mut c).expect("flush"),
        2,
        "one commit, one revision"
    );
    assert_eq!(w.staged_extents(), 0);
    assert!(
        read_all(&mut c, b"tenant", b"/vols/db0") == model,
        "all of it at once"
    );

    // An unaligned window.
    let mut vol = c.open_volume(b"tenant", b"/vols/db0").unwrap().unwrap();
    let mut win = vec![0u8; 60_000];
    c.volume_read(&mut vol, 25_123, &mut win).expect("window");
    assert!(win[..] == model[25_123..25_123 + 60_000]);
    // Out-of-range I/O is refused.
    assert!(c.volume_read(&mut vol, size - 10, &mut [0u8; 32]).is_err());
    assert!(w.write(&mut c, size, b"x").is_err());

    // A flush with nothing staged commits nothing.
    assert_eq!(w.flush(&mut c).expect("empty flush"), 2);

    // ── Restart: the committed revision is what persists. ──
    w.write(&mut c, 0, &pat(8, 100))
        .expect("stage, never flushed");
    drop(w);
    drop(c);
    drop(server);
    let _server = spawn_server(&socket, dir.path(), 0);
    let mut c = LoamClient::connect(&socket).expect("reconnect");
    let vol = c.open_volume(b"tenant", b"/vols/db0").unwrap().unwrap();
    assert_eq!(vol.revision, 2);
    assert!(read_all(&mut c, b"tenant", b"/vols/db0") == model);

    // The lease the dropped writer held is still live, and it replays
    // across the restart: nobody else may delete the volume under it.
    assert_eq!(
        nak(c.delete_volume(b"tenant", b"/vols/db0")),
        admin_wire::STATUS_LEASE_HELD
    );
    assert!(c.open_volume(b"tenant", b"/vols/db0").unwrap().is_some());
}

#[test]
fn a_depth_two_volume_maps_across_leaves() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let _server = spawn_server(&socket, dir.path(), 0);
    let mut c = LoamClient::connect(&socket).expect("connect");

    // One full leaf of 4 KiB extents and three more: depth 2, two leaves.
    let es = 4096u64;
    let size = (1024 + 3) * es;
    let vol = c
        .create_volume(b"t", b"/deep", size, es as u32)
        .expect("create");
    assert_eq!(vol.depth, 2);
    let mut w = VolumeWriter::open(&mut c, vol, random_holder(), 60_000).unwrap();
    // Straddle the leaf boundary (extents 1023 | 1024), and hit the
    // last extent.
    let span = pat(5, 3 * es as usize);
    w.write(&mut c, 1022 * es + 17, &span).unwrap();
    w.write(&mut c, size - 9, &pat(6, 9)).unwrap();
    w.flush(&mut c).unwrap();

    let mut vol = c.open_volume(b"t", b"/deep").unwrap().unwrap();
    let mut got = vec![0u8; span.len()];
    c.volume_read(&mut vol, 1022 * es + 17, &mut got).unwrap();
    assert_eq!(got, span);
    let mut tail = [0u8; 9];
    c.volume_read(&mut vol, size - 9, &mut tail).unwrap();
    assert_eq!(&tail[..], &pat(6, 9)[..]);
    let mut untouched = vec![0xFFu8; 8192];
    c.volume_read(&mut vol, 10 * es, &mut untouched).unwrap();
    assert!(untouched.iter().all(|&b| b == 0));

    // Rewriting only the second leaf leaves the first leaf's page as it
    // was: the new root names the same first-leaf digest.
    let before = c.volume_bodies(&vol.root_digest).unwrap();
    w.write(&mut c, 1025 * es, &pat(7, 10)).unwrap();
    w.flush(&mut c).unwrap();
    let vol2 = c.open_volume(b"t", b"/deep").unwrap().unwrap();
    let after = c.volume_bodies(&vol2.root_digest).unwrap();
    assert_eq!(
        before[0], after[0],
        "the unchanged leaf is shared, not rewritten"
    );
    assert_ne!(vol.root_digest, vol2.root_digest);
}

#[test]
fn a_crash_between_the_bodies_and_the_commit_leaves_the_old_root() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let _server = spawn_server(&socket, dir.path(), 0);
    let mut c = LoamClient::connect(&socket).expect("connect");
    let vol = c.create_volume(b"t", b"/v", 64 * 1024, 16 * 1024).unwrap();
    let mut w = VolumeWriter::open(&mut c, vol, random_holder(), 500).unwrap();
    w.write(&mut c, 0, &[0xA1; 64 * 1024]).unwrap();
    w.flush(&mut c).unwrap();

    // Every body of the next flush lands — then the writer dies before
    // the commit.
    w.write(&mut c, 0, &[0xB2; 64 * 1024]).unwrap();
    w.prepare(&mut c).expect("bodies written");
    assert!(
        c.get_body(&sha(&[0xB2; 16 * 1024])).unwrap().is_some(),
        "the new extent is in the store"
    );
    drop(w);

    let vol = c.open_volume(b"t", b"/v").unwrap().unwrap();
    assert_eq!(vol.revision, 2, "still the last committed revision");
    assert!(
        read_all(&mut c, b"t", b"/v").iter().all(|&b| b == 0xA1),
        "and all of it: never a mix of the two"
    );

    // Once the dead writer's lease lapses, a new one takes over and
    // commits on top of the old root.
    std::thread::sleep(Duration::from_millis(600));
    let mut w2 = VolumeWriter::open(&mut c, vol, random_holder(), 60_000).expect("takeover");
    w2.write(&mut c, 16 * 1024, &[0xC3; 16]).unwrap();
    assert_eq!(w2.flush(&mut c).unwrap(), 3);
    let all = read_all(&mut c, b"t", b"/v");
    assert!(all[..16 * 1024].iter().all(|&b| b == 0xA1));
    assert!(all[16 * 1024..16 * 1024 + 16].iter().all(|&b| b == 0xC3));
}

#[test]
fn a_second_writer_is_refused_the_lease() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let _server = spawn_server(&socket, dir.path(), 0);
    let mut c = LoamClient::connect(&socket).expect("connect");
    c.create_volume(b"t", b"/v", 64 * 1024, 16 * 1024).unwrap();
    let v1 = c.open_volume(b"t", b"/v").unwrap().unwrap();
    let v2 = c.open_volume(b"t", b"/v").unwrap().unwrap();
    let mut a = VolumeWriter::open(&mut c, v1, random_holder(), 60_000).unwrap();
    assert_eq!(
        nak(VolumeWriter::open(&mut c, v2, random_holder(), 60_000)),
        admin_wire::STATUS_LEASE_HELD
    );
    // Nor can anyone commit around it without the lease: a hand-built
    // commit under an invented holder is refused at the bind.
    assert_eq!(
        c.volume_record(
            admin_wire::VOLUME_BEGIN,
            b"t",
            b"/v",
            &random_holder(),
            a.lease().fence,
            0,
            &[],
        )
        .unwrap()
        .0,
        admin_wire::STATUS_LEASE_LOST
    );
    a.write(&mut c, 0, b"mine").unwrap();
    a.flush(&mut c).unwrap();
    // Released, the next writer gets it under the next fence.
    let fence = a.lease().fence;
    a.release(&mut c).unwrap();
    let v3 = c.open_volume(b"t", b"/v").unwrap().unwrap();
    let b = VolumeWriter::open(&mut c, v3, random_holder(), 60_000).unwrap();
    assert_eq!(b.lease().fence, fence + 1);
}

#[test]
fn two_writers_race_to_the_next_revision_and_exactly_one_wins() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let _server = spawn_server(&socket, dir.path(), 0);
    let mut c = LoamClient::connect(&socket).expect("connect");
    c.create_volume(b"t", b"/v", 64 * 1024, 16 * 1024).unwrap();

    // Two attachments under one holder identity both hold the lease, so
    // the fence cannot tell them apart: the revision has to.
    let holder = random_holder();
    let v1 = c.open_volume(b"t", b"/v").unwrap().unwrap();
    let v2 = c.open_volume(b"t", b"/v").unwrap().unwrap();
    let mut a = VolumeWriter::open(&mut c, v1, holder, 60_000).unwrap();
    let mut b = VolumeWriter::open(&mut c, v2, holder, 60_000).unwrap();
    a.write(&mut c, 0, &[0xAA; 100]).unwrap();
    b.write(&mut c, 20_000, &[0xBB; 100]).unwrap();
    a.prepare(&mut c).unwrap();
    b.prepare(&mut c).unwrap();

    assert_eq!(a.commit(&mut c).expect("the first to commit wins"), 2);
    assert_eq!(
        nak(b.commit(&mut c)),
        admin_wire::STATUS_CONFLICT,
        "the second built on revision 1, which is gone"
    );
    // The loser is ended — no silent merge, no retry on top of a view
    // that is no longer the volume.
    assert!(matches!(
        b.write(&mut c, 0, b"x"),
        Err(ClientError::Volume(_))
    ));
    let all = read_all(&mut c, b"t", b"/v");
    assert!(all[..100].iter().all(|&x| x == 0xAA));
    assert!(
        all[20_000..20_100].iter().all(|&x| x == 0),
        "nothing of the loser's flush is visible"
    );
    // Reopened, it writes on top of what is there.
    let v = c.open_volume(b"t", b"/v").unwrap().unwrap();
    let mut b2 = VolumeWriter::open(&mut c, v, holder, 60_000).unwrap();
    b2.write(&mut c, 20_000, &[0xBB; 100]).unwrap();
    assert_eq!(b2.flush(&mut c).unwrap(), 3);
    let all = read_all(&mut c, b"t", b"/v");
    assert!(
        all[..100].iter().all(|&x| x == 0xAA) && all[20_000..20_100].iter().all(|&x| x == 0xBB)
    );
}

#[test]
fn an_expired_lease_takeover_refuses_the_old_writers_commit() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let _server = spawn_server(&socket, dir.path(), 0);
    let mut c = LoamClient::connect(&socket).expect("connect");
    let vol = c.create_volume(b"t", b"/v", 64 * 1024, 16 * 1024).unwrap();
    let mut a = VolumeWriter::open(&mut c, vol, random_holder(), 400).unwrap();
    a.write(&mut c, 0, &[0xA1; 100]).unwrap();
    a.prepare(&mut c)
        .expect("a's bodies are written under its lease");

    // A stalls past its lease; B takes the volume over and commits.
    std::thread::sleep(Duration::from_millis(500));
    let v = c.open_volume(b"t", b"/v").unwrap().unwrap();
    let mut b = VolumeWriter::open(&mut c, v, random_holder(), 60_000).expect("takeover");
    assert!(b.lease().fence > a.lease().fence);
    b.write(&mut c, 0, &[0xB1; 100]).unwrap();
    assert_eq!(b.flush(&mut c).unwrap(), 2);

    // A wakes up still believing it holds the volume. Its commit carries
    // the old fence and is refused at the bind.
    assert_eq!(nak(a.commit(&mut c)), admin_wire::STATUS_LEASE_LOST);
    assert!(a.write(&mut c, 0, b"x").is_err(), "and the writer is ended");
    let all = read_all(&mut c, b"t", b"/v");
    assert!(
        all[..100].iter().all(|&x| x == 0xB1),
        "only B's write stands"
    );
}

/// A body is referenced if some bound root reaches it. The GC keeps
/// every page and extent of a committed root and of a snapshot, keeps
/// everything while a flush is open, and collects what commits have
/// superseded.
#[test]
fn the_gc_follows_the_maps_and_never_collects_an_undecided_flush() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let _server = spawn_server(&socket, dir.path(), 1);
    let mut c = LoamClient::connect(&socket).expect("connect");
    let within = Duration::from_secs(30);
    let es = 4096usize;

    let vol = c
        .create_volume(b"t", b"/v", 4 * es as u64, es as u32)
        .unwrap();
    let mut w = VolumeWriter::open(&mut c, vol, random_holder(), 60_000).unwrap();
    let (x1, y, x2) = (vec![0x11u8; es], vec![0x22u8; es], vec![0x33u8; es]);
    w.write(&mut c, 0, &x1).unwrap();
    w.write(&mut c, es as u64, &y).unwrap();
    w.flush(&mut c).unwrap();
    let root2 = w.volume().root_digest;
    w.write(&mut c, 0, &x2).unwrap();
    w.flush(&mut c).unwrap();

    // X1 and the revision-2 root are superseded: collected.
    eventually(within, "the superseded extent to be collected", || {
        c.get_body(&sha(&x1)).unwrap().is_none()
    });
    eventually(within, "the superseded root to be collected", || {
        c.get_body(&root2).unwrap().is_none()
    });
    assert!(
        c.get_body(&sha(&y)).unwrap().is_some(),
        "a committed extent stays"
    );
    assert!(c.get_body(&sha(&x2)).unwrap().is_some());
    assert!(c.get_body(&w.volume().root_digest).unwrap().is_some());

    // A flush in flight: its bodies are in the store and no bound root
    // reaches them. The GC must keep them however long the commit takes.
    let z = vec![0x44u8; es];
    w.write(&mut c, 2 * es as u64, &z).unwrap();
    w.prepare(&mut c).unwrap();
    // An orphan put now is kept too: nothing is provable while a flush
    // is open.
    let stray = c.put_body(b"an orphan put during the flush").unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        c.get_body(&sha(&z)).unwrap().is_some(),
        "the undecided flush's extent was not collected"
    );
    assert!(c.get_body(&stray).unwrap().is_some());
    assert_eq!(w.commit(&mut c).unwrap(), 4);
    let all = read_all(&mut c, b"t", b"/v");
    assert!(all[2 * es..3 * es].iter().all(|&b| b == 0x44));

    // Once the flush is decided, collection resumes.
    eventually(within, "the orphan put during the flush", || {
        c.get_body(&stray).unwrap().is_none()
    });
    for (what, d) in [("x2", sha(&x2)), ("y", sha(&y)), ("z", sha(&z))] {
        assert!(c.get_body(&d).unwrap().is_some(), "{what} is committed");
    }

    // A snapshot pins a root, and that root pins its extents, through
    // any number of later overwrites.
    let manifest = c.snapshot_create(b"t", b"snap").unwrap();
    assert_eq!(loam_client::manifest_wire::peek(&manifest).unwrap().1, 1);
    let snapped = all.clone();
    w.write(&mut c, 0, &[0x55; 4 * 4096]).unwrap();
    w.flush(&mut c).unwrap();
    let witness = c.put_body(b"collected once the pass has run").unwrap();
    eventually(within, "a later orphan to be collected", || {
        c.get_body(&witness).unwrap().is_none()
    });
    assert_eq!(
        read_all(&mut c, b"snap", b"/v"),
        snapped,
        "the snapshot reads the version it froze"
    );
    assert!(read_all(&mut c, b"t", b"/v").iter().all(|&b| b == 0x55));

    // Dropping the snapshot and the volume leaves nothing reachable.
    assert_eq!(c.snapshot_delete(b"snap").unwrap(), 1);
    w.release(&mut c).unwrap();
    assert!(c.delete_volume(b"t", b"/v").unwrap());
    eventually(within, "every extent of the dropped volume", || {
        [sha(&x2), sha(&y), sha(&z), sha(&[0x55; 4096])]
            .iter()
            .all(|d| c.get_body(d).unwrap().is_none())
    });
}

#[test]
fn a_volume_snapshot_restores_as_a_volume_and_exports_whole() {
    let src_dir = tempfile::tempdir().unwrap();
    let src_sock = src_dir.path().join("admin.sock");
    let _src = spawn_server(&src_sock, src_dir.path(), 0);
    let dst_dir = tempfile::tempdir().unwrap();
    let dst_sock = dst_dir.path().join("admin.sock");
    let _dst = spawn_server(&dst_sock, dst_dir.path(), 0);
    let mut src = LoamClient::connect(&src_sock).unwrap();
    let mut dst = LoamClient::connect(&dst_sock).unwrap();

    let es = 4096u64;
    let vol = src
        .create_volume(b"t", b"/v", (1024 + 2) * es, es as u32)
        .unwrap();
    let mut w = VolumeWriter::open(&mut src, vol, random_holder(), 60_000).unwrap();
    w.write(&mut src, 1023 * es, &pat(9, 2 * es as usize))
        .unwrap();
    w.flush(&mut src).unwrap();
    let want = read_all(&mut src, b"t", b"/v");

    let manifest = src.snapshot_create(b"t", b"snap").unwrap();
    // A clone in place is a volume, and reads the same.
    assert_eq!(src.snapshot_restore(&manifest, b"clone").unwrap(), 1);
    assert_eq!(read_all(&mut src, b"clone", b"/v"), want);
    // Exported, every page and extent the root reaches travels with it.
    let (sent, bound) = loam_client::export_snapshot(&mut src, &mut dst, &manifest, b"t").unwrap();
    assert_eq!(bound, 1);
    assert!(sent >= 4, "root, two leaves and the written extents");
    assert_eq!(read_all(&mut dst, b"t", b"/v"), want);
}

/// Nothing but a fenced VOLUME record changes a volume: a plain bind,
/// delete or bind-as-volume through the admin surface is refused, and
/// deletion goes through the lease like a commit.
#[test]
fn plain_namespace_ops_cannot_bypass_a_volume() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let _server = spawn_server(&socket, dir.path(), 0);
    let mut c = LoamClient::connect(&socket).expect("connect");
    let vol = c.create_volume(b"t", b"/v", 64 * 1024, 16 * 1024).unwrap();
    let root_oid = loam_client::object_id_for(&vol.root_digest);
    let file = c.put_file(b"t", b"/f", 1, b"a plain file").unwrap();
    let file_oid = loam_client::object_id_for(&file);

    assert_eq!(
        nak(c.bind(b"t", b"/v", file_oid.as_bytes(), 99)),
        admin_wire::STATUS_NAK,
        "a plain bind cannot replace a volume"
    );
    assert_eq!(
        nak(c.put_file(b"t", b"/v", 99, b"clobber")),
        admin_wire::STATUS_NAK,
        "nor can a composed write"
    );
    assert_eq!(
        nak(c.bind_as(
            b"t",
            b"/v2",
            root_oid.as_bytes(),
            loam_client::KIND_VOLUME,
            1
        )),
        admin_wire::STATUS_NAK,
        "a plain bind cannot create a volume binding"
    );
    assert_eq!(
        nak(c.delete_file(b"t", b"/v")),
        admin_wire::STATUS_NAK,
        "a plain delete does not remove a volume"
    );
    assert!(c.lookup(b"t", b"/v2").unwrap().is_none());
    let b = c.lookup(b"t", b"/v").unwrap().expect("still bound");
    assert_eq!(
        (b.object_id, b.revision, b.kind),
        (root_oid.into_bytes(), 1, loam_client::KIND_VOLUME)
    );
    assert!(
        matches!(c.delete_volume(b"t", b"/f"), Err(ClientError::Volume(_))),
        "a file is not deleted as a volume"
    );

    // A writer holds it: deletion is refused until the lease is released.
    let mut w = VolumeWriter::open(&mut c, vol, random_holder(), 60_000).unwrap();
    w.write(&mut c, 0, b"x").unwrap();
    w.flush(&mut c).unwrap();
    assert_eq!(
        nak(c.delete_volume(b"t", b"/v")),
        admin_wire::STATUS_LEASE_HELD
    );
    w.release(&mut c).unwrap();
    assert!(c.delete_volume(b"t", b"/v").unwrap());
    assert!(c.open_volume(b"t", b"/v").unwrap().is_none());
    assert!(
        !c.delete_volume(b"t", b"/v").unwrap(),
        "nothing left to delete"
    );
    // And it can be created again.
    c.create_volume(b"t", b"/v", 64 * 1024, 16 * 1024).unwrap();
}

/// A writer that dies mid-flush does not keep the GC off the store for
/// good: once its lease has expired, the next sweep ends its flush and
/// collects what it wrote, and its commit, if it ever comes, is refused.
#[test]
fn a_crashed_writers_flush_stops_guarding_once_its_lease_expires() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let _server = spawn_server(&socket, dir.path(), 1);
    let mut c = LoamClient::connect(&socket).expect("connect");
    let vol = c.create_volume(b"t", b"/v", 16 * 1024, 4096).unwrap();
    // Long enough that opening, writing and preparing finish inside it on
    // a loaded host; the expiry under test comes after the writer stalls.
    let mut w = VolumeWriter::open(&mut c, vol, random_holder(), 3_000).unwrap();
    let extent = vec![0x6Du8; 4096];
    w.write(&mut c, 0, &extent).unwrap();
    w.prepare(&mut c).expect("bodies written, flush open");
    assert!(c.get_body(&sha(&extent)).unwrap().is_some());

    // The writer stalls. Past its lease, the sweep reclaims its bodies.
    eventually(
        Duration::from_secs(30),
        "the stalled flush's extent to be collected",
        || c.get_body(&sha(&extent)).unwrap().is_none(),
    );
    assert_eq!(nak(w.commit(&mut c)), admin_wire::STATUS_LEASE_LOST);
    let vol = c.open_volume(b"t", b"/v").unwrap().unwrap();
    assert_eq!(vol.revision, 1, "the volume never saw the flush");
    assert!(read_all(&mut c, b"t", b"/v").iter().all(|&b| b == 0));
}
