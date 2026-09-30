//! The `loam_volume` PIC as a `storage.block` source, against a real
//! loam-server.
//!
//! The module's step body runs in-process on a host syscall table, and
//! its admin channel is carried to the server's unix socket — the same
//! admin wire the node graph's `admin_router` answers, so this is the
//! co-located composition with the socket standing in for the channel
//! edge. The test is the block consumer: it drives CAPS, EXEC, SUBMIT and
//! REAP exactly as a consumer's `BlockClient` would, stepping the module
//! between retries.
//!
//! What these pin:
//! - the contract rules of Fluxor's block conformance corpus, adapted to
//!   a networked source: `EXEC` may answer `EAGAIN` while the module
//!   fetches or commits, and a durable fence is the volume's commit
//!   point (`RevisionMonotone`), not a local device's;
//! - that what the module commits is a volume `loam-client` reads back
//!   byte for byte;
//! - one writer: a second instance is refused while the lease is live,
//!   and a writer that lost its lease fails closed without landing a
//!   byte;
//! - durability: a flushed volume survives a restart of the server and
//!   of the module, and writes never flushed are gone.

mod support;

#[allow(
    dead_code,
    unused_imports,
    reason = "shared fluxor SDK include; each includer uses a subset"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

#[allow(
    dead_code,
    unused_imports,
    reason = "shared fluxor SDK include; each includer uses a subset"
)]
mod sha256_impl {
    include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
}
mod sha256 {
    pub use super::sha256_impl::Sha256;
}

#[path = "../../../modules/common/mechanics/loam_limits.rs"]
mod limits;

#[path = "../../../modules/common/mechanics/loam_admin_wire.rs"]
mod admin;

#[path = "../../../modules/common/mechanics/loam_volume_map_wire.rs"]
mod map_wire;

#[allow(
    dead_code,
    reason = "shared PIC body include; each includer drives a subset"
)]
#[path = "../../../modules/common/replicated/loam_volume_body.rs"]
mod body;

use abi::contracts::storage::block::{self as blk, caps, ioctl, op, Caps, Cpl, Req};
use abi::fence::Fence;
use loam_client::LoamClient;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use support::{spawn_ready, Proc};

const EIO: i32 = -5;
const EAGAIN: i32 = -11;
const EBUSY: i32 = -16;
const EINVAL: i32 = -22;

const ROOT: &[u8] = b"tenant";

// ── The host syscall table ─────────────────────────────────────────
//
// Channels are byte streams, per test thread, so suites running in
// parallel never see each other's traffic.

thread_local! {
    static CHANS: RefCell<HashMap<i32, VecDeque<u8>>> = RefCell::new(HashMap::new());
    static EPOCH: Instant = Instant::now();
    static SEED: RefCell<u64> = const { RefCell::new(0) };
}

unsafe extern "C" fn chan_read(h: i32, buf: *mut u8, len: usize) -> i32 {
    CHANS.with(|c| {
        let mut c = c.borrow_mut();
        let q = c.entry(h).or_default();
        let n = q.len().min(len);
        for i in 0..n {
            let b = q.pop_front().unwrap_or(0);
            unsafe { *buf.add(i) = b };
        }
        n as i32
    })
}

unsafe extern "C" fn chan_write(h: i32, data: *const u8, len: usize) -> i32 {
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    CHANS.with(|c| c.borrow_mut().entry(h).or_default().extend(bytes));
    len as i32
}

fn chan_take(h: i32) -> Vec<u8> {
    CHANS.with(|c| c.borrow_mut().entry(h).or_default().drain(..).collect())
}

fn chan_put_front(h: i32, bytes: &[u8]) {
    CHANS.with(|c| {
        let mut c = c.borrow_mut();
        let q = c.entry(h).or_default();
        for b in bytes.iter().rev() {
            q.push_front(*b);
        }
    });
}

fn chan_push(h: i32, bytes: &[u8]) {
    CHANS.with(|c| c.borrow_mut().entry(h).or_default().extend(bytes));
}

unsafe extern "C" fn provider_call(handle: i32, op: u32, arg: *mut u8, len: usize) -> i32 {
    match op {
        // TIMER::MILLIS
        0x0602 => {
            let ms = EPOCH.with(|e| e.elapsed().as_millis() as u64);
            unsafe { std::ptr::copy_nonoverlapping(ms.to_le_bytes().as_ptr(), arg, len.min(8)) };
            0
        }
        // CSPRNG: distinct per call and per run is all a holder needs.
        0x0C3C => {
            use std::hash::{BuildHasher, Hasher};
            for i in 0..len {
                let v = SEED.with(|s| {
                    let mut s = s.borrow_mut();
                    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
                    h.write_u64(*s);
                    h.write_u128(EPOCH.with(|e| e.elapsed().as_nanos()));
                    *s = h.finish();
                    *s
                });
                unsafe { *arg.add(i) = v as u8 };
            }
            0
        }
        // LOG_WRITE
        0x0C40 => {
            let msg = unsafe { std::slice::from_raw_parts(arg, len) };
            eprintln!("[level {handle}] {}", String::from_utf8_lossy(msg));
            0
        }
        _ => -38,
    }
}

unsafe extern "C" fn no_poll(_h: i32, _e: u32) -> i32 {
    -1
}
unsafe extern "C" fn no_alloc(_s: u32) -> *mut u8 {
    std::ptr::null_mut()
}
unsafe extern "C" fn no_free(_p: *mut u8) {}
unsafe extern "C" fn no_realloc(_p: *mut u8, _n: u32) -> *mut u8 {
    std::ptr::null_mut()
}
unsafe extern "C" fn no_open(_c: u32, _o: u32, _cfg: *const u8, _l: usize) -> i32 {
    -1
}
unsafe extern "C" fn no_query(_h: i32, _k: u32, _o: *mut u8, _l: usize) -> i32 {
    -1
}
unsafe extern "C" fn no_close(_h: i32) -> i32 {
    -1
}
unsafe extern "C" fn no_peek(_h: i32, _b: *mut u8, _l: usize) -> i32 {
    -1
}
unsafe extern "C" fn no_call_sel(
    _sel: *const u8,
    _sel_len: usize,
    _op_handle: i32,
    _op: u32,
    _arg: *mut u8,
    _arg_len: usize,
) -> i32 {
    -1
}

fn syscalls() -> SyscallTable {
    SyscallTable {
        version: 1,
        channel_read: chan_read,
        channel_write: chan_write,
        channel_poll: no_poll,
        heap_alloc: no_alloc,
        heap_free: no_free,
        heap_realloc: no_realloc,
        provider_open: no_open,
        provider_call,
        provider_query: no_query,
        provider_close: no_close,
        channel_peek: no_peek,
        telemetry_enabled: std::ptr::null(),
        provider_call_sel: no_call_sel,
    }
}

// ── One module instance ────────────────────────────────────────────

struct Node {
    // The body keeps a pointer to the table, so it lives as long as the
    // state does.
    _sys: Box<SyscallTable>,
    mem: Vec<u64>,
    resp: i32,
    req: i32,
    frozen: bool,
}

impl Node {
    fn new(id: i32, path: &[u8], ttl_ms: u32, block_size: u32) -> Node {
        let size = core::mem::size_of::<body::ModuleState>();
        let mut n = Node {
            _sys: Box::new(syscalls()),
            mem: vec![0u64; size / 8 + 1],
            resp: id * 10 + 1,
            req: id * 10 + 2,
            frozen: false,
        };
        let sys: *const SyscallTable = &*n._sys;
        let p = n.mem.as_mut_ptr() as *mut u8;
        let rc = unsafe { body::module_new_impl(n.resp, id * 10 + 3, n.req, p, size, sys) };
        assert_eq!(rc, 0, "module_new");
        unsafe { body::configure(p, ROOT, path, ttl_ms, block_size) };
        n
    }

    fn state(&self) -> &body::ModuleState {
        unsafe { &*(self.mem.as_ptr() as *const body::ModuleState) }
    }

    fn step(&mut self) -> i32 {
        unsafe { body::module_step_impl(self.mem.as_mut_ptr() as *mut u8) }
    }

    fn ioctl(&mut self, cmd: u32, arg: &mut [u8]) -> i32 {
        unsafe {
            body::block_ioctl(
                self.mem.as_mut_ptr() as *mut core::ffi::c_void,
                cmd,
                arg.as_mut_ptr(),
            )
        }
    }

    fn caps_rc(&mut self) -> (i32, Option<Caps>) {
        let mut b = [0u8; caps::LEN];
        let rc = self.ioctl(ioctl::CAPS, &mut b);
        (rc, Caps::decode(&b))
    }
}

// ── The admin link: every instance's channel pair over one socket ──

struct Bridge {
    sock: UnixStream,
    rx: Vec<u8>,
    routes: HashMap<u32, i32>,
}

impl Bridge {
    fn connect(socket: &Path) -> Bridge {
        let sock = UnixStream::connect(socket).expect("connect admin socket");
        sock.set_read_timeout(Some(Duration::from_micros(200)))
            .unwrap();
        Bridge {
            sock,
            rx: Vec::new(),
            routes: HashMap::new(),
        }
    }

    /// Carry each instance's requests to the server and each ack back to
    /// the instance that asked, by correlation id.
    fn pump(&mut self, nodes: &[&Node]) {
        for n in nodes {
            let bytes = chan_take(n.req);
            let mut at = 0;
            while at < bytes.len() {
                match admin::request_len(&bytes[at..]) {
                    Ok(len) if at + len <= bytes.len() => {
                        let frame = &bytes[at..at + len];
                        let cid = u32::from_le_bytes(frame[1..5].try_into().unwrap());
                        self.routes.insert(cid, n.resp);
                        self.sock.write_all(frame).expect("send to server");
                        at += len;
                    }
                    Ok(_) | Err(admin::WireError::Truncated) => break,
                    Err(e) => panic!("module sent an unframeable request: {e:?}"),
                }
            }
            chan_put_front(n.req, &bytes[at..]);
        }
        let mut buf = [0u8; 65536];
        loop {
            match self.sock.read(&mut buf) {
                Ok(0) => panic!("server closed the admin connection"),
                Ok(k) => self.rx.extend_from_slice(&buf[..k]),
                Err(_) => break,
            }
        }
        loop {
            match body::ack_len(&self.rx) {
                Ok(Some(len)) => {
                    let frame: Vec<u8> = self.rx.drain(..len).collect();
                    let cid = u32::from_le_bytes(frame[1..5].try_into().unwrap());
                    if let Some(resp) = self.routes.remove(&cid) {
                        chan_push(resp, &frame);
                    }
                }
                Ok(None) => break,
                Err(()) => panic!("server sent an ack the module never asked for"),
            }
        }
    }
}

struct World {
    bridge: Bridge,
    nodes: Vec<Node>,
}

impl World {
    fn new(socket: &Path) -> World {
        World {
            bridge: Bridge::connect(socket),
            nodes: Vec::new(),
        }
    }

    fn tick(&mut self) {
        let refs: Vec<&Node> = self.nodes.iter().collect();
        self.bridge.pump(&refs);
        for n in &mut self.nodes {
            if !n.frozen {
                n.step();
            }
        }
        std::thread::sleep(Duration::from_micros(100));
    }

    fn until(&mut self, what: &str, mut done: impl FnMut(&mut World) -> bool) {
        let start = Instant::now();
        while !done(self) {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "timed out waiting for {what}"
            );
            self.tick();
        }
    }

    /// Step until node `i` mounts (CAPS answers) or fails; its CAPS rc.
    fn mount(&mut self, i: usize) -> i32 {
        let mut rc = EAGAIN;
        self.until("the device to attach", |w| {
            rc = w.nodes[i].caps_rc().0;
            rc != EAGAIN
        });
        rc
    }

    /// EXEC, retried across steps while the module answers `EAGAIN`.
    fn exec(&mut self, i: usize, r: &Req) -> (i32, Cpl) {
        let mut b = [0u8; blk::req::LEN + blk::cpl::LEN];
        let start = Instant::now();
        loop {
            r.encode(&mut b);
            let rc = self.nodes[i].ioctl(ioctl::EXEC, &mut b);
            if rc != EAGAIN {
                return (rc, Cpl::decode(&b[blk::req::LEN..]).unwrap());
            }
            if start.elapsed() > Duration::from_secs(30) {
                let st = self.nodes[i].state();
                panic!(
                    "EXEC never completed: op {} lba {}; commit phase {}, job {}, \
                     staged {}, commits {}, fetches {}, revision {}, io {}/{}/{}, job_at {}, fail {}",
                    r.op, r.lba, st.commit, st.job, st.staged, st.commits, st.fetches, st.revision, st.io_sent, st.io_len, st.io_rx, st.job_at, st.fail
                );
            }
            self.tick();
        }
    }

    fn submit(&mut self, i: usize, r: &Req) -> i32 {
        let mut b = [0u8; blk::req::LEN];
        r.encode(&mut b);
        self.nodes[i].ioctl(ioctl::SUBMIT, &mut b)
    }

    fn reap(&mut self, i: usize) -> Option<Cpl> {
        let mut b = [0u8; blk::cpl::LEN];
        match self.nodes[i].ioctl(ioctl::REAP, &mut b) {
            1 => Some(Cpl::decode(&b).unwrap()),
            0 => None,
            rc => panic!("REAP returned {rc}"),
        }
    }

    /// Reap `n` completions, stepping while they are still in flight.
    fn reap_n(&mut self, i: usize, n: usize) -> Vec<Cpl> {
        let mut out = Vec::new();
        self.until("completions", |w| {
            while let Some(c) = w.reap(i) {
                out.push(c);
            }
            out.len() >= n
        });
        out
    }
}

// ── Requests ───────────────────────────────────────────────────────

fn data(op: u8, flags: u8, lba: u64, n: u32, buf: &mut [u8], tag: u64) -> Req {
    Req {
        op,
        flags,
        nblocks: n,
        lba,
        buf_ptr: buf.as_mut_ptr() as u64,
        buf_len: buf.len() as u32,
        tag,
    }
}

fn bare(op: u8, flags: u8, lba: u64, n: u32, tag: u64) -> Req {
    Req {
        op,
        flags,
        nblocks: n,
        lba,
        buf_ptr: 0,
        buf_len: 0,
        tag,
    }
}

fn fence_of(c: &Cpl) -> Option<Fence> {
    if c.fence_len == 0 {
        None
    } else {
        Some(
            Fence::decode(c.fence_bytes())
                .expect("a completion fence decodes")
                .0,
        )
    }
}

/// The revision a durable completion names, checking it is the commit
/// point of the device `caps` describes.
fn committed_at(c: &Cpl, caps: &Caps) -> u64 {
    match fence_of(c) {
        Some(Fence::RevisionMonotone { source, revision }) => {
            assert_eq!(
                u64::from_le_bytes(source[..8].try_into().unwrap()),
                caps.device_id,
                "a durable fence names the device CAPS describes"
            );
            revision
        }
        other => panic!("a durable completion's fence, got {other:?}"),
    }
}

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i * 7) as u8) ^ (i >> 9) as u8)
        .collect()
}

// ── The server ─────────────────────────────────────────────────────

fn spawn_server(dir: &Path) -> Proc {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_loam-server"));
    cmd.args([
        "--socket",
        dir.join("admin.sock").to_str().unwrap(),
        "--ns-wal",
        dir.join("ns.wal").to_str().unwrap(),
        "--obj-wal",
        dir.join("obj.wal").to_str().unwrap(),
        "--fleet",
        &format!("dir:{}", dir.join("bodies").display()),
        "--tick-us",
        "500",
        "--gc-interval",
        "0",
    ]);
    spawn_ready(cmd, "admin socket on").0
}

fn create(dir: &Path, path: &[u8], size: u64, extent: u32) {
    let mut c = LoamClient::connect(dir.join("admin.sock")).expect("connect");
    c.create_volume(ROOT, path, size, extent).expect("create");
}

/// Read `len` bytes at `off` of the committed volume with loam-client.
fn committed(dir: &Path, path: &[u8], off: u64, len: usize) -> (u64, Vec<u8>) {
    let mut c = LoamClient::connect(dir.join("admin.sock")).expect("connect");
    let mut vol = c.open_volume(ROOT, path).expect("open").expect("bound");
    let mut out = vec![0u8; len];
    c.volume_read(&mut vol, off, &mut out).expect("read");
    (vol.revision, out)
}

// ── Tests ──────────────────────────────────────────────────────────

/// Fluxor's block conformance rules, on a depth-2 volume with a short
/// tail extent, then the committed volume read back with loam-client.
#[test]
fn a_volume_serves_the_block_contract() {
    let dir = tempfile::tempdir().unwrap();
    let _server = spawn_server(dir.path());
    // 1281 extents of 32 KiB: two leaves, the last extent 12 KiB.
    let size = 40 * 1024 * 1024 + 12 * 1024;
    create(dir.path(), b"/vols/c", size, 32 * 1024);

    let mut w = World::new(&dir.path().join("admin.sock"));
    w.nodes.push(Node::new(1, b"/vols/c", 30_000, 4096));
    assert_eq!(w.mount(0), caps::LEN as i32, "the device attaches");
    let c = w.nodes[0]
        .caps_rc()
        .1
        .expect("CAPS is a record the contract defines");
    assert_eq!(c.logical_block_size, 4096);
    assert_eq!(c.block_count, size / 4096);
    assert_eq!(c.max_blocks, 8, "one request is at most one extent");
    assert_eq!(c.queue_depth as usize, body::QUEUE_DEPTH);
    assert_eq!(
        c.flags,
        caps::F_WRITE | caps::F_FLUSH | caps::F_ASYNC,
        "no discard, no native FUA, write buffers lent until reaped"
    );
    let lbs = c.logical_block_size as usize;
    let last = c.block_count - 1;
    let mut model: HashMap<u64, Vec<u8>> = HashMap::new();

    // Writes round-trip at both ends; an un-FUA write is Volatile, a
    // read carries no fence.
    for (lba, seed) in [(0u64, 0x11u8), (last, 0x22)] {
        let mut wb = pattern(seed, lbs);
        let (rc, cpl) = w.exec(0, &data(op::WRITE, 0, lba, 1, &mut wb, 7));
        assert_eq!(rc, 0, "write at {lba}");
        assert_eq!(cpl.tag, 7, "the completion echoes the tag");
        assert_eq!(fence_of(&cpl), Some(Fence::Volatile));
        let mut rb = vec![0u8; lbs];
        let (rc, cpl) = w.exec(0, &data(op::READ, 0, lba, 1, &mut rb, 8));
        assert_eq!(rc, 0, "read at {lba}");
        assert_eq!(fence_of(&cpl), None, "a read carries no fence");
        assert_eq!(rb, wb, "read back what was written at {lba}");
        model.insert(lba, wb);
    }

    // The largest request, across an extent boundary (blocks 4..12 span
    // extents 0 and 1).
    let n = c.max_blocks;
    let mut wb = pattern(0x33, n as usize * lbs);
    assert_eq!(w.exec(0, &data(op::WRITE, 0, 4, n, &mut wb, 9)).0, 0);
    let mut rb = vec![0u8; wb.len()];
    assert_eq!(w.exec(0, &data(op::READ, 0, 4, n, &mut rb, 9)).0, 0);
    assert_eq!(rb, wb, "a full-size request round-trips");
    for k in 0..n as u64 {
        model.insert(4 + k, wb[k as usize * lbs..(k as usize + 1) * lbs].to_vec());
    }

    // FUA is durable at completion, at the volume's commit point.
    let mut wb = pattern(0x44, lbs);
    let (rc, cpl) = w.exec(0, &data(op::WRITE, blk::F_FUA, 1, 1, &mut wb, 10));
    assert_eq!(rc, 0);
    let r1 = committed_at(&cpl, &c);
    assert!(r1 >= 2, "a FUA write committed past the creation revision");
    model.insert(1, wb);

    // A byte-identical retry is idempotent and owes no new commit.
    let mut wb = pattern(0x55, lbs);
    assert_eq!(w.exec(0, &data(op::WRITE, 0, 2, 1, &mut wb, 11)).0, 0);
    assert_eq!(w.exec(0, &data(op::WRITE, 0, 2, 1, &mut wb, 11)).0, 0);
    let mut rb = vec![0u8; lbs];
    w.exec(0, &data(op::READ, 0, 2, 1, &mut rb, 12));
    assert_eq!(rb, wb, "a byte-identical retry is idempotent");
    model.insert(2, wb.clone());
    let (rc, cpl) = w.exec(0, &bare(op::FLUSH, 0, 0, 0, 13));
    assert_eq!(rc, 0, "FLUSH");
    let r2 = committed_at(&cpl, &c);
    assert!(r2 > r1, "the flush committed the staged write");
    let (rc, cpl) = w.exec(0, &bare(op::FLUSH, 0, 0, 0, 14));
    assert_eq!(rc, 0);
    assert_eq!(committed_at(&cpl, &c), r2, "nothing new to commit");
    assert_eq!(w.exec(0, &data(op::WRITE, 0, 2, 1, &mut wb, 15)).0, 0);
    let (_, cpl) = w.exec(0, &bare(op::FLUSH, 0, 0, 0, 16));
    assert_eq!(
        committed_at(&cpl, &c),
        r2,
        "a retried write of committed bytes stages nothing"
    );

    // Refused before anything runs.
    let mut one = vec![0u8; lbs];
    let past = data(op::READ, 0, c.block_count, 1, &mut one, 1);
    assert_eq!(w.exec(0, &past).0, EINVAL, "past the end");
    let mut big = vec![0u8; (n as usize + 1) * lbs];
    let over = data(op::READ, 0, 0, n + 1, &mut big, 1);
    assert_eq!(w.exec(0, &over).0, EINVAL, "more than max_blocks");
    let mut short = vec![0u8; lbs / 2];
    let short_req = data(op::READ, 0, 0, 1, &mut short, 1);
    assert_eq!(
        w.exec(0, &short_req).0,
        EINVAL,
        "a buffer short of its blocks"
    );
    let mut undefined = [0u8; blk::req::LEN + blk::cpl::LEN];
    bare(op::FLUSH, 0, 0, 0, 1).encode(&mut undefined);
    undefined[blk::req::OP] = 9;
    assert_eq!(
        w.nodes[0].ioctl(ioctl::EXEC, &mut undefined),
        EINVAL,
        "an undefined op"
    );
    assert_eq!(
        w.exec(0, &bare(op::DISCARD, 0, 3, 1, 15)).0,
        EINVAL,
        "no discard"
    );

    // The pipeline: every submitted tag reaped exactly once.
    let depth = c.queue_depth as usize;
    let mut bufs: Vec<Vec<u8>> = (0..depth).map(|i| pattern(0x70 + i as u8, lbs)).collect();
    for (i, b) in bufs.iter_mut().enumerate() {
        let lba = 16 + i as u64;
        assert_eq!(
            w.submit(0, &data(op::WRITE, 0, lba, 1, b, 100 + i as u64)),
            0
        );
    }
    let mut extra = pattern(0x7F, lbs);
    assert_eq!(
        w.submit(0, &data(op::WRITE, 0, 0, 1, &mut extra, 999)),
        EAGAIN,
        "the queue has a bound, and says so"
    );
    let mut seen: Vec<u64> = w
        .reap_n(0, depth)
        .into_iter()
        .map(|cpl| {
            assert_eq!(cpl.status, 0, "pipelined write {}", cpl.tag);
            assert_eq!(fence_of(&cpl), Some(Fence::Volatile));
            cpl.tag
        })
        .collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..depth as u64).map(|i| 100 + i).collect::<Vec<_>>());
    assert!(w.reap(0).is_none(), "nothing more to reap");
    for (i, b) in bufs.iter().enumerate() {
        model.insert(16 + i as u64, b.clone());
    }
    // A queued flush, then a PREFLUSH read behind it.
    assert_eq!(w.submit(0, &bare(op::FLUSH, 0, 0, 0, 200)), 0);
    let mut rb = vec![0u8; lbs];
    assert_eq!(
        w.submit(0, &data(op::READ, blk::F_PREFLUSH, 16, 1, &mut rb, 201)),
        0
    );
    let done = w.reap_n(0, 2);
    let flush = done.iter().find(|x| x.tag == 200).expect("flush reaped");
    assert_eq!(flush.status, 0);
    let r3 = committed_at(flush, &c);
    assert!(r3 > r2);
    assert_eq!(done.iter().find(|x| x.tag == 201).unwrap().status, 0);
    assert_eq!(rb, bufs[0], "a PREFLUSH read after its flush");

    // The committed volume, read by loam-client, is what was flushed.
    assert_eq!(
        w.nodes[0].state().commits,
        3,
        "FUA, FLUSH and the queued FLUSH"
    );
    drop(w);
    for (lba, want) in &model {
        let (rev, got) = committed(dir.path(), b"/vols/c", lba * lbs as u64, lbs);
        assert_eq!(rev, r3, "loam-client sees the module's last commit");
        assert_eq!(&got, want, "block {lba} as loam-client reads it");
    }
}

/// Many extents on a depth-1 volume of small extents: partial writes
/// read-modify-write through fetches, the staged set commits on its own
/// when full, and a second writer is refused. The flushed volume then
/// survives a restart of the server and of the module; what was never
/// flushed does not.
#[test]
fn a_flushed_volume_survives_a_restart_and_has_one_writer() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn_server(dir.path());
    let extents = 128u64;
    let size = extents * 4096;
    create(dir.path(), b"/vols/r", size, 4096);

    let mut w = World::new(&dir.path().join("admin.sock"));
    let ttl = 1500;
    w.nodes.push(Node::new(1, b"/vols/r", ttl, 512));
    assert_eq!(w.mount(0), caps::LEN as i32);
    let c = w.nodes[0].caps_rc().1.unwrap();
    assert_eq!((c.logical_block_size, c.max_blocks), (512, 8));

    // Seed `STAGED_MAX + 2` even extents whole: the one after the staged
    // set is full commits the set on its own.
    let seeds = body::STAGED_MAX as u64 + 2;
    let mut model = vec![0u8; size as usize];
    for e in (0..2 * seeds).step_by(2) {
        let mut wb = pattern(e as u8 + 1, 4096);
        let (rc, _) = w.exec(0, &data(op::WRITE, 0, e * 8, 8, &mut wb, e));
        let st = w.nodes[0].state();
        assert_eq!(
            rc, 0,
            "whole-extent write {e}: commits {}, abandoned {} (last status {:#04x})",
            st.commits, st.abandoned, st.abandon_status
        );
        model[(e * 4096) as usize..((e + 1) * 4096) as usize].copy_from_slice(&wb);
    }
    assert_eq!(
        w.nodes[0].state().commits,
        1,
        "a full staged set commits itself"
    );
    let (rc, cpl) = w.exec(0, &bare(op::FLUSH, 0, 0, 0, 1));
    assert_eq!(rc, 0);
    let seeded = committed_at(&cpl, &c);
    assert_eq!(w.nodes[0].state().commits, 2);
    // Reading as many never-written extents as the cache holds fills it
    // with zeros and evicts the seeded ones, so the partial writes below
    // must fetch.
    for e in extents / 2..extents / 2 + body::EXTENT_SLOTS as u64 {
        let mut rb = vec![0xFFu8; 4096];
        assert_eq!(w.exec(0, &data(op::READ, 0, e * 8, 8, &mut rb, 40)).0, 0);
        assert!(
            rb.iter().all(|&b| b == 0),
            "a never-written extent reads zeros"
        );
    }
    // Partial writes: inside a seeded extent, straddling a zero extent
    // into a seeded one, and the last block.
    for (k, (lba, n)) in [(3u64, 1usize), (63, 2), (extents * 8 - 1, 1)]
        .iter()
        .enumerate()
    {
        let mut wb = pattern(0x90 + k as u8, n * 512);
        assert_eq!(
            w.exec(0, &data(op::WRITE, 0, *lba, *n as u32, &mut wb, 50))
                .0,
            0
        );
        let at = (*lba * 512) as usize;
        model[at..at + wb.len()].copy_from_slice(&wb);
    }
    let (rc, cpl) = w.exec(0, &bare(op::FLUSH, 0, 0, 0, 2));
    assert_eq!(rc, 0);
    let flushed = committed_at(&cpl, &c);
    assert!(flushed > seeded);
    assert_eq!(
        w.nodes[0].state().fetches,
        2,
        "the two seeded extents a partial write touched were fetched"
    );

    // A second instance of the same volume is refused by the lease.
    w.nodes.push(Node::new(2, b"/vols/r", ttl, 512));
    assert_eq!(w.mount(1), EBUSY, "one writer per volume");

    // A write that is never flushed, then the writer vanishes.
    let mut lost = pattern(0xEE, 512);
    assert_eq!(w.exec(0, &data(op::WRITE, 0, 5, 1, &mut lost, 60)).0, 0);
    let mut back = vec![0u8; size as usize];
    for e in 0..extents {
        let at = (e * 4096) as usize;
        let (rc, _) = w.exec(
            0,
            &data(op::READ, 0, e * 8, 8, &mut back[at..at + 4096], 70),
        );
        assert_eq!(rc, 0);
    }
    let mut with_lost = model.clone();
    with_lost[5 * 512..6 * 512].copy_from_slice(&lost);
    assert!(back == with_lost, "the writer reads its own staged write");
    drop(w);

    // Restart the server; the dead writer's lease must lapse first.
    drop(server);
    let _server = spawn_server(dir.path());
    std::thread::sleep(Duration::from_millis(ttl as u64 + 200));
    let mut w = World::new(&dir.path().join("admin.sock"));
    w.nodes.push(Node::new(3, b"/vols/r", ttl, 512));
    assert_eq!(w.mount(0), caps::LEN as i32, "remounted after the restart");
    assert_eq!(
        w.nodes[0].state().revision,
        flushed,
        "at the flushed revision"
    );
    let mut back = vec![0u8; size as usize];
    for e in 0..extents {
        let at = (e * 4096) as usize;
        let (rc, _) = w.exec(
            0,
            &data(op::READ, 0, e * 8, 8, &mut back[at..at + 4096], 80),
        );
        assert_eq!(rc, 0);
    }
    assert!(
        back == model,
        "every flushed byte, and none of the unflushed one"
    );
}

/// A writer that cannot renew stops before its lease lapses: its staged
/// writes never land, every request after fails, and the writer that
/// takes over commits undisturbed.
#[test]
fn a_writer_that_loses_its_lease_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let _server = spawn_server(dir.path());
    create(dir.path(), b"/vols/d", 16 * 4096, 4096);

    let mut w = World::new(&dir.path().join("admin.sock"));
    let ttl = 1000;
    w.nodes.push(Node::new(1, b"/vols/d", ttl, 4096));
    assert_eq!(w.mount(0), caps::LEN as i32);
    let mut stale = pattern(0xA1, 4096);
    assert_eq!(w.exec(0, &data(op::WRITE, 0, 3, 1, &mut stale, 1)).0, 0);

    // The first writer stalls past its TTL; a second takes the volume.
    w.nodes[0].frozen = true;
    std::thread::sleep(Duration::from_millis(ttl as u64 + 200));
    w.nodes.push(Node::new(2, b"/vols/d", ttl, 4096));
    assert_eq!(w.mount(1), caps::LEN as i32, "the successor attaches");
    let c = w.nodes[1].caps_rc().1.unwrap();
    let mut fresh = pattern(0xB2, 4096);
    assert_eq!(w.exec(1, &data(op::WRITE, 0, 4, 1, &mut fresh, 2)).0, 0);
    let (rc, cpl) = w.exec(1, &bare(op::FLUSH, 0, 0, 0, 3));
    assert_eq!(rc, 0);
    let rev = committed_at(&cpl, &c);

    // The stalled writer wakes: closed, not merged.
    w.nodes[0].frozen = false;
    w.tick();
    let (rc, _) = w.exec(0, &bare(op::FLUSH, 0, 0, 0, 4));
    assert_eq!(rc, EIO, "a writer past its lease fails closed");
    let mut rb = vec![0u8; 4096];
    assert_eq!(w.exec(0, &data(op::READ, 0, 4, 1, &mut rb, 5)).0, EIO);
    assert_eq!(w.nodes[0].caps_rc().0, EIO, "the device is gone");
    for _ in 0..50 {
        w.tick();
    }
    assert_eq!(w.nodes[1].state().revision, rev, "nothing landed after it");
    drop(w);

    let (r, got) = committed(dir.path(), b"/vols/d", 3 * 4096, 2 * 4096);
    assert_eq!(r, rev);
    assert!(
        got[..4096].iter().all(|&b| b == 0),
        "the stale write never landed"
    );
    assert_eq!(&got[4096..], &fresh[..], "the successor's write did");
}

/// The attach flow takes the writer lease itself, binds its fence into the
/// key release, and hands the device its holder. The device re-acquires
/// that same lease — same holder, same fence — rather than contending for
/// it; and a device told a fence the lease is not under refuses to serve.
#[test]
fn a_device_takes_over_the_attach_flows_lease_and_its_fence() {
    let dir = tempfile::tempdir().unwrap();
    let _server = spawn_server(dir.path());
    create(dir.path(), b"/vols/h", 16 * 4096, 4096);
    let mut c = LoamClient::connect(dir.path().join("admin.sock")).expect("connect");
    let holder = [0x5Au8; 16];
    let lease = c
        .acquire_lease(ROOT, b"/vols/h", &holder, 30_000)
        .expect("the attach flow's lease");
    drop(c);
    let hex: String = holder.iter().map(|b| format!("{b:02x}")).collect();

    let mut w = World::new(&dir.path().join("admin.sock"));
    let mut n = Node::new(1, b"/vols/h", 30_000, 4096);
    unsafe {
        let s = &mut *(n.mem.as_mut_ptr() as *mut body::ModuleState);
        body::set_holder(s, hex.as_bytes());
        body::set_fence(s, lease.fence.to_string().as_bytes());
    }
    w.nodes.push(n);
    assert_eq!(
        w.mount(0),
        caps::LEN as i32,
        "the device serves under the flow's lease"
    );
    assert_eq!(w.nodes[0].state().lease_fence, lease.fence);

    // Told another fence, it does not serve: the key was released for the
    // lease under the fence it was given.
    let mut n = Node::new(2, b"/vols/h", 30_000, 4096);
    unsafe {
        let s = &mut *(n.mem.as_mut_ptr() as *mut body::ModuleState);
        body::set_holder(s, hex.as_bytes());
        body::set_fence(s, (lease.fence + 1).to_string().as_bytes());
    }
    w.nodes.push(n);
    assert!(
        w.mount(1) < 0,
        "a device under the wrong fence refuses to serve"
    );

    // A malformed holder is a configuration error, not a random holder.
    let mut bad = Node::new(3, b"/vols/h", 30_000, 4096);
    unsafe {
        let s = &mut *(bad.mem.as_mut_ptr() as *mut body::ModuleState);
        body::set_holder(s, b"not-hex");
    }
    w.nodes.push(bad);
    assert!(w.mount(2) < 0);
}
