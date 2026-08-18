//! Long-running PIC graph runtime for `loam-server`. Hosts four
//! PIC bodies (admin_router, namespace_router, body_store,
//! object_index) wired together via in-process channels, plus
//! the fake-fs syscalls a PIC expects on the host profile.
//!
//! This is a parallel module to `crate::pic` — `pic.rs` exists
//! for the per-command CLI which only ever runs one PIC at a
//! time, while this `runtime.rs` runs all four concurrently.
//! Keeping them separate avoids the static-state aliasing the
//! single-PIC harness would otherwise have to defend against.

#![allow(
    dead_code,
    static_mut_refs,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use anyhow::{anyhow, Result};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Mutex;
use std::time::Duration;

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
pub mod sha256 {
    pub use super::sha256_impl::Sha256;
}

#[path = "../../../modules/common/mechanics/loam_wire.rs"]
pub mod ns_wire;

#[path = "../../../modules/common/mechanics/loam_body_wire.rs"]
pub mod body_wire;

#[path = "../../../modules/common/mechanics/loam_object_wire.rs"]
pub mod obj_wire;

#[path = "../../../modules/common/mechanics/loam_admin_wire.rs"]
pub mod admin_wire;

#[path = "../../../modules/common/mechanics/wal_io.rs"]
pub mod wal;

#[path = "../../../modules/common/mechanics/namespace_pic_state.rs"]
mod ns_state;

mod wire {
    pub use super::ns_wire::*;
}
mod state {
    pub use super::ns_state::*;
}

#[path = "../../../modules/common/mechanics/loam_snapshot.rs"]
pub mod snapshot;

#[allow(
    dead_code,
    reason = "shared PIC body include; each includer drives a subset"
)]
#[path = "../../../modules/common/mechanics/namespace_pic_body.rs"]
pub mod ns_body;

// Object body wrapping (same pattern as pic.rs).
pub mod obj_scope {
    pub use super::abi::SyscallTable;
    pub mod wire {
        pub use super::super::obj_wire::*;
    }
    pub mod state {
        // Notional dir: tools/loam-cli/src/runtime/obj_scope/state/
        // — 6 levels up to workspace root.
        #[path = "../../../../../../modules/common/mechanics/object_pic_state.rs"]
        pub mod inner;
        pub use inner::*;
    }
    pub mod wal {
        pub use super::super::wal::*;
    }
    #[allow(
        dead_code,
        reason = "shared PIC body include; each includer drives a subset"
    )]
    #[path = "../../../../../modules/common/mechanics/object_pic_body.rs"]
    pub mod body;
}
pub use obj_scope::body as obj_body;

// Body store body wrapping.
pub mod body_store_scope {
    pub use super::abi::SyscallTable;
    pub mod sha256 {
        pub use super::super::sha256_impl::Sha256;
    }
    pub mod wire {
        pub use super::super::body_wire::*;
    }
    #[allow(
        dead_code,
        reason = "shared PIC body include; each includer drives a subset"
    )]
    #[path = "../../../../../modules/common/mechanics/body_store_body.rs"]
    pub mod body;
    #[path = "../../../../../modules/common/mechanics/loam_ec_wire.rs"]
    pub mod ec_wire;
    #[path = "../../../../../modules/common/mechanics/loam_extent_wire.rs"]
    pub mod extent_wire;
}
pub use body_store_scope::body as body_store_body;

#[path = "../../../modules/common/replicated/loam_placement_wire.rs"]
pub mod placement_wire;

// body_fanout_router wrapping: needs `super::{SyscallTable,
// body_wire, placement_wire, placement}`.
pub mod fanout_scope {
    pub use super::abi::SyscallTable;
    pub mod body_wire {
        pub use super::super::body_wire::*;
    }
    pub mod placement_wire {
        pub use super::super::placement_wire::*;
    }
    #[allow(
        dead_code,
        reason = "shared PIC body include; each includer drives a subset"
    )]
    #[path = "../../../../../modules/common/replicated/body_fanout_router_body.rs"]
    pub mod body;
    #[path = "../../../../../modules/common/replicated/loam_placement.rs"]
    pub mod placement;
}
pub use fanout_scope::body as fanout_body;

// admin_router body wrapping. The body file expects
// `super::admin` (admin wire), `super::ns_wire`, `super::body_wire`,
// `super::obj_wire`, `super::SyscallTable`.
pub mod admin_scope {
    pub use super::abi::SyscallTable;
    pub mod admin {
        pub use super::super::admin_wire::*;
    }
    pub mod ns_wire {
        pub use super::super::ns_wire::*;
    }
    pub mod body_wire {
        pub use super::super::body_wire::*;
    }
    pub mod obj_wire {
        pub use super::super::obj_wire::*;
    }
    #[allow(
        dead_code,
        reason = "shared PIC body include; each includer drives a subset"
    )]
    #[path = "../../../../../modules/common/mechanics/admin_router_body.rs"]
    pub mod body;
}
pub use admin_scope::body as admin_body;

// ── Channels ────────────────────────────────────────────────────

pub const CHAN_ADMIN_IN: i32 = 100;
pub const CHAN_ADMIN_OUT: i32 = 101;
pub const CHAN_NS_REQ: i32 = 102;
pub const CHAN_NS_RESP: i32 = 103;
pub const CHAN_BODY_REQ: i32 = 104;
pub const CHAN_BODY_RESP: i32 = 105;
pub const CHAN_OBJ_REQ: i32 = 106;
pub const CHAN_OBJ_RESP: i32 = 107;

/// Per-fleet-member downstream channels for the fanout router:
/// member i's request channel is CHAN_FLEET_BASE + 2i, its
/// response channel CHAN_FLEET_BASE + 2i + 1.
pub const MAX_SERVER_FLEET: usize = 8;
pub const CHAN_FLEET_BASE: i32 = 120;

pub const fn fleet_req_chan(i: usize) -> i32 {
    CHAN_FLEET_BASE + 2 * i as i32
}
pub const fn fleet_resp_chan(i: usize) -> i32 {
    CHAN_FLEET_BASE + 2 * i as i32 + 1
}

static ADMIN_IN: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());
static ADMIN_OUT: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());
static NS_REQ: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());
static NS_RESP: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());
static BODY_REQ: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());
static BODY_RESP: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());
static OBJ_REQ: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());
static OBJ_RESP: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());

#[allow(
    clippy::declare_interior_mutable_const,
    reason = "array-repeat initializer for the static fleet queues; never read as a shared const"
)]
const EMPTY_Q: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());
static FLEET_REQ: [Mutex<VecDeque<Vec<u8>>>; MAX_SERVER_FLEET] = [EMPTY_Q; MAX_SERVER_FLEET];
static FLEET_RESP: [Mutex<VecDeque<Vec<u8>>>; MAX_SERVER_FLEET] = [EMPTY_Q; MAX_SERVER_FLEET];

fn fleet_chan_idx(h: i32) -> Option<(usize, bool)> {
    let off = h - CHAN_FLEET_BASE;
    if off >= 0 && (off as usize) < 2 * MAX_SERVER_FLEET {
        Some(((off / 2) as usize, off % 2 == 1))
    } else {
        None
    }
}

static FS_FILES: Mutex<Vec<Option<File>>> = Mutex::new(Vec::new());

unsafe extern "C" fn chan_read(h: i32, buf: *mut u8, len: usize) -> i32 {
    let payload = match h {
        CHAN_ADMIN_IN => ADMIN_IN.lock().unwrap().pop_front(),
        CHAN_NS_REQ => NS_REQ.lock().unwrap().pop_front(),
        CHAN_NS_RESP => NS_RESP.lock().unwrap().pop_front(),
        CHAN_BODY_REQ => BODY_REQ.lock().unwrap().pop_front(),
        CHAN_BODY_RESP => BODY_RESP.lock().unwrap().pop_front(),
        CHAN_OBJ_REQ => OBJ_REQ.lock().unwrap().pop_front(),
        CHAN_OBJ_RESP => OBJ_RESP.lock().unwrap().pop_front(),
        _ => match fleet_chan_idx(h) {
            Some((i, true)) => FLEET_RESP[i].lock().unwrap().pop_front(),
            Some((i, false)) => FLEET_REQ[i].lock().unwrap().pop_front(),
            None => None,
        },
    };
    match payload {
        Some(p) => {
            let n = p.len().min(len);
            unsafe { std::ptr::copy_nonoverlapping(p.as_ptr(), buf, n) };
            n as i32
        }
        None => 0,
    }
}

unsafe extern "C" fn chan_write(h: i32, data: *const u8, len: usize) -> i32 {
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    let q = match h {
        CHAN_ADMIN_OUT => &ADMIN_OUT,
        CHAN_NS_REQ => &NS_REQ,
        CHAN_NS_RESP => &NS_RESP,
        CHAN_BODY_REQ => &BODY_REQ,
        CHAN_BODY_RESP => &BODY_RESP,
        CHAN_OBJ_REQ => &OBJ_REQ,
        CHAN_OBJ_RESP => &OBJ_RESP,
        _ => match fleet_chan_idx(h) {
            Some((i, true)) => &FLEET_RESP[i],
            Some((i, false)) => &FLEET_REQ[i],
            None => return -1,
        },
    };
    q.lock().unwrap().push_back(bytes);
    len as i32
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

// fs syscall slot table (mirrors pic_harness.rs).

const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_OPEN_CREATE: u32 = 0x0909;
const FS_UNLINK: u32 = 0x090A;

fn fs_slot_for(file: File) -> i32 {
    let mut files = FS_FILES.lock().unwrap();
    for (i, slot) in files.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(file);
            return i as i32;
        }
    }
    files.push(Some(file));
    (files.len() - 1) as i32
}

unsafe extern "C" fn fs_provider_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    match op {
        FS_OPEN | FS_OPEN_CREATE => {
            if arg.is_null() || arg_len == 0 {
                return -22;
            }
            let bytes = unsafe { std::slice::from_raw_parts(arg as *const u8, arg_len) };
            let path = match std::str::from_utf8(bytes) {
                Ok(p) => p,
                Err(_) => return -22,
            };
            let mut opts = OpenOptions::new();
            opts.read(true).write(true);
            if op == FS_OPEN_CREATE {
                opts.create(true);
            }
            match opts.open(path) {
                Ok(f) => fs_slot_for(f),
                Err(_) => -19,
            }
        }
        FS_READ => {
            if arg.is_null() || arg_len == 0 {
                return -22;
            }
            let mut files = FS_FILES.lock().unwrap();
            let f = match files.get_mut(handle as usize).and_then(|s| s.as_mut()) {
                Some(f) => f,
                None => return -22,
            };
            let buf = unsafe { std::slice::from_raw_parts_mut(arg, arg_len) };
            match f.read(buf) {
                Ok(n) => n as i32,
                Err(_) => -1,
            }
        }
        FS_SEEK => {
            if arg.is_null() || arg_len < 4 {
                return -22;
            }
            let bytes = unsafe { std::slice::from_raw_parts(arg as *const u8, 4) };
            let offset = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let mut files = FS_FILES.lock().unwrap();
            let f = match files.get_mut(handle as usize).and_then(|s| s.as_mut()) {
                Some(f) => f,
                None => return -22,
            };
            match f.seek(SeekFrom::Start(offset as u64)) {
                Ok(pos) => pos as i32,
                Err(_) => -1,
            }
        }
        FS_WRITE => {
            if arg.is_null() || arg_len == 0 {
                return -22;
            }
            let buf = unsafe { std::slice::from_raw_parts(arg as *const u8, arg_len) };
            let mut files = FS_FILES.lock().unwrap();
            let f = match files.get_mut(handle as usize).and_then(|s| s.as_mut()) {
                Some(f) => f,
                None => return -22,
            };
            match f.write(buf) {
                Ok(n) => n as i32,
                Err(_) => -1,
            }
        }
        FS_UNLINK => {
            if arg.is_null() || arg_len == 0 {
                return -22;
            }
            let path = unsafe { std::slice::from_raw_parts(arg, arg_len) };
            let path = match std::str::from_utf8(path) {
                Ok(p) => p,
                Err(_) => return -22,
            };
            match std::fs::remove_file(path) {
                Ok(_) => 0,
                Err(_) => -1,
            }
        }
        FS_FSYNC => {
            let files = FS_FILES.lock().unwrap();
            let f = match files.get(handle as usize).and_then(|s| s.as_ref()) {
                Some(f) => f,
                None => return -22,
            };
            match f.sync_data() {
                Ok(_) => 0,
                Err(_) => -1,
            }
        }
        FS_STAT => {
            if arg.is_null() || arg_len < 8 {
                return -22;
            }
            let files = FS_FILES.lock().unwrap();
            let f = match files.get(handle as usize).and_then(|s| s.as_ref()) {
                Some(f) => f,
                None => return -22,
            };
            let meta = match f.metadata() {
                Ok(m) => m,
                Err(_) => return -1,
            };
            let size = meta.len().min(u32::MAX as u64) as u32;
            let mtime: u32 = 0;
            let out = unsafe { std::slice::from_raw_parts_mut(arg, 8) };
            out[..4].copy_from_slice(&size.to_le_bytes());
            out[4..8].copy_from_slice(&mtime.to_le_bytes());
            0
        }
        FS_CLOSE => {
            let mut files = FS_FILES.lock().unwrap();
            if let Some(slot) = files.get_mut(handle as usize) {
                *slot = None;
            }
            0
        }
        _ => -1,
    }
}

pub fn make_syscalls() -> SyscallTable {
    SyscallTable {
        version: 1,
        channel_read: chan_read,
        channel_write: chan_write,
        channel_poll: no_poll,
        heap_alloc: no_alloc,
        heap_free: no_free,
        heap_realloc: no_realloc,
        provider_open: no_open,
        provider_call: fs_provider_call,
        provider_query: no_query,
        provider_close: no_close,
        channel_peek: no_peek,
        telemetry_enabled: std::ptr::null(),
        provider_call_sel: no_call_sel,
    }
}

// ── Module storage ─────────────────────────────────────────────

pub struct ModuleStorage {
    backing: Box<[u64]>,
}

impl ModuleStorage {
    pub fn new(size_bytes: usize) -> Self {
        let words = size_bytes.div_ceil(8).max(1);
        Self {
            backing: vec![0u64; words].into_boxed_slice(),
        }
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.backing.as_mut_ptr() as *mut u8
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.backing.as_ptr() as *const u8
    }
    pub fn len(&self) -> usize {
        self.backing.len() * 8
    }
}

// ── Server ────────────────────────────────────────────────────────

pub struct Server {
    syscalls: SyscallTable,
    admin: ModuleStorage,
    ns: ModuleStorage,
    body_store: ModuleStorage,
    obj: ModuleStorage,
    /// Fleet mode: body_fanout_router between admin_router and
    /// `fleet_stores` (local members) + bridge-pumped remote
    /// members. Empty when running the single-body_store graph.
    fanout: Option<ModuleStorage>,
    fleet_stores: Vec<ModuleStorage>,
    sock_conn: Option<std::os::unix::net::UnixStream>,
    read_buf: Vec<u8>,
}

impl Server {
    pub fn new() -> Result<Self> {
        // Drain any leftover channel state from a previous run
        // in the same process (tests).
        ADMIN_IN.lock().unwrap().clear();
        ADMIN_OUT.lock().unwrap().clear();
        NS_REQ.lock().unwrap().clear();
        NS_RESP.lock().unwrap().clear();
        BODY_REQ.lock().unwrap().clear();
        BODY_RESP.lock().unwrap().clear();
        OBJ_REQ.lock().unwrap().clear();
        OBJ_RESP.lock().unwrap().clear();
        FS_FILES.lock().unwrap().clear();

        for q in FLEET_REQ.iter().chain(FLEET_RESP.iter()) {
            q.lock().unwrap().clear();
        }

        Ok(Self {
            syscalls: make_syscalls(),
            admin: ModuleStorage::new(core::mem::size_of::<admin_body::ModuleState>()),
            ns: ModuleStorage::new(core::mem::size_of::<ns_body::ModuleState>()),
            body_store: ModuleStorage::new(core::mem::size_of::<body_store_body::ModuleState>()),
            obj: ModuleStorage::new(core::mem::size_of::<obj_body::ModuleState>()),
            fanout: None,
            fleet_stores: Vec::new(),
            sock_conn: None,
            read_buf: vec![0u8; 8192],
        })
    }

    /// Fleet mode: admin/namespace/object PICs plus a
    /// body_fanout_router fronting `fleet_len` members. Members
    /// listed in `local_members` (member index, body root) run as
    /// in-process body_store instances on their fleet channels;
    /// the rest are bridge-pumped by the caller (loam-server's
    /// TCP bridges). All-must-succeed PUT across `replica_count`
    /// rendezvous-chosen members; GET/HEAD fall back; scrub heals
    /// when `scrub_interval` != 0.
    #[allow(
        clippy::too_many_arguments,
        reason = "bounded no_std step functions pass explicit scalar params"
    )]
    pub fn spin_up_pics_fleet(
        &mut self,
        ns_wal: &str,
        obj_wal: &str,
        local_members: &[(usize, String)],
        fleet_len: usize,
        replica_count: u8,
        scrub_interval: u32,
    ) -> Result<()> {
        if fleet_len == 0 || fleet_len > MAX_SERVER_FLEET {
            return Err(anyhow!(
                "fleet size {fleet_len} out of range 1..={MAX_SERVER_FLEET}"
            ));
        }
        self.spin_up_pics_remote_body(ns_wal, obj_wal)?;

        let mut fanout = ModuleStorage::new(core::mem::size_of::<fanout_body::ModuleState>());
        let req: Vec<i32> = (0..fleet_len).map(fleet_req_chan).collect();
        let resp: Vec<i32> = (0..fleet_len).map(fleet_resp_chan).collect();
        let rc = unsafe {
            fanout_body::module_new_with_targets_impl(
                CHAN_BODY_REQ,
                CHAN_BODY_RESP,
                -1,
                &req,
                &resp,
                replica_count,
                scrub_interval,
                fanout.as_mut_ptr(),
                fanout.len(),
                &self.syscalls,
            )
        };
        if rc != 0 {
            return Err(anyhow!("body_fanout_router init rc={rc}"));
        }
        // Static fleet snapshot: every wired member, epoch 1. (No
        // placement_router in the host runtime — membership is
        // fixed at launch; member DEATH is handled by the router's
        // fallback + the bridge's synthesized NAKs, not by
        // shrinking the snapshot.)
        let members: Vec<u8> = (0..fleet_len as u8).collect();
        unsafe { fanout_body::set_fleet_for_test(fanout.as_mut_ptr(), 1, &members) };
        self.fanout = Some(fanout);

        for (idx, root) in local_members {
            if *idx >= fleet_len {
                return Err(anyhow!(
                    "local member index {idx} >= fleet size {fleet_len}"
                ));
            }
            let mut store =
                ModuleStorage::new(core::mem::size_of::<body_store_body::ModuleState>());
            let rc = unsafe {
                body_store_body::module_new_impl(
                    fleet_req_chan(*idx),
                    fleet_resp_chan(*idx),
                    store.as_mut_ptr(),
                    store.len(),
                    &self.syscalls,
                )
            };
            if rc != 0 {
                return Err(anyhow!("fleet body_store {idx} init rc={rc}"));
            }
            unsafe {
                body_store_body::set_root_dir(store.as_mut_ptr(), root.as_bytes());
            }
            self.fleet_stores.push(store);
        }
        Ok(())
    }

    pub fn spin_up_pics(&mut self, ns_wal: &str, obj_wal: &str, body_root: &str) -> Result<()> {
        let rc = unsafe {
            ns_body::module_new_with_wal_impl(
                CHAN_NS_REQ,
                CHAN_NS_RESP,
                ns_wal.as_bytes(),
                self.ns.as_mut_ptr(),
                self.ns.len(),
                &self.syscalls,
            )
        };
        if rc != 0 {
            return Err(anyhow!("namespace_router init rc={rc}"));
        }
        let rc = unsafe {
            obj_body::module_new_with_wal_impl(
                CHAN_OBJ_REQ,
                CHAN_OBJ_RESP,
                obj_wal.as_bytes(),
                self.obj.as_mut_ptr(),
                self.obj.len(),
                &self.syscalls,
            )
        };
        if rc != 0 {
            return Err(anyhow!("object_index init rc={rc}"));
        }
        let rc = unsafe {
            body_store_body::module_new_impl(
                CHAN_BODY_REQ,
                CHAN_BODY_RESP,
                self.body_store.as_mut_ptr(),
                self.body_store.len(),
                &self.syscalls,
            )
        };
        if rc != 0 {
            return Err(anyhow!("body_store init rc={rc}"));
        }
        unsafe {
            body_store_body::set_root_dir(self.body_store.as_mut_ptr(), body_root.as_bytes());
        }
        let rc = unsafe {
            admin_body::module_new_with_objects_impl(
                CHAN_ADMIN_IN,
                CHAN_ADMIN_OUT,
                CHAN_NS_REQ,
                CHAN_NS_RESP,
                CHAN_BODY_REQ,
                CHAN_BODY_RESP,
                CHAN_OBJ_REQ,
                CHAN_OBJ_RESP,
                self.admin.as_mut_ptr(),
                self.admin.len(),
                &self.syscalls,
            )
        };
        if rc != 0 {
            return Err(anyhow!("admin_router init rc={rc}"));
        }
        Ok(())
    }

    /// Single tick: socket I/O + step every PIC body once.
    fn tick(&mut self) {
        // Accept-then-pump shape: each tick reads from the open
        // socket (if any), steps the four PICs, and drains
        // admin_out back to the socket.

        // Read socket → admin_in.
        if let Some(ref mut conn) = self.sock_conn {
            conn.set_nonblocking(true).ok();
            match conn.read(&mut self.read_buf) {
                Ok(0) => {
                    // peer closed
                    self.sock_conn = None;
                }
                Ok(n) => {
                    ADMIN_IN
                        .lock()
                        .unwrap()
                        .push_back(self.read_buf[..n].to_vec());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    self.sock_conn = None;
                }
            }
        }

        // Step each PIC. admin_router steps first so it forwards
        // new requests; then downstream PICs handle their inputs;
        // then admin_router again drains responses. In fleet mode
        // the fanout router steps before AND after the stores so a
        // request fans out and its responses aggregate in one tick.
        unsafe {
            admin_body::module_step_impl(self.admin.as_mut_ptr());
            ns_body::module_step_impl(self.ns.as_mut_ptr());
            if let Some(f) = &mut self.fanout {
                fanout_body::module_step_impl(f.as_mut_ptr());
            }
            body_store_body::module_step_impl(self.body_store.as_mut_ptr());
            for store in &mut self.fleet_stores {
                body_store_body::module_step_impl(store.as_mut_ptr());
            }
            if let Some(f) = &mut self.fanout {
                fanout_body::module_step_impl(f.as_mut_ptr());
            }
            obj_body::module_step_impl(self.obj.as_mut_ptr());
            admin_body::module_step_impl(self.admin.as_mut_ptr());
        }

        // Drain admin_out → socket.
        if let Some(ref mut conn) = self.sock_conn {
            let mut out = ADMIN_OUT.lock().unwrap();
            while let Some(frame) = out.pop_front() {
                if conn.write_all(&frame).is_err() {
                    self.sock_conn = None;
                    break;
                }
            }
        }
    }

    pub fn run(&mut self, listener: std::os::unix::net::UnixListener, tick_delay: Duration) {
        loop {
            // Accept a new connection if we don't have one.
            if self.sock_conn.is_none() {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(true).ok();
                        self.sock_conn = Some(stream);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
            self.tick();
            std::thread::sleep(tick_delay);
        }
    }

    /// Single-shot, in-process variant: runs `tick` until the
    /// admin_out has at least one frame or `max_ticks` is hit.
    /// Used by the in-process integration test.
    pub fn drain_one_response(&mut self, max_ticks: u32) -> Option<Vec<u8>> {
        for _ in 0..max_ticks {
            self.tick();
            let mut out = ADMIN_OUT.lock().unwrap();
            if let Some(frame) = out.pop_front() {
                return Some(frame);
            }
        }
        None
    }

    pub fn push_admin_request(&mut self, frame: Vec<u8>) {
        ADMIN_IN.lock().unwrap().push_back(frame);
    }

    /// One tick from outside (the server main loop runs socket +
    /// bridge pumping around it).
    pub fn tick_once(&mut self) {
        self.tick();
    }

    /// Take the unix-socket connection out of the tick loop so a
    /// caller (the S3 handler) can drain admin_out itself without
    /// tick() forwarding frames to the unix client. Restore with
    /// `restore_sock_conn`.
    pub fn take_sock_conn(&mut self) -> Option<std::os::unix::net::UnixStream> {
        self.sock_conn.take()
    }

    pub fn restore_sock_conn(&mut self, conn: Option<std::os::unix::net::UnixStream>) {
        self.sock_conn = conn;
    }

    pub fn set_sock_conn(&mut self, conn: std::os::unix::net::UnixStream) {
        self.sock_conn = Some(conn);
    }

    pub fn has_sock_conn(&self) -> bool {
        self.sock_conn.is_some()
    }

    /// Admin node whose body plane lives on ANOTHER node: spin up
    /// admin/namespace/object PICs but no local body_store — the
    /// body_req/body_resp channels are pumped by a network bridge
    /// instead. (A zeroed body_store state no-ops its step.)
    pub fn spin_up_pics_remote_body(&mut self, ns_wal: &str, obj_wal: &str) -> Result<()> {
        let rc = unsafe {
            ns_body::module_new_with_wal_impl(
                CHAN_NS_REQ,
                CHAN_NS_RESP,
                ns_wal.as_bytes(),
                self.ns.as_mut_ptr(),
                self.ns.len(),
                &self.syscalls,
            )
        };
        if rc != 0 {
            return Err(anyhow!("namespace_router init rc={rc}"));
        }
        let rc = unsafe {
            obj_body::module_new_with_wal_impl(
                CHAN_OBJ_REQ,
                CHAN_OBJ_RESP,
                obj_wal.as_bytes(),
                self.obj.as_mut_ptr(),
                self.obj.len(),
                &self.syscalls,
            )
        };
        if rc != 0 {
            return Err(anyhow!("object_index init rc={rc}"));
        }
        let rc = unsafe {
            admin_body::module_new_with_objects_impl(
                CHAN_ADMIN_IN,
                CHAN_ADMIN_OUT,
                CHAN_NS_REQ,
                CHAN_NS_RESP,
                CHAN_BODY_REQ,
                CHAN_BODY_RESP,
                CHAN_OBJ_REQ,
                CHAN_OBJ_RESP,
                self.admin.as_mut_ptr(),
                self.admin.len(),
                &self.syscalls,
            )
        };
        if rc != 0 {
            return Err(anyhow!("admin_router init rc={rc}"));
        }
        Ok(())
    }

    /// Enable the admin_router's orphan-body GC (0 = off).
    pub fn set_gc_interval(&mut self, interval: u32) {
        unsafe { admin_body::set_gc_interval(self.admin.as_mut_ptr(), interval) };
    }

    /// Body node: only body_store runs; its channels are fed by a
    /// network bridge serving a remote admin node.
    pub fn spin_up_body_only(&mut self, body_root: &str) -> Result<()> {
        let rc = unsafe {
            body_store_body::module_new_impl(
                CHAN_BODY_REQ,
                CHAN_BODY_RESP,
                self.body_store.as_mut_ptr(),
                self.body_store.len(),
                &self.syscalls,
            )
        };
        if rc != 0 {
            return Err(anyhow!("body_store init rc={rc}"));
        }
        unsafe {
            body_store_body::set_root_dir(self.body_store.as_mut_ptr(), body_root.as_bytes());
        }
        Ok(())
    }
}

// ── Body-channel access for network bridging ───────────────────────
//
// The bridge on the admin node pops body_req (admin_router's
// downstream writes) and pushes body_resp; the bridge on the body
// node does the reverse. Same queues the PICs use — a bridged
// channel is indistinguishable from a local one.

pub fn pop_body_req() -> Option<Vec<u8>> {
    BODY_REQ.lock().unwrap().pop_front()
}

pub fn push_body_req(frame: Vec<u8>) {
    BODY_REQ.lock().unwrap().push_back(frame);
}

pub fn pop_body_resp() -> Option<Vec<u8>> {
    BODY_RESP.lock().unwrap().pop_front()
}

pub fn push_body_resp(frame: Vec<u8>) {
    BODY_RESP.lock().unwrap().push_back(frame);
}

pub fn pop_admin_out() -> Option<Vec<u8>> {
    ADMIN_OUT.lock().unwrap().pop_front()
}

// Per-member fleet channel access for the loam-server TCP bridges:
// a remote member's requests are popped here and framed to its
// body node; its responses come back the other way. When a member
// is DOWN, the bridge drains its requests and pushes synthesized
// NAKs instead — the fanout router's fallback machinery treats the
// dead member exactly like a NAK-ing one.

pub fn pop_fleet_req(i: usize) -> Option<Vec<u8>> {
    FLEET_REQ.get(i)?.lock().unwrap().pop_front()
}

pub fn push_fleet_resp(i: usize, frame: Vec<u8>) {
    if let Some(q) = FLEET_RESP.get(i) {
        q.lock().unwrap().push_back(frame);
    }
}
