//! In-process PIC driver. Mirrors the test harness pattern
//! (`tests/common/mechanics/pic_harness.rs` in the loam crate): real `fs`
//! syscalls backed by `std::fs`, fake channel syscalls backed by
//! a `VecDeque<Vec<u8>>`. Each CLI command resets state, runs one
//! step, drains the output channel, and prints.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Mutex;

// fluxor SDK + PIC modules. Path-includes resolve from this file.

#[allow(
    dead_code,
    unused_imports,
    reason = "shared fluxor SDK include; each includer uses a subset"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
pub use abi::SyscallTable;

// Reused sha256 from the SDK so the body_store body's `super::sha256::Sha256`
// resolves. Same name + shape as the body_store PIC's mod.rs.
#[allow(
    dead_code,
    unused_imports,
    reason = "shared fluxor SDK include; each includer uses a subset"
)]
mod sha256_impl {
    include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
}
pub mod sha256 {
    #[allow(
        unused_imports,
        reason = "consumed by #[path]-included PIC bodies via super::sha256"
    )]
    pub use super::sha256_impl::Sha256;
}

// Wire formats. Multiple PICs use different `wire` aliases; we
// give body_store its own wrapper module via #[path] tricks.
#[path = "../../../modules/common/mechanics/loam_wire.rs"]
pub mod ns_wire;

#[path = "../../../modules/common/mechanics/loam_body_wire.rs"]
pub mod body_wire;

#[path = "../../../modules/common/mechanics/loam_admin_wire.rs"]
pub mod admin_wire;

#[path = "../../../modules/common/mechanics/namespace_pic_state.rs"]
mod state;

#[path = "../../../modules/common/mechanics/wal_io.rs"]
pub mod wal;

// namespace_router body uses `super::wire`, `super::state`,
// `super::wal`, `super::SyscallTable` — all visible at this
// module's crate-root-ish scope via the aliases above (ns_wire is
// imported as `wire` below) so we forward via a local `wire` mod.
mod wire {
    pub use super::ns_wire::*;
}

#[path = "../../../modules/common/mechanics/loam_snapshot.rs"]
pub mod snapshot;

#[allow(
    dead_code,
    reason = "shared PIC body include; each includer drives a subset"
)]
#[path = "../../../modules/common/mechanics/namespace_pic_body.rs"]
pub mod ns_body;

// object_index body looks for `super::wire` (= loam_object_wire),
// `super::state` (= object_pic_state), `super::wal`,
// `super::SyscallTable`. Wrap so its `super::*` lookups land
// correctly without colliding with the namespace `wire` alias.
#[path = "../../../modules/common/mechanics/loam_object_wire.rs"]
pub mod obj_wire;

pub mod obj_scope {
    pub use super::abi::SyscallTable;
    pub mod wire {
        pub use super::super::obj_wire::*;
    }
    pub mod state {
        // Notional dir: tools/loam-cli/src/pic/obj_scope/state/.
        // Six levels up reaches the workspace root.
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

// body_store body looks for `super::wire`, `super::sha256`, and
// `super::SyscallTable`. The `wire` name above is taken by
// ns_wire; wrap body_store in a scope that re-aliases `wire`.
pub mod body_store_scope {
    pub use super::abi::SyscallTable;
    pub mod sha256 {
        pub use super::super::sha256_impl::Sha256;
    }
    pub mod wire {
        pub use super::super::body_wire::*;
    }
    // Notional dir: `tools/loam-cli/src/pic/body_store_scope/`.
    // Up five levels reaches the workspace root.
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

// ── In-process channels ──────────────────────────────────────────
//
// Each CLI command sees a fresh state via `reset_state()`. Only
// CHAN_IN and CHAN_OUT are used (one PIC per command).

pub const CHAN_IN: i32 = 1;
pub const CHAN_OUT: i32 = 2;

static INBOUND: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());
static OUTBOUND: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static FS_FILES: Mutex<Vec<Option<File>>> = Mutex::new(Vec::new());

pub fn reset_state() {
    INBOUND.lock().unwrap().clear();
    OUTBOUND.lock().unwrap().clear();
    FS_FILES.lock().unwrap().clear();
}

pub fn push_inbound(payload: Vec<u8>) {
    INBOUND.lock().unwrap().push_back(payload);
}

pub fn drain_outbound() -> Vec<u8> {
    std::mem::take(&mut *OUTBOUND.lock().unwrap())
}

// ── Channel syscalls ─────────────────────────────────────────────

unsafe extern "C" fn chan_read(_h: i32, buf: *mut u8, len: usize) -> i32 {
    let mut inb = INBOUND.lock().unwrap();
    if let Some(p) = inb.pop_front() {
        let n = p.len().min(len);
        unsafe { std::ptr::copy_nonoverlapping(p.as_ptr(), buf, n) };
        n as i32
    } else {
        0
    }
}

unsafe extern "C" fn chan_write(_h: i32, data: *const u8, len: usize) -> i32 {
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    OUTBOUND.lock().unwrap().extend_from_slice(slice);
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

// ── Real `fs` syscall (slot-table backed by std::fs) ────────────
//
// Mirrors fluxor linux dispatch including FS_OPEN_CREATE.

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
        FS_OPEN => {
            if arg.is_null() || arg_len == 0 {
                return -22;
            }
            let bytes = unsafe { std::slice::from_raw_parts(arg as *const u8, arg_len) };
            let path = match std::str::from_utf8(bytes) {
                Ok(p) => p,
                Err(_) => return -22,
            };
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(f) => fs_slot_for(f),
                Err(_) => -19,
            }
        }
        FS_OPEN_CREATE => {
            if arg.is_null() || arg_len == 0 {
                return -22;
            }
            let bytes = unsafe { std::slice::from_raw_parts(arg as *const u8, arg_len) };
            let path = match std::str::from_utf8(bytes) {
                Ok(p) => p,
                Err(_) => return -22,
            };
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
            {
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

// ── ModuleState scratch allocator ────────────────────────────────

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
