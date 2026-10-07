#![no_std]
#![allow(
    dead_code,
    reason = "SDK runtime/params include! lands at crate root; each shim drives a subset"
)]

// Loam's object_provider PIC module: the canonical `storage.object`
// surface, answered from the admin plane over one link to `admin_gate`.
// Step body in `modules/common/mechanics/object_provider_body.rs`; ports
// and parameters in `manifest.toml`.

use core::ffi::c_void;

#[allow(
    dead_code,
    unused_imports,
    reason = "shared fluxor SDK include; each module uses a subset"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

// SHA-256: content digests for uploads, scope objects for grants.
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");

#[path = "../../common/mechanics/loam_limits.rs"]
mod limits;

#[path = "../../common/mechanics/loam_hash.rs"]
mod hash;

#[path = "../../common/mechanics/loam_body_wire.rs"]
mod body_wire;

#[path = "../../common/mechanics/loam_admin_wire.rs"]
mod admin;

#[path = "../../common/mechanics/object_provider_body.rs"]
mod body;

/// Longest `spool_dir`: the body's own ceiling, so the parameter and
/// the spool paths built from it cannot disagree.
const SPOOL_DIR_MAX: usize = body::SPOOL_DIR_MAX;
/// Longest `volume` name.
const VOLUME_MAX: usize = 32;

mod params_def {
    use super::{SCHEMA_MAX, SPOOL_DIR_MAX, VOLUME_MAX};

    pub struct Config {
        pub spool_dir: [u8; SPOOL_DIR_MAX],
        pub spool_dir_len: usize,
        pub volume: [u8; VOLUME_MAX],
        pub volume_len: usize,
        /// A value was given that does not fit: refused, never clipped.
        pub too_long: bool,
    }

    define_params! {
        Config;
        1, spool_dir, str, 0
            => |s, d, len| {
                if len > SPOOL_DIR_MAX {
                    s.too_long = true;
                    return;
                }
                let mut i = 0usize;
                while i < len {
                    s.spool_dir[i] = *d.add(i);
                    i += 1;
                }
                s.spool_dir_len = len;
            };
        // A keyed provider: reached by this volume's selector, leaving the
        // graph's default `storage.object` slot to another provider. Absent:
        // the default provider.
        2, volume, str, 0
            => |s, d, len| {
                if len > VOLUME_MAX {
                    s.too_long = true;
                    return;
                }
                let mut i = 0usize;
                while i < len {
                    s.volume[i] = *d.add(i);
                    i += 1;
                }
                s.volume_len = len;
            };
    }
}

unsafe fn refuse(sys: &SyscallTable, why: &[u8]) -> i32 {
    dev_log(sys, 1, why.as_ptr(), why.len());
    -22
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<body::ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// The module ABI's constructor: `state_ptr` points to `state_size`
/// zeroed bytes this module owns, `params` to `params_len` bytes, and
/// `syscalls` to the runtime's table, all valid for the call.
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        let sys = &*(syscalls as *const SyscallTable);
        let mut cfg = params_def::Config {
            spool_dir: [0; SPOOL_DIR_MAX],
            spool_dir_len: 0,
            volume: [0; VOLUME_MAX],
            volume_len: 0,
            too_long: false,
        };
        if !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01 {
            params_def::parse_tlv(&mut cfg, params, params_len);
        }
        if cfg.too_long || cfg.spool_dir_len == 0 {
            return refuse(
                sys,
                b"[object_provider] spool_dir is required (a directory of at most 192 bytes); volume is at most 32 bytes",
            );
        }
        if in_chan < 0 || out_chan < 0 {
            return refuse(
                sys,
                b"[object_provider] admin_in and admin_out must be wired to an admin_gate link",
            );
        }
        let rc = body::module_new_impl(
            in_chan,
            out_chan,
            &cfg.spool_dir[..cfg.spool_dir_len],
            state_ptr,
            state_size,
            syscalls as *const SyscallTable,
        );
        if rc == 0 && cfg.volume_len > 0 {
            let s = &mut *(state_ptr as *mut body::ModuleState);
            s.selector = abi::kernel_abi::provider_selector::hash(&cfg.volume[..cfg.volume_len]);
        }
        rc
    }
}

/// # Safety
/// The module ABI's step: the state pointer is the state `module_new`
/// initialised, and the runtime steps it from one caller at a time.
#[no_mangle]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    unsafe { body::module_step_impl(state_ptr) }
}

// ── storage.object provider exports ─────────────────────────────────

/// The selector this provider answers to: the hash of its `volume`, or 0
/// (the default provider) when it has none.
#[no_mangle]
#[link_section = ".text.module_provider_selector"]
pub extern "C" fn module_provider_selector(state: *mut u8) -> u32 {
    if state.is_null() {
        return 0;
    }
    // SAFETY: the loader passes this module's own initialised state.
    unsafe { (*(state as *const body::ModuleState)).selector }
}

#[no_mangle]
#[link_section = ".text.module_provides_contract"]
pub extern "C" fn module_provides_contract() -> u32 {
    body::CONTRACT_STORAGE_OBJECT
}

/// # Safety
/// The loader passes this module's own state pointer and a caller
/// buffer valid for `arg_len` bytes.
#[export_name = "module_provider_dispatch"]
#[link_section = ".text.module_provider_dispatch"]
pub unsafe extern "C" fn object_provider_dispatch(
    state_ptr: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    body::provider_dispatch_impl(state_ptr, handle, opcode, arg, arg_len)
}

// Panic handler comes from `runtime.rs` via the include! above.
