#![no_std]

// Loam's body_store PIC module. Disk-backed content-addressed
// object body store; bodies live at `<root_dir>/<hex(sha256)>`.
// Step body in `modules/common/mechanics/body_store_body.rs`. `root_dir`
// is configured via the `root_dir` TLV param (tag = 1); without
// it PUT/GET respond ERR_NO_ROOT.

use core::ffi::c_void;

#[allow(dead_code, unused_imports, reason = "shared fluxor SDK include; each module uses a subset")]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_body_wire.rs"]
mod wire;

mod sha256 {
    pub use super::Sha256;
}

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_ec_wire.rs"]
mod ec_wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_extent_wire.rs"]
mod extent_wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/body_store_body.rs"]
mod body;

mod params_def {
    use super::body::{ModuleState, ROOT_DIR_BUF};
    use super::SCHEMA_MAX;

    define_params! {
        ModuleState;
        1, root_dir, str, 0
            => |s, d, len| {
                if len == 0 || len > ROOT_DIR_BUF { return; }
                let mut i = 0usize;
                while i < len {
                    s.root_dir[i] = *d.add(i);
                    i += 1;
                }
                s.root_dir_len = len as u16;
            };
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<body::ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
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
        let sys = syscalls as *const SyscallTable;
        let rc = body::module_new_impl(in_chan, out_chan, state_ptr, state_size, sys);
        if rc != 0 {
            return rc;
        }
        decode_root_dir_params(state_ptr, params, params_len);
        0
    }
}

/// Decode the `root_dir` param: either a TLV blob (`[0xFE, 0x01, …]`)
/// with `tag = 1` entry, or a raw byte slice. Mirrors the dual-mode
/// decoder in `namespace_pic_body::decode_wal_path_params`.
unsafe fn decode_root_dir_params(
    state_ptr: *mut u8,
    params: *const u8,
    params_len: usize,
) {
    if params.is_null() || params_len == 0 {
        return;
    }
    let is_tlv = params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
    if is_tlv {
        params_def::parse_tlv(
            &mut *(state_ptr as *mut body::ModuleState),
            params,
            params_len,
        );
        return;
    }
    let raw = core::slice::from_raw_parts(params, params_len);
    body::set_root_dir(state_ptr, raw);
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    unsafe { body::module_step_impl(state_ptr) }
}

// Panic handler comes from `runtime.rs` via the include! above.
