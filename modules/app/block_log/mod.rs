#![no_std]

// Loam's block_log PIC. Channel-fronted append-only log. Step
// body in `modules/common/mechanics/block_log_body.rs`. `log_path` is
// configured via the `log_path` TLV param (tag = 1).

use core::ffi::c_void;

#[allow(dead_code, unused_imports, reason = "shared fluxor SDK include; each module uses a subset")]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_log_wire.rs"]
mod wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/block_log_body.rs"]
mod body;

mod params_def {
    use super::body::{ModuleState, LOG_PATH_BUF};
    use super::SCHEMA_MAX;

    define_params! {
        ModuleState;
        1, log_path, str, 0
            => |s, d, len| {
                if len == 0 || len > LOG_PATH_BUF { return; }
                let mut i = 0usize;
                while i < len {
                    s.log_path[i] = *d.add(i);
                    i += 1;
                }
                s.log_path_len = len as u16;
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
        decode_log_path_params(state_ptr, params, params_len);
        body::open_log_from_state(state_ptr)
    }
}

unsafe fn decode_log_path_params(state_ptr: *mut u8, params: *const u8, params_len: usize) {
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
    body::set_log_path(state_ptr, raw);
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    unsafe { body::module_step_impl(state_ptr) }
}

// Panic handler comes from `runtime.rs` via the include! above.
