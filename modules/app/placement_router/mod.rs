#![no_std]

// Loam's placement_router PIC module. The step-body logic lives in
// `modules/common/replicated/placement_router_body.rs`, path-included below;
// this file is the thin `#[no_mangle] extern "C"` glue plus the
// `define_params!` schema that lets the fluxor build tool pack a
// YAML `params: { seed_members: [0,1,2] }` field into the TLV blob
// the kernel hands to `module_new`.

#![allow(dead_code, reason = "SDK runtime/params include! lands at crate root; each shim drives a subset")]
use core::ffi::c_void;

#[allow(dead_code, unused_imports, reason = "shared fluxor SDK include; each module uses a subset")]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/replicated/loam_placement_wire.rs"]
mod placement_wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/replicated/placement_router_body.rs"]
mod body;

/// TLV parameter schema. `tag = 1` carries the launch-time fleet
/// member list as a raw byte array (one byte per member id). The
/// handler stages the bytes via `decode_seed_params`, which calls
/// the body's atomic-update path so the epoch ticks to 1 before
/// the first `module_step`.
mod params_def {
    use super::body::ModuleState;
    use super::placement_wire::MAX_FLEET;
    use super::SCHEMA_MAX;

    define_params! {
        ModuleState;
        1, seed_members, str, 0
            => |s, d, len| {
                if len == 0 || len > MAX_FLEET { return; }
                // Re-use the body's atomic-update path so the epoch
                // bumps + emitted_current resets in one place.
                let slice = core::slice::from_raw_parts(d, len);
                super::body::apply_fleet_update_pub(s, slice);
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
        body::decode_seed_params(state_ptr, params, params_len);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    unsafe { body::module_step_impl(state_ptr) }
}
