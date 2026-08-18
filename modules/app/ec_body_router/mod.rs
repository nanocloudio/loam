#![no_std]

// Loam's ec_body_router PIC module. Step body in
// `modules/common/replicated/ec_body_router_body.rs`.
//
// Like body_fanout_router, only slot-0 in/out arrive through
// `module_new`; resolving the per-target downstream channels by name
// with `dev_channel_port` is outstanding work (RFC 0005 P1.1). Until
// then the host harness drives the body's internals directly via
// `module_new_with_targets_impl`.

use core::ffi::c_void;

#[allow(dead_code, unused_imports, reason = "shared fluxor SDK include; each module uses a subset")]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");

mod sha256 {
    pub use super::Sha256;
}

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/replicated/loam_placement_wire.rs"]
mod placement_wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/replicated/loam_placement.rs"]
mod placement;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_body_wire.rs"]
mod body_wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_ec.rs"]
mod ec;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_ec_wire.rs"]
mod ec_wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/replicated/ec_body_router_body.rs"]
mod body;

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
    _params: *const u8,
    _params_len: usize,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        // Slot-0 in = body_requests; slot-0 out = body_responses.
        // No downstream targets wired — production wiring is
        // blocked on the channel-port lookup helper (same as
        // body_fanout_router). Default geometry 4+2.
        body::module_new_with_targets_impl(
            in_chan,
            out_chan,
            -1,
            &[],
            &[],
            4,
            2,
            0,
            state_ptr,
            state_size,
            syscalls as *const SyscallTable,
        )
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    unsafe { body::module_step_impl(state_ptr) }
}
