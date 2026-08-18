#![no_std]

// Loam's admin_router PIC module. Front-door for external admin
// clients. Step body in `modules/common/mechanics/admin_router_body.rs`.
//
// Phase 4a: only the slot-0 input/output pair is wired by the
// kernel via `module_new`. Downstream namespace_router channels
// need explicit channel-port lookup once that helper exists; for
// now the PIC won't function inside a real graph without
// follow-up wiring. The host PIC harness exercises the body's
// internals directly.

use core::ffi::c_void;

#[allow(dead_code, unused_imports, reason = "shared fluxor SDK include; each module uses a subset")]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_admin_wire.rs"]
mod admin;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_wire.rs"]
mod ns_wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_body_wire.rs"]
mod body_wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_object_wire.rs"]
mod obj_wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/admin_router_body.rs"]
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
        // Slot-0 input = admin_in. Slot-0 output = admin_out.
        // ns_req / ns_resp default to -1 here; production
        // wiring overrides via channel-port lookup. The host
        // harness calls `module_new_impl` directly with explicit
        // ns_req/ns_resp.
        body::module_new_impl(
            in_chan,
            out_chan,
            -1,
            -1,
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

// Panic handler comes from `runtime.rs` via the include! above.
