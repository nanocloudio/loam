#![no_std]
#![allow(
    dead_code,
    reason = "SDK runtime/params include! lands at crate root; each shim drives a subset"
)]

// Loam's loam_volume PIC module: a `storage.block` source over one
// Loam volume. Step body in
// `modules/common/replicated/loam_volume_body.rs`.
//
// Ports: `admin_resp` in[0] carries the node's admin acks, `blocks`
// out[0] is the block channel consumers wire to, `admin_req` out[1]
// carries admin requests to the node. Both admin ports speak the raw
// loam admin wire, one request and its ack at a time.

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
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");

mod sha256 {
    pub use super::Sha256;
}

#[allow(
    dead_code,
    reason = "shared PIC body; each module shim drives a subset"
)]
#[path = "../../common/mechanics/loam_limits.rs"]
mod limits;

#[allow(
    dead_code,
    reason = "shared PIC body; each module shim drives a subset"
)]
#[path = "../../common/mechanics/loam_admin_wire.rs"]
mod admin;

#[path = "../../common/mechanics/loam_volume_map_wire.rs"]
mod map_wire;

#[allow(
    dead_code,
    reason = "shared PIC body; each module shim drives a subset"
)]
#[path = "../../common/replicated/loam_volume_body.rs"]
mod body;

mod params_def {
    use super::body::{set_path, set_root, ModuleState};
    use super::p_u32;
    use super::SCHEMA_MAX;

    define_params! {
        ModuleState;

        1, root, str, 0
            => |s, d, len| { set_root(s, core::slice::from_raw_parts(d, len)); };

        2, path, str, 0
            => |s, d, len| { set_path(s, core::slice::from_raw_parts(d, len)); };

        3, lease_ttl_ms, u32, 30000
            => |s, d, len| { s.ttl_ms = p_u32(d, len, 0, 30000); };

        4, block_size, u32, 4096
            => |s, d, len| { s.block_size = p_u32(d, len, 0, 4096); };

        5, holder, str, 0
            => |s, d, len| { super::body::set_holder(s, core::slice::from_raw_parts(d, len)); };

        6, fence, str, 0
            => |s, d, len| { super::body::set_fence(s, core::slice::from_raw_parts(d, len)); };
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<body::ModuleState>() as u32
}

/// Consumers wait for the lease and the committed root: `Ready` gates
/// them.
#[no_mangle]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 {
    1
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
        if sys.is_null() {
            return -1;
        }
        // `admin_req`, the second output.
        let req_chan = dev_channel_port(&*sys, 1, 1);
        let rc = body::module_new_impl(in_chan, out_chan, req_chan, state_ptr, state_size, sys);
        if rc != 0 {
            return rc;
        }
        let s = &mut *(state_ptr as *mut body::ModuleState);
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        if out_chan >= 0 {
            dev_channel_register_ioctl(
                &*sys,
                out_chan,
                state_ptr as *mut c_void,
                Some(body::block_ioctl),
            );
        }
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    unsafe { body::module_step_impl(state_ptr) }
}

// Panic handler comes from `runtime.rs` via the include! above.
