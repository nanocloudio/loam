#![no_std]
#![allow(
    dead_code,
    reason = "SDK runtime/params include! lands at crate root; each shim drives a subset"
)]

// Loam's loam_volume PIC module: a `storage.block` source over one
// Loam volume. Step body in
// `modules/common/replicated/loam_volume_body.rs`.
//
// Ports: `admin_in` in[0] carries the admin plane's answers, `blocks`
// out[0] is the block channel consumers wire to, `admin_out` out[1]
// carries requests to the admin plane. The admin pair is either an
// in-graph link to `admin_gate` (`[session:u32][frame]` records) or
// the clear side of a client-mode `tls` (net_proto), as the `admin`
// parameter says; one request and its ack at a time.

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

#[path = "../../common/mechanics/loam_limits.rs"]
mod limits;

#[path = "../../common/mechanics/loam_admin_wire.rs"]
mod admin;

#[path = "../../common/mechanics/loam_body_wire.rs"]
mod body_wire;

#[path = "../../common/mechanics/loam_volume_map_wire.rs"]
mod map_wire;

#[path = "../../common/mechanics/admin_client.rs"]
mod admin_client;

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

        7, capability, str, 0
            => |s, d, len| { super::body::set_capability(s, core::slice::from_raw_parts(d, len)); };

        8, admin, str, 0
            => |s, d, len| { super::body::set_admin(s, core::slice::from_raw_parts(d, len)); };

        9, session, u32, 1
            => |s, d, len| { s.link_session = p_u32(d, len, 0, 1); };
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
        let sys = syscalls as *const SyscallTable;
        if sys.is_null() {
            return -1;
        }
        // `admin_in` is the first input; `admin_out` the second output.
        let admin_out = dev_channel_port(&*sys, 1, 1);
        let rc = body::module_new_impl(out_chan, state_ptr, state_size, sys);
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
        if in_chan < 0 || admin_out < 0 {
            let why = b"[loam_volume] admin_in and admin_out must be wired";
            dev_log(&*sys, 1, why.as_ptr(), why.len());
            return -22;
        }
        let tag = dev_requester_tag(&*sys);
        body::connect(state_ptr, in_chan, admin_out, tag);
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

/// # Safety
/// The module ABI's step: the state pointer is the state `module_new`
/// initialised, and the runtime steps it from one caller at a time.
#[no_mangle]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    unsafe { body::module_step_impl(state_ptr) }
}

/// Stop taking requests, commit what is staged, release the writer
/// lease, then report done from `module_step`.
///
/// # Safety
/// The module ABI's drain: `state_ptr` is the state `module_new`
/// initialised, and the runtime drains it from one caller at a time.
#[no_mangle]
#[link_section = ".text.module_drain"]
pub unsafe extern "C" fn module_drain(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    unsafe { body::drain(&mut *(state_ptr as *mut body::ModuleState)) };
    0
}

// Panic handler comes from `runtime.rs` via the include! above.
