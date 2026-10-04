#![no_std]
#![allow(
    dead_code,
    reason = "SDK runtime/params include! lands at crate root; each shim drives a subset"
)]

// Loam's admin_router PIC module: composes the admin wire's
// operations over the namespace, object and body planes. Step body in
// `modules/common/mechanics/admin_router_body.rs`.
//
// `admin_in` / `admin_out` carry admin-wire requests and answers from
// one client — `admin_gate`, which multiplexes every session onto it.
// Downstream, `ns_req` / `ns_resp` reach namespace_router, `obj_req` /
// `obj_resp` object_index, and `body_req` / `body_resp` the body plane
// (body_store, or a body router in front of several) in body frames.
// The namespace pair is required; a graph without the object or body
// pair serves only the operations that do not touch them.

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

#[path = "../../common/mechanics/loam_admin_wire.rs"]
mod admin;

#[path = "../../common/mechanics/loam_limits.rs"]
mod limits;

#[path = "../../common/mechanics/loam_wire.rs"]
mod ns_wire;

#[path = "../../common/mechanics/loam_body_wire.rs"]
mod body_wire;

#[path = "../../common/mechanics/body_frame.rs"]
mod body_frame;

#[path = "../../common/mechanics/loam_object_wire.rs"]
mod obj_wire;

#[path = "../../common/mechanics/loam_volume_map_wire.rs"]
mod map_wire;

#[allow(
    dead_code,
    reason = "shared PIC body; each module shim drives a subset"
)]
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

/// Input indices after `admin_in`.
const NS_RESP_IN: u8 = 1;
const OBJ_RESP_IN: u8 = 2;
const BODY_RESP_IN: u8 = 3;
/// Output indices after `admin_out`.
const NS_REQ_OUT: u8 = 1;
const OBJ_REQ_OUT: u8 = 2;
const BODY_REQ_OUT: u8 = 3;

mod params_def {
    use super::{p_u32, SCHEMA_MAX};

    pub struct Config {
        pub gc_interval: u32,
    }

    define_params! {
        Config;
        1, gc_interval, u32, 0
            => |s, d, len| { s.gc_interval = p_u32(d, len, 0, 0); };
    }
}

unsafe fn refuse(sys: &SyscallTable, why: &[u8]) -> i32 {
    dev_log(sys, 1, why.as_ptr(), why.len());
    -22
}

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
        let mut cfg = params_def::Config { gc_interval: 0 };
        if !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01 {
            params_def::parse_tlv(&mut cfg, params, params_len);
        }
        let pair = |o: u8, i: u8| (dev_channel_port(sys, 1, o), dev_channel_port(sys, 0, i));
        let (ns_req, ns_resp) = pair(NS_REQ_OUT, NS_RESP_IN);
        let (obj_req, obj_resp) = pair(OBJ_REQ_OUT, OBJ_RESP_IN);
        let (body_req, body_resp) = pair(BODY_REQ_OUT, BODY_RESP_IN);
        if ns_req < 0 || ns_resp < 0 {
            return refuse(
                sys,
                b"[admin_router] the namespace pair (ns_req, ns_resp) is required",
            );
        }
        if (obj_req < 0) != (obj_resp < 0) || (body_req < 0) != (body_resp < 0) {
            return refuse(
                sys,
                b"[admin_router] a downstream pair is wired in one direction only",
            );
        }
        if cfg.gc_interval != 0 && (obj_req < 0 || body_req < 0) {
            return refuse(
                sys,
                b"[admin_router] gc_interval needs the object and body pairs",
            );
        }
        let rc = body::module_new_with_objects_impl(
            in_chan,
            out_chan,
            ns_req,
            ns_resp,
            body_req,
            body_resp,
            obj_req,
            obj_resp,
            state_ptr,
            state_size,
            syscalls as *const SyscallTable,
        );
        if rc != 0 {
            return rc;
        }
        body::set_gc_interval(state_ptr, cfg.gc_interval);
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

// Panic handler comes from `runtime.rs` via the include! above.
