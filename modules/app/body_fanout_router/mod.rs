#![no_std]
#![allow(
    dead_code,
    reason = "SDK runtime/params include! lands at crate root; each shim drives a subset"
)]

// Loam's body_fanout_router PIC module. Step body in
// `modules/common/replicated/body_fanout_router_body.rs`.
//
// Upstream, `body_requests` / `body_responses` speak body frames to
// admin_router. Downstream, member `i` is the pair `member{i}_req` /
// `member{i}_resp`: a body_store in the same graph, or one on another
// node behind `remote_channel`. Members are wired from 0 without gaps,
// at most `ROUTER_MEMBERS` of them, and the fleet starts as all of
// them; `fleet_epoch`, when wired, carries placement_router's updates.

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

#[path = "../../common/mechanics/loam_limits.rs"]
mod limits;

#[path = "../../common/mechanics/body_frame.rs"]
mod body_frame;

#[path = "../../common/replicated/member_io.rs"]
mod member_io;

#[path = "../../common/replicated/loam_placement_wire.rs"]
mod placement_wire;

#[path = "../../common/replicated/loam_placement.rs"]
mod placement;

#[path = "../../common/mechanics/loam_body_wire.rs"]
mod body_wire;

#[allow(
    dead_code,
    reason = "shared PIC body; each module shim drives a subset"
)]
#[path = "../../common/replicated/body_fanout_router_body.rs"]
mod body;

/// Member port pairs the manifest declares.
const MEMBER_PORTS: usize = 8;
/// Input index of `member0_resp` (after `body_requests`, `fleet_epoch`).
const MEMBER_RESP_BASE: u8 = 2;
/// Output index of `member0_req` (after `body_responses`).
const MEMBER_REQ_BASE: u8 = 1;
/// Input index of `fleet_epoch`.
const FLEET_EPOCH_IN: u8 = 1;

mod params_def {
    use super::{p_u32, p_u8, SCHEMA_MAX};

    pub struct Config {
        pub replicas: u8,
        pub scrub_interval: u32,
    }

    define_params! {
        Config;
        1, replicas, u8, 0
            => |s, d, len| { s.replicas = p_u8(d, len, 0, 0); };
        2, scrub_interval, u32, 0
            => |s, d, len| { s.scrub_interval = p_u32(d, len, 0, 0); };
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
            replicas: 0,
            scrub_interval: 0,
        };
        if !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01 {
            params_def::parse_tlv(&mut cfg, params, params_len);
        }
        let fleet_in = dev_channel_port(sys, 0, FLEET_EPOCH_IN);
        let mut req = [-1i32; MEMBER_PORTS];
        let mut resp = [-1i32; MEMBER_PORTS];
        let mut n = 0usize;
        let mut gap = false;
        for i in 0..MEMBER_PORTS {
            let r = dev_channel_port(sys, 1, MEMBER_REQ_BASE + i as u8);
            let a = dev_channel_port(sys, 0, MEMBER_RESP_BASE + i as u8);
            match (r >= 0, a >= 0) {
                (true, true) => {
                    if gap {
                        return refuse(
                            sys,
                            b"[body_fanout_router] members must be wired from member0 without gaps",
                        );
                    }
                    req[n] = r;
                    resp[n] = a;
                    n += 1;
                }
                (false, false) => gap = true,
                _ => {
                    return refuse(
                        sys,
                        b"[body_fanout_router] a member is wired in one direction only",
                    );
                }
            }
        }
        if n == 0 {
            return refuse(sys, b"[body_fanout_router] no member is wired");
        }
        if n > limits::ROUTER_MEMBERS {
            return refuse(
                sys,
                b"[body_fanout_router] more members are wired than this profile's ROUTER_MEMBERS",
            );
        }
        let replicas = if cfg.replicas == 0 {
            n.min(3) as u8
        } else {
            cfg.replicas
        };
        if replicas as usize > n {
            return refuse(
                sys,
                b"[body_fanout_router] replicas exceeds the wired members",
            );
        }
        body::module_new_impl(
            in_chan,
            out_chan,
            fleet_in,
            &req[..n],
            &resp[..n],
            replicas,
            cfg.scrub_interval,
            state_ptr,
            state_size,
            syscalls as *const SyscallTable,
        )
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
