#![no_std]

// Loam's raft_metadata_client PIC module. Implements the proposer
// adapter between the public-surface PICs (namespace_router,
// object_index, block_allocator) and a Clustor replica group.
//
// The step body lives in `modules/common/replicated/raft_proposer_body.rs`;
// this file is the `#[no_mangle] extern "C"` glue and the
// `define_params!` schema for `wal_path` + `mode`.

use core::ffi::c_void;

#[allow(dead_code, unused_imports, reason = "shared fluxor SDK include; each module uses a subset")]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/replicated/loam_decision_wire.rs"]
mod wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/wal_io.rs"]
mod wal;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/replicated/raft_proposer_body.rs"]
mod body;

mod params_def {
    use super::body::{ModuleState, MODE_REPLICATED, MODE_SINGLE_REPLICA, WAL_PATH_BUF};
    use super::SCHEMA_MAX;

    define_params! {
        ModuleState;
        1, wal_path, str, 0
            => |s, d, len| {
                if len == 0 || len > WAL_PATH_BUF { return; }
                let mut i = 0usize;
                while i < len {
                    s.wal_path[i] = *d.add(i);
                    i += 1;
                }
                s.wal_path_len = len as u16;
            };
        2, mode, u8, MODE_SINGLE_REPLICA as u32
            => |s, d, len| {
                if len == 0 { return; }
                let m = *d;
                s.mode = if m == MODE_REPLICATED { MODE_REPLICATED } else { MODE_SINGLE_REPLICA };
            };
        3, self_id, u8, 0
            => |s, d, len| {
                if len == 0 { return; }
                s.self_id = *d;
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
        // The kernel hands the first manifest input as `in_chan`
        // (= `metadata_ops`) and the first declared output as
        // `out_chan` (= `metadata_results`). The optional Clustor
        // channels are looked up by port index: clustor_requests =
        // out[1], clustor_commits = in[1]. Unwired ports resolve to
        // -1 and the body stays in single-replica mode.
        let clustor_out = dev_channel_port(&*sys, 1, 1);
        let clustor_in = dev_channel_port(&*sys, 0, 1);
        let rc = body::module_new_full_impl(
            in_chan, clustor_out, out_chan, clustor_in, state_ptr, state_size, sys,
        );
        if rc != 0 {
            return rc;
        }
        body::decode_wal_path_params(state_ptr, params, params_len);
        // Decode mode from the same TLV blob if present.
        if !params.is_null() && params_len >= 4 {
            let is_tlv = *params == 0xFE && *params.add(1) == 0x01;
            if is_tlv {
                params_def::parse_tlv(
                    &mut *(state_ptr as *mut body::ModuleState),
                    params,
                    params_len,
                );
            }
        }
        // A failed WAL open is reported through the heartbeat and by
        // refusing proposals, not by refusing to instantiate: a module
        // that never starts never steps, so its absence is the only
        // symptom and the cause is invisible. Nothing is logged here —
        // the network the diagnostic transport rides comes up as part
        // of this same graph, so an init-time line has nowhere to go.
        let _ = body::open_wal_from_state(state_ptr);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    let rc = unsafe { body::module_step_impl(state_ptr) };
    unsafe { heartbeat(state_ptr) };
    rc
}

/// Periodic heartbeat: what the plane has taken in and what it has
/// resolved.
///
/// Without it, a proposer that never opened its WAL and a proposer with
/// nothing to do are both simply silent — which is the pair a bring-up
/// most needs to tell apart, and telling them apart from outside is
/// otherwise guesswork. Fields: `w` the WAL descriptor (a leading `-`
/// means it never opened), `p`/`c`/`a` proposals taken in, committed
/// and refused, `e` decode and append failures, `q` in flight.
unsafe fn heartbeat(state_ptr: *mut u8) {
    if state_ptr.is_null() {
        return;
    }
    let s = &*(state_ptr as *const body::ModuleState);
    // Power-of-two mask rather than a remainder: a remainder by a
    // runtime value pulls a divide-by-zero panic path into a build
    // that must stay panic-free.
    if s.ticks & 0x7FF != 0 {
        return;
    }
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return,
    };
    let mut line =
        *b"[loam-mp] wal=+00000000 p=00000000 c=00000000 a=00000000 e=00000000 q=00000000";
    // Report the descriptor when the WAL opened, and the provider's
    // refusal code when it did not — the code is what separates "no
    // such path" from "the provider rejected the name".
    let (sign_at, hex_at) = (14usize, 15usize);
    let wal_field = if s.wal_fd >= 0 {
        s.wal_fd
    } else {
        s.wal_open_rc
    };
    if wal_field < 0 {
        line[sign_at] = b'-';
    }
    write_hex(&mut line, hex_at, wal_field.unsigned_abs());
    write_hex(&mut line, 26, s.proposed);
    write_hex(&mut line, 37, s.committed);
    write_hex(&mut line, 48, s.aborted);
    write_hex(&mut line, 59, s.apply_errors);
    write_hex(&mut line, 70, body::in_flight(state_ptr));
    dev_log(sys, 3, line.as_ptr(), line.len());
}

fn write_hex(dst: &mut [u8], at: usize, value: u32) {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut n = value;
    let mut i = at + 8;
    while i > at {
        i -= 1;
        dst[i] = HEX[(n & 0xF) as usize];
        n >>= 4;
    }
}

// Panic handler comes from `runtime.rs` via the include! above.
