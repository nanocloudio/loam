#![no_std]

// Metadata-plane load generator.
//
// Offers `loam_decision_wire` Propose records — each carrying a
// `loam_wire` Bind as its opaque inner payload — into
// `raft_metadata_client.metadata_ops`, which is the same shape the
// plane carries in production. Every record gets a distinct path and a
// distinct correlation id, so a downstream counter can pair each result
// with the request that produced it and no bind collides with another.
//
// Offered load is what this module controls; achieved load is what the
// plane does with it. The two diverge exactly when the plane is
// saturated, which is the measurement worth having, so the generator
// never paces itself off the consumer's progress.
//
// Params (TLV):
//   1  inject_period   ticks between batches (default 1 = every tick)
//   2  batch_per_step  records per batch, capped by MAX_OPS_PER_STEP
//   3  total           records to offer, 0 = unbounded (default 0)
//   4  warmup_ticks    ticks to wait before the first batch
//   5  report_ticks    ticks between report lines (default 1000)
//   6  plane           0 = metadata plane (Propose records, default)
//                      1 = namespace surface (bare bind requests)

use core::ffi::c_void;

#[allow(dead_code, unused_imports, reason = "shared fluxor SDK include; each module uses a subset")]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_wire.rs"]
mod wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/replicated/loam_decision_wire.rs"]
mod decision;

/// Ceiling on records emitted in one step, whatever `batch_per_step`
/// asks for. The step stays bounded so the scheduler keeps its budget.
const MAX_OPS_PER_STEP: u32 = 8;

const NAMESPACE_ROOT: &[u8] = b"acme";

define_params! {
    ModuleState;

    1, inject_period, u32, 1
        => |s, d, len| { s.inject_period = p_u32(d, len, 0, 1); };
    2, batch_per_step, u32, 4
        => |s, d, len| { s.batch_per_step = p_u32(d, len, 0, 4); };
    3, total, u32, 0
        => |s, d, len| { s.total = p_u32(d, len, 0, 0); };
    4, warmup_ticks, u32, 0
        => |s, d, len| { s.warmup_ticks = p_u32(d, len, 0, 0); };
    5, report_ticks, u32, 1000
        => |s, d, len| { s.report_ticks = p_u32(d, len, 0, 1000); };
    6, plane, u32, PLANE_METADATA
        => |s, d, len| { s.plane = p_u32(d, len, 0, PLANE_METADATA); };
}

/// Offer Propose records into the replicated metadata plane
/// (`raft_metadata_client.metadata_ops`).
pub const PLANE_METADATA: u32 = 0;
/// Offer bare bind requests into a namespace surface
/// (`namespace_router.requests`), which proposes them itself when it
/// is wired in replicated mode. Same load, entered a layer higher.
pub const PLANE_NAMESPACE: u32 = 1;

#[repr(C)]
pub struct ModuleState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    ticks: u32,
    /// Ticks left before the next batch. Counting down avoids a
    /// remainder by a runtime value, which a bare-metal build cannot
    /// take (it pulls in a division-by-zero panic path).
    period_left: u32,
    /// Sequence behind both the bind path and the correlation id, so
    /// every offered record is distinguishable from every other.
    seq: u32,
    emitted: u32,
    /// Records the channel refused. Offered-minus-emitted is the
    /// generator's own backpressure, distinct from the plane refusing a
    /// proposal it accepted off the channel.
    refused: u32,
    inject_period: u32,
    batch_per_step: u32,
    total: u32,
    warmup_ticks: u32,
    report_ticks: u32,
    plane: u32,
    last_report_tick: u32,
    window_offered: u32,
    window_emitted: u32,
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if state_ptr.is_null() || syscalls.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state_ptr as *mut ModuleState);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;
        s.ticks = 0;
        s.seq = 0;
        s.emitted = 0;
        s.refused = 0;
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        if s.inject_period == 0 {
            s.inject_period = 1;
        }
        if s.report_ticks == 0 {
            s.report_ticks = 1000;
        }
        s.period_left = s.warmup_ticks;
        s.last_report_tick = 0;
        s.window_offered = 0;
        s.window_emitted = 0;
        0
    }
}

/// Report write attempts against records accepted.
///
/// Without both numbers a shortfall downstream is unattributable: a
/// plane committing below the offered rate and a generator that never
/// got its records onto the channel look identical from the consumer's
/// end.
///
/// `o` counts write attempts and `e` counts records the channel took,
/// so `o - e` is this module's own backpressure. A refused write is
/// retried with the same sequence next tick rather than skipped — the
/// generator is lossless by construction — which is why a retried
/// record shows up in `o` more than once. `E` and `R` are the same
/// two quantities since boot.
unsafe fn emit_report(s: &ModuleState, syscalls: &SyscallTable) {
    let mut line = [0u8; 96];
    let mut pos = 0usize;
    pos += copy_tag(&mut line[pos..], b"[loam-lg] w=");
    pos += write_hex_u32(&mut line[pos..], s.ticks.wrapping_sub(s.last_report_tick));
    pos += copy_tag(&mut line[pos..], b" o=");
    pos += write_hex_u32(&mut line[pos..], s.window_offered);
    pos += copy_tag(&mut line[pos..], b" e=");
    pos += write_hex_u32(&mut line[pos..], s.window_emitted);
    pos += copy_tag(&mut line[pos..], b" E=");
    pos += write_hex_u32(&mut line[pos..], s.emitted);
    pos += copy_tag(&mut line[pos..], b" R=");
    pos += write_hex_u32(&mut line[pos..], s.refused);
    dev_log(syscalls, 3, line.as_ptr(), pos);
}

fn copy_tag(dst: &mut [u8], tag: &[u8]) -> usize {
    let mut i = 0usize;
    while i < tag.len() && i < dst.len() {
        dst[i] = tag[i];
        i += 1;
    }
    i
}

fn write_hex_u32(dst: &mut [u8], value: u32) -> usize {
    if dst.len() < 8 {
        return 0;
    }
    let mut n = value;
    let mut i = 8usize;
    while i > 0 {
        i -= 1;
        dst[i] = HEX[(n & 0xF) as usize];
        n >>= 4;
    }
    8
}

/// Write `value` as `width` lowercase hex digits ending at `end`.
fn write_hex(dst: &mut [u8], end: usize, width: usize, value: u32) {
    let mut n = value;
    let mut i = end;
    let mut w = 0;
    while w < width {
        i -= 1;
        dst[i] = HEX[(n & 0xF) as usize];
        n >>= 4;
        w += 1;
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    unsafe {
        if state_ptr.is_null() {
            return -1;
        }
        let s = &mut *(state_ptr as *mut ModuleState);
        s.ticks = s.ticks.wrapping_add(1);

        let syscalls = match s.syscalls.as_ref() {
            Some(t) => t,
            None => return -1,
        };

        if s.ticks.wrapping_sub(s.last_report_tick) >= s.report_ticks {
            emit_report(s, syscalls);
            s.last_report_tick = s.ticks;
            s.window_offered = 0;
            s.window_emitted = 0;
        }

        if s.period_left > 0 {
            s.period_left -= 1;
            return 0;
        }
        s.period_left = s.inject_period - 1;

        // `total == 0` runs until the graph stops, which is what a soak
        // wants; a bounded run is what a repeatable measurement wants.
        if s.total != 0 && s.emitted >= s.total {
            return 0;
        }

        let mut budget = s.batch_per_step;
        if budget > MAX_OPS_PER_STEP {
            budget = MAX_OPS_PER_STEP;
        }

        let mut done: u32 = 0;
        while done < budget {
            if s.total != 0 && s.emitted >= s.total {
                break;
            }

            let mut path_bytes = *b"/p000000";
            write_hex(&mut path_bytes, 8, 6, s.seq);
            let mut oid_bytes = *b"o000000";
            write_hex(&mut oid_bytes, 7, 6, s.seq);

            let mut inner = [0u8; 64];
            let inner_len = match wire::encode_bind(
                &mut inner,
                NAMESPACE_ROOT,
                &path_bytes,
                &oid_bytes,
                0,
                s.seq as u64 + 1,
            ) {
                Ok(n) => n,
                Err(_) => break,
            };

            // Entering at the namespace surface means offering the bind
            // itself; entering at the metadata plane means offering it
            // already wrapped as a proposal. The payload is the same
            // record either way, which is what makes the two comparable.
            let mut buf = [0u8; 128];
            let n = if s.plane == PLANE_NAMESPACE {
                if inner_len > buf.len() {
                    break;
                }
                buf[..inner_len].copy_from_slice(&inner[..inner_len]);
                inner_len
            } else {
                // Correlation ids start at 1: zero is reserved as
                // "untagged" and would make the record unaddressable.
                match decision::encode_propose(
                    &mut buf,
                    decision::PLANE_NAMESPACE,
                    s.seq.wrapping_add(1),
                    &inner[..inner_len],
                ) {
                    Ok(n) => n,
                    Err(_) => break,
                }
            };

            s.window_offered = s.window_offered.wrapping_add(1);
            let wrote = (syscalls.channel_write)(s.out_chan, buf.as_ptr(), n);
            if wrote != n as i32 {
                // The channel is full: the plane is not draining as fast
                // as this batch offers. Stop here and retry next tick
                // rather than spinning against a full ring.
                s.refused = s.refused.wrapping_add(1);
                break;
            }
            s.seq = s.seq.wrapping_add(1);
            s.emitted = s.emitted.wrapping_add(1);
            s.window_emitted = s.window_emitted.wrapping_add(1);
            done += 1;
        }
        0
    }
}

const HEX: [u8; 16] = *b"0123456789abcdef";
