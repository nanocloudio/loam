#![no_std]

// Metadata-plane throughput counter.
//
// Drains `loam_decision_wire` results and reports what the plane
// actually resolved, per window and since boot:
//
//   [loam-tp] w=NNNNNNNN c=NNNNNNNN a=NNNNNNNN C=NNNNNNNN A=NNNNNNNN
//
//   w  ticks in the window        c/a  committed/aborted this window
//   C/A  committed/aborted since boot          (all values hex)
//
// Counting RECORDS, not bytes, is the whole point: a Committed carries
// a variable-length payload, so a byte count reports payload size
// rather than operations resolved. The per-window pair is what a rate
// is read from; the totals are what a soak is checked against.
//
// Aborted is reported beside Committed rather than folded into it — a
// plane that refuses everything and a plane that commits everything
// both look busy, and only the split tells them apart.
//
// `stream` selects what the input carries. The plane emits decision
// records; a public surface emits a one-byte acknowledgement per
// operation. Both resolve into the same committed/refused pair, so both
// are counted the same way and read the same way — but a surface's
// acks are not decision records, and parsing them as such would report
// every one of them as malformed.

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

#[allow(
    dead_code,
    reason = "shared PIC body; each module shim drives a subset"
)]
#[path = "../../common/replicated/loam_decision_wire.rs"]
mod wire;

const READ_BUF: usize = 512;
/// Reassembly for records that span reads. Sized past the largest
/// record the plane emits so a single record always fits.
const ASM: usize = 8192;
const MAX_DRAIN_PER_STEP: u32 = 32;

define_params! {
    ModuleState;

    1, report_ticks, u32, 1000
        => |s, d, len| { s.report_ticks = p_u32(d, len, 0, 1000); };

    2, stream, u32, STREAM_DECISIONS
        => |s, d, len| { s.stream = p_u32(d, len, 0, STREAM_DECISIONS); };
}

/// Input carries `loam_decision_wire` records from the metadata plane.
const STREAM_DECISIONS: u32 = 0;
/// Input carries a public surface's one-byte acknowledgements.
const STREAM_ACKS: u32 = 1;

/// Surface refusals. Anything else acknowledges the operation it
/// echoes, so the opcode itself is the success byte.
const ACK_REFUSED: u8 = 0xFF;
const ACK_NOT_READY: u8 = 0xFE;

#[repr(C)]
pub struct ModuleState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    ticks: u32,
    last_report_tick: u32,
    report_ticks: u32,
    stream: u32,
    window_committed: u32,
    window_aborted: u32,
    total_committed: u32,
    total_aborted: u32,
    /// Records whose opcode the wire does not know. A non-zero value
    /// means this channel is carrying something that is not a decision
    /// record, which invalidates the rate above it.
    unparsed: u32,
    asm: [u8; ASM],
    asm_len: usize,
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
    in_chan: i32,
    _out_chan: i32,
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
        s.in_chan = in_chan;
        s.ticks = 0;
        s.last_report_tick = 0;
        s.window_committed = 0;
        s.window_aborted = 0;
        s.total_committed = 0;
        s.total_aborted = 0;
        s.unparsed = 0;
        s.asm_len = 0;
        s.stream = STREAM_DECISIONS;
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        if s.report_ticks == 0 {
            s.report_ticks = 1000;
        }
        0
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

        if s.in_chan >= 0 {
            let mut drained: u32 = 0;
            while drained < MAX_DRAIN_PER_STEP {
                let space = ASM - s.asm_len;
                if space < READ_BUF {
                    break;
                }
                let n =
                    (syscalls.channel_read)(s.in_chan, s.asm.as_mut_ptr().add(s.asm_len), READ_BUF);
                if n <= 0 {
                    break;
                }
                s.asm_len += n as usize;
                drained = drained.wrapping_add(1);
            }

            let mut off = 0usize;
            if s.stream == STREAM_ACKS {
                // One byte, one operation: nothing to reassemble.
                while off < s.asm_len {
                    match s.asm[off] {
                        ACK_REFUSED | ACK_NOT_READY => {
                            s.window_aborted = s.window_aborted.wrapping_add(1);
                            s.total_aborted = s.total_aborted.wrapping_add(1);
                        }
                        _ => {
                            s.window_committed = s.window_committed.wrapping_add(1);
                            s.total_committed = s.total_committed.wrapping_add(1);
                        }
                    }
                    off += 1;
                }
            } else {
                loop {
                    match wire::record_len(&s.asm[off..s.asm_len]) {
                        Ok(Some(len)) => {
                            match s.asm[off] {
                                wire::OP_COMMITTED => {
                                    s.window_committed = s.window_committed.wrapping_add(1);
                                    s.total_committed = s.total_committed.wrapping_add(1);
                                }
                                wire::OP_ABORTED => {
                                    s.window_aborted = s.window_aborted.wrapping_add(1);
                                    s.total_aborted = s.total_aborted.wrapping_add(1);
                                }
                                // The replay marker is a lifecycle signal,
                                // not an operation; counting it would
                                // inflate the first window of every boot.
                                _ => {}
                            }
                            off += len;
                        }
                        // Incomplete tail: keep it for the next read.
                        Ok(None) => break,
                        // Not a decision record. Skip one byte to resync
                        // rather than stall on a stream we cannot parse.
                        Err(_) => {
                            s.unparsed = s.unparsed.wrapping_add(1);
                            off += 1;
                        }
                    }
                }
            }
            if off > 0 {
                let remaining = s.asm_len - off;
                let mut i = 0usize;
                while i < remaining {
                    s.asm[i] = s.asm[off + i];
                    i += 1;
                }
                s.asm_len = remaining;
            }
        }

        if s.ticks.wrapping_sub(s.last_report_tick) >= s.report_ticks {
            emit_report(s, syscalls);
            s.last_report_tick = s.ticks;
            s.window_committed = 0;
            s.window_aborted = 0;
        }
        0
    }
}

unsafe fn emit_report(s: &ModuleState, syscalls: &SyscallTable) {
    let mut line = [0u8; 96];
    let mut pos = 0usize;
    pos += copy_tag(&mut line[pos..], b"[loam-tp] w=");
    pos += write_hex_u32(&mut line[pos..], s.ticks.wrapping_sub(s.last_report_tick));
    pos += copy_tag(&mut line[pos..], b" c=");
    pos += write_hex_u32(&mut line[pos..], s.window_committed);
    pos += copy_tag(&mut line[pos..], b" a=");
    pos += write_hex_u32(&mut line[pos..], s.window_aborted);
    pos += copy_tag(&mut line[pos..], b" C=");
    pos += write_hex_u32(&mut line[pos..], s.total_committed);
    pos += copy_tag(&mut line[pos..], b" A=");
    pos += write_hex_u32(&mut line[pos..], s.total_aborted);
    if s.unparsed != 0 {
        pos += copy_tag(&mut line[pos..], b" bad=");
        pos += write_hex_u32(&mut line[pos..], s.unparsed);
    }
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

const HEX: [u8; 16] = *b"0123456789abcdef";
