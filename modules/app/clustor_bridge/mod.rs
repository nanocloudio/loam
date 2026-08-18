#![no_std]
// Bridge: loam_decision_wire ⇄ Clustor replica group.
//
// Proposal path: raw loam Propose records (with correlation_id) arrive
// on `proposals`; each is wrapped VERBATIM as the opaque command body
// of a `MSG_CLIENT_PROPOSAL` and written to `clustor_out`
// (→ consensus.proposals).
//
// Commit path: `clustor_in` (← consensus.committed_entries)
// carries enveloped `MSG_COMMITTED_ENTRY` payloads of
// [term u64][index u64][body]. The body is the loam Propose record we
// proposed; it is decoded and re-emitted on `commits` as a loam
// Committed with witness_epoch = the Raft commit index and
// witness_quorum = the `witness_quorum` param (voter count; 1 for a
// single-node group).
//
// Clustor never inspects the command bytes (opaque-command contract,
// consumer_facade.md), so no clustor-side change is required.

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

// The Clustor consumer facade — the only surface a downstream replicated
// consumer binds to. It owns the channel envelope (type ids, framing,
// reassembly) and the committed-entry payload decode, so the bridge holds no
// copy of Clustor's wire vocabulary and cannot drift from it.
#[allow(dead_code, reason = "shared consumer facade; the bridge drives a subset")]
#[path = "../../../target/fluxor/clustor-common/replica_facade.rs"]
mod facade;

const MAX_OPS_PER_STEP: u32 = 4;
const BUF: usize = 4400;

define_params! {
    ModuleState;

    1, witness_quorum, u8, 1
        => |s, d, len| { s.witness_quorum = p_u8(d, len, 1, 1); };
}

#[repr(C)]
pub struct ModuleState {
    ticks: u32,
    syscalls: *const SyscallTable,
    proposals_in: i32,
    commits_out: i32,
    clustor_in: i32,
    clustor_out: i32,
    witness_quorum: u8,
    // Envelope reassembly for clustor_in (header + payload may arrive
    // across reads on a byte-stream channel).
    asm: [u8; BUF],
    asm_len: usize,
    // The same, for the inbound proposal stream: the proposer forwards
    // several records per step, so they coalesce into one read.
    req_asm: [u8; BUF],
    req_asm_len: usize,
    buf: [u8; BUF],
    forwarded: u32,
    committed: u32,
    errors: u32,
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        // Port order per manifest: in[0]=proposals, in[1]=clustor_in;
        // out[0]=commits, out[1]=clustor_out.
        s.proposals_in = in_chan;
        s.commits_out = out_chan;
        s.clustor_in = dev_channel_port(sys, 0, 1);
        s.clustor_out = dev_channel_port(sys, 1, 1);
        s.asm_len = 0;
        s.req_asm_len = 0;
        s.ticks = 0;
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // Level 3: the diagnostic transport a bring-up watches carries
        // level 3, so a lifecycle signal logged quieter is invisible
        // exactly when it is needed.
        dev_log(sys, 3, b"[clustor_bridge] ready".as_ptr(), 22);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        s.ticks = s.ticks.wrapping_add(1);
        // Power-of-two mask rather than a remainder: a remainder by a
        // runtime value pulls a divide-by-zero panic path into a build
        // that must stay panic-free.
        if s.ticks & 0x7FF == 0 {
            // ASCII only — dev_log strips NULs, so raw bytes never go
            // here. Eight hex digits per counter: two decimal digits
            // wrap at a hundred, which reads as "did nothing" for a
            // bridge that has carried thousands.
            let mut m = *b"[bridge] f=00000000 c=00000000 e=00000000";
            let d = |v: u32, at: usize, m: &mut [u8]| {
                let mut n = v;
                let mut i = at + 8;
                while i > at {
                    i -= 1;
                    m[i] = HEX[(n & 0xF) as usize];
                    n >>= 4;
                }
            };
            d(s.forwarded, 11, &mut m);
            d(s.committed, 22, &mut m);
            d(s.errors, 33, &mut m);
            dev_log(sys, 3, m.as_ptr(), m.len());
        }

        // ── Proposal path: loam Propose → MSG_CLIENT_PROPOSAL ────────
        if s.proposals_in >= 0 && s.clustor_out >= 0 {
            // The proposer forwards up to a step's worth of records, so
            // one read carries several and can end mid-record. Refill,
            // then take whole records off the front.
            loop {
                let space = s.req_asm.len() - s.req_asm_len;
                if space == 0 {
                    break;
                }
                let n =
                    (sys.channel_read)(s.proposals_in, s.req_asm.as_mut_ptr().add(s.req_asm_len), space);
                if n <= 0 {
                    break;
                }
                s.req_asm_len += n as usize;
            }

            let mut n_ops = 0u32;
            let mut off = 0usize;
            while n_ops < MAX_OPS_PER_STEP {
                let rec_len = match wire::record_len(&s.req_asm[off..s.req_asm_len]) {
                    Ok(Some(len)) => len,
                    Ok(None) => break,
                    Err(_) => {
                        // Not a decision record; skip a byte to resync.
                        s.errors = s.errors.wrapping_add(1);
                        off += 1;
                        n_ops += 1;
                        continue;
                    }
                };
                let rec = &s.req_asm[off..off + rec_len] as *const [u8];
                let rec = &*rec;
                off += rec_len;

                // Validate it really is a Propose before forwarding.
                if wire::decode_propose(rec).is_err() {
                    s.errors = s.errors.wrapping_add(1);
                    n_ops += 1;
                    continue;
                }
                // Envelope and payload compose into one buffer so this
                // is a single channel write, which is what keeps the
                // frame atomic against the reader splitting the stream.
                match facade::frame(&mut s.buf, facade::MSG_CLIENT_PROPOSAL, rec) {
                    Ok(total) => {
                        let wrote = (sys.channel_write)(s.clustor_out, s.buf.as_ptr(), total);
                        if wrote == total as i32 {
                            s.forwarded = s.forwarded.wrapping_add(1);
                        } else {
                            s.errors = s.errors.wrapping_add(1);
                        }
                    }
                    Err(_) => {
                        s.errors = s.errors.wrapping_add(1);
                    }
                }
                n_ops += 1;
            }
            if off > 0 {
                let remaining = s.req_asm_len - off;
                let mut i = 0usize;
                while i < remaining {
                    s.req_asm[i] = s.req_asm[off + i];
                    i += 1;
                }
                s.req_asm_len = remaining;
            }
        }

        // ── Commit path: MSG_COMMITTED_ENTRY → loam Committed ────────
        if s.clustor_in >= 0 && s.commits_out >= 0 {
            // Refill the reassembly buffer.
            loop {
                let space = s.asm.len() - s.asm_len;
                if space == 0 {
                    break;
                }
                let n = (sys.channel_read)(s.clustor_in, s.asm.as_mut_ptr().add(s.asm_len), space);
                if n <= 0 {
                    break;
                }
                s.asm_len += n as usize;
            }
            // Drain whole frames; an incomplete tail stays for the next read.
            let mut off = 0usize;
            while let Some((msg_type, payload, consumed)) =
                facade::next_frame(&s.asm[off..s.asm_len])
            {
                if msg_type == facade::MSG_COMMITTED_ENTRY {
                    if let Some(entry) = facade::CommittedEntry::decode(payload) {
                        match wire::decode_propose(entry.command) {
                            Ok(p) => {
                                let mut out = [0u8; BUF];
                                match wire::encode_committed(
                                    &mut out,
                                    p.plane,
                                    p.correlation_id,
                                    s.witness_quorum,
                                    entry.index, // witness epoch = the commit index
                                    p.inner,
                                ) {
                                    Ok(m) => {
                                        (sys.channel_write)(s.commits_out, out.as_ptr(), m);
                                        s.committed = s.committed.wrapping_add(1);
                                    }
                                    Err(_) => {
                                        s.errors = s.errors.wrapping_add(1);
                                    }
                                }
                            }
                            Err(_) => {
                                // Not a loam-originated entry (a foreign
                                // consumer sharing the group): skip silently.
                            }
                        }
                    }
                }
                off += consumed;
            }
            if off > 0 {
                s.asm.copy_within(off..s.asm_len, 0);
                s.asm_len -= off;
            }
        }
        0
    }
}

const HEX: [u8; 16] = *b"0123456789abcdef";
