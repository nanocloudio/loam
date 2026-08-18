#![no_std]
// Metadata-plane e2e probe: one Propose in, one Committed out,
// verified. Exercises proposer WAL → clustor_bridge → Raft (WAL,
// quorum, commit) → apply → bridge → Committed, end to end.

use core::ffi::c_void;

#[allow(dead_code, unused_imports, reason = "shared fluxor SDK include; each module uses a subset")]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/replicated/loam_decision_wire.rs"]
mod wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_wire.rs"]
mod ns_wire;

/// The namespace bind this probe proposes.
///
/// It is a real `loam_wire` Bind record, not an opaque marker. A probe
/// that proposes arbitrary bytes proves the proposer, the bridge, the
/// replica and the commit stream — but it does not prove that what
/// round-tripped was a *binding*, which is the thing the plane exists
/// to replicate. The verdict below decodes the committed inner payload
/// back into a bind and checks its fields, so "the metadata plane
/// commits a bind" is a claim the probe actually tests.
const PROBE_ROOT: &[u8] = b"acme";
const PROBE_PATH: &[u8] = b"/probe/replicated-bind";
const PROBE_OBJECT: &[u8] = b"probe-object-1";
const PROBE_REVISION: u64 = 1;

/// Encode the probe's bind into `dst`, returning its length.
fn encode_probe_bind(dst: &mut [u8]) -> Option<usize> {
    ns_wire::encode_bind(
        dst,
        PROBE_ROOT,
        PROBE_PATH,
        PROBE_OBJECT,
        0,
        PROBE_REVISION,
    )
    .ok()
}

/// Does `inner` decode back to the bind this probe proposed?
fn is_probe_bind(inner: &[u8]) -> bool {
    match ns_wire::decode_bind(inner) {
        Ok(b) => {
            b.namespace_root == PROBE_ROOT
                && b.path == PROBE_PATH
                && b.object_id == PROBE_OBJECT
                && b.revision == PROBE_REVISION
        }
        Err(_) => false,
    }
}

#[repr(C)]
pub struct ModuleState {
    syscalls: *const SyscallTable,
    results_in: i32,
    ops_out: i32,
    phase: u8,
    ticks: u32,
    buf: [u8; 4400],
    /// Reassembly for `metadata_results`. The plane can answer with
    /// several records in one read — a replay marker, a refusal and a
    /// commit can all land together — and a read can end mid-record.
    asm: [u8; 4400],
    asm_len: usize,
    /// The verdict, re-emitted on a cadence once reached. A one-shot
    /// line is unobservable here: the network the diagnostic transport
    /// rides comes up as part of this same graph, so anything said in
    /// the first seconds is said to nobody. Repeating it is what makes
    /// it an assertable signal rather than a race.
    verdict: u8,
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
    _params: *const u8,
    _params_len: usize,
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
        s.syscalls = syscalls as *const SyscallTable;
        s.results_in = in_chan;
        s.ops_out = out_chan;
        s.phase = 0;
        s.ticks = 0;
        s.asm_len = 0;
        s.verdict = 0;
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
        match s.phase {
            0 => {
                // Give the group a moment to elect a leader.
                if s.ticks < 50 {
                    return 0;
                }
                let mut inner = [0u8; 256];
                let inner_len = match encode_probe_bind(&mut inner) {
                    Some(n) => n,
                    None => {
                        s.verdict = 2;
                        s.phase = 2;
                        return 0;
                    }
                };
                let n = match wire::encode_propose(
                    &mut s.buf,
                    wire::PLANE_NAMESPACE,
                    0,
                    &inner[..inner_len],
                ) {
                    Ok(n) => n,
                    Err(_) => {
                        s.verdict = 2;
                        s.phase = 2;
                        return 0;
                    }
                };
                (sys.channel_write)(s.ops_out, s.buf.as_ptr(), n);
                s.phase = 1;
            }
            1 if s.ticks % 500 == 0 && s.ticks < 29_500 => {
                // Re-propose until committed: an early Propose can be
                // dropped while the group is still electing. Same
                // correlation semantics (proposer assigns fresh ids;
                // duplicate binds are idempotent at the namespace PIC).
                let mut inner = [0u8; 256];
                if let Some(inner_len) = encode_probe_bind(&mut inner) {
                    if let Ok(n) = wire::encode_propose(
                        &mut s.buf,
                        wire::PLANE_NAMESPACE,
                        0,
                        &inner[..inner_len],
                    ) {
                        (sys.channel_write)(s.ops_out, s.buf.as_ptr(), n);
                    }
                }
            }
            1 => {
                loop {
                    let space = s.asm.len() - s.asm_len;
                    if space == 0 {
                        break;
                    }
                    let n = (sys.channel_read)(
                        s.results_in,
                        s.asm.as_mut_ptr().add(s.asm_len),
                        space,
                    );
                    if n <= 0 {
                        break;
                    }
                    s.asm_len += n as usize;
                }

                let mut off = 0usize;
                let mut verdict = 0u8; // 0 none, 1 pass, 2 mismatch
                while let Ok(Some(len)) = wire::record_len(&s.asm[off..s.asm_len]) {
                    let rec_start = off;
                    off += len;
                    match s.asm[rec_start] {
                        // Lifecycle marker, and a refusal the plane is
                        // entitled to make before its WAL is open. A
                        // probe that treats either as failure reports
                        // flakiness — it re-proposes and waits instead.
                        wire::OP_REPLAY_DRAINED | wire::OP_ABORTED => continue,
                        _ => {}
                    }
                    match wire::decode_committed(&s.asm[rec_start..rec_start + len]) {
                        Ok(c) if is_probe_bind(c.inner) && c.witness_epoch > 0 => {
                            verdict = 1;
                            break;
                        }
                        _ => {
                            verdict = 2;
                            break;
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

                match verdict {
                    1 | 2 => s.verdict = verdict,
                    _ => {
                        // Patience covers election and dial races. A
                        // probe that gives up before the group settles
                        // reports flakiness, not failure.
                        if s.ticks > 30_000 {
                            s.verdict = 3;
                            s.phase = 2;
                        }
                        return 0;
                    }
                }
                s.phase = 2;
            }
            // Verdict reached: repeat it on a cadence so it is
            // observable whenever the transport came up.
            2 if s.ticks & 0x1FF == 0 => match s.verdict {
                1 => dev_log(sys, 3, b"[meta_e2e] PASS".as_ptr(), 15),
                2 => dev_log(sys, 3, b"[meta_e2e] FAIL mismatch".as_ptr(), 24),
                _ => dev_log(sys, 3, b"[meta_e2e] FAIL timeout".as_ptr(), 23),
            },
            _ => {}
        }
        0
    }
}
