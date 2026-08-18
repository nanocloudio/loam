// Shared step-body implementation for `raft_metadata_client`.
//
// Acts as the proposer-side adapter between the public-surface
// PICs (`namespace_router`, `object_index`, `block_allocator`)
// and a Clustor replica group. Two modes:
//
//   MODE_SINGLE_REPLICA (default; what runs today on a single
//      device with no real Clustor peer): every Propose is
//      durably logged, then immediately echoed back as a
//      Committed event tagged `LocalDurable` (witness_quorum =
//      1, witness_epoch = monotone u64). Producers consuming
//      the `metadata_results` channel see the same byte shape
//      they will see once a real Clustor PIC sits behind us.
//
//   MODE_REPLICATED: each Propose is durably logged then
//      forwarded to `clustor_requests`. Committed events
//      arriving on `clustor_commits` carry an upstream
//      witness (quorum/epoch) that we copy verbatim into the
//      outgoing Committed on `metadata_results`.
//
// Durability: every Propose lands in the proposer's own WAL
// before it leaves the PIC. After a restart, replay re-emits
// each logged Propose to the downstream commit path so the
// producer doesn't have to retry.

const MAX_OPS_PER_STEP: u32 = 4;
const READ_BUF: usize = 4200; // header + MAX_INNER
/// Reassembly capacity for `metadata_ops`. Holds one maximal record
/// plus a read's worth of the next, so a record that straddles reads
/// always has somewhere to land.
const OPS_ASM: usize = READ_BUF * 2;
const PENDING_CAP: usize = 256;

pub const MODE_SINGLE_REPLICA: u8 = 0;
pub const MODE_REPLICATED: u8 = 1;
/// Re-forward a pending proposal if its commit hasn't round-tripped
/// within this many ticks (~10 s at 20 TPS, ~2.5 s at 250 µs ticks —
/// generously past any election + group-commit latency).
pub const FORWARD_RETRY_TICKS: u16 = 200;

pub const WAL_PATH_BUF: usize = 256;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PendingEntry {
    pub in_use: u8,
    pub plane: u8,
    /// Replicated mode: set once the proposal has been forwarded to
    /// the Clustor channel; cleared again by the catch-up if no commit
    /// arrives within FORWARD_RETRY_TICKS (proposals sent before the
    /// group elects a leader are consumed and lost — at-least-once
    /// delivery is required, and consumers make duplicates idempotent
    /// via revision-gated upserts). Replayed WAL entries start at 0.
    pub forwarded: u8,
    /// Ticks since forwarding (see `forwarded`).
    pub forward_age: u16,
    pub correlation_id: u32,
    /// The correlation id the producer chose, carried alongside the
    /// node-scoped `correlation_id` this proposer assigns. The
    /// node-scoped id addresses the Clustor round trip; this one
    /// addresses the producer, and every record emitted on
    /// `metadata_results` carries it. Without it a producer holding
    /// more than one operation in flight cannot tell which result
    /// belongs to which request.
    pub origin_correlation_id: u32,
    pub inner_len: u16,
    // Inner payload, sized to the wire-format cap. The pending
    // table is large; `ModuleState` is zero-initialized via
    // `core::ptr::write_bytes` in `init_state` so we don't need
    // Default-derives that std refuses for arrays > 32.
    pub inner: [u8; super::wire::MAX_INNER],
}

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    pub ops_in_chan: i32,      // metadata_ops (from public PICs)
    pub clustor_out_chan: i32, // clustor_requests (to Clustor PIC; -1 in single-replica)
    pub results_out_chan: i32, // metadata_results (downstream consumers)
    pub clustor_in_chan: i32,  // commits from Clustor PIC (-1 in single-replica)
    pub wal_fd: i32,
    pub append_scratch: [u8; super::wal::APPEND_SCRATCH],
    pub wal_path: [u8; WAL_PATH_BUF],
    pub wal_path_len: u16,
    pub mode: u8,
    /// Number of WAL-replayed proposals whose commit hasn't
    /// round-tripped yet. When this reaches 0 (immediately on a fresh
    /// boot), a single OP_REPLAY_DRAINED marker is emitted on
    /// `metadata_results` so read surfaces know replay converged.
    pub replay_outstanding: u32,
    pub replay_marker_sent: u8,
    /// One-shot: the WAL has been rotated this boot (see the marker
    /// block in module_step). The proposer WAL is a delivery buffer —
    /// every replayed record has committed downstream by marker time,
    /// so the history is dead weight that would replay through Raft
    /// again next boot (observed: 4-minute boots at ~260 records).
    pub wal_rotated: u8,
    /// A `wal_path` was configured but could not be opened. The
    /// proposer still instantiates — a module that refuses to start is
    /// simply absent, and absence is the least diagnosable failure
    /// there is — but it refuses every proposal instead of accepting
    /// them without a durable backing, which would be worse than not
    /// starting at all.
    pub wal_unavailable: u8,
    /// The provider's return code from the last WAL open attempt. The
    /// code is what distinguishes "no such path" from "the provider
    /// refused the name" from "the device errored", and none of those
    /// are guessable from the outside.
    pub wal_open_rc: i32,
    /// The WAL open should be attempted again on a later step; see
    /// `WalOpenError::Again`.
    pub wal_retry: u8,
    /// Reassembly for the `clustor_commits` byte stream (records
    /// coalesce across reads; same discipline as every other stream).
    pub cin_asm: [u8; 8192],
    pub cin_asm_len: usize,
    /// Reassembly for the `metadata_ops` byte stream. Producers batch,
    /// so one read routinely returns several Propose records and may
    /// end mid-record; both are the stream behaving normally.
    pub ops_asm: [u8; OPS_ASM],
    pub ops_asm_len: usize,
    pub next_correlation_id: u32,
    /// Node id stamped into the high byte of every assigned
    /// correlation id. Proposals from different nodes in a
    /// replica group land in disjoint correlation spaces, so a
    /// committed entry is attributable to exactly one proposer —
    /// without this, every node's proposer can match a foreign
    /// commit whose (local-counter) id collides with its own.
    pub self_id: u8,
    pub next_epoch: u64,
    pub ticks: u32,
    pub proposed: u32,
    pub committed: u32,
    pub aborted: u32,
    pub apply_errors: u32,
    pub pending: [PendingEntry; PENDING_CAP],
}

/// Channel-only init (no WAL, no Clustor commits channel). The
/// PIC mod.rs is responsible for wiring `mode`, `wal_path`, and
/// `clustor_in_chan` after this returns; if they're left at
/// defaults the proposer runs in single-replica mode against a
/// volatile WAL (Committed events still emit; durability is lost
/// across restart).
pub unsafe fn module_new_impl(
    ops_in_chan: i32,
    results_out_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(
        ops_in_chan,
        -1,
        results_out_chan,
        -1,
        state_ptr,
        state_size,
        syscalls,
    )
}

/// Full init with explicit Clustor channels (call from mod.rs
/// after looking up the upstream/downstream channel handles).
pub unsafe fn module_new_full_impl(
    ops_in_chan: i32,
    clustor_out_chan: i32,
    results_out_chan: i32,
    clustor_in_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(
        ops_in_chan,
        clustor_out_chan,
        results_out_chan,
        clustor_in_chan,
        state_ptr,
        state_size,
        syscalls,
    )
}

unsafe fn init_state(
    ops_in_chan: i32,
    clustor_out_chan: i32,
    results_out_chan: i32,
    clustor_in_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    if state_ptr.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<ModuleState>() {
        return -2;
    }
    // Zero the whole state — `pending` is large and we need every
    // slot's `in_use` byte to start at 0.
    core::ptr::write_bytes(state_ptr, 0u8, state_size);
    let s = &mut *(state_ptr as *mut ModuleState);
    s.syscalls = syscalls;
    s.ops_in_chan = ops_in_chan;
    s.clustor_out_chan = clustor_out_chan;
    s.results_out_chan = results_out_chan;
    s.clustor_in_chan = clustor_in_chan;
    s.wal_fd = -1;
    s.mode = MODE_SINGLE_REPLICA;
    s.next_correlation_id = 1;
    s.next_epoch = 1;
    // Channel-only boots (no WAL) have nothing to replay: the marker
    // goes out on the first step.
    s.replay_outstanding = 0;
    s.replay_marker_sent = 0;
    s.wal_rotated = 0;
    s.cin_asm_len = 0;
    s.ops_asm_len = 0;
    0
}

/// See `namespace_pic_body::decode_wal_path_params`. The proposer
/// reuses the same dual-format (TLV with tag=1, or raw bytes).
pub unsafe fn decode_wal_path_params(state_ptr: *mut u8, params: *const u8, params_len: usize) {
    if state_ptr.is_null() || params.is_null() || params_len == 0 {
        return;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    let is_tlv = params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
    if is_tlv {
        let mut off = 4usize;
        while off + 2 <= params_len {
            let tag = *params.add(off);
            let elen = *params.add(off + 1) as usize;
            off += 2;
            if tag == 0xFF {
                break;
            }
            if tag == 1 && off + elen <= params_len {
                let copy = elen.min(WAL_PATH_BUF);
                let src = params.add(off);
                let mut i = 0usize;
                while i < copy {
                    s.wal_path[i] = *src.add(i);
                    i += 1;
                }
                s.wal_path_len = copy as u16;
                return;
            }
            off += elen;
        }
        return;
    }
    let copy = params_len.min(WAL_PATH_BUF);
    let src = params;
    let mut i = 0usize;
    while i < copy {
        s.wal_path[i] = *src.add(i);
        i += 1;
    }
    s.wal_path_len = copy as u16;
}

pub unsafe fn open_wal_from_state(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &*(state_ptr as *const ModuleState);
    let len = s.wal_path_len as usize;
    if len == 0 || len > WAL_PATH_BUF {
        return 0;
    }
    let path_ptr = s.wal_path.as_ptr();
    let path = core::slice::from_raw_parts(path_ptr, len);
    open_and_replay_wal(state_ptr, path)
}

pub unsafe fn open_and_replay_wal(state_ptr: *mut u8, wal_path: &[u8]) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return -1,
    };
    let fd = match super::wal::wal_open_or_create(sys, wal_path) {
        Ok(fd) => fd,
        Err(e) => {
            s.wal_unavailable = 1;
            s.wal_open_rc = match e {
                super::wal::WalOpenError::NotFound => -19,
                super::wal::WalOpenError::Again => -11,
                super::wal::WalOpenError::OpenFailed(rc) => rc,
            };
            // "Again" is the provider saying it has not finished, not
            // that it refused: on a profile where the filesystem sits
            // over a real device, creating a file needs I/O that does
            // not fit in one bounded step. Retry it on later steps
            // instead of spending the whole run without a WAL.
            s.wal_retry = u8::from(matches!(e, super::wal::WalOpenError::Again));
            return -3;
        }
    };
    s.wal_fd = fd;

    // Replay every Propose record back into the pending table so
    // a restart-after-crash retries downstream emission for any
    // proposal that didn't make it to its consumer.
    let mut scratch = [0u8; super::wal::MAX_WAL_REC];
    let state_for_cb: *mut u8 = state_ptr;
    let mut replay_errors: u32 = 0;
    let replay_rc = super::wal::wal_replay(sys, fd, &mut scratch, |payload| {
        let s_cb = &mut *(state_for_cb as *mut ModuleState);
        if let Ok(p) = super::wire::decode_propose(payload) {
            // The WAL holds the Propose verbatim, so a replayed entry
            // still carries the correlation id its producer chose and
            // its eventual result stays addressable.
            if reserve_pending(s_cb, p.plane, p.correlation_id, p.inner).is_err() {
                replay_errors = replay_errors.wrapping_add(1);
            }
        } else {
            replay_errors = replay_errors.wrapping_add(1);
        }
        true
    });
    if replay_rc.is_ok() {
        // Pending entries now hold the replayed proposals; the
        // first few steps will drain them downstream.
        s.apply_errors = replay_errors;
    }
    // Everything in the pending table right now came from replay.
    let mut n: u32 = 0;
    for slot in s.pending.iter() {
        if slot.in_use != 0 {
            n += 1;
        }
    }
    s.replay_outstanding = n;
    s.replay_marker_sent = 0;
    0
}

/// Reserve a pending slot, copy the inner bytes, and assign a
/// fresh correlation id. Returns the assigned correlation id.
unsafe fn reserve_pending(
    s: &mut ModuleState,
    plane: u8,
    origin_correlation_id: u32,
    inner: &[u8],
) -> Result<u32, ()> {
    if inner.len() > super::wire::MAX_INNER {
        return Err(());
    }
    for slot in s.pending.iter_mut() {
        if slot.in_use == 0 {
            slot.in_use = 1;
            slot.plane = plane;
            slot.origin_correlation_id = origin_correlation_id;
            // Node-scoped id: self_id in the high byte, a 24-bit
            // local counter below it (wraps past zero).
            slot.correlation_id =
                ((s.self_id as u32) << 24) | (s.next_correlation_id & 0x00FF_FFFF);
            slot.inner_len = inner.len() as u16;
            let dst = slot.inner.as_mut_ptr();
            let src = inner.as_ptr();
            core::ptr::copy_nonoverlapping(src, dst, inner.len());
            s.next_correlation_id = s.next_correlation_id.wrapping_add(1) & 0x00FF_FFFF;
            if s.next_correlation_id == 0 {
                s.next_correlation_id = 1;
            }
            return Ok(slot.correlation_id);
        }
    }
    Err(())
}

/// Tell the producer its proposal did not enter the plane, addressed by
/// the correlation id the producer chose.
///
/// A refusal that is only counted is indistinguishable from one still in
/// flight: the producer waits out its own timeout and, under sustained
/// offered load, keeps offering into a plane that is already refusing.
/// Every path that declines a proposal emits this.
unsafe fn emit_aborted_for(s: &mut ModuleState, origin_correlation_id: u32) {
    let scratch_ptr: *mut u8 = s.append_scratch.as_mut_ptr();
    let scratch_cap = s.append_scratch.len();
    let scratch = core::slice::from_raw_parts_mut(scratch_ptr, scratch_cap);
    let n = match super::wire::encode_aborted(scratch, origin_correlation_id) {
        Ok(n) => n,
        Err(_) => return,
    };
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return,
    };
    (sys.channel_write)(s.results_out_chan, scratch.as_ptr(), n);
    s.aborted = s.aborted.wrapping_add(1);
}

/// How many proposals the plane is currently carrying unresolved.
/// The shim reports this: in-flight that stays bounded under load is
/// backpressure working, and in-flight that climbs is a leak.
pub unsafe fn in_flight(state_ptr: *const u8) -> u32 {
    if state_ptr.is_null() {
        return 0;
    }
    let s = &*(state_ptr as *const ModuleState);
    let mut n = 0u32;
    for slot in s.pending.iter() {
        if slot.in_use != 0 {
            n += 1;
        }
    }
    n
}

unsafe fn find_pending(s: &mut ModuleState, correlation_id: u32) -> Option<&mut PendingEntry> {
    for slot in s.pending.iter_mut() {
        if slot.in_use != 0 && slot.correlation_id == correlation_id {
            return Some(slot);
        }
    }
    None
}

/// Emit a Committed record for `correlation_id` on the results
/// channel. Releases the pending slot on success.
///
/// SAFETY: `s` must be valid for the duration. Internally we
/// alias raw pointers into `s.pending[i].inner` and
/// `s.append_scratch` — the body runs single-threaded so this
/// non-overlapping write is sound.
unsafe fn emit_committed_for(
    s: &mut ModuleState,
    correlation_id: u32,
    witness_quorum: u8,
    witness_epoch: u64,
) -> bool {
    // Pull the fields we need from the pending entry, then drop
    // the &mut PendingEntry borrow so we can use `s.syscalls` and
    // `s.append_scratch` freely.
    let (plane, origin, inner_len, inner_ptr) = {
        let pending = match find_pending(s, correlation_id) {
            Some(p) => p,
            None => return false,
        };
        (
            pending.plane,
            pending.origin_correlation_id,
            pending.inner_len as usize,
            pending.inner.as_ptr(),
        )
    };
    let scratch_ptr: *mut u8 = s.append_scratch.as_mut_ptr();
    let scratch_cap = s.append_scratch.len();
    let inner = core::slice::from_raw_parts(inner_ptr, inner_len);
    let scratch = core::slice::from_raw_parts_mut(scratch_ptr, scratch_cap);
    let n = match super::wire::encode_committed(
        scratch,
        plane,
        origin,
        witness_quorum,
        witness_epoch,
        inner,
    ) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let results_chan = s.results_out_chan;
    let sys_ptr = s.syscalls;
    let sys = match sys_ptr.as_ref() {
        Some(t) => t,
        None => return false,
    };
    let wrote = (sys.channel_write)(results_chan, scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        return false;
    }
    // Free the pending slot only after the downstream write
    // succeeded; on failure the entry stays and the next tick
    // retries.
    if let Some(pending) = find_pending(s, correlation_id) {
        pending.in_use = 0;
        pending.inner_len = 0;
        if s.replay_outstanding > 0 {
            // Replayed pendings were forwarded before any live ingest
            // and Raft commits in submission order, so the first
            // `replay_outstanding` frees are the replayed ones.
            s.replay_outstanding -= 1;
        }
    }
    s.committed = s.committed.wrapping_add(1);
    true
}

/// Forward a pending proposal on `clustor_out_chan` (Replicated
/// mode). Doesn't free the pending slot — that happens when the
/// Committed event arrives on `clustor_in_chan`.
unsafe fn forward_to_clustor(s: &mut ModuleState, correlation_id: u32) -> bool {
    if s.clustor_out_chan < 0 {
        return false;
    }
    let (plane, inner_len, inner_ptr) = {
        let pending = match find_pending(s, correlation_id) {
            Some(p) => p,
            None => return false,
        };
        (
            pending.plane,
            pending.inner_len as usize,
            pending.inner.as_ptr(),
        )
    };
    let scratch_ptr: *mut u8 = s.append_scratch.as_mut_ptr();
    let scratch_cap = s.append_scratch.len();
    let inner = core::slice::from_raw_parts(inner_ptr, inner_len);
    let scratch = core::slice::from_raw_parts_mut(scratch_ptr, scratch_cap);
    let n = match super::wire::encode_propose(scratch, plane, correlation_id, inner) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let out_chan = s.clustor_out_chan;
    let sys_ptr = s.syscalls;
    let sys = match sys_ptr.as_ref() {
        Some(t) => t,
        None => return false,
    };
    let wrote = (sys.channel_write)(out_chan, scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        return false;
    }
    true
}

pub unsafe fn module_step_impl(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    s.ticks = s.ticks.wrapping_add(1);

    // One retry per step while the provider is still working on the
    // open. Proposals are refused meanwhile — see `wal_unavailable` —
    // so nothing is acked without a durable backing in the interim.
    if s.wal_retry != 0 {
        s.wal_retry = 0;
        s.wal_unavailable = 0;
        open_wal_from_state(state_ptr);
    }

    let s = &mut *(state_ptr as *mut ModuleState);
    let syscalls = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return -1,
    };

    // ── 1. Drain inbound Propose requests from public PICs. ────
    //
    // `metadata_ops` is a byte stream. A producer that batches puts
    // several records into one read, and a read can end mid-record;
    // both are normal. Refill a reassembly buffer, then take whole
    // records off the front of it — up to the step budget, leaving the
    // rest for the next step rather than dropping it.
    if s.ops_in_chan >= 0 {
        loop {
            let space = OPS_ASM - s.ops_asm_len;
            if space < READ_BUF {
                break;
            }
            let n = (syscalls.channel_read)(
                s.ops_in_chan,
                s.ops_asm.as_mut_ptr().add(s.ops_asm_len),
                READ_BUF,
            );
            if n <= 0 {
                break;
            }
            s.ops_asm_len += n as usize;
        }
    }

    let mut handled: u32 = 0;
    let mut ops_off: usize = 0;
    while handled < MAX_OPS_PER_STEP {
        let rec_len = match super::wire::record_len(&s.ops_asm[ops_off..s.ops_asm_len]) {
            // A whole record is present.
            Ok(Some(len)) => len,
            // Nothing, or an incomplete tail: keep it and wait.
            Ok(None) => break,
            // Not a decision record at all. Skip one byte to resync
            // rather than stall forever on a stream we cannot parse.
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                ops_off += 1;
                handled = handled.wrapping_add(1);
                continue;
            }
        };
        let bytes = &s.ops_asm[ops_off..ops_off + rec_len] as *const [u8];
        let bytes = &*bytes;
        ops_off += rec_len;

        let decoded = match super::wire::decode_propose(bytes) {
            Ok(d) => d,
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                handled = handled.wrapping_add(1);
                continue;
            }
        };

        let origin = decoded.correlation_id;

        // A configured WAL that would not open means this proposer has
        // no durable backing. Accepting proposals anyway would ack
        // writes that cannot survive a restart, so every one is
        // refused, visibly, until the WAL is available.
        if s.wal_unavailable != 0 {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            emit_aborted_for(s, origin);
            handled = handled.wrapping_add(1);
            continue;
        }

        // Durability first: log the proposal before doing anything
        // else. If it cannot be logged it has not been accepted, and
        // the producer is told so.
        if s.wal_fd >= 0
            && super::wal::wal_append(syscalls, s.wal_fd, bytes, &mut s.append_scratch).is_err()
        {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            emit_aborted_for(s, origin);
            handled = handled.wrapping_add(1);
            continue;
        }

        // Reserve a pending slot. A full table means the plane is
        // already carrying PENDING_CAP proposals it has not resolved —
        // upstream is offering faster than downstream is committing,
        // which is exactly the state a producer has to see to back off.
        let cid = match reserve_pending(s, decoded.plane, origin, decoded.inner) {
            Ok(cid) => cid,
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                emit_aborted_for(s, origin);
                handled = handled.wrapping_add(1);
                continue;
            }
        };
        s.proposed = s.proposed.wrapping_add(1);

        match s.mode {
            MODE_REPLICATED => {
                if forward_to_clustor(s, cid) {
                    if let Some(p) = find_pending(s, cid) {
                        p.forwarded = 1;
                        p.forward_age = 0;
                    }
                }
            }
            _ => {
                // Single-replica: emit Committed immediately
                // with a synthetic LocalDurable witness
                // (quorum = 1, epoch = monotone counter).
                let epoch = s.next_epoch;
                s.next_epoch = s.next_epoch.wrapping_add(1);
                emit_committed_for(s, cid, 1, epoch);
            }
        }

        handled = handled.wrapping_add(1);
    }
    // Keep whatever the step budget did not reach. Records left here
    // are pending work, not discarded work.
    if ops_off > 0 {
        let remaining = s.ops_asm_len - ops_off;
        let mut i = 0usize;
        while i < remaining {
            s.ops_asm[i] = s.ops_asm[ops_off + i];
            i += 1;
        }
        s.ops_asm_len = remaining;
    }

    // ── 2. Drain inbound Committed events from Clustor PIC. ────
    if s.clustor_in_chan >= 0 {
        // Refill reassembly from the byte stream.
        loop {
            let space = s.cin_asm.len() - s.cin_asm_len;
            if space == 0 {
                break;
            }
            let n = (syscalls.channel_read)(
                s.clustor_in_chan,
                s.cin_asm.as_mut_ptr().add(s.cin_asm_len),
                space,
            );
            if n <= 0 {
                break;
            }
            s.cin_asm_len += n as usize;
        }
        // Walk complete records: Committed [0x11][plane][corr u32]
        // [quorum][epoch u64][len u16 @15..17][inner]; Aborted
        // [0x12][corr u32] (5 bytes).
        let mut off = 0usize;
        while off < s.cin_asm_len {
            match s.cin_asm[off] {
                super::wire::OP_COMMITTED => {
                    if s.cin_asm_len - off < 17 {
                        break;
                    }
                    let inner_len =
                        u16::from_le_bytes([s.cin_asm[off + 15], s.cin_asm[off + 16]]) as usize;
                    let rec_len = 17 + inner_len;
                    if s.cin_asm_len - off < rec_len {
                        break;
                    }
                    let corr = u32::from_le_bytes([
                        s.cin_asm[off + 2],
                        s.cin_asm[off + 3],
                        s.cin_asm[off + 4],
                        s.cin_asm[off + 5],
                    ]);
                    let quorum = s.cin_asm[off + 6];
                    let epoch = u64::from_le_bytes([
                        s.cin_asm[off + 7],
                        s.cin_asm[off + 8],
                        s.cin_asm[off + 9],
                        s.cin_asm[off + 10],
                        s.cin_asm[off + 11],
                        s.cin_asm[off + 12],
                        s.cin_asm[off + 13],
                        s.cin_asm[off + 14],
                    ]);
                    emit_committed_for(s, corr, quorum, epoch);
                    off += rec_len;
                }
                super::wire::OP_ABORTED => {
                    if s.cin_asm_len - off < 5 {
                        break;
                    }
                    let corr = u32::from_le_bytes([
                        s.cin_asm[off + 1],
                        s.cin_asm[off + 2],
                        s.cin_asm[off + 3],
                        s.cin_asm[off + 4],
                    ]);
                    // The group refused this proposal. Free the slot and
                    // pass the refusal on, re-addressed from the
                    // node-scoped id the group answered to the id the
                    // producer is waiting on.
                    if let Some(p) = find_pending(s, corr) {
                        let origin = p.origin_correlation_id;
                        p.in_use = 0;
                        p.inner_len = 0;
                        emit_aborted_for(s, origin);
                    } else {
                        s.aborted = s.aborted.wrapping_add(1);
                    }
                    off += 5;
                }
                _ => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    off += 1; // resync
                }
            }
        }
        if off > 0 {
            s.cin_asm.copy_within(off..s.cin_asm_len, 0);
            s.cin_asm_len -= off;
        }
    }

    // ── Replay-drained marker: one-shot, once every replayed
    // proposal has committed (immediately on a fresh boot). Read
    // surfaces downstream gate on it.
    if s.replay_marker_sent == 0 && s.replay_outstanding == 0 {
        let m = [super::wire::OP_REPLAY_DRAINED];
        let wrote = (syscalls.channel_write)(s.results_out_chan, m.as_ptr(), 1);
        if wrote == 1 {
            s.replay_marker_sent = 1;
        } // else: channel full — retry next tick
    }

    // WAL rotation: once replay has drained AND no pending proposal
    // is in flight, every logged record is committed downstream —
    // rotate so the next boot replays only its own tail.
    if s.wal_rotated == 0 && s.replay_marker_sent == 1 && s.wal_fd >= 0 {
        let mut any_pending = false;
        for slot in s.pending.iter() {
            if slot.in_use != 0 {
                any_pending = true;
                break;
            }
        }
        if !any_pending && s.wal_path_len > 0 {
            let plen = s.wal_path_len as usize;
            let mut path = [0u8; WAL_PATH_BUF];
            path[..plen].copy_from_slice(&s.wal_path[..plen]);
            match super::wal::wal_rotate(syscalls, s.wal_fd, &path[..plen]) {
                Ok(fd) => {
                    s.wal_fd = fd;
                    s.wal_rotated = 1;
                }
                Err(_) => {
                    // Keep the old WAL; retry next tick is pointless
                    // (fd is closed) — mark rotated to avoid thrash.
                    s.wal_fd = -1;
                    s.wal_rotated = 1;
                }
            }
        }
    }

    // ── 3. Single-replica catch-up: re-drive any pending entry
    // whose Committed emission failed last tick (e.g. downstream
    // backpressure). Bounded per-tick work.
    if s.mode == MODE_REPLICATED {
        // Replicated catch-up: forward any pending entry that hasn't
        // been sent to Clustor yet — WAL-replayed proposals after a
        // restart land here. Forward-once (the flag), bounded per
        // tick; the slot frees when the Committed round-trips.
        let mut to_fwd: [u32; MAX_OPS_PER_STEP as usize] = [0; MAX_OPS_PER_STEP as usize];
        let mut to_fwd_n: usize = 0;
        for slot in s.pending.iter_mut() {
            if slot.in_use == 0 {
                continue;
            }
            if slot.forwarded != 0 {
                slot.forward_age = slot.forward_age.saturating_add(1);
                if slot.forward_age >= FORWARD_RETRY_TICKS {
                    // commit never arrived — likely swallowed by a
                    // pre-leadership window. Re-forward.
                    slot.forwarded = 0;
                    slot.forward_age = 0;
                }
            }
            if slot.forwarded == 0 && (to_fwd_n as u32) < MAX_OPS_PER_STEP {
                to_fwd[to_fwd_n] = slot.correlation_id;
                to_fwd_n += 1;
            }
        }
        let mut i = 0usize;
        while i < to_fwd_n {
            let cid = to_fwd[i];
            if forward_to_clustor(s, cid) {
                if let Some(p) = find_pending(s, cid) {
                    p.forwarded = 1;
                    p.forward_age = 0;
                }
            } else {
                break; // backpressure: retry next tick
            }
            i += 1;
        }
    }

    if s.mode == MODE_SINGLE_REPLICA {
        let mut retried: u32 = 0;
        // Snapshot the correlation ids first to avoid holding a
        // mutable borrow of `s.pending` across the emit call,
        // which itself touches `s.append_scratch`.
        let mut to_retry: [u32; MAX_OPS_PER_STEP as usize] = [0; MAX_OPS_PER_STEP as usize];
        let mut to_retry_n: usize = 0;
        for slot in s.pending.iter() {
            if slot.in_use != 0 && (to_retry_n as u32) < MAX_OPS_PER_STEP {
                to_retry[to_retry_n] = slot.correlation_id;
                to_retry_n += 1;
            }
        }
        while retried < to_retry_n as u32 {
            let cid = to_retry[retried as usize];
            let epoch = s.next_epoch;
            s.next_epoch = s.next_epoch.wrapping_add(1);
            if !emit_committed_for(s, cid, 1, epoch) {
                break;
            }
            retried = retried.wrapping_add(1);
        }
    }

    0
}
