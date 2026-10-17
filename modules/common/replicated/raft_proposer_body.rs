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

const READ_BUF: usize = 4200; // header + MAX_INNER
/// Reassembly capacity for `metadata_ops`. Holds one maximal record
/// plus a read's worth of the next, so a record that straddles reads
/// always has somewhere to land.
const OPS_ASM: usize = READ_BUF * 2;

pub const MODE_SINGLE_REPLICA: u8 = 0;
pub const MODE_REPLICATED: u8 = 1;
/// Re-forward a pending proposal if its commit hasn't round-tripped
/// within this many ticks (~10 s at 20 TPS, ~2.5 s at 250 µs ticks —
/// generously past any election + group-commit latency).
pub const FORWARD_RETRY_TICKS: u16 = 200;

/// Inline WAL-path buffer size: the register's `WAL_PATH_BUF`.
pub const WAL_PATH_BUF: usize = super::limits::WAL_PATH_BUF;

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
    /// are guessable from the outside. `EAGAIN` (-11) while the open is
    /// still undecided, so the heartbeat tells a slow device from a
    /// refusal.
    pub wal_open_rc: i32,
    /// Where the WAL's boot stands (`BOOT_*`). No `fs` call waits on the
    /// device, so opening the WAL (create + name fence) and replaying it
    /// may each take the provider several steps; the module's steps
    /// drive them, and no proposal is read until they are done.
    pub boot: u8,
    /// The WAL's open, resumed across steps.
    pub opener: super::wal::WalOpener,
    /// The WAL's replay into the pending table, resumed across steps.
    /// Its partial record lives in the appender's idle frame buffer,
    /// which no append needs until boot is done.
    pub replay: super::wal::WalReplay,
    /// Replayed records that did not decode or found no pending slot.
    pub replay_errors: u32,
    /// The WAL's rotation (see `wal_rotated`), resumed across steps.
    /// While it is busy nothing is appended: the rename discards the
    /// old file, and a proposal logged to it meanwhile would be lost
    /// with it.
    pub rotator: super::wal::WalRotator,
    /// Resumable WAL append. Owns the staged frame, so a device that
    /// answers `E_AGAIN` costs a later step rather than a refused
    /// proposal.
    pub appender: super::wal::WalAppender,
    /// The Propose still owed to the Clustor channel. A channel may
    /// accept only part of a write; abandoning the remainder and
    /// re-encoding the whole record on a later retry leaves a
    /// truncated prefix on the wire, and the bridge's frame splitter
    /// then parses across the seam — corrupting the NEXT record rather
    /// than the one that was cut. The remainder is resumed instead.
    pub forward_out: super::reply_out::ReplyOut<{ super::wal::APPEND_SCRATCH }>,
    /// A Propose has left `metadata_ops` and is staged for durability.
    /// It is not reserved, forwarded, or aborted until the append
    /// resolves, and no other proposal is consumed meanwhile.
    pub wal_staged: u8,
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
    pub pending: [PendingEntry; super::limits::PROPOSER_PENDING],
}

/// No WAL boot in progress: one is done (or failed, which
/// `wal_unavailable` then records), or none is configured.
pub const BOOT_READY: u8 = 0;
/// The WAL is being opened (created on first boot, its name fenced).
pub const BOOT_OPEN: u8 = 1;
/// The WAL is open and being replayed into the pending table.
pub const BOOT_REPLAY: u8 = 2;

/// Replayed records handed to the pending table per step. Bounds a boot
/// step's work; a long log spans more steps rather than one long one.
const WAL_REPLAY_PER_STEP: u32 = 64;

/// `EAGAIN`, reported in `wal_open_rc` while the open is undecided.
const E_AGAIN: i32 = -11;
/// `EIO`, reported in `wal_open_rc` when a rotation replaced the log
/// but could not reopen it.
const E_IO: i32 = -5;

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
    s.wal_staged = 0;
    core::ptr::write_bytes(
        core::ptr::addr_of_mut!(s.appender) as *mut u8,
        0,
        core::mem::size_of::<super::wal::WalAppender>(),
    );
    s.mode = MODE_SINGLE_REPLICA;
    s.next_correlation_id = 1;
    s.next_epoch = 1;
    // Channel-only boots (no WAL) have nothing to replay: the marker
    // goes out on the first step.
    s.replay_outstanding = 0;
    s.replay_marker_sent = 0;
    s.wal_rotated = 0;
    // Zeroed (above) is a valid idle opener, unstarted replay and idle
    // rotator; a channel-only boot has nothing to open.
    s.boot = BOOT_READY;
    s.cin_asm_len = 0;
    s.ops_asm_len = 0;
    0
}

/// See `namespace_pic_body::decode_wal_path_params`.
pub unsafe fn decode_wal_path_params(
    state_ptr: *mut u8,
    params: *const u8,
    params_len: usize,
) -> i32 {
    if state_ptr.is_null() {
        return -22;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    match super::wal::decode_wal_path(params, params_len, &mut s.wal_path) {
        Ok(n) => {
            s.wal_path_len = n as u16;
            0
        }
        Err(()) => -22,
    }
}

/// Arm the boot of the WAL named in `wal_path` (decoded from params);
/// a proposer with no `wal_path` runs against no log and boots at once.
/// Nothing is opened here: the open and the replay run from
/// `module_step_impl`, which reads no proposal until both are done.
pub unsafe fn begin_wal_boot_from_state(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    let len = s.wal_path_len as usize;
    if len == 0 || len > WAL_PATH_BUF {
        return 0;
    }
    if let Some(sys) = s.syscalls.as_ref() {
        // A boot re-armed mid-open must not leak the descriptor the
        // abandoned open holds.
        s.opener.abandon(sys);
    }
    s.wal_fd = -1;
    s.wal_unavailable = 0;
    s.wal_open_rc = E_AGAIN;
    // The appender's tail knowledge belongs to the previous fd.
    s.appender.reset();
    s.wal_staged = 0;
    s.replay.reset();
    s.replay_errors = 0;
    s.boot = BOOT_OPEN;
    0
}

/// Record `wal_path` as this proposer's WAL and arm its boot; see
/// `begin_wal_boot_from_state`. A path that does not fit is refused now,
/// since no later step could open it.
pub unsafe fn begin_wal_boot(state_ptr: *mut u8, wal_path: &[u8]) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    if wal_path.is_empty() || wal_path.len() > WAL_PATH_BUF {
        return -3;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    for (d, b) in s.wal_path.iter_mut().zip(wal_path.iter()) {
        *d = *b;
    }
    s.wal_path_len = wal_path.len() as u16;
    begin_wal_boot_from_state(state_ptr)
}

/// A WAL that would not open, or could not be read back, leaves this
/// proposer without a durable backing. It still steps — a module that
/// refuses to start is simply absent, which is the least diagnosable
/// failure there is — but `wal_unavailable` refuses every proposal, and
/// `wal_open_rc` carries the provider's code to the heartbeat.
fn wal_failed(s: &mut ModuleState, rc: i32) {
    s.wal_fd = -1;
    s.wal_unavailable = 1;
    s.wal_open_rc = rc;
    s.boot = BOOT_READY;
}

/// Drive the WAL's open and replay one step further. True once the
/// proposer may take proposals: the WAL is open and replayed, none is
/// configured, or the boot failed (proposals are then refused, not
/// held).
unsafe fn boot(state_ptr: *mut u8, sys: &super::SyscallTable) -> bool {
    let s = &mut *(state_ptr as *mut ModuleState);
    if s.boot == BOOT_OPEN {
        let len = (s.wal_path_len as usize).min(WAL_PATH_BUF);
        // The same bytes on every poll: an undecided open is collected
        // only by re-asking the byte-identical request.
        let path = core::slice::from_raw_parts(s.wal_path.as_ptr(), len);
        match s.opener.poll(sys, path, true) {
            // The provider has not finished — on a profile where the
            // filesystem sits over a real device, creating a file and
            // fencing its name need I/O that does not fit in one step.
            super::wal::OpenPoll::Pending => return false,
            super::wal::OpenPoll::Ready(fd) => {
                s.wal_fd = fd;
                s.wal_open_rc = 0;
                s.replay.reset();
                s.replay_errors = 0;
                s.boot = BOOT_REPLAY;
            }
            super::wal::OpenPoll::Failed(e) => {
                let rc = match e {
                    super::wal::WalOpenError::NotFound => -19,
                    super::wal::WalOpenError::OpenFailed(rc) => rc,
                    // No durable name for the log: EROFS, because the
                    // artefact cannot be published on this provider and
                    // retrying will not change that.
                    super::wal::WalOpenError::NameUnfenceable => -30,
                };
                wal_failed(s, rc);
                return true;
            }
        }
    }
    if s.boot == BOOT_REPLAY {
        // Replay every Propose record back into the pending table so a
        // restart-after-crash retries downstream emission for any
        // proposal that didn't make it to its consumer.
        let fd = s.wal_fd;
        // The idle frame outlives the step, as a replay's buffer must;
        // the callback reaches the rest of the state through the
        // pointer, never the appender.
        let scratch: &mut [u8] = &mut *(s.appender.idle_buffer() as *mut [u8]);
        let replay: &mut super::wal::WalReplay = &mut *(&mut s.replay as *mut _);
        let polled = replay.poll(sys, fd, scratch, WAL_REPLAY_PER_STEP, |payload| {
            let s_cb = &mut *(state_ptr as *mut ModuleState);
            if let Ok(p) = super::wire::decode_propose(payload) {
                // The WAL holds the Propose verbatim, so a replayed entry
                // still carries the correlation id its producer chose and
                // its eventual result stays addressable.
                if reserve_pending(s_cb, p.plane, p.correlation_id, p.inner).is_err() {
                    s_cb.replay_errors = s_cb.replay_errors.wrapping_add(1);
                }
            } else {
                s_cb.replay_errors = s_cb.replay_errors.wrapping_add(1);
            }
            true
        });
        let s = &mut *(state_ptr as *mut ModuleState);
        match polled {
            super::wal::ReplayPoll::Pending => return false,
            super::wal::ReplayPoll::Done(_) => {
                // Pending entries now hold the replayed proposals; the
                // first few steps will drain them downstream.
                s.apply_errors = s.replay_errors;
                s.boot = BOOT_READY;
            }
            // A log that could not be read back may hold proposals the
            // table lacks, so it is no log to propose against. What did
            // replay is still real and still drains downstream.
            super::wal::ReplayPoll::Failed(e) => {
                let rc = match e {
                    super::wal::WalReplayError::SeekFailed(rc)
                    | super::wal::WalReplayError::ReadFailed(rc)
                    | super::wal::WalReplayError::StatFailed(rc) => rc,
                };
                let _ = super::wal::wal_close(sys, fd);
                s.apply_errors = s.replay_errors;
                wal_failed(s, rc);
            }
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
    }
    true
}

/// Drive the WAL's rotation one step further, starting one when idle.
unsafe fn poll_rotation(s: &mut ModuleState, sys: &super::SyscallTable) {
    let len = (s.wal_path_len as usize).min(WAL_PATH_BUF);
    // The same path on every poll of one rotation.
    let path = core::slice::from_raw_parts(s.wal_path.as_ptr(), len);
    match s.rotator.rotate(sys, s.wal_fd, path) {
        // Undecided: intake stays gated on `rotator.busy()`.
        super::wal::RotateOutcome::Pending => {}
        super::wal::RotateOutcome::Rotated(fd) => {
            s.wal_fd = fd;
            // Fresh, empty file: the appender's tail knowledge belongs
            // to the rotated-away fd.
            s.appender.reset();
            s.wal_rotated = 1;
        }
        // Left intact, and still the right log to propose against — the
        // next boot just replays more of it.
        super::wal::RotateOutcome::Skipped => {
            s.wal_rotated = 1;
        }
        super::wal::RotateOutcome::Lost => {
            // Replaced but not reopenable, so there is no log to propose
            // against. Refusing is the honest answer: `wal_unavailable`
            // gates intake until a later open succeeds. Marked rotated so
            // the attempt does not thrash.
            s.appender.reset();
            s.wal_rotated = 1;
            wal_failed(s, E_IO);
        }
    }
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

#[allow(
    clippy::manual_find,
    reason = "an explicit scan keeps the PIC build panic-free: iterator adapters pull core::panicking paths the bare-metal SDK does not carry"
)]
unsafe fn find_pending(s: &mut ModuleState, correlation_id: u32) -> Option<&mut PendingEntry> {
    for slot in s.pending.iter_mut() {
        if slot.in_use != 0 && slot.correlation_id == correlation_id {
            return Some(slot);
        }
    }
    None
}

/// The proof a single-replica commit can honestly carry.
///
/// There is no group here, so there is nothing to prove: quorum is
/// one voter, and the witness stays zero because a commitment to an
/// agreement that never happened would be a fiction a consumer would
/// read as replication. `CommitProof::is_replicated` is false for
/// this shape, so downstream reports `LocalDurable` — which is what
/// a durably-logged write on one device actually achieved.
///
/// `source` still names this node's log, so two nodes' fences never
/// compare as ordered, and `index` still advances, so a consumer can
/// tell a later commit from an earlier one on the same log.
fn local_proof(s: &ModuleState, index: u64) -> super::wire::CommitProof {
    super::wire::CommitProof {
        source: local_source(s),
        term: 0,
        index,
        quorum: 1,
        witness: [0u8; 32],
    }
}

/// This node's log identity.
///
/// Built from the WAL path and `self_id` — the two things that
/// already distinguish one proposer from another — so two nodes'
/// commits never compare as ordered. Recomputed rather than cached
/// because both inputs are set during init and a cached copy would
/// depend on the order they arrive in.
fn local_source(s: &ModuleState) -> [u8; 16] {
    let len = s.wal_path_len as usize;
    let path = &s.wal_path[..len.min(WAL_PATH_BUF)];
    let a = super::hash::fnv1a64(path);
    let mut seed = [0u8; 1];
    seed[0] = s.self_id;
    let b = super::hash::fnv1a64(&seed) ^ a.rotate_left(17);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&a.to_le_bytes());
    out[8..16].copy_from_slice(&b.to_le_bytes());
    out
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
    proof: &super::wire::CommitProof,
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
    let n = match super::wire::encode_committed(scratch, plane, origin, proof, inner) {
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
    if !s.forward_out.stage(&scratch[..n]) {
        return false;
    }
    s.forward_out.flush(sys.channel_write, out_chan)
}

/// Take a durably-logged proposal into the pending table and start it
/// downstream.
///
/// A full table means the plane is already carrying `super::limits::PROPOSER_PENDING`
/// proposals it has not resolved — upstream is offering faster than
/// downstream is committing, which is exactly the state a producer has
/// to see to back off.
unsafe fn admit_proposal(s: &mut ModuleState, plane: u8, origin: u32, inner: &[u8]) {
    let cid = match reserve_pending(s, plane, origin, inner) {
        Ok(cid) => cid,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            emit_aborted_for(s, origin);
            return;
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
            // Single-replica: emit Committed immediately with a
            // synthetic LocalDurable witness (quorum = 1, epoch =
            // monotone counter).
            let index = s.next_epoch;
            s.next_epoch = s.next_epoch.wrapping_add(1);
            let proof = local_proof(s, index);
            emit_committed_for(s, cid, &proof);
        }
    }
}

/// Resolve the proposal a staged append took off `metadata_ops`.
/// `durable` licenses admission; without it the proposal is aborted,
/// because a refusal the producer can see is the only honest answer to
/// a durability failure.
unsafe fn resolve_staged(s: &mut ModuleState, durable: bool) {
    s.wal_staged = 0;
    // Copy the staged frame out first: everything below borrows the
    // local, so admitting or aborting can take `s` mutably.
    let mut record = [0u8; READ_BUF];
    let n = s.appender.payload().len();
    if n == 0 || n > record.len() {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    record[..n].copy_from_slice(s.appender.payload());
    let (plane, origin, inner_len, inner) = match super::wire::decode_propose(&record[..n]) {
        Ok(d) => {
            let mut inner = [0u8; super::wire::MAX_INNER];
            let len = d.inner.len().min(inner.len());
            inner[..len].copy_from_slice(&d.inner[..len]);
            (d.plane, d.correlation_id, len, inner)
        }
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    if !durable {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        emit_aborted_for(s, origin);
        return;
    }
    admit_proposal(s, plane, origin, &inner[..inner_len]);
}

pub unsafe fn module_step_impl(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    s.ticks = s.ticks.wrapping_add(1);

    let syscalls = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return -1,
    };

    // The WAL's boot owns the step until it is done. A proposal taken
    // before the open decides would have no log to land in, and one
    // taken before the replay finishes would race the replayed ones for
    // pending slots and correlation ids. Nothing is read meanwhile.
    if !boot(state_ptr, syscalls) {
        return 0;
    }
    let s = &mut *(state_ptr as *mut ModuleState);

    // A rotation in flight is resumed before any intake, and gates it:
    // nothing may be appended to a log the rename is about to discard.
    if s.rotator.busy() {
        poll_rotation(s, syscalls);
    }

    // A Propose still owed to the Clustor channel owns the step. It
    // has already been logged and reserved, so re-encoding it later
    // would double-forward; the remainder is resumed instead, and no
    // new proposal is taken while it is outstanding.
    if s.clustor_out_chan >= 0
        && !s
            .forward_out
            .flush(syscalls.channel_write, s.clustor_out_chan)
    {
        return 0;
    }

    // A staged append owns the step until it resolves: the proposal it
    // describes has left `metadata_ops` and no other work may overtake
    // it, reuse the frame buffer, or be admitted ahead of it.
    if s.wal_staged != 0 {
        match s.appender.poll(syscalls, s.wal_fd) {
            super::wal::AppendState::Pending => return 0,
            super::wal::AppendState::Durable => resolve_staged(s, true),
            _ => resolve_staged(s, false),
        }
    }

    // ── 1. Drain inbound Propose requests from public PICs. ────
    //
    // `metadata_ops` is a byte stream. A producer that batches puts
    // several records into one read, and a read can end mid-record;
    // both are normal. Refill a reassembly buffer, then take whole
    // records off the front of it — up to the step budget, leaving the
    // rest for the next step rather than dropping it.
    if s.ops_in_chan >= 0 && !s.rotator.busy() {
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
    while handled < super::limits::OPS_PER_STEP && !s.rotator.busy() {
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
        // else. The append is staged, not completed here — a device
        // that has accepted the frame but not finished it leaves the
        // proposal staged and the step returns. If the append fails
        // the proposal has not been accepted, and the producer is
        // told so.
        if s.wal_fd >= 0 {
            match s.appender.begin(syscalls, s.wal_fd, bytes) {
                super::wal::AppendState::Durable => {}
                super::wal::AppendState::Pending => {
                    s.wal_staged = 1;
                    break;
                }
                _ => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    emit_aborted_for(s, origin);
                    handled = handled.wrapping_add(1);
                    continue;
                }
            }
        }

        admit_proposal(s, decoded.plane, origin, decoded.inner);
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
        // Record boundaries and field offsets both come from the wire
        // module: it owns the layout, so a change there reaches this
        // drain without anyone remembering to update an offset here.
        let mut off = 0usize;
        while off < s.cin_asm_len {
            let rec_len = match super::wire::record_len(&s.cin_asm[off..s.cin_asm_len]) {
                Ok(Some(n)) => n,
                // A whole record has not arrived yet: leave the tail
                // for the next read.
                Ok(None) => break,
                // Unknown opcode. Skip one byte to resync rather than
                // stall forever on a stream we cannot parse.
                Err(_) => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    off += 1;
                    continue;
                }
            };
            match s.cin_asm[off] {
                super::wire::OP_COMMITTED => {
                    match super::wire::decode_committed(&s.cin_asm[off..off + rec_len]) {
                        Ok(c) => {
                            let proof = c.proof;
                            let corr = c.correlation_id;
                            emit_committed_for(s, corr, &proof);
                        }
                        Err(_) => {
                            s.apply_errors = s.apply_errors.wrapping_add(1);
                        }
                    }
                    off += rec_len;
                }
                super::wire::OP_ABORTED => {
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
                    off += rec_len;
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
    if s.wal_rotated == 0
        && s.replay_marker_sent == 1
        && s.wal_fd >= 0
        && s.wal_staged == 0
        && !s.rotator.busy()
    {
        let mut any_pending = false;
        for slot in s.pending.iter() {
            if slot.in_use != 0 {
                any_pending = true;
                break;
            }
        }
        if !any_pending && s.wal_path_len > 0 {
            // Started here, resumed at the top of later steps until it
            // decides; intake waits for it.
            poll_rotation(s, syscalls);
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
        let mut to_fwd: [u32; super::limits::OPS_PER_STEP as usize] =
            [0; super::limits::OPS_PER_STEP as usize];
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
            if slot.forwarded == 0 && (to_fwd_n as u32) < super::limits::OPS_PER_STEP {
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
        let mut to_retry: [u32; super::limits::OPS_PER_STEP as usize] =
            [0; super::limits::OPS_PER_STEP as usize];
        let mut to_retry_n: usize = 0;
        for slot in s.pending.iter() {
            if slot.in_use != 0 && (to_retry_n as u32) < super::limits::OPS_PER_STEP {
                to_retry[to_retry_n] = slot.correlation_id;
                to_retry_n += 1;
            }
        }
        while retried < to_retry_n as u32 {
            let cid = to_retry[retried as usize];
            let index = s.next_epoch;
            s.next_epoch = s.next_epoch.wrapping_add(1);
            let proof = local_proof(s, index);
            if !emit_committed_for(s, cid, &proof) {
                break;
            }
            retried = retried.wrapping_add(1);
        }
    }

    0
}
