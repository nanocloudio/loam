// Shared step-body implementation for namespace_router. Path-included
// by both the embedded PIC module (modules/namespace_router/mod.rs)
// and the host test harness (tests/pic_entry_points.rs).
//
// Splits the no_std-mandatory `#[no_mangle] extern "C"` glue (which
// lives in the PIC mod.rs) from the actual logic (which lives here
// and is callable from std tests). The PIC mod.rs is a 20-line shim
// over these implementations.
//
// Two init entry points:
//
//   `module_new_impl`          — channel-only; the arena is the sole
//                                state. Lost across module re-creation.
//   `module_new_with_wal_impl` — opens a pre-existing WAL file via the
//                                fluxor `fs` contract, replays its
//                                records into the arena, and configures
//                                the step body to durable-log each
//                                future op before applying it.
//
// Order on the apply path is log-then-arena. A WAL append that fsyncs
// before the in-memory state mutates means a successful arena state
// always has a durable backing, and a producer retry after a WAL
// failure is safe (no in-memory state was committed).

// Arena holds every committed binding for this PIC instance — the
// WAL is replayed straight into it on init, so the cap is the total
// live binding budget per PIC instance, not just a hot cache size.
// Bump per-instance for larger working sets; multi-PIC deployments
// shard further by partition (see `src/placement.rs`).
// ModuleState is dominated by the arena: `BindingSlot` is 384 B on
// the embedded profile, so 256 slots is ~96 KiB of the ~116 KiB the
// whole struct occupies there, the rest being the reassembly buffers
// and the append scratch. The kernel heap-allocates it, so the cap
// and the module's memory budget move together — see
// `docs/limit_register.md`, which carries the figures and the test
// that pins them.
//
// Which cap applies is the capacity profile: an explicit
// `--cfg loam_profile`, with the build target as the fallback. The
// pack step passes no profile, so a bare-metal image takes the
// `embedded` default.
const ARENA_CAPACITY: usize = super::limits::NAMESPACE_SLOTS;
/// Concurrent `LOOKUP` handles. Bounded like every other arena here:
/// a provider that can be asked for unlimited handles is a provider
/// with an unbounded step.
pub const NS_OPEN_MAX: usize = 16;

/// One resolved-entry handle. `slot` indexes the binding arena;
/// `revision` pins the view the lookup observed.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct NsOpenSlot {
    pub in_use: u8,
    pub slot: u32,
    pub revision: u64,
}
const READ_BUF: usize = 256;
/// Reassembly capacity for `requests`. Sized to hold a full step's
/// budget plus one more read, so refilling never starves the step: a
/// buffer that only fits two reads caps intake at two records per step
/// regardless of what the budget allows.
const REQ_ASM: usize = READ_BUF * (super::limits::OPS_PER_STEP as usize + 1);

/// Inline WAL-path buffer in `ModuleState`. The TLV parameter
/// handler populates this; the PIC mod.rs uses it to drive
/// `open_and_replay_wal` after init. 256 bytes covers any
/// reasonable filesystem path with headroom.
pub const WAL_PATH_BUF: usize = 256;

/// The namespace PIC answers with a 1-byte ack or an encoded lookup /
/// list / referenced response, all bounded by a read buffer.
pub type Reply = super::reply_out::ReplyOut<READ_BUF>;

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    /// Slot-0 input channel from the PIC ABI. Manifest declares this as
    /// `requests`: encoded NamespaceEvent payloads from the producer.
    pub in_chan: i32,
    /// Slot-0 output channel from the PIC ABI. Manifest declares this as
    /// `responses`: one byte per request, opcode on OK or 0xFF on NAK.
    /// The other manifest outputs (`metadata_ops`, `metrics`) are not
    /// yet wired in the PIC step body — they require explicit lookup
    /// via `dev_channel_port` and are tracked in
    /// `loam/docs/native_fluxor.md` alongside the Raft integration.
    pub out_chan: i32,
    /// Replication channels (looked up via `dev_channel_port` by the
    /// PIC mod.rs). When both are set, mutating ops are NOT applied
    /// locally on receipt: they are proposed to the metadata plane
    /// (loam_decision_wire Propose, plane=namespace) and applied +
    /// acked only when the Committed comes back on `committed_chan`.
    /// LOOKUP stays a local read either way.
    pub metadata_ops_chan: i32,
    pub committed_chan: i32,
    pub replicated: u8,
    /// Count of proposals THIS router forwarded whose commit hasn't
    /// round-tripped yet. drain_committed only acks `responses` while
    /// this is non-zero: replayed commits (proposer-WAL or Raft-log
    /// replay at boot) arrive when it is 0 and are applied WITHOUT
    /// acking — they answer no live request, and unsolicited ack bytes
    /// would desynchronize the requester's response stream. Raft's
    /// total order keeps the FIFO count aligned for live requests.
    pub outstanding: u32,
    /// Set when the proposer's OP_REPLAY_DRAINED marker arrives on
    /// `committed`. Until then (replicated mode only) LOOKUPs answer
    /// with a NOT_READY nak so readers retry instead of consuming a
    /// mid-replay (stale) pointer. Direct-apply mode is born ready.
    pub read_ready: u8,
    /// Reassembly for the `committed` byte stream: records coalesce
    /// across channel reads (atomic writes, streaming reads), so the
    /// drain walks complete records and carries partial tails.
    pub cmt_asm: [u8; 8192],
    pub cmt_asm_len: usize,
    /// Proof from the most recently applied committed record, and
    /// whether one has been applied at all.
    ///
    /// The fence this PIC reports is only ever as strong as the last
    /// commit it actually applied, so the proof is retained at the
    /// point of application rather than reconstructed later. Cleared
    /// state means nothing has been applied and there is nothing to
    /// claim.
    pub last_proof: super::decision::CommitProof,
    pub has_proof: u8,
    /// Reassembly for the `requests` byte stream. A batching producer
    /// puts several records into one read and a read can end
    /// mid-record; both are the stream behaving normally.
    pub req_asm: [u8; REQ_ASM],
    pub req_asm_len: usize,
    /// Set while walking past bytes that do not start a record. One
    /// NAK is emitted on entering that state, not one per byte: a
    /// producer that sent one bad record should hear about it once.
    pub req_resyncing: u8,
    /// Open handles minted by `namespace::LOOKUP` and consumed by
    /// `STAT` / `CLOSE`. Resolution is snapshot-relative: a handle
    /// records the revision it observed so a later `STAT` answers
    /// against the same view, which is what the surface promises.
    pub ns_open: [NsOpenSlot; NS_OPEN_MAX],
    /// The answer this module owes. A channel that refuses the write
    /// leaves it owed rather than lost; no new work is taken until it
    /// lands.
    pub reply: Reply,
    pub bindings: super::state::PicNamespaceState<ARENA_CAPACITY>,
    pub ticks: u32,
    pub ops_applied: u32,
    pub apply_errors: u32,
    /// `fs`-contract fd for the WAL, or -1 in channel-only mode. When
    /// set, each successful apply path writes a record + fsyncs before
    /// the arena mutates.
    pub wal_fd: i32,
    /// Per-record scratch for the replicated-mode Propose encode.
    /// Sized to hold the 8-byte header plus the largest legal payload
    /// — avoids any runtime allocation under no_std.
    pub append_scratch: [u8; super::wal::APPEND_SCRATCH],
    /// Resumable WAL append. Owns the staged frame, so a device that
    /// answers `E_AGAIN` costs a later step rather than an operation
    /// refusal.
    pub appender: super::wal::WalAppender,
    /// Which stream the staged append belongs to: `WAL_STAGE_NONE`,
    /// `WAL_STAGE_REQUEST`, or `WAL_STAGE_COMMITTED`. While it is not
    /// `NONE` the step consumes no new work — the record it describes
    /// has been taken off its stream and is not applied, acked, or
    /// discarded until the append resolves.
    pub wal_stage: u8,
    /// Committed-stream staging: whether the record answers a live
    /// local request and therefore owes an ack byte.
    pub wal_stage_live: u8,
    /// Object ids a lifecycle sweep has reserved for deletion, by
    /// hash. A BIND naming a reserved id is refused with
    /// `NAK_RESERVED` so the sweep's absence proof holds up to the
    /// deletion. Arena-only and never logged — see
    /// `loam_wire::encode_gc_reserve_req`.
    pub gc_reserved: [u64; GC_RESERVE_MAX],
    /// Inline WAL path, populated by the TLV `wal_path` param
    /// handler in the PIC mod.rs. `wal_path_len == 0` means
    /// channel-only mode (no WAL).
    pub wal_path: [u8; WAL_PATH_BUF],
    pub wal_path_len: u16,
    /// On-disk namespace snapshot (see common/mechanics/loam_snapshot.rs):
    /// the durable full record that lets this arena be a HOT CACHE
    /// — lookup misses binary-search it, full arenas evict
    /// snapshot-covered slots, deletes tombstone until compaction.
    pub snap_active: u8,
    pub snap_slot: u8,
    pub snap_fd: i32,
    pub snap_count: u32,
    pub snap_gen: u64,
    /// Incremental compactor: merges (old snapshot × arena) into
    /// the other generation slot, bounded records per step.
    pub cmp_running: u8,
    pub cmp_target_slot: u8,
    pub cmp_writer_fd: i32,
    pub cmp_writer_count: u32,
    pub cmp_writer_gen: u64,
    pub cmp_snap_idx: u32,
    pub cmp_last_key_valid: u8,
    pub cmp_last_ns: u64,
    pub cmp_last_path: u64,
    pub snapshots_written: u32,
    pub evictions: u32,
    pub snap_misses: u32,
    /// Live `namespace::SUBSCRIBE` registrations. Each holds the
    /// prefix it watches and the channel to push `namespace.change`
    /// onto.
    pub subs: [SubSlot; NS_SUB_MAX],
    /// Scratch for one encoded event. Sized from the register.
    pub event_buf: [u8; super::change_wire::EVENT_MAX],
}

/// Concurrent change subscriptions. Small on purpose: each slot costs
/// its prefix inline, and a graph wires a bounded set of consumers.
pub const NS_SUB_MAX: usize = 8;

/// One `namespace::SUBSCRIBE` registration.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SubSlot {
    pub in_use: u8,
    /// Set when a push was refused by a full channel. The subscriber's
    /// view is now incomplete, so it is owed a LOST sentinel and
    /// nothing else until it has been sent one. Dropping events
    /// silently is the failure this flag exists to make impossible.
    pub lost_pending: u8,
    pub prefix: [u8; super::limits::MAX_PATH],
    pub prefix_len: u16,
    pub sink_chan: i32,
    pub sequence: u32,
}

impl SubSlot {
    pub const fn empty() -> Self {
        Self {
            in_use: 0,
            lost_pending: 0,
            prefix: [0u8; super::limits::MAX_PATH],
            prefix_len: 0,
            sink_chan: -1,
            sequence: 0,
        }
    }
    pub fn prefix(&self) -> &[u8] {
        &self.prefix[..self.prefix_len as usize]
    }
}

/// Concurrent deletion reservations. The sweep holds one at a time;
/// the spare slots absorb a second sweep instance without making the
/// table a queue.
pub const GC_RESERVE_MAX: usize = 4;
/// Nak byte for a BIND refused because its object id is reserved for
/// deletion. Distinct from the generic 0xFF so a client can tell
/// "retry this" from "this was wrong".
pub const NAK_RESERVED: u8 = 0xFD;

pub const WAL_STAGE_NONE: u8 = 0;
pub const WAL_STAGE_REQUEST: u8 = 1;
pub const WAL_STAGE_COMMITTED: u8 = 2;

/// Compactor work bound per step.
const CMP_RECORDS_PER_STEP: usize = 32;
/// Compaction triggers at 3/4 arena occupancy.
const CMP_TRIGGER_NUM: usize = 3;
const CMP_TRIGGER_DEN: usize = 4;

/// SAFETY: caller must ensure `state_ptr` is non-null, points to at
/// least `core::mem::size_of::<ModuleState>()` bytes of writable
/// memory, and the memory will outlive any subsequent
/// `module_step_impl` call. `syscalls` must point to a valid
/// `super::SyscallTable` for the lifetime of the module instance.
pub unsafe fn module_new_impl(
    in_chan: i32,
    out_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(in_chan, out_chan, state_ptr, state_size, syscalls)
}

/// Open + replay a WAL at `wal_path`, then initialize the module so
/// future apply calls durable-log before mutating the arena.
///
/// Returns:
///   `0` on success (WAL opened + replayed; torn tails OK).
///   `-1` for null state/syscalls.
///   `-2` for an undersized state buffer.
///   `-3` if the WAL file is missing or otherwise refuses to open
///        (fluxor's `fs` provider does NOT auto-create — see
///        `modules/common/mechanics/wal_io.rs:wal_open`).
///
/// SAFETY: same constraints as `module_new_impl`, plus `wal_path`
/// must be a valid byte slice for the duration of this call.
pub unsafe fn module_new_with_wal_impl(
    in_chan: i32,
    out_chan: i32,
    wal_path: &[u8],
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    let rc = init_state(in_chan, out_chan, state_ptr, state_size, syscalls);
    if rc != 0 {
        return rc;
    }
    open_and_replay_wal(state_ptr, wal_path)
}

/// Open + replay a WAL against an already-initialized `ModuleState`.
/// Used by the TLV path (init_state → parse_tlv populates state's
/// inline path → open_and_replay) AND by the raw-bytes path
/// (`module_new_with_wal_impl`).
///
/// SAFETY: `state_ptr` must reference a `ModuleState` already
/// initialized via `init_state` or equivalent.
pub unsafe fn open_and_replay_wal(state_ptr: *mut u8, wal_path: &[u8]) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return -1,
    };
    // Create-on-missing so first-boot doesn't require an
    // external pre-touch step. Existing files open cleanly with
    // the same opcode.
    let fd = match super::wal::wal_open_or_create(sys, wal_path) {
        Ok(fd) => fd,
        Err(_) => return -3,
    };
    s.wal_fd = fd;
    // The appender's tail knowledge belongs to the previous fd.
    s.appender.reset();
    s.wal_stage = WAL_STAGE_NONE;
    s.wal_stage_live = 0;
    // Stash the path: the snapshot compactor derives its
    // generation filenames from it. The TLV boot path passes
    // `&s.wal_path` itself — skip the (overlapping) self-copy.
    if wal_path.len() <= WAL_PATH_BUF && wal_path.as_ptr() != s.wal_path.as_ptr() {
        s.wal_path[..wal_path.len()].copy_from_slice(wal_path);
        s.wal_path_len = wal_path.len() as u16;
    } else if wal_path.as_ptr() == s.wal_path.as_ptr() {
        s.wal_path_len = wal_path.len() as u16;
    }

    // Open the best (highest valid generation) snapshot BEFORE
    // replay: the WAL tail is revision-gated, so replaying over
    // any snapshot generation converges.
    s.snap_fd = -1;
    // `minimal` carries no snapshot tier: the arena is the whole set
    // there and the WAL is its durable record. Guarding at the one
    // activation point keeps every downstream `snap_active != 0`
    // check correct without a second condition, and lets the
    // optimiser drop the compactor with it.
    if super::limits::SNAPSHOT_TIER {
        if let Some((snap, slot)) = super::snapshot::snap_open_best(sys, wal_path) {
            s.snap_active = 1;
            s.snap_slot = slot;
            s.snap_fd = snap.fd;
            s.snap_count = snap.count;
            s.snap_gen = snap.generation;
        }
    }

    let mut scratch = [0u8; super::wal::MAX_WAL_REC];
    let sptr = state_ptr as *mut ModuleState;
    let mut replay_errors: u32 = 0;
    let replay_rc = super::wal::wal_replay(sys, fd, &mut scratch, |payload| {
        if apply_op(&mut *sptr, sys, payload).is_err() {
            replay_errors = replay_errors.wrapping_add(1);
        }
        true
    });
    if let Ok(applied) = replay_rc {
        s.ops_applied = applied;
        s.apply_errors = replay_errors;
    }
    0
}

/// Populate `state.wal_path[..wal_path_len]` from the kernel-
/// supplied params blob. Two recognized encodings:
///
/// 1. TLV (`[0xFE, 0x01, payload_len:u16 LE, entries…]`) — what
///    the fluxor build tool packs from YAML
///    `params: { wal_path: "..." }`. We scan for `tag=1` and copy
///    its bytes verbatim.
/// 2. Raw byte string — direct path; backward-compat path for
///    host test harnesses that pre-date the TLV schema.
///
/// Empty/null `params` leaves the state in channel-only mode.
///
/// This decoder lives in the body file (rather than mod.rs) so
/// host tests can drive it through the path-included `body`
/// module. The PIC mod.rs's `define_params!` still owns the
/// schema metadata embedded in `.param_schema` for the fluxor
/// build tool.
///
/// SAFETY: `state_ptr` must reference an initialized
/// `ModuleState`; `params` must be a valid byte slice for the
/// duration of the call.
pub unsafe fn decode_wal_path_params(state_ptr: *mut u8, params: *const u8, params_len: usize) {
    if state_ptr.is_null() {
        return;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    if let Some(n) = super::wal::decode_wal_path(params, params_len, &mut s.wal_path) {
        s.wal_path_len = n as u16;
    }
}

/// Open a WAL using the path the TLV param handler stored in
/// `state.wal_path[..wal_path_len]`. Returns 0 when `wal_path_len
/// == 0` (channel-only mode), otherwise delegates to
/// `open_and_replay_wal`.
///
/// SAFETY: `state_ptr` must reference an initialized `ModuleState`.
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

unsafe fn init_state(
    in_chan: i32,
    out_chan: i32,
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
    let s = &mut *(state_ptr as *mut ModuleState);
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.metadata_ops_chan = -1;
    s.committed_chan = -1;
    s.replicated = 0;
    s.outstanding = 0;
    s.cmt_asm_len = 0;
    s.last_proof = super::decision::CommitProof {
        source: [0u8; 16],
        term: 0,
        index: 0,
        quorum: 0,
        witness: [0u8; 32],
    };
    s.has_proof = 0;
    s.req_asm_len = 0;
    s.req_resyncing = 0;
    for slot in s.ns_open.iter_mut() {
        slot.in_use = 0;
    }
    s.read_ready = 1; // replicated init clears it (see set_replication_channels)
                      // In-place zeroing, NOT `= State::new()`: at service-class
                      // capacity the by-value construction is a multi-MB stack
                      // temporary. empty() slots are all-zero, so this is identical.
    core::ptr::write_bytes(
        core::ptr::addr_of_mut!(s.bindings) as *mut u8,
        0,
        core::mem::size_of::<super::state::PicNamespaceState<ARENA_CAPACITY>>(),
    );
    s.ticks = 0;
    s.ops_applied = 0;
    s.apply_errors = 0;
    s.wal_fd = -1;
    s.wal_stage = WAL_STAGE_NONE;
    s.wal_stage_live = 0;
    core::ptr::write_bytes(
        core::ptr::addr_of_mut!(s.appender) as *mut u8,
        0,
        core::mem::size_of::<super::wal::WalAppender>(),
    );
    s.gc_reserved = [0u64; GC_RESERVE_MAX];
    s.snap_fd = -1;
    s.cmp_writer_fd = -1;
    s.wal_path_len = 0;
    for sub in s.subs.iter_mut() {
        sub.in_use = 0;
        sub.lost_pending = 0;
        sub.prefix_len = 0;
        sub.sink_chan = -1;
        sub.sequence = 0;
    }
    // `append_scratch` and `wal_path` are caller-zeroed; bytes are
    // overwritten as records and the TLV param flow.
    0
}

/// SAFETY: caller must have previously initialized `state_ptr` via
/// `module_new_impl`; the underlying `super::SyscallTable` must still be
/// valid.
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

    // An owed answer owns the step until the channel takes it. The
    // record it answers has already left its stream and changed the
    // arena, so letting new work overtake it would leave a requester
    // with a mutation and no reply.
    if !s.reply.flush(syscalls.channel_write, s.out_chan) {
        return 0;
    }

    // A staged append owns the step until it resolves: the record it
    // describes has left its stream and no other work may overtake
    // it, reuse the frame buffer, or acknowledge ahead of it.
    if s.wal_stage != WAL_STAGE_NONE {
        match s.appender.poll(syscalls, s.wal_fd) {
            super::wal::AppendState::Pending => return 0,
            super::wal::AppendState::Durable => resolve_staged(s, syscalls, true),
            _ => resolve_staged(s, syscalls, false),
        }
    }

    // Incremental snapshot compaction: bounded records/step.
    compaction_step(s, syscalls);

    // `requests` is a byte stream. Refill a reassembly buffer, then
    // take whole records off the front of it — up to the step budget,
    // leaving the rest for the next step rather than discarding it.
    if s.in_chan >= 0 {
        loop {
            // Saturating, and the accumulated length is clamped below:
            // a read that reports more than the window it was given
            // would otherwise underflow this subtraction, and the next
            // pass would read at a wild offset. Trusting a length from
            // outside the module is how a bounded buffer stops being
            // bounded.
            let space = REQ_ASM.saturating_sub(s.req_asm_len);
            if space < READ_BUF {
                break;
            }
            let n = (syscalls.channel_read)(
                s.in_chan,
                s.req_asm.as_mut_ptr().add(s.req_asm_len),
                READ_BUF,
            );
            if n <= 0 {
                break;
            }
            let got = (n as usize).min(space);
            s.req_asm_len = (s.req_asm_len + got).min(REQ_ASM);
        }
    }

    let mut handled: u32 = 0;
    let mut req_off: usize = 0;
    while handled < super::limits::OPS_PER_STEP {
        // An answer still owed means the channel is not draining;
        // another record could not be answered either.
        if s.reply.owed() {
            break;
        }
        let rec_len = match super::wire::request_record_len(&s.req_asm[req_off..s.req_asm_len]) {
            Ok(Some(len)) => len,
            // Nothing, or an incomplete tail: keep it and wait.
            Ok(None) => break,
            // Not a request record. NAK it and skip one byte to
            // resync — a byte stream offers no frame to skip to, and
            // silence would leave the producer waiting on a request
            // this PIC will never act on.
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                if s.req_resyncing == 0 {
                    s.req_resyncing = 1;
                    respond(s, syscalls, 0xFF);
                }
                req_off += 1;
                handled = handled.wrapping_add(1);
                continue;
            }
        };
        s.req_resyncing = 0;
        let bytes = &s.req_asm[req_off..req_off + rec_len] as *const [u8];
        let bytes = &*bytes;
        req_off += rec_len;

        // Pre-validate opcode. Cheap, doesn't mutate. Catches
        // garbage before we touch durable storage.
        let op = match super::wire::peek_opcode(bytes) {
            Some(
                op @ (super::wire::OP_BIND
                | super::wire::OP_RENAME
                | super::wire::OP_UNBIND
                | super::wire::OP_LOOKUP
                | super::wire::OP_LIST
                | super::wire::OP_REFERENCED
                | super::wire::OP_GC_RESERVE
                | super::wire::OP_GC_RELEASE),
            ) => op,
            _ => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                respond(s, syscalls, 0xFF);
                handled = handled.wrapping_add(1);
                continue;
            }
        };

        // Reservations take the same path as every other mutating
        // record — logged, and proposed in replicated mode — so they
        // land in the same order as the binds they must exclude.
        // `apply_op` is where both are resolved.

        // Read ops (LOOKUP) don't touch the WAL or the arena —
        // they answer from current arena state and return a
        // length-prefixed response payload, not the standard
        // 1-byte ack.
        if op == super::wire::OP_LOOKUP
            || op == super::wire::OP_LIST
            || op == super::wire::OP_REFERENCED
        {
            if s.replicated != 0 && s.read_ready == 0 {
                // Replay hasn't converged: answering now could serve a
                // stale pointer. Distinct NOT_READY nak → reader retries.
                respond(s, syscalls, 0xFE);
                handled = handled.wrapping_add(1);
                continue;
            }
            match op {
                super::wire::OP_LOOKUP => handle_lookup(s, syscalls, bytes),
                super::wire::OP_LIST => handle_list(s, syscalls, bytes),
                _ => handle_referenced(s, syscalls, bytes),
            }
            handled = handled.wrapping_add(1);
            continue;
        }

        // Replicated mode: mutating ops are proposed to the metadata
        // plane instead of being applied here. The apply + 1-byte ack
        // happen in drain_committed() when the commit round-trips.
        if s.replicated != 0 {
            match super::decision::encode_propose(
                &mut s.append_scratch,
                super::decision::PLANE_NAMESPACE,
                0,
                bytes,
            ) {
                Ok(n) => {
                    let wrote =
                        (syscalls.channel_write)(s.metadata_ops_chan, s.append_scratch.as_ptr(), n);
                    if wrote != n as i32 {
                        s.apply_errors = s.apply_errors.wrapping_add(1);
                        respond(s, syscalls, 0xFF);
                    } else {
                        s.outstanding = s.outstanding.wrapping_add(1);
                    }
                }
                Err(_) => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    respond(s, syscalls, 0xFF);
                }
            }
            handled = handled.wrapping_add(1);
            continue;
        }

        // A WAL that was configured and is now gone is not the same
        // as never having had one: the arena would mutate with no
        // durable backing while the ack claimed otherwise. Refuse
        // until an open succeeds again.
        if s.wal_fd < 0 && s.wal_path_len > 0 {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            respond(s, syscalls, 0xFF);
            handled = handled.wrapping_add(1);
            continue;
        }

        // Durability first: a successful arena mutation must have a
        // durable backing by the time we ack. The append is staged,
        // not completed here — a device that has accepted the frame
        // but not finished it leaves the record staged and the step
        // returns; the arena and the ack wait for the fence.
        if s.wal_fd >= 0 {
            match s.appender.begin(syscalls, s.wal_fd, bytes) {
                super::wal::AppendState::Durable => {}
                super::wal::AppendState::Pending => {
                    s.wal_stage = WAL_STAGE_REQUEST;
                    break;
                }
                _ => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    respond(s, syscalls, 0xFF);
                    handled = handled.wrapping_add(1);
                    continue;
                }
            }
        }

        // The WAL already has the record. An arena rejection (e.g.
        // AlreadyBound) replays the same way, so net state stays
        // consistent whichever side of a restart it lands on.
        let result = apply_op(s, syscalls, bytes);
        if result.is_ok() {
            s.ops_applied = s.ops_applied.wrapping_add(1);
        } else {
            s.apply_errors = s.apply_errors.wrapping_add(1);
        }
        respond_applied(s, syscalls, bytes, result);
        handled = handled.wrapping_add(1);
    }
    // Keep whatever the step budget did not reach. Records left here
    // are pending work, not discarded work.
    if req_off > 0 {
        let remaining = s.req_asm_len - req_off;
        let mut i = 0usize;
        while i < remaining {
            s.req_asm[i] = s.req_asm[req_off + i];
            i += 1;
        }
        s.req_asm_len = remaining;
    }

    if s.replicated != 0 {
        drain_committed(s, syscalls);
    }
    0
}

/// Replicated-mode setter, called by the PIC mod.rs after
/// `dev_channel_port` lookups. Both channels present ⇒ replicated.
///
/// # Safety
/// `state_ptr` must point at an initialized `ModuleState`.
pub unsafe fn set_replication_channels(
    state_ptr: *mut u8,
    metadata_ops_chan: i32,
    committed_chan: i32,
) {
    if state_ptr.is_null() {
        return;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    s.metadata_ops_chan = metadata_ops_chan;
    s.committed_chan = committed_chan;
    s.replicated = u8::from(metadata_ops_chan >= 0 && committed_chan >= 0);
    if s.replicated != 0 {
        // Not readable until the proposer signals replay convergence.
        s.read_ready = 0;
    }
}

/// Drain Committed records from the metadata plane and apply them.
/// Record: [0x11][plane][corr u32][quorum u8][epoch u64][len u16][inner].
/// The inner bytes are the original namespace event — the same shape
/// `requests` carries — so the apply path is shared. Each applied op
/// acks 1 byte to `responses` (the requester sees the ack only after
/// the metadata plane committed: that IS the fence).
unsafe fn drain_committed(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    // Refill the reassembly buffer from the byte stream.
    loop {
        let space = s.cmt_asm.len() - s.cmt_asm_len;
        if space == 0 {
            break;
        }
        let n = (syscalls.channel_read)(
            s.committed_chan,
            s.cmt_asm.as_mut_ptr().add(s.cmt_asm_len),
            space,
        );
        if n <= 0 {
            break;
        }
        s.cmt_asm_len += n as usize;
    }
    // Record boundaries and field offsets come from the decision wire
    // rather than from constants restated here: this drain is where
    // the commit proof enters the PIC, and an offset copied into this
    // file is how a field on that record stops being read.
    let mut off = 0usize;
    while off < s.cmt_asm_len {
        let rec_len = match super::decision::record_len(&s.cmt_asm[off..s.cmt_asm_len]) {
            Ok(Some(n)) => n,
            Ok(None) => break, // partial record: wait for more bytes
            Err(_) => {
                // Unknown opcode: skip one byte to resync.
                s.apply_errors = s.apply_errors.wrapping_add(1);
                off += 1;
                continue;
            }
        };
        if s.cmt_asm[off] == super::decision::OP_REPLAY_DRAINED {
            s.read_ready = 1;
            off += rec_len;
            continue;
        }
        let (inner_len, proof) =
            match super::decision::decode_committed(&s.cmt_asm[off..off + rec_len]) {
                Ok(c) if c.plane == super::decision::PLANE_NAMESPACE => (c.inner.len(), c.proof),
                _ => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    off += rec_len;
                    continue;
                }
            };
        // Copy the inner out so the arena/WAL calls don't alias cmt_asm.
        let mut inner_buf = [0u8; READ_BUF];
        if inner_len > inner_buf.len() {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            off += rec_len;
            continue;
        }
        let hdr = super::decision::COMMITTED_HDR;
        inner_buf[..inner_len].copy_from_slice(&s.cmt_asm[off + hdr..off + hdr + inner_len]);
        let inner = &inner_buf[..inner_len];
        let live = s.outstanding > 0;
        // The local WAL is this PIC's recovery authority (see
        // `docs/architecture.md`), so a committed record that cannot
        // be logged locally must not be applied or acked: the plane
        // upstream is a delivery buffer, not a replayable history.
        // That holds whether the append fails or the log is gone
        // altogether — `wal_path_len` is what separates a lost log
        // from channel-only mode, where there was never one to lose.
        if s.wal_fd < 0 && s.wal_path_len > 0 {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            if live {
                s.outstanding -= 1;
                respond(s, syscalls, 0xFF);
            }
            off += rec_len;
            continue;
        }
        if s.wal_fd >= 0 {
            match s.appender.begin(syscalls, s.wal_fd, inner) {
                super::wal::AppendState::Durable => {}
                super::wal::AppendState::Pending => {
                    s.wal_stage = WAL_STAGE_COMMITTED;
                    s.wal_stage_live = u8::from(live);
                    off += rec_len;
                    break;
                }
                _ => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    if live {
                        s.outstanding -= 1;
                        respond(s, syscalls, 0xFF);
                    }
                    off += rec_len;
                    continue;
                }
            }
        }
        let result = apply_op(s, syscalls, inner);
        match result {
            Ok(_) => {
                s.ops_applied = s.ops_applied.wrapping_add(1);
                s.last_proof = proof;
                s.has_proof = 1;
                if live {
                    s.outstanding -= 1;
                    respond_applied(s, syscalls, inner, result);
                }
            }
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                if live {
                    s.outstanding -= 1;
                    respond_applied(s, syscalls, inner, result);
                }
            }
        }
        off += rec_len;
    }
    if off > 0 {
        s.cmt_asm.copy_within(off..s.cmt_asm_len, 0);
        s.cmt_asm_len -= off;
    }
}

/// Staged-record buffer. Sized by what the appender can hold, NOT by
/// `READ_BUF` — that is the channel-read chunk size, and a record
/// reassembled across chunks is legitimately larger. Undersizing here
/// refuses a record the WAL already made durable, so the requester is
/// told it failed and replay applies it anyway.
const STAGED_REC: usize = super::wal::MAX_WAL_REC;

/// Resolve the record a staged append took off its stream. `durable`
/// licenses the arena mutation and the success ack; without it the
/// record is refused, because a refusal the requester can see is the
/// only honest answer to a durability failure.
unsafe fn resolve_staged(s: &mut ModuleState, syscalls: &super::SyscallTable, durable: bool) {
    let stage = core::mem::replace(&mut s.wal_stage, WAL_STAGE_NONE);
    let live = s.wal_stage_live != 0;
    s.wal_stage_live = 0;
    let owes_ack = stage == WAL_STAGE_REQUEST || live;
    if !durable {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        if stage == WAL_STAGE_COMMITTED && live {
            s.outstanding = s.outstanding.saturating_sub(1);
        }
        if owes_ack {
            respond(s, syscalls, 0xFF);
        }
        return;
    }
    let mut payload = [0u8; STAGED_REC];
    let n = s.appender.payload().len();
    if n == 0 || n > payload.len() {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        if stage == WAL_STAGE_COMMITTED && live {
            s.outstanding = s.outstanding.saturating_sub(1);
        }
        if owes_ack {
            respond(s, syscalls, 0xFF);
        }
        return;
    }
    payload[..n].copy_from_slice(s.appender.payload());
    let result = apply_op(s, syscalls, &payload[..n]);
    if stage == WAL_STAGE_COMMITTED && live {
        s.outstanding = s.outstanding.saturating_sub(1);
    }
    if result.is_ok() {
        s.ops_applied = s.ops_applied.wrapping_add(1);
    } else {
        s.apply_errors = s.apply_errors.wrapping_add(1);
    }
    if owes_ack {
        let mut echo = [0u8; READ_BUF];
        echo[..n].copy_from_slice(&payload[..n]);
        respond_applied(s, syscalls, &echo[..n], result);
    }
}

/// Serve a LOOKUP request: look up the binding in the arena,
/// build a Found/NotFound response, write it to out_chan. No
/// arena mutation, no WAL write — reads are idempotent and
/// channel-only.
unsafe fn handle_lookup(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let req = match super::wire::decode_lookup_req(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            respond(s, syscalls, 0xFF);
            return;
        }
    };
    let (ns_h, p_h) = super::state::key_hash(req.namespace_root, req.path);
    let arena_hit = s
        .bindings
        .lookup_hashed(ns_h, p_h, req.namespace_root, req.path)
        .copied();
    let n = match arena_hit {
        Some(slot) if slot.kind == super::state::KIND_TOMBSTONE => {
            // A tombstone masks any on-disk snapshot record.
            super::wire::encode_lookup_not_found(&mut s.append_scratch)
        }
        Some(slot) => {
            let oid = slot.object_id();
            super::wire::encode_lookup_found(&mut s.append_scratch, oid, slot.revision, slot.kind)
        }
        None if s.snap_active != 0 => {
            // MISS PATH: binary-search the on-disk snapshot —
            // the arena is a hot cache, not the whole set.
            let snap = super::snapshot::OpenSnapshot {
                fd: s.snap_fd,
                count: s.snap_count,
                generation: s.snap_gen,
            };
            match super::snapshot::snap_search(syscalls, &snap, ns_h, p_h) {
                Some(rec) => {
                    s.snap_misses = s.snap_misses.wrapping_add(1);
                    super::wire::encode_lookup_found(
                        &mut s.append_scratch,
                        &rec.oid[..rec.oid_len as usize],
                        rec.revision,
                        rec.kind,
                    )
                }
                None => super::wire::encode_lookup_not_found(&mut s.append_scratch),
            }
        }
        None => super::wire::encode_lookup_not_found(&mut s.append_scratch),
    };
    match n {
        Ok(n) => {
            if s.out_chan >= 0 {
                let _ = s
                    .reply
                    .send(syscalls.channel_write, s.out_chan, &s.append_scratch[..n]);
            }
        }
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            respond(s, syscalls, 0xFF);
        }
    }
}

/// Serve a LIST request: one page of the namespace's listable
/// paths from the arena. Read-only, channel-only, cursor-paged —
/// same discipline as LOOKUP.
unsafe fn handle_list(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let req = match super::wire::decode_list_req(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            respond(s, syscalls, 0xFF);
            return;
        }
    };
    let max = (req.max as usize).min(super::wire::MAX_LIST_PAGE);
    let mut paths_buf = [[0u8; super::state::MAX_LIST_PATH]; super::wire::MAX_LIST_PAGE];
    let mut lens = [0usize; super::wire::MAX_LIST_PAGE];
    let mut count = 0usize;
    // Cursor space: [0, capacity) walks the arena, then
    // [capacity, capacity + snap_count) walks the snapshot,
    // skipping records the arena already answered for (its entry
    // — live or tombstone — is authoritative).
    let arena_cap = s.bindings.capacity() as u32;
    let next_cursor = if req.cursor < arena_cap {
        let nc = s
            .bindings
            .list_page(req.namespace_root, req.cursor, max, |path| {
                if count < super::wire::MAX_LIST_PAGE {
                    let take = path.len().min(super::state::MAX_LIST_PATH);
                    paths_buf[count][..take].copy_from_slice(&path[..take]);
                    lens[count] = take;
                    count += 1;
                }
            });
        if nc != 0 {
            nc
        } else if s.snap_active != 0 && s.snap_count > 0 {
            arena_cap // continue into the snapshot region
        } else {
            0
        }
    } else {
        req.cursor
    };
    let next_cursor = if next_cursor >= arena_cap && s.snap_active != 0 {
        let ns_h = super::state::fnv1a64(req.namespace_root);
        let snap = super::snapshot::OpenSnapshot {
            fd: s.snap_fd,
            count: s.snap_count,
            generation: s.snap_gen,
        };
        let mut idx = next_cursor - arena_cap;
        while idx < s.snap_count && count < max {
            match super::snapshot::snap_read_at(syscalls, &snap, idx) {
                Some(rec) => {
                    idx += 1;
                    if rec.ns_hash != ns_h
                        || rec.path_len == 0
                        || s.bindings
                            .lookup_hashed(
                                rec.ns_hash,
                                rec.path_hash,
                                &rec.root[..rec.root_len as usize],
                                &rec.path[..rec.path_len as usize],
                            )
                            .is_some()
                    {
                        continue;
                    }
                    let take = (rec.path_len as usize).min(super::state::MAX_LIST_PATH);
                    paths_buf[count][..take].copy_from_slice(&rec.path[..take]);
                    lens[count] = take;
                    count += 1;
                }
                None => {
                    idx = s.snap_count;
                    break;
                }
            }
        }
        if idx >= s.snap_count {
            0
        } else {
            arena_cap + idx
        }
    } else {
        next_cursor
    };
    let mut slices: [&[u8]; super::wire::MAX_LIST_PAGE] = [&[]; super::wire::MAX_LIST_PAGE];
    for i in 0..count {
        slices[i] = &paths_buf[i][..lens[i]];
    }
    match super::wire::encode_list_resp(&mut s.append_scratch, next_cursor, &slices[..count]) {
        Ok(n) => {
            if s.out_chan >= 0 {
                let _ = s
                    .reply
                    .send(syscalls.channel_write, s.out_chan, &s.append_scratch[..n]);
            }
        }
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            respond(s, syscalls, 0xFF);
        }
    }
}

/// Serve a REFERENCED request: does any binding hold this object
/// id? Read-only, channel-only.
unsafe fn handle_referenced(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let (cursor, oid) = match super::wire::decode_referenced_req(bytes) {
        Ok(v) => v,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            respond(s, syscalls, 0xFF);
            return;
        }
    };
    // Page 0 checks the arena (fast, complete for the hot set);
    // every page scans a bounded window of the snapshot. The
    // conservative direction survives: hash-only records (no
    // inline oid bytes) count as referenced.
    const REF_SCAN_PER_CALL: u32 = 128;
    let mut referenced = cursor == 0 && s.bindings.object_id_referenced(oid);
    let mut next_cursor = 0u32;
    if !referenced && s.snap_active != 0 {
        let snap = super::snapshot::OpenSnapshot {
            fd: s.snap_fd,
            count: s.snap_count,
            generation: s.snap_gen,
        };
        let end = cursor.saturating_add(REF_SCAN_PER_CALL).min(s.snap_count);
        let mut idx = cursor;
        while idx < end {
            match super::snapshot::snap_read_at(syscalls, &snap, idx) {
                Some(rec) => {
                    let matches = if rec.oid_len == 0 {
                        true // hash-only: conservative
                    } else {
                        &rec.oid[..(rec.oid_len as usize).min(rec.oid.len())] == oid
                    };
                    if matches {
                        referenced = true;
                        break;
                    }
                }
                None => {
                    // Read failure: conservative.
                    referenced = true;
                    break;
                }
            }
            idx += 1;
        }
        if !referenced && end < s.snap_count {
            next_cursor = end;
        }
    }
    let mut out = [0u8; 6];
    if s.out_chan >= 0
        && super::wire::encode_referenced_resp(&mut out, referenced, next_cursor).is_ok()
    {
        let _ = s.reply.send(syscalls.channel_write, s.out_chan, &out);
    }
}

/// Answer one applied record. A reserve carries whether the id is now
/// held — the sweep needs the grant, not just an ack — and a bind
/// refused by a standing reservation gets its own nak so the client
/// can tell "retry this" from "this was wrong".
unsafe fn respond_applied(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    payload: &[u8],
    result: Result<u8, ApplyFault>,
) {
    match result {
        Ok(op) if op == super::wire::OP_GC_RESERVE => {
            let held = match super::wire::decode_gc_reserve_req(payload) {
                Ok(id) => s.gc_reserved.contains(&super::state::fnv1a64(id)),
                Err(_) => false,
            };
            let mut buf = [0u8; 2];
            if let Ok(n) = super::wire::encode_gc_reserve_resp(&mut buf, held) {
                if s.out_chan >= 0 {
                    let _ = s.reply.send(syscalls.channel_write, s.out_chan, &buf[..n]);
                }
            }
        }
        Ok(op) => respond(s, syscalls, op),
        Err(ApplyFault::Reserved) => respond(s, syscalls, NAK_RESERVED),
        Err(ApplyFault::Rejected) => respond(s, syscalls, 0xFF),
    }
}

/// Why an apply produced no state change. `Reserved` is a deliberate,
/// deterministic refusal — the id is held for deletion — and every
/// replica reaches it at the same point in the log. `Rejected` is
/// everything else.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ApplyFault {
    Reserved,
    Rejected,
}

/// Apply one op with snapshot semantics wrapped around the pure
/// arena apply:
///
/// - UNBIND with an active snapshot TOMBSTONES (masking the
///   on-disk record) instead of clearing, at the binding's
///   current revision so a later re-bind wins normally.
/// - a full arena evicts one snapshot-covered slot and retries
///   (never while the compactor is mid-merge — eviction before
///   the new generation is durable would serve stale reads).
unsafe fn apply_op(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    payload: &[u8],
) -> Result<u8, ApplyFault> {
    let op = super::wire::peek_opcode(payload).ok_or(ApplyFault::Rejected)?;
    // Deletion reservations are applied HERE, in log order, rather
    // than when the request arrives. That is what makes them safe
    // against a replicated bind: every replica applies the same
    // reserve, release and bind records in the same order, so every
    // replica reaches the same admission decision for a bind naming a
    // reserved id. Checking at arrival instead would be a local
    // decision about a globally ordered stream — the leader could
    // admit a bind that a follower refuses.
    if op == super::wire::OP_GC_RESERVE || op == super::wire::OP_GC_RELEASE {
        let object_id =
            super::wire::decode_gc_reserve_req(payload).map_err(|_| ApplyFault::Rejected)?;
        let oid_h = super::state::fnv1a64(object_id);
        if op == super::wire::OP_GC_RELEASE {
            for slot in s.gc_reserved.iter_mut() {
                if *slot == oid_h {
                    *slot = 0;
                }
            }
        } else if !s.gc_reserved.contains(&oid_h) {
            // A full table leaves the id unreserved. The sweep reads
            // that back and leaves the descriptor for a later pass,
            // which is the conservative direction.
            if let Some(slot) = s.gc_reserved.iter_mut().find(|slot| **slot == 0) {
                *slot = oid_h;
            }
        }
        return Ok(op);
    }
    if op == super::wire::OP_BIND {
        let dec = super::wire::decode_bind(payload).map_err(|_| ApplyFault::Rejected)?;
        if s.gc_reserved
            .contains(&super::state::fnv1a64(dec.object_id))
        {
            return Err(ApplyFault::Reserved);
        }
    }
    if op == super::wire::OP_UNBIND && s.snap_active != 0 {
        let dec = super::wire::decode_unbind(payload).map_err(|_| ApplyFault::Rejected)?;
        let (ns_h, p_h) = super::state::key_hash(dec.namespace_root, dec.path);
        let revision = match s
            .bindings
            .lookup_hashed(ns_h, p_h, dec.namespace_root, dec.path)
        {
            Some(slot) if slot.kind == super::state::KIND_TOMBSTONE => {
                return Err(ApplyFault::Rejected)
            }
            Some(slot) => slot.revision,
            None => {
                let snap = super::snapshot::OpenSnapshot {
                    fd: s.snap_fd,
                    count: s.snap_count,
                    generation: s.snap_gen,
                };
                match super::snapshot::snap_search(syscalls, &snap, ns_h, p_h) {
                    Some(rec) => rec.revision,
                    None => return Err(ApplyFault::Rejected),
                }
            }
        };
        let mut res = s.bindings.tombstone(dec.namespace_root, dec.path, revision);
        if res == Err(super::state::ApplyError::OutOfCapacity) && s.bindings.evict_one_snapshotted()
        {
            s.evictions = s.evictions.wrapping_add(1);
            res = s.bindings.tombstone(dec.namespace_root, dec.path, revision);
        }
        return res
            .map(|_| super::wire::OP_UNBIND)
            .map_err(|_| ApplyFault::Rejected);
    }
    match apply_to_arena(&mut s.bindings, payload) {
        Ok(op) => Ok(op),
        Err(_) => {
            // Retry once behind an eviction if the arena is FULL —
            // other rejections (AlreadyBound, NotBound) replay the
            // same way and stay rejected.
            if s.snap_active != 0
                && s.bindings.occupied_count() == s.bindings.capacity()
                && s.bindings.evict_one_snapshotted()
            {
                s.evictions = s.evictions.wrapping_add(1);
                return apply_to_arena(&mut s.bindings, payload).map_err(|_| ApplyFault::Rejected);
            }
            Err(ApplyFault::Rejected)
        }
    }
}

/// Build a snapshot record from an arena slot (field widths align
/// by construction: MAX_OBJECT_ID/MAX_LIST_ROOT/MAX_LIST_PATH ==
/// the snapshot's MAX_OID/MAX_ROOT/MAX_PATH).
fn snap_record_from_slot(slot: &super::state::BindingSlot) -> super::snapshot::SnapRecord {
    let mut r = super::snapshot::SnapRecord::empty();
    r.ns_hash = slot.namespace_hash;
    r.path_hash = slot.path_hash;
    r.revision = slot.revision;
    r.kind = slot.kind;
    r.oid_len = slot.object_id_len;
    r.oid = slot.object_id_bytes;
    r.root_len = slot.root_len;
    r.root = slot.root_bytes;
    r.path_len = slot.path_len;
    r.path = slot.path_bytes;
    r
}

unsafe fn compaction_abort(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    if s.cmp_writer_fd >= 0 {
        let _ = (syscalls.provider_call)(
            s.cmp_writer_fd,
            0x0903, /* FS_CLOSE */
            core::ptr::null_mut(),
            0,
        );
    }
    s.cmp_writer_fd = -1;
    s.cmp_running = 0;
}

/// One bounded slice of the merge compaction. Trigger, merge, and
/// finalize all live here; called once per step.
unsafe fn compaction_step(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    if s.cmp_running == 0 {
        if s.wal_path_len == 0 {
            return;
        }
        let occupied = s.bindings.occupied_count();
        let cap = s.bindings.capacity();
        if occupied * CMP_TRIGGER_DEN < cap * CMP_TRIGGER_NUM {
            return;
        }
        // HYSTERESIS: under pressure, only re-compact when enough
        // NEW data has accumulated (or the arena is wedged full of
        // dirt). Without this, occupancy stays above the trigger
        // after a snapshot, compaction re-runs continuously, and
        // eviction — gated off mid-merge — never gets to relieve
        // the pressure: a livelock into OutOfCapacity.
        let dirty = s.bindings.dirty_count();
        let meaningful_dirt = dirty * 8 >= cap;
        let wedged = occupied == cap && dirty > 0;
        if s.snap_active != 0 && !meaningful_dirt && !wedged {
            return;
        }
        let target = if s.snap_active != 0 {
            s.snap_slot ^ 1
        } else {
            0
        };
        let gen = if s.snap_active != 0 {
            s.snap_gen + 1
        } else {
            1
        };
        let mut path = [0u8; 300];
        let n =
            super::snapshot::snap_path(&s.wal_path[..s.wal_path_len as usize], target, &mut path);
        if n == 0 {
            return;
        }
        let writer = match super::snapshot::snap_writer_start(syscalls, &path[..n], gen) {
            Some(w) => w,
            None => return,
        };
        s.cmp_running = 1;
        s.cmp_target_slot = target;
        s.cmp_writer_fd = writer.fd;
        s.cmp_writer_count = 0;
        s.cmp_writer_gen = gen;
        s.cmp_snap_idx = 0;
        s.cmp_last_key_valid = 0;
        return;
    }

    let old_snap = super::snapshot::OpenSnapshot {
        fd: s.snap_fd,
        count: s.snap_count,
        generation: s.snap_gen,
    };
    let mut writer = super::snapshot::SnapWriter {
        fd: s.cmp_writer_fd,
        count: s.cmp_writer_count,
        generation: s.cmp_writer_gen,
    };
    for _ in 0..CMP_RECORDS_PER_STEP {
        let last = if s.cmp_last_key_valid != 0 {
            Some((s.cmp_last_ns, s.cmp_last_path))
        } else {
            None
        };
        let arena_next = s.bindings.min_key_above(last);
        let old_next = if s.snap_active != 0 && s.cmp_snap_idx < s.snap_count {
            match super::snapshot::snap_read_at(syscalls, &old_snap, s.cmp_snap_idx) {
                Some(r) => Some(r),
                None => {
                    compaction_abort(s, syscalls);
                    return;
                }
            }
        } else {
            None
        };
        match (arena_next, old_next) {
            (None, None) => {
                // Merge complete: make the new generation durable,
                // switch to it, rotate the WAL, drop superseded
                // tombstones.
                if !super::snapshot::snap_writer_finish(syscalls, &mut writer) {
                    compaction_abort(s, syscalls);
                    return;
                }
                let mut path = [0u8; 300];
                let n = super::snapshot::snap_path(
                    &s.wal_path[..s.wal_path_len as usize],
                    s.cmp_target_slot,
                    &mut path,
                );
                let reopened = super::snapshot::snap_open_one(syscalls, &path[..n]);
                let new_snap = match reopened {
                    Some(v) => v,
                    None => {
                        compaction_abort(s, syscalls);
                        return;
                    }
                };
                if s.snap_fd >= 0 {
                    let _ = (syscalls.provider_call)(
                        s.snap_fd,
                        0x0903, /* FS_CLOSE */
                        core::ptr::null_mut(),
                        0,
                    );
                }
                s.snap_active = 1;
                s.snap_slot = s.cmp_target_slot;
                s.snap_fd = new_snap.fd;
                s.snap_count = new_snap.count;
                s.snap_gen = new_snap.generation;
                if s.wal_fd >= 0 {
                    match super::wal::wal_rotate(
                        syscalls,
                        s.wal_fd,
                        &s.wal_path[..s.wal_path_len as usize],
                    ) {
                        Ok(super::wal::RotateOutcome::Rotated(new_fd)) => {
                            s.wal_fd = new_fd;
                            s.appender.reset();
                        }
                        // The log was left intact: boot replays the
                        // snapshot plus a longer tail, which costs time
                        // and nothing else.
                        Ok(super::wal::RotateOutcome::Skipped) => {}
                        // Replaced but not reopenable. `wal_path_len`
                        // still says a log was configured, which is
                        // what lets the write path refuse rather than
                        // silently drop to no durability.
                        Err(_) => {
                            s.wal_fd = -1;
                            s.appender.reset();
                        }
                    }
                }
                let tag = (s.cmp_writer_gen % 251 + 1) as u8;
                s.bindings.finalize_emitted(tag);
                s.cmp_writer_fd = -1;
                s.cmp_running = 0;
                s.snapshots_written = s.snapshots_written.wrapping_add(1);
                return;
            }
            (Some((idx, key)), old) => {
                let take_arena = match &old {
                    Some(rec) => key <= rec.key(),
                    None => true,
                };
                if take_arena {
                    let slot = match s.bindings.slot_ref(idx) {
                        Some(sl) => *sl,
                        None => {
                            compaction_abort(s, syscalls);
                            return;
                        }
                    };
                    if slot.kind != super::state::KIND_TOMBSTONE {
                        let rec = snap_record_from_slot(&slot);
                        if !super::snapshot::snap_writer_append(syscalls, &mut writer, &rec) {
                            compaction_abort(s, syscalls);
                            return;
                        }
                    }
                    // Tag the emit; promoted to snapshot-covered
                    // only when this generation is durable.
                    let tag = (s.cmp_writer_gen % 251 + 1) as u8;
                    s.bindings.mark_emitted(idx, tag);
                    if let Some(rec) = &old {
                        if rec.key() == key {
                            s.cmp_snap_idx += 1; // superseded
                        }
                    }
                    s.cmp_last_ns = key.0;
                    s.cmp_last_path = key.1;
                    s.cmp_last_key_valid = 1;
                } else if let Some(rec) = old {
                    if !super::snapshot::snap_writer_append(syscalls, &mut writer, &rec) {
                        compaction_abort(s, syscalls);
                        return;
                    }
                    s.cmp_snap_idx += 1;
                }
            }
            (None, Some(rec)) => {
                if !super::snapshot::snap_writer_append(syscalls, &mut writer, &rec) {
                    compaction_abort(s, syscalls);
                    return;
                }
                s.cmp_snap_idx += 1;
            }
        }
    }
    s.cmp_writer_count = writer.count;
    s.cmp_writer_fd = writer.fd;
}

/// Decode a channel-wire (or WAL-replay) payload and apply it to
/// the arena. Pure function: no syscalls, no I/O. Used by both
/// `module_step_impl` (live apply) and `module_new_with_wal_impl`
/// (replay apply).
pub(super) fn apply_to_arena(
    bindings: &mut super::state::PicNamespaceState<ARENA_CAPACITY>,
    payload: &[u8],
) -> Result<u8, ()> {
    let op = super::wire::peek_opcode(payload).ok_or(())?;
    match op {
        super::wire::OP_BIND => {
            let dec = super::wire::decode_bind(payload).map_err(|_| ())?;
            bindings
                .bind(
                    dec.namespace_root,
                    dec.path,
                    dec.object_id,
                    dec.kind,
                    dec.revision,
                )
                .map_err(|_| ())?;
            Ok(super::wire::OP_BIND)
        }
        super::wire::OP_RENAME => {
            let dec = super::wire::decode_rename(payload).map_err(|_| ())?;
            bindings
                .rename(dec.namespace_root, dec.from, dec.to, dec.new_revision)
                .map_err(|_| ())?;
            Ok(super::wire::OP_RENAME)
        }
        super::wire::OP_UNBIND => {
            let dec = super::wire::decode_unbind(payload).map_err(|_| ())?;
            bindings
                .unbind(dec.namespace_root, dec.path)
                .map_err(|_| ())?;
            Ok(super::wire::OP_UNBIND)
        }
        _ => Err(()),
    }
}

// ── storage.namespace provider surface ─────────────────────────────
//
// The canonical surface, answered by `provider_call` rather than over
// a channel. A manifest that declares `provides = ["storage.namespace"]`
// is only true if these exports exist: the loader registers a provider
// by resolving `module_provides_contract` + `module_provider_dispatch`,
// so a declaration without them advertises a surface nothing can reach.
//
// COST NOTE. `SUBSCRIBE`'s initial listing and `CHANGES` both walk
// the whole arena inside one `provider_call`. That is O(arena), the
// same order every other op here already pays — `live_slot` scans
// linearly for LOOKUP, STAT and DELETE — so it is consistent with
// the module rather than a new hazard. It is still a real number at
// service-class capacity (8192 slots), and paging `CHANGES` on a
// cursor the way `LIST` and `OP_REFERENCED` are paged is the obvious
// next move if it starts to bind. The OUTPUT is already bounded: a
// window that does not fit the caller's buffer answers LOST.
//
// What is implemented is exactly what `CAPS` reports, and that is now
// the whole surface: the mandatory read ops, BIND, RENAME, DELETE,
// and the two change ops. SUBSCRIBE and CHANGES are what make loam
// usable as a control-plane store — level-triggered reconciliation is
// how nanocloud's forty store-consuming modules are built, and a
// store that must be polled cannot be that store.

/// `storage.namespace` contract id.
pub const CONTRACT_STORAGE_NAMESPACE: u32 = 0x0013;

pub const NS_OP_LOOKUP: u32 = 0x1300;
pub const NS_OP_STAT: u32 = 0x1301;
pub const NS_OP_LIST: u32 = 0x1302;
pub const NS_OP_RENAME: u32 = 0x1303;
pub const NS_OP_DELETE: u32 = 0x1304;
pub const NS_OP_SUBSCRIBE: u32 = 0x1305;
pub const NS_OP_CHANGES: u32 = 0x1307;
pub const NS_OP_CLOSE: u32 = 0x1306;
pub const NS_OP_BIND: u32 = 0x1308;
pub const NS_OP_CAPS: u32 = 0x13FF;

/// Capability bits this provider sets: BIND(0), RENAME(1), DELETE(2),
/// SUBSCRIBE(3), CHANGES(4). Every optional op on the surface. The
/// mandatory read ops carry no bit.
pub const NS_CAPS: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4);

/// Subscription handles are returned above the LOOKUP handle space so
/// `CLOSE` can tell the two apart from the handle alone — the contract
/// gives CLOSE one opcode for both.
const SUB_HANDLE_BASE: i32 = 0x4000;

const E_INVAL: i32 = -22;
const E_NOENT: i32 = -2;
const E_NOSYS: i32 = -38;
const E_EXIST: i32 = -17;
const E_MFILE: i32 = -24;

/// Write one `LIST` entry into `out`, answering whether it fitted.
///
/// `trailer` is the room the mandatory cursor record must keep, reserved
/// before any entry is written: a full buffer carrying entries and no way to
/// continue would have the caller parse a page it cannot follow.
///
/// A name the entry header cannot express is passed over as though it did
/// fit. `name_len` is one byte and this namespace binds paths far longer, so
/// the frame cannot carry such a name and the contract has no "skipped"
/// signal to report it with. Recorded as a contract gap rather than hidden.
///
/// The ceiling is 254, not 255: the trailing cursor record is marked with
/// `0xFF` in the same position an entry carries `name_len`, so a name of
/// exactly 255 bytes would produce an entry a consumer reads as the end of
/// the page — every later entry lost, and silently. Emitting one would be
/// worse than omitting it, which is why the length a byte can hold is not
/// the length this writes.
fn list_take(out: &mut [u8], w: &mut usize, name: &[u8], kind: u8, trailer: usize) -> bool {
    if name.is_empty() || name.len() >= u8::MAX as usize {
        return true;
    }
    let need = 2 + name.len();
    if *w + need + trailer > out.len() {
        return false;
    }
    let at = *w;
    out[at] = name.len() as u8;
    out[at + 1] = kind;
    out[at + 2..at + 2 + name.len()].copy_from_slice(name);
    *w = at + need;
    true
}

/// The strongest fence this provider can honestly claim right now.
///
/// Claimed from the PROOF in hand, never from the mode configured.
/// Being wired for replication says where records come from; it says
/// nothing about whether any of them reached a quorum, so it cannot
/// be what licenses a `ReplicatedDurable` claim. What licenses it is
/// a commit record whose proof carries a real quorum and a real
/// witness — `CommitProof::is_replicated`, which is the one place
/// that rule lives.
///
/// The ladder, strongest first:
///
/// - An applied commit whose proof is replicated: `ReplicatedDurable`
///   carrying that proof verbatim, so a consumer can order it against
///   another fence from the same log and detect a fork against a
///   divergent one.
/// - Otherwise a WAL: `LocalDurable`. This covers single-replica
///   mode, where every commit is durably logged by one voter — real
///   durability, no replication — and a replicated deployment before
///   its first commit round-trips.
/// - Otherwise `Volatile`. No WAL is no durability, and the whole
///   point of the fence axis is that a consumer can tell these apart.
unsafe fn achieved_fence(s: &ModuleState) -> super::abi::fence::Fence {
    if s.has_proof != 0 && s.last_proof.is_replicated() {
        let p = &s.last_proof;
        return super::abi::fence::Fence::ReplicatedDurable {
            source: p.source,
            commit_index: p.index,
            // The Raft term is the epoch the fence lattice orders on.
            // It is `u64` upstream and `u32` here; a term that
            // outruns `u32` would alias an older one, so it is
            // saturated rather than wrapped — an epoch that stops
            // advancing refuses to order, while a wrapped one would
            // silently order a new fence under an old one.
            epoch: if p.term > u32::MAX as u64 {
                u32::MAX
            } else {
                p.term as u32
            },
            quorum: p.quorum,
            witness: p.witness,
        };
    }
    if s.wal_fd >= 0 {
        super::abi::fence::Fence::LocalDurable { device_id: 0 }
    } else {
        super::abi::fence::Fence::Volatile
    }
}

/// Pull the trailing `[fence_out_ptr u64][fence_out_cap u16]` pair
/// out of an argument buffer at `off`. Absent is legal — a caller
/// that does not want the fence simply omits it.
fn read_fence_out(a: &[u8], off: usize) -> (*mut u8, usize) {
    if a.len() < off + 10 {
        return (core::ptr::null_mut(), 0);
    }
    let p = u64::from_le_bytes([
        a[off],
        a[off + 1],
        a[off + 2],
        a[off + 3],
        a[off + 4],
        a[off + 5],
        a[off + 6],
        a[off + 7],
    ]);
    let c = u16::from_le_bytes([a[off + 8], a[off + 9]]) as usize;
    (p as *mut u8, c)
}

/// A stable 16-byte source id for a namespace root.
///
/// `ViewConsistent` and `RevisionMonotone` carry an explicit source
/// so two unrelated namespaces at the same revision do not compare as
/// dominating each other. Loam mints no ObjectIds, so the root's own
/// bytes are the identity: FNV over the root, twice with different
/// seeds, gives 16 stable bytes that differ when the roots differ.
/// Not a secret and not a cryptographic id — it exists to keep the
/// fence lattice honest, nothing more.
fn view_source(root: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let a = super::state::fnv1a64(root);
    // Second half over the root with a byte appended, so a root and
    // its prefix cannot collide into the same source.
    let mut b = super::state::fnv1a64(root);
    b ^= 0x9E37_79B9_7F4A_7C15;
    out[0..8].copy_from_slice(&a.to_le_bytes());
    out[8..16].copy_from_slice(&b.to_le_bytes());
    out
}

/// Write a VIEW fence — what revision this read observed — into a
/// caller-supplied out-parameter.
///
/// Distinct from `write_fence_out`, which reports DURABILITY. A read
/// has not committed anything, so a durability fence answers a
/// question nobody asked; what a `CHANGES` caller needs is the
/// revision its window covered, because that is its next `since`.
/// The contract says so explicitly, and a snapshot depends on it: a
/// manifest is only a point-in-time record if something states which
/// point in time.
unsafe fn write_view_fence_out(root: &[u8], revision: u64, ptr: *mut u8, cap: usize) {
    if ptr.is_null() || cap < super::abi::fence::WIRE_MAX_LEN {
        return;
    }
    let buf = core::slice::from_raw_parts_mut(ptr, cap);
    let _ = super::abi::fence::Fence::ViewConsistent {
        source: view_source(root),
        revision,
    }
    .encode(buf);
}

/// Write the achieved fence into a caller-supplied out-parameter.
/// A short or absent buffer is the caller's error, not a reason to
/// fail the operation that already happened.
unsafe fn write_fence_out(s: &ModuleState, ptr: *mut u8, cap: usize) {
    if ptr.is_null() || cap < super::abi::fence::WIRE_MAX_LEN {
        return;
    }
    let buf = core::slice::from_raw_parts_mut(ptr, cap);
    let _ = achieved_fence(s).encode(buf);
}

/// Write a response, if anyone is listening.
///
/// `responses` is optional wiring: a graph that only drives the
/// surface and observes it elsewhere leaves it unconnected. Writing to
/// an unwired port is not a no-op at the syscall boundary, so every
/// response goes through here rather than assuming a reader exists.
/// Take ownership of the one-byte answer this record owes. A channel
/// that refuses it leaves it owed and the step re-offers it, rather
/// than dropping an answer for a record already applied.
unsafe fn respond(s: &mut ModuleState, syscalls: &super::SyscallTable, byte: u8) {
    if s.out_chan < 0 {
        return;
    }
    let _ = s.reply.send(syscalls.channel_write, s.out_chan, &[byte]);
}

/// Push one change to every subscriber watching a matching prefix.
///
/// Called AFTER the arena has been mutated, so what a subscriber sees
/// is a change that happened, never one that was about to. A sink
/// that refuses the write (a full channel) does not lose the event
/// quietly: the subscription is flagged `lost_pending`, and the next
/// successful push is the LOST sentinel, which tells the consumer to
/// relist through `CHANGES` instead of trusting an incomplete stream.
/// Silent loss is the one failure a level-triggered reconciler cannot
/// detect for itself, which is why it is not an option here.
unsafe fn notify_change(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    kind: u8,
    key: &[u8],
    value: &[u8],
) {
    // The arena stamped this mutation as it applied it, so the event
    // and the slot carry the SAME position — a subscriber and a
    // `CHANGES` caller therefore agree about ordering, which is the
    // whole point of the pair.
    let rev = s.bindings.change_seq();
    for i in 0..NS_SUB_MAX {
        if s.subs[i].in_use == 0 || s.subs[i].sink_chan < 0 {
            continue;
        }
        if !super::change_wire::under_prefix(key, s.subs[i].prefix()) {
            continue;
        }
        push_to_sub(s, syscalls, i, rev, kind, key, value);
    }
}

/// Encode and push one event to subscription `i`, settling any owed
/// LOST sentinel first.
unsafe fn push_to_sub(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    i: usize,
    rev: u64,
    kind: u8,
    key: &[u8],
    value: &[u8],
) {
    let chan = s.subs[i].sink_chan;
    if s.subs[i].lost_pending != 0 {
        let seq = s.subs[i].sequence;
        let Some(n) = super::change_wire::encode_lost_event(&mut s.event_buf, seq, rev) else {
            return;
        };
        if (syscalls.channel_write)(chan, s.event_buf.as_ptr(), n) != n as i32 {
            return; // still blocked; stay owed
        }
        s.subs[i].sequence = seq.wrapping_add(1);
        s.subs[i].lost_pending = 0;
        // The sentinel told the consumer to relist, so this event is
        // covered by the relist it will now perform.
        return;
    }
    let seq = s.subs[i].sequence;
    let Some(n) = super::change_wire::encode_event(&mut s.event_buf, seq, rev, kind, key, value)
    else {
        s.subs[i].lost_pending = 1;
        return;
    };
    if (syscalls.channel_write)(chan, s.event_buf.as_ptr(), n) == n as i32 {
        s.subs[i].sequence = seq.wrapping_add(1);
    } else {
        s.subs[i].lost_pending = 1;
    }
}

/// Find the live binding for `path`, or `None`.
///
/// A deleted binding stays in the arena as a tombstone so the deletion
/// itself replicates and survives replay. Every provider op has to
/// look past one: a tombstone is the record of an absence, not a
/// binding, and answering with it would resurrect a deleted name.
unsafe fn live_slot(s: &ModuleState, path: &[u8]) -> Option<(u32, u64)> {
    let (ns_h, p_h) = super::state::key_hash(&[], path);
    for i in 0..s.bindings.capacity() {
        if let Some(slot) = s.bindings.slot_ref(i) {
            if slot.occupied
                && slot.matches(ns_h, p_h, &[], path)
                && slot.kind != super::state::KIND_TOMBSTONE
            {
                return Some((i as u32, slot.revision));
            }
        }
    }
    None
}

unsafe fn alloc_handle(s: &mut ModuleState, slot: u32, revision: u64) -> i32 {
    for (i, h) in s.ns_open.iter_mut().enumerate() {
        if h.in_use == 0 {
            h.in_use = 1;
            h.slot = slot;
            h.revision = revision;
            return i as i32;
        }
    }
    E_MFILE
}

/// Answer one `storage.namespace` call.
///
/// # Safety
/// `state_ptr` must point at an initialized `ModuleState`; `arg` must
/// be valid for `arg_len` bytes.
pub unsafe fn provider_dispatch_impl(
    state_ptr: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state_ptr.is_null() {
        return E_INVAL;
    }
    let s = &mut *(state_ptr as *mut ModuleState);

    if opcode == super::abi::fence::QUERY_OP {
        if arg.is_null() || arg_len < super::abi::fence::WIRE_MAX_LEN {
            return E_INVAL;
        }
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return match achieved_fence(s).encode(buf) {
            Some(n) => n as i32,
            None => E_INVAL,
        };
    }

    match opcode {
        NS_OP_CAPS => NS_CAPS as i32,

        // `arg` is the path; returns a handle onto the resolved entry.
        NS_OP_LOOKUP => {
            if arg.is_null() || arg_len == 0 {
                return E_INVAL;
            }
            let path = core::slice::from_raw_parts(arg, arg_len);
            match live_slot(s, path) {
                Some((idx, rev)) => alloc_handle(s, idx, rev),
                None => E_NOENT,
            }
        }

        // `handle` is a LOOKUP handle; writes [kind][revision][target].
        NS_OP_STAT => {
            let idx = handle as usize;
            if handle < 0 || idx >= NS_OPEN_MAX || s.ns_open[idx].in_use == 0 {
                return E_INVAL;
            }
            let (slot_idx, pinned_rev) = (s.ns_open[idx].slot, s.ns_open[idx].revision);
            let entry = match s.bindings.slot_ref(slot_idx as usize) {
                Some(e) if e.occupied && e.revision == pinned_rev => e,
                // The view the handle pinned is gone. Re-LOOKUP is the
                // documented recovery; answering against a newer entry
                // would silently break the snapshot promise.
                _ => return E_NOENT,
            };
            let target = entry.object_id();
            let need = 1 + 8 + 2 + target.len();
            if arg.is_null() || arg_len < need {
                return E_INVAL;
            }
            let out = core::slice::from_raw_parts_mut(arg, arg_len);
            out[0] = entry.kind;
            out[1..9].copy_from_slice(&entry.revision.to_le_bytes());
            out[9..11].copy_from_slice(&(target.len() as u16).to_le_bytes());
            out[11..11 + target.len()].copy_from_slice(target);
            need as i32
        }

        // One opcode closes both handle kinds; the base tells them
        // apart, so a caller never has to say which it holds.
        NS_OP_CLOSE => {
            if handle >= SUB_HANDLE_BASE {
                let idx = (handle - SUB_HANDLE_BASE) as usize;
                if idx >= NS_SUB_MAX || s.subs[idx].in_use == 0 {
                    return E_INVAL;
                }
                s.subs[idx].in_use = 0;
                s.subs[idx].sink_chan = -1;
                s.subs[idx].lost_pending = 0;
                return 0;
            }
            let idx = handle as usize;
            if handle < 0 || idx >= NS_OPEN_MAX || s.ns_open[idx].in_use == 0 {
                return E_INVAL;
            }
            s.ns_open[idx].in_use = 0;
            0
        }

        // [path_len u16][path][kind][flags][target_len u16][target]
        // [fence_out_ptr u64][fence_out_cap u16]
        NS_OP_BIND => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let a = core::slice::from_raw_parts(arg, arg_len);
            let path_len = u16::from_le_bytes([a[0], a[1]]) as usize;
            let mut off = 2usize;
            if arg_len < off + path_len + 4 {
                return E_INVAL;
            }
            let path = &a[off..off + path_len];
            off += path_len;
            let kind = a[off];
            let flags = a[off + 1];
            off += 2;
            let target_len = u16::from_le_bytes([a[off], a[off + 1]]) as usize;
            off += 2;
            if arg_len < off + target_len {
                return E_INVAL;
            }
            let target = &a[off..off + target_len];
            off += target_len;

            let (fence_ptr, fence_cap) = if arg_len >= off + 10 {
                let p = u64::from_le_bytes([
                    a[off],
                    a[off + 1],
                    a[off + 2],
                    a[off + 3],
                    a[off + 4],
                    a[off + 5],
                    a[off + 6],
                    a[off + 7],
                ]);
                let c = u16::from_le_bytes([a[off + 8], a[off + 9]]) as usize;
                (p as *mut u8, c)
            } else {
                (core::ptr::null_mut(), 0)
            };

            // The arena gates a rebind on a strictly higher revision.
            // Without a caller-supplied revision, a replace request
            // advances past the current one and a plain bind does not,
            // which is what makes `flags` mean what the contract says.
            let existing = live_slot(s, path).map(|(_, rev)| rev);
            let revision = match existing {
                Some(rev) => {
                    if flags & 1 == 0 {
                        return E_EXIST;
                    }
                    rev.wrapping_add(1)
                }
                None => 1,
            };

            match s.bindings.bind(&[], path, target, kind, revision) {
                Ok(_) => {
                    write_fence_out(s, fence_ptr, fence_cap);
                    let k = if existing.is_some() {
                        super::change_wire::KIND_MODIFIED
                    } else {
                        super::change_wire::KIND_ADDED
                    };
                    // Copy the key and value out before notifying: the
                    // borrow of `arg` cannot outlive the &mut on state
                    // that the push needs.
                    let mut kb = [0u8; super::limits::MAX_PATH];
                    let mut vb = [0u8; super::limits::MAX_OBJECT_ID];
                    kb[..path.len()].copy_from_slice(path);
                    vb[..target.len()].copy_from_slice(target);
                    let (klen, vlen) = (path.len(), target.len());
                    let sys = &*s.syscalls;
                    notify_change(s, sys, k, &kb[..klen], &vb[..vlen]);
                    0
                }
                Err(super::state::ApplyError::KeyTooLong) => E_INVAL,
                Err(_) => E_EXIST,
            }
        }

        NS_OP_DELETE => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let a = core::slice::from_raw_parts(arg, arg_len);
            let path_len = u16::from_le_bytes([a[0], a[1]]) as usize;
            if arg_len < 2 + path_len {
                return E_INVAL;
            }
            let path = &a[2..2 + path_len];
            let rev = match live_slot(s, path) {
                Some((_, rev)) => rev,
                None => return E_NOENT,
            };
            match s.bindings.tombstone(&[], path, rev.wrapping_add(1)) {
                Ok(_) => {
                    let mut kb = [0u8; super::limits::MAX_PATH];
                    kb[..path.len()].copy_from_slice(path);
                    let klen = path.len();
                    let sys = &*s.syscalls;
                    notify_change(s, sys, super::change_wire::KIND_DELETED, &kb[..klen], &[]);
                    0
                }
                Err(super::state::ApplyError::KeyTooLong) => E_INVAL,
                Err(_) => E_NOENT,
            }
        }

        // [from_len u16][from][to_len u16][to]
        // [fence_out_ptr u64][fence_out_cap u16]
        NS_OP_RENAME => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let a = core::slice::from_raw_parts(arg, arg_len);
            let from_len = u16::from_le_bytes([a[0], a[1]]) as usize;
            let mut off = 2usize;
            if arg_len < off + from_len + 2 {
                return E_INVAL;
            }
            let from = &a[off..off + from_len];
            off += from_len;
            let to_len = u16::from_le_bytes([a[off], a[off + 1]]) as usize;
            off += 2;
            if arg_len < off + to_len {
                return E_INVAL;
            }
            let to = &a[off..off + to_len];
            off += to_len;
            let (fence_ptr, fence_cap) = read_fence_out(a, off);

            // Rename is a move, so the change stream carries it as the
            // two events a consumer's table has to apply: the old key
            // is gone and the new one exists. Collapsing it into one
            // event would leave every consumer holding a stale entry
            // under the old name.
            let Some((idx, rev)) = live_slot(s, from) else {
                return E_NOENT;
            };
            if live_slot(s, to).is_some() {
                return E_EXIST;
            }
            let mut vb = [0u8; super::limits::MAX_OBJECT_ID];
            let mut vlen = 0usize;
            if let Some(slot) = s.bindings.slot_ref(idx as usize) {
                let oid = slot.object_id();
                vlen = oid.len();
                vb[..vlen].copy_from_slice(oid);
            }
            match s.bindings.rename(&[], from, to, rev.wrapping_add(1)) {
                Ok(_) => {
                    write_fence_out(s, fence_ptr, fence_cap);
                    let mut fb = [0u8; super::limits::MAX_PATH];
                    let mut tb = [0u8; super::limits::MAX_PATH];
                    fb[..from.len()].copy_from_slice(from);
                    tb[..to.len()].copy_from_slice(to);
                    let (flen, tlen) = (from.len(), to.len());
                    let sys = &*s.syscalls;
                    notify_change(s, sys, super::change_wire::KIND_DELETED, &fb[..flen], &[]);
                    notify_change(
                        s,
                        sys,
                        super::change_wire::KIND_ADDED,
                        &tb[..tlen],
                        &vb[..vlen],
                    );
                    0
                }
                Err(super::state::ApplyError::KeyTooLong) => E_INVAL,
                Err(super::state::ApplyError::DestinationOccupied) => E_EXIST,
                Err(_) => E_NOENT,
            }
        }

        // [prefix_len u16][prefix][sink_chan u32][flags u8]
        //
        // Returns a subscription handle. `flags` bit 0 asks for the
        // current listing as synthesised Added events; fluxor's own
        // `table_consumer` core leaves it clear and takes the snapshot
        // through CHANGES(since=0) instead, so cold start and LOST
        // recovery run the same code. Both are supported: refusing the
        // flag would make this provider the odd one out.
        NS_OP_SUBSCRIBE => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let a = core::slice::from_raw_parts(arg, arg_len);
            let plen = u16::from_le_bytes([a[0], a[1]]) as usize;
            if arg_len < 2 + plen + 5 || plen > super::limits::MAX_PATH {
                return E_INVAL;
            }
            let prefix = &a[2..2 + plen];
            let off = 2 + plen;
            let sink = u32::from_le_bytes([a[off], a[off + 1], a[off + 2], a[off + 3]]) as i32;
            let flags = a[off + 4];

            let Some(idx) = (0..NS_SUB_MAX).find(|&i| s.subs[i].in_use == 0) else {
                return E_MFILE;
            };
            let mut pb = [0u8; super::limits::MAX_PATH];
            pb[..plen].copy_from_slice(prefix);
            s.subs[idx].prefix[..plen].copy_from_slice(prefix);
            s.subs[idx].prefix_len = plen as u16;
            s.subs[idx].sink_chan = sink;
            s.subs[idx].sequence = 0;
            s.subs[idx].lost_pending = 0;
            s.subs[idx].in_use = 1;

            if flags & 1 != 0 {
                // Synthesise the current listing as Added events, in
                // slot order. Bounded by the arena, like LIST.
                let sys = &*s.syscalls;
                for i in 0..s.bindings.capacity() {
                    let Some(slot) = s.bindings.slot_ref(i) else {
                        continue;
                    };
                    if !slot.occupied
                        || slot.kind == super::state::KIND_TOMBSTONE
                        || slot.path_len == 0
                    {
                        continue;
                    }
                    let mut kb = [0u8; super::limits::MAX_PATH];
                    let mut vb = [0u8; super::limits::MAX_OBJECT_ID];
                    let (k, v) = (slot.path(), slot.object_id());
                    let (klen, vlen) = (k.len(), v.len());
                    kb[..klen].copy_from_slice(k);
                    vb[..vlen].copy_from_slice(v);
                    let rev = slot.change_rev;
                    if !super::change_wire::under_prefix(&kb[..klen], &pb[..plen]) {
                        continue;
                    }
                    push_to_sub(
                        s,
                        sys,
                        idx,
                        rev,
                        super::change_wire::KIND_ADDED,
                        &kb[..klen],
                        &vb[..vlen],
                    );
                }
            }
            SUB_HANDLE_BASE + idx as i32
        }

        // [prefix_len u16][prefix][since u64][out_ptr u64][out_cap u32]
        // [fence_out_ptr u64][fence_out_cap u16]
        //
        // The synchronous dual of SUBSCRIBE: "what changed under
        // `prefix` since revision `since`?". `since = 0` is the full
        // current snapshot as Added records — the relist a consumer
        // performs on cold start and after a LOST.
        NS_OP_CHANGES => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let a = core::slice::from_raw_parts(arg, arg_len);
            let plen = u16::from_le_bytes([a[0], a[1]]) as usize;
            let mut off = 2usize;
            if arg_len < off + plen + 8 + 8 + 4 {
                return E_INVAL;
            }
            let mut pb = [0u8; super::limits::MAX_PATH];
            if plen > super::limits::MAX_PATH {
                return E_INVAL;
            }
            pb[..plen].copy_from_slice(&a[off..off + plen]);
            off += plen;
            let since = u64::from_le_bytes([
                a[off],
                a[off + 1],
                a[off + 2],
                a[off + 3],
                a[off + 4],
                a[off + 5],
                a[off + 6],
                a[off + 7],
            ]);
            off += 8;
            let out_ptr = u64::from_le_bytes([
                a[off],
                a[off + 1],
                a[off + 2],
                a[off + 3],
                a[off + 4],
                a[off + 5],
                a[off + 6],
                a[off + 7],
            ]) as *mut u8;
            off += 8;
            let out_cap = u32::from_le_bytes([a[off], a[off + 1], a[off + 2], a[off + 3]]) as usize;
            off += 4;
            let (fence_ptr, fence_cap) = read_fence_out(a, off);
            if out_ptr.is_null() || out_cap < super::change_wire::CHANGES_HEADER {
                return E_INVAL;
            }
            let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);

            // A window we can no longer account for is answered LOST,
            // never with a silently short one. `since > change_rev` is
            // a client ahead of us — also a relist, since we cannot
            // prove what it missed.
            let head = s.bindings.change_seq();
            // The arena is a hot cache, so a window is only
            // answerable while the evidence is still resident. Below
            // the horizon — a slot evicted, a tombstone compacted
            // away — the honest answer is LOST, because a short
            // window that looked complete is exactly what a
            // level-triggered consumer cannot detect.
            let horizon = s.bindings.change_horizon();
            if (since != 0 && since < horizon) || since > head {
                out[0] = super::change_wire::STATUS_LOST;
                out[1..5].copy_from_slice(&0u32.to_le_bytes());
                write_view_fence_out(&pb[..plen], head, fence_ptr, fence_cap);
                return super::change_wire::CHANGES_HEADER as i32;
            }

            let mut n = super::change_wire::CHANGES_HEADER;
            let mut count = 0u32;
            for i in 0..s.bindings.capacity() {
                let Some(slot) = s.bindings.slot_ref(i) else {
                    continue;
                };
                if !slot.occupied || slot.path_len == 0 {
                    continue;
                }
                // Ordered on the CHANGE stream, never on the
                // per-key pointer revision: a freshly bound path
                // starts at revision 1 no matter what else has
                // happened, so filtering on that would drop every new
                // key from a delta window.
                if since != 0 && slot.change_rev <= since {
                    continue;
                }
                let tomb = slot.kind == super::state::KIND_TOMBSTONE;
                // since = 0 is a SNAPSHOT: it answers "what is there",
                // so a tombstone — the record of an absence — has no
                // place in it. A delta window carries it as Deleted.
                if tomb && since == 0 {
                    continue;
                }
                if !super::change_wire::under_prefix(slot.path(), &pb[..plen]) {
                    continue;
                }
                let kind = if tomb {
                    super::change_wire::KIND_DELETED
                } else if since == 0 {
                    super::change_wire::KIND_ADDED
                } else {
                    super::change_wire::KIND_MODIFIED
                };
                let value: &[u8] = if tomb { &[] } else { slot.object_id() };
                match super::change_wire::encode_record(
                    &mut out[n..],
                    slot.change_rev,
                    kind,
                    slot.path(),
                    value,
                ) {
                    Some(written) => {
                        n += written;
                        count += 1;
                    }
                    // The caller's buffer is full. Answering LOST is
                    // the honest response: a truncated window that
                    // looked complete is exactly the bug this surface
                    // exists to prevent, and the contract already has
                    // a code for "relist".
                    None => {
                        out[0] = super::change_wire::STATUS_LOST;
                        out[1..5].copy_from_slice(&0u32.to_le_bytes());
                        write_view_fence_out(&pb[..plen], head, fence_ptr, fence_cap);
                        return super::change_wire::CHANGES_HEADER as i32;
                    }
                }
            }
            out[0] = super::change_wire::STATUS_EVENTS;
            out[1..5].copy_from_slice(&count.to_le_bytes());
            // The revision this window COVERS — the caller's next
            // `since`, and the point in time a snapshot manifest
            // built from it records.
            write_view_fence_out(&pb[..plen], head, fence_ptr, fence_cap);
            n as i32
        }

        // List the keys under a prefix, one page per call.
        //
        // The contract's surface is ONE FLAT KEYSPACE: `LOOKUP` above
        // resolves through `live_slot`, which hashes with an empty
        // root, so that is the root listed here too. Naming a root is
        // the channel wire's job, and a caller that wants one uses
        // it. The prefix filters the PATH, which is the only thing
        // this state can filter on.
        //
        // arg is
        //   [prefix_len u16][prefix][cursor_len u16][cursor]
        //   [out_buf u64][out_cap u32][fence_ptr u64][fence_cap u16]
        NS_OP_LIST => {
            if arg.is_null() || arg_len < 4 || s.syscalls.is_null() {
                return E_INVAL;
            }
            let a = core::slice::from_raw_parts(arg, arg_len);
            let le64 = |at: usize| -> u64 {
                let mut b = [0u8; 8];
                let mut i = 0usize;
                while i < 8 {
                    b[i] = a[at + i];
                    i += 1;
                }
                u64::from_le_bytes(b)
            };
            let prefix_len = u16::from_le_bytes([a[0], a[1]]) as usize;
            let mut p = 2usize;
            if arg_len < p + prefix_len + 2 {
                return E_INVAL;
            }
            let prefix = &a[p..p + prefix_len];
            p += prefix_len;
            let cursor_len = u16::from_le_bytes([a[p], a[p + 1]]) as usize;
            p += 2;
            // Through the output buffer is required; the fence pair after
            // it is optional, which `read_fence_out` is the reader for.
            if arg_len < p + cursor_len + 8 + 4 {
                return E_INVAL;
            }
            // The cursor is opaque to the caller and four little-endian
            // bytes to us: the position in the walk below. A shorter one
            // is read as far as it goes, and an absent one starts over.
            let mut cbytes = [0u8; 4];
            let take = cursor_len.min(4);
            let mut i = 0usize;
            while i < take {
                cbytes[i] = a[p + i];
                i += 1;
            }
            let cursor = u32::from_le_bytes(cbytes);
            p += cursor_len;
            let out_ptr = le64(p) as usize as *mut u8;
            p += 8;
            let out_cap = u32::from_le_bytes([a[p], a[p + 1], a[p + 2], a[p + 3]]) as usize;
            p += 4;
            let (fence_ptr, fence_cap) = read_fence_out(a, p);
            if out_ptr.is_null() {
                return E_INVAL;
            }
            // The trailing cursor record is mandatory, so its worst case
            // is reserved before any entry is written. Without that a
            // full buffer would carry entries and no way to continue.
            const CURSOR_RECORD_BYTES: usize = 2 + 4;
            let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
            let mut w = 0usize;
            let arena_cap = s.bindings.capacity() as u32;
            // The table the loader handed this module, checked non-null
            // above; the snapshot phase reads through it.
            let sys = &*s.syscalls;

            // The arena first, then the snapshot: the same two-phase
            // cursor space `handle_list` walks, because a key evicted to
            // the snapshot is still bound and a listing that skipped it
            // would be wrong rather than short.
            let mut resume: Option<u32> = None;
            let mut done = false;
            if cursor < arena_cap {
                match s.bindings.list_page_prefixed(
                    &[],
                    prefix,
                    cursor,
                    usize::MAX,
                    |path, kind| list_take(out, &mut w, path, kind, CURSOR_RECORD_BYTES),
                ) {
                    Some(idx) => resume = Some(idx),
                    None => {
                        if s.snap_active != 0 && s.snap_count > 0 {
                            resume = Some(arena_cap);
                        } else {
                            done = true;
                        }
                    }
                }
            } else {
                resume = Some(cursor);
            }

            if !done {
                if let Some(at) = resume {
                    if at >= arena_cap && s.snap_active != 0 {
                        let snap = super::snapshot::OpenSnapshot {
                            fd: s.snap_fd,
                            count: s.snap_count,
                            generation: s.snap_gen,
                        };
                        let ns_h = super::state::fnv1a64(&[]);
                        let mut idx = at - arena_cap;
                        let mut stalled = false;
                        while idx < s.snap_count {
                            match super::snapshot::snap_read_at(sys, &snap, idx) {
                                Some(rec) => {
                                    let path = &rec.path[..(rec.path_len as usize)
                                        .min(super::state::MAX_LIST_PATH)];
                                    // The arena's entry, live or tombstone,
                                    // is authoritative for a key it holds.
                                    let shadowed = s
                                        .bindings
                                        .lookup_hashed(
                                            rec.ns_hash,
                                            rec.path_hash,
                                            &rec.root[..rec.root_len as usize],
                                            path,
                                        )
                                        .is_some();
                                    if rec.ns_hash != ns_h
                                        || rec.path_len == 0
                                        || shadowed
                                        || !path.starts_with(prefix)
                                    {
                                        idx += 1;
                                        continue;
                                    }
                                    if !list_take(out, &mut w, path, rec.kind, CURSOR_RECORD_BYTES)
                                    {
                                        stalled = true;
                                        break;
                                    }
                                    idx += 1;
                                }
                                None => {
                                    idx = s.snap_count;
                                    break;
                                }
                            }
                        }
                        resume = if stalled || idx < s.snap_count {
                            Some(arena_cap + idx)
                        } else {
                            None
                        };
                    }
                }
            }

            let next = if done { None } else { resume };
            // A buffer that cannot hold one entry and the trailer cannot
            // be paged out of: answering an empty page with a cursor that
            // does not advance would have the caller ask forever. That is
            // the one case the contract's "page rather than refuse" has
            // no answer for, so it is refused.
            if w == 0 && next.is_some() && out_cap < CURSOR_RECORD_BYTES + 3 {
                return E_INVAL;
            }
            match next {
                Some(at) => {
                    if w + 6 > out_cap {
                        return E_INVAL;
                    }
                    out[w] = 0xFF;
                    out[w + 1] = 4;
                    out[w + 2..w + 6].copy_from_slice(&at.to_le_bytes());
                    w += 6;
                }
                None => {
                    if w + 2 > out_cap {
                        return E_INVAL;
                    }
                    out[w] = 0xFF;
                    out[w + 1] = 0;
                    w += 2;
                }
            }

            if !fence_ptr.is_null() && fence_cap >= super::abi::fence::WIRE_MAX_LEN {
                let fbuf = core::slice::from_raw_parts_mut(fence_ptr, fence_cap);
                let _ = achieved_fence(s).encode(fbuf);
            }
            w as i32
        }

        // Not implemented. For the ops `CAPS` carries a bit for, that
        // bitmap says so too; for the rest, this errno is the whole of
        // the answer. Returning it rather than a wrong answer is what
        // lets a consumer branch on it.
        _ => E_NOSYS,
    }
}
