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
// ModuleState size at this cap: BindingSlot(~40B) × 256 + 4 KiB
// append scratch + headers ≈ 14 KiB.
// Capacity profile: bare-metal PIC builds (target_os = "none")
// keep the bounded embedded arena; host-runtime builds (the
// loam-server standalone service, host tests) get service-class
// capacity. A per-silicon fmod capacity knob is tracked in RFC
// 0004 — modules loaded on the host profile today still carry the
// embedded profile.
#[cfg(target_os = "none")]
const ARENA_CAPACITY: usize = 256;
#[cfg(not(target_os = "none"))]
const ARENA_CAPACITY: usize = 8192;
const MAX_OPS_PER_STEP: u32 = 4;
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
const REQ_ASM: usize = READ_BUF * (MAX_OPS_PER_STEP as usize + 1);

/// Inline WAL-path buffer in `ModuleState`. The TLV parameter
/// handler populates this; the PIC mod.rs uses it to drive
/// `open_and_replay_wal` after init. 256 bytes covers any
/// reasonable filesystem path with headroom.
pub const WAL_PATH_BUF: usize = 256;

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
    pub bindings: super::state::PicNamespaceState<ARENA_CAPACITY>,
    pub ticks: u32,
    pub ops_applied: u32,
    pub apply_errors: u32,
    /// `fs`-contract fd for the WAL, or -1 in channel-only mode. When
    /// set, each successful apply path writes a record + fsyncs before
    /// the arena mutates.
    pub wal_fd: i32,
    /// Per-record scratch reused across appends. Sized to hold the
    /// 8-byte header plus the largest legal payload — avoids any
    /// runtime allocation under no_std.
    pub append_scratch: [u8; super::wal::APPEND_SCRATCH],
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
}

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
    if let Some((snap, slot)) = super::snapshot::snap_open_best(sys, wal_path) {
        s.snap_active = 1;
        s.snap_slot = slot;
        s.snap_fd = snap.fd;
        s.snap_count = snap.count;
        s.snap_gen = snap.generation;
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
    if state_ptr.is_null() || params.is_null() || params_len == 0 {
        return;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    let is_tlv = params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
    if is_tlv {
        // Scan the TLV stream for tag=1 (wal_path). Entries are
        // `[tag:u8][len:u8][bytes:len]`; `0xFF` is the end marker.
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
    // Raw-bytes fallback.
    let copy = params_len.min(WAL_PATH_BUF);
    let src = params;
    let mut i = 0usize;
    while i < copy {
        s.wal_path[i] = *src.add(i);
        i += 1;
    }
    s.wal_path_len = copy as u16;
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
    s.snap_fd = -1;
    s.cmp_writer_fd = -1;
    s.wal_path_len = 0;
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
    while handled < MAX_OPS_PER_STEP {
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
                | super::wire::OP_REFERENCED),
            ) => op,
            _ => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                respond(s, syscalls, 0xFF);
                handled = handled.wrapping_add(1);
                continue;
            }
        };

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
        // Propose = [0x10][plane=0x01][corr u32=0][len u16][inner].
        if s.replicated != 0 {
            let hdr = 8usize;
            if hdr + bytes.len() <= s.append_scratch.len() && bytes.len() <= u16::MAX as usize {
                s.append_scratch[0] = 0x10; // OP_PROPOSE (loam_decision_wire)
                s.append_scratch[1] = 0x01; // PLANE_NAMESPACE
                s.append_scratch[2..6].copy_from_slice(&0u32.to_le_bytes());
                s.append_scratch[6..8].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
                s.append_scratch[hdr..hdr + bytes.len()].copy_from_slice(bytes);
                let n = hdr + bytes.len();
                let wrote =
                    (syscalls.channel_write)(s.metadata_ops_chan, s.append_scratch.as_ptr(), n);
                if wrote != n as i32 {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    respond(s, syscalls, 0xFF);
                } else {
                    s.outstanding = s.outstanding.wrapping_add(1);
                }
            } else {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                respond(s, syscalls, 0xFF);
            }
            handled = handled.wrapping_add(1);
            continue;
        }

        // Durability first: a successful arena mutation must have a
        // durable backing by the time we ack. If WAL append fails,
        // skip the arena and nak; the producer's retry will land
        // clean once the device is happy.
        if s.wal_fd >= 0 {
            let wal_rc = super::wal::wal_append(syscalls, s.wal_fd, bytes, &mut s.append_scratch);
            if wal_rc.is_err() {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                respond(s, syscalls, 0xFF);
                handled = handled.wrapping_add(1);
                continue;
            }
        }

        match apply_op(s, syscalls, bytes) {
            Ok(_) => {
                s.ops_applied = s.ops_applied.wrapping_add(1);
                respond(s, syscalls, op);
            }
            Err(_) => {
                // Arena rejected (e.g. AlreadyBound) — the WAL
                // already has the record. On replay the same
                // arena rejection happens; net state is consistent.
                s.apply_errors = s.apply_errors.wrapping_add(1);
                respond(s, syscalls, 0xFF);
            }
        }
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
    // Walk complete records. Committed = [0x11][plane][corr u32]
    // [quorum u8][epoch u64][len u16 @15..17][inner]; marker = [0x13].
    let mut off = 0usize;
    while off < s.cmt_asm_len {
        let b0 = s.cmt_asm[off];
        if b0 == 0x13 {
            s.read_ready = 1;
            off += 1;
            continue;
        }
        if b0 != 0x11 {
            // Unknown/garbage byte: skip one to resync.
            s.apply_errors = s.apply_errors.wrapping_add(1);
            off += 1;
            continue;
        }
        if s.cmt_asm_len - off < 17 {
            break; // partial header: wait for more bytes
        }
        let inner_len = u16::from_le_bytes([s.cmt_asm[off + 15], s.cmt_asm[off + 16]]) as usize;
        let rec_len = 17 + inner_len;
        if s.cmt_asm_len - off < rec_len {
            break; // partial record
        }
        let plane = s.cmt_asm[off + 1];
        if plane != 0x01 {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            off += rec_len;
            continue;
        }
        // Copy the inner out so the arena/WAL calls don't alias cmt_asm.
        let mut inner_buf = [0u8; READ_BUF];
        if inner_len > inner_buf.len() {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            off += rec_len;
            continue;
        }
        inner_buf[..inner_len].copy_from_slice(&s.cmt_asm[off + 17..off + 17 + inner_len]);
        let inner = &inner_buf[..inner_len];
        if s.wal_fd >= 0 {
            let _ = super::wal::wal_append(syscalls, s.wal_fd, inner, &mut s.append_scratch);
        }
        let live = s.outstanding > 0;
        match apply_op(s, syscalls, inner) {
            Ok(op) => {
                s.ops_applied = s.ops_applied.wrapping_add(1);
                if live {
                    s.outstanding -= 1;
                    respond(s, syscalls, op);
                }
            }
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                if live {
                    s.outstanding -= 1;
                    respond(s, syscalls, 0xFF);
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
    let arena_hit = s.bindings.lookup_hashed(ns_h, p_h).copied();
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
                let _ = (syscalls.channel_write)(s.out_chan, s.append_scratch.as_ptr(), n);
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
                            .lookup_hashed(rec.ns_hash, rec.path_hash)
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
                let _ = (syscalls.channel_write)(s.out_chan, s.append_scratch.as_ptr(), n);
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
        let _ = (syscalls.channel_write)(s.out_chan, out.as_ptr(), out.len());
    }
}

/// Apply one op with snapshot semantics wrapped around the pure
/// arena apply:
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
) -> Result<u8, ()> {
    let op = super::wire::peek_opcode(payload).ok_or(())?;
    if op == super::wire::OP_UNBIND && s.snap_active != 0 {
        let dec = super::wire::decode_unbind(payload).map_err(|_| ())?;
        let (ns_h, p_h) = super::state::key_hash(dec.namespace_root, dec.path);
        let revision = match s.bindings.lookup_hashed(ns_h, p_h) {
            Some(slot) if slot.kind == super::state::KIND_TOMBSTONE => return Err(()),
            Some(slot) => slot.revision,
            None => {
                let snap = super::snapshot::OpenSnapshot {
                    fd: s.snap_fd,
                    count: s.snap_count,
                    generation: s.snap_gen,
                };
                match super::snapshot::snap_search(syscalls, &snap, ns_h, p_h) {
                    Some(rec) => rec.revision,
                    None => return Err(()),
                }
            }
        };
        let mut res = s.bindings.tombstone(dec.namespace_root, dec.path, revision);
        if res == Err(super::state::ApplyError::OutOfCapacity) && s.bindings.evict_one_snapshotted()
        {
            s.evictions = s.evictions.wrapping_add(1);
            res = s.bindings.tombstone(dec.namespace_root, dec.path, revision);
        }
        return res.map(|_| super::wire::OP_UNBIND).map_err(|_| ());
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
                return apply_to_arena(&mut s.bindings, payload).map_err(|_| ());
            }
            Err(())
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
                    if let Ok(new_fd) = super::wal::wal_rotate(
                        syscalls,
                        s.wal_fd,
                        &s.wal_path[..s.wal_path_len as usize],
                    ) {
                        s.wal_fd = new_fd;
                    } else {
                        s.wal_fd = -1;
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
// What is implemented is exactly what `CAPS` reports. The arena holds
// binding paths inline, so the read surface and BIND/DELETE are real;
// SUBSCRIBE, CHANGES and RENAME are not implemented here and their
// capability bits stay clear, which is the two-step procedure the
// contract prescribes rather than a silent gap.

/// `storage.namespace` contract id.
pub const CONTRACT_STORAGE_NAMESPACE: u32 = 0x0013;

pub const NS_OP_LOOKUP: u32 = 0x1300;
pub const NS_OP_STAT: u32 = 0x1301;
pub const NS_OP_LIST: u32 = 0x1302;
pub const NS_OP_DELETE: u32 = 0x1304;
pub const NS_OP_CLOSE: u32 = 0x1306;
pub const NS_OP_BIND: u32 = 0x1308;
pub const NS_OP_CAPS: u32 = 0x13FF;

/// Capability bits this provider sets. BIND and DELETE only: the ops
/// below them are the mandatory read surface, and the bits left clear
/// are ops a caller must not assume.
pub const NS_CAPS: u32 = (1 << 0) | (1 << 2);

const E_INVAL: i32 = -22;
const E_NOENT: i32 = -2;
const E_NOSYS: i32 = -38;
const E_EXIST: i32 = -17;
const E_MFILE: i32 = -24;

/// The strongest fence this provider can honestly claim right now.
///
/// Replicated mode commits through a quorum, so a bind that has
/// round-tripped is `ReplicatedDurable`. Single-node with a WAL is
/// `LocalDurable`. Without a WAL there is no durability to claim and
/// the honest answer is `Volatile` — the whole point of the fence axis
/// is that a consumer can tell those apart.
unsafe fn achieved_fence(s: &ModuleState) -> super::abi::fence::Fence {
    if s.replicated != 0 {
        super::abi::fence::Fence::ReplicatedDurable {
            source: [0u8; 16],
            commit_index: s.ops_applied as u64,
            epoch: 0,
            quorum: 0,
            witness: [0u8; 32],
        }
    } else if s.wal_fd >= 0 {
        super::abi::fence::Fence::LocalDurable { device_id: 0 }
    } else {
        super::abi::fence::Fence::Volatile
    }
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
unsafe fn respond(s: &ModuleState, syscalls: &super::SyscallTable, byte: u8) {
    if s.out_chan < 0 {
        return;
    }
    let b = [byte];
    let _ = (syscalls.channel_write)(s.out_chan, b.as_ptr(), 1);
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
            if slot.occupied && slot.matches(ns_h, p_h) && slot.kind != super::state::KIND_TOMBSTONE
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

        NS_OP_CLOSE => {
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
                    0
                }
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
                Ok(_) => 0,
                Err(_) => E_NOENT,
            }
        }

        // Not implemented, and `CAPS` says so. Returning ENOSYS rather
        // than a wrong answer is what lets a consumer branch on it.
        _ => E_NOSYS,
    }
}
