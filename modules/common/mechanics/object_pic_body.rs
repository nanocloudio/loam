// Shared step-body implementation for object_index. Path-included
// by both the embedded PIC module (modules/object_index/mod.rs) and
// the host test harness (tests/pic_object.rs).
//
// Mirrors the structure of `namespace_pic_body.rs`: log-then-arena
// for every successful apply when a WAL is configured. The PIC
// arena holds a 64-slot hash-keyed object table; full descriptors
// stay on the WAL.

// Arena cap = total live object descriptors per PIC instance after
// WAL replay. See `namespace_pic_body.rs` for the rationale.
// ModuleState size: ObjectSlot(~48B) × 256 + 4 KiB scratch ≈ 16 KiB.
// Capacity profile — see namespace_pic_body.rs.
const ARENA_CAPACITY: usize = super::limits::OBJECT_SLOTS;
/// One read holds the largest request record, so a request arriving
/// one per buffer is never cut.
const READ_BUF: usize = super::wire::PUT_RECORD_MAX;
/// Reassembly capacity for `requests`. Sized to hold a full step's
/// budget plus one more read, so refilling never starves the step.
const REQ_ASM: usize = READ_BUF * (super::limits::OPS_PER_STEP as usize + 1);

/// Inline WAL-path buffer size; see `namespace_pic_body.rs`.
pub const WAL_PATH_BUF: usize = super::limits::WAL_PATH_BUF;

/// The object PIC answers with a 1-byte ack or an encoded get
/// response; both sit well inside a read buffer.
pub type Reply = super::reply_out::ReplyOut<READ_BUF>;

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    /// Reassembly for the `requests` byte stream. A batching producer
    /// puts several records into one read and a read can end
    /// mid-record; both are the stream behaving normally.
    pub req_asm: [u8; REQ_ASM],
    pub req_asm_len: usize,
    /// Set while walking past bytes that do not start a record. One
    /// NAK is emitted on entering that state, not one per byte.
    pub req_resyncing: u8,
    /// The answer this module owes. A channel that refuses the write
    /// leaves it owed rather than lost; no new work is taken until it
    /// lands.
    pub reply: Reply,
    pub objects: super::state::PicObjectState<ARENA_CAPACITY>,
    pub ticks: u32,
    pub ops_applied: u32,
    pub apply_errors: u32,
    pub wal_fd: i32,
    pub append_scratch: [u8; super::wal::APPEND_SCRATCH],
    /// Resumable WAL append. Owns the staged frame, so a device that
    /// answers `E_AGAIN` costs a later step rather than an operation
    /// refusal.
    pub appender: super::wal::WalAppender,
    /// A record has left `requests` and is staged for durability. It
    /// is not applied, acked, or discarded until the append resolves,
    /// and no other work is consumed meanwhile.
    pub wal_staged: u8,
    pub wal_path: [u8; WAL_PATH_BUF],
    pub wal_path_len: u16,
    /// Where the WAL's boot stands (`BOOT_*`). No `fs` call waits on the
    /// device, so opening and replaying the WAL may each take the
    /// provider several steps; the module's steps drive them, and no
    /// request is read until they are done.
    pub boot: u8,
    /// A failed boot has been reported as this module's step error.
    pub boot_reported: u8,
    /// The WAL's open (create + name fence), resumed across steps.
    pub opener: super::wal::WalOpener,
    /// The WAL's replay into the arena, resumed across steps. Its
    /// partial record lives in the appender's idle frame buffer, which
    /// no append needs until boot is done.
    pub replay: super::wal::WalReplay,
    /// Replayed records the arena refused.
    pub replay_errors: u32,
}

/// No WAL boot in progress: one is done, or none is configured.
pub const BOOT_READY: u8 = 0;
/// The WAL is being opened (created on first boot, its name fenced).
pub const BOOT_OPEN: u8 = 1;
/// The WAL is open and being replayed into the arena.
pub const BOOT_REPLAY: u8 = 2;
/// The WAL could not be opened or replayed. The step reports it once
/// as an error, then refuses every mutation: the arena carries no
/// durable backing, and an ack would claim one.
pub const BOOT_FAILED: u8 = 3;

/// Replayed records handed to the arena per step. Bounds a boot step's
/// work; a long log spans more steps rather than one long one.
const WAL_REPLAY_PER_STEP: u32 = 64;

/// What a failed WAL boot reports from the step, as `module_new` used
/// to when it opened the WAL itself.
const BOOT_FAILED_RC: i32 = -3;

/// Channel-only init. No WAL — arena is the sole state and is lost
/// across module re-creation.
pub unsafe fn module_new_impl(
    in_chan: i32,
    out_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(in_chan, out_chan, state_ptr, state_size, syscalls)
}

/// WAL-backed init. Arms the WAL's boot: the steps that follow open it
/// via the fluxor `fs` contract (creating it on first boot), replay its
/// records into the arena, then leave the step body in durable-log
/// mode.
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
    begin_wal_boot(state_ptr, wal_path)
}

/// Record `wal_path` as this module's WAL and arm its boot. Nothing is
/// opened here: the open and the replay run from `module_step_impl`,
/// which reads no request until both are done. A path that does not
/// fit is refused now, since no later step could open it.
pub unsafe fn begin_wal_boot(state_ptr: *mut u8, wal_path: &[u8]) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    if wal_path.is_empty() || wal_path.len() > WAL_PATH_BUF {
        return BOOT_FAILED_RC;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    for (d, b) in s.wal_path.iter_mut().zip(wal_path.iter()) {
        *d = *b;
    }
    s.wal_path_len = wal_path.len() as u16;
    begin_wal_boot_from_state(state_ptr)
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
/// a module with no `wal_path` runs channel-only and boots at once.
/// The open and the replay run from `module_step_impl`.
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
    // The appender's tail knowledge belongs to the previous fd.
    s.appender.reset();
    s.wal_staged = 0;
    s.replay.reset();
    s.replay_errors = 0;
    s.boot_reported = 0;
    s.boot = BOOT_OPEN;
    0
}

/// Drive the WAL's open and replay one step further. True once the
/// module may take requests: the WAL is open and replayed, none is
/// configured, or the boot failed (requests are then refused, not
/// held).
unsafe fn boot(s: &mut ModuleState, sys: &super::SyscallTable) -> bool {
    if s.boot == BOOT_OPEN {
        let len = (s.wal_path_len as usize).min(WAL_PATH_BUF);
        // The same bytes on every poll: an undecided open is collected
        // only by re-asking the byte-identical request.
        let path = core::slice::from_raw_parts(s.wal_path.as_ptr(), len);
        match s.opener.poll(sys, path, true) {
            super::wal::OpenPoll::Pending => return false,
            super::wal::OpenPoll::Ready(fd) => {
                s.wal_fd = fd;
                s.replay.reset();
                s.replay_errors = 0;
                s.boot = BOOT_REPLAY;
            }
            // `NameUnfenceable` lands here too: a WAL whose name a power
            // cut can erase carries no durability claim.
            super::wal::OpenPoll::Failed(_) => {
                s.boot = BOOT_FAILED;
                return true;
            }
        }
    }
    if s.boot == BOOT_REPLAY {
        let fd = s.wal_fd;
        let scratch = s.appender.idle_buffer();
        let objects = &mut s.objects;
        let replay_errors = &mut s.replay_errors;
        let polled = s
            .replay
            .poll(sys, fd, scratch, WAL_REPLAY_PER_STEP, |payload| {
                if apply_to_arena(objects, payload).is_err() {
                    *replay_errors = replay_errors.wrapping_add(1);
                }
                true
            });
        match polled {
            super::wal::ReplayPoll::Pending => return false,
            super::wal::ReplayPoll::Done(applied) => {
                s.ops_applied = applied;
                s.apply_errors = s.replay_errors;
                s.boot = BOOT_READY;
            }
            // A log that could not be read back holds records the arena
            // lacks; mutating on top of it would ack against a state the
            // next boot does not reproduce.
            super::wal::ReplayPoll::Failed(_) => {
                let _ = super::wal::wal_close(sys, fd);
                s.wal_fd = -1;
                s.boot = BOOT_FAILED;
            }
        }
    }
    true
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
    // In-place zeroing — see namespace_pic_body.rs (stack size).
    core::ptr::write_bytes(
        core::ptr::addr_of_mut!(s.objects) as *mut u8,
        0,
        core::mem::size_of::<super::state::PicObjectState<ARENA_CAPACITY>>(),
    );
    s.ticks = 0;
    s.ops_applied = 0;
    s.apply_errors = 0;
    s.req_asm_len = 0;
    s.req_resyncing = 0;
    s.wal_fd = -1;
    s.wal_staged = 0;
    core::ptr::write_bytes(
        core::ptr::addr_of_mut!(s.appender) as *mut u8,
        0,
        core::mem::size_of::<super::wal::WalAppender>(),
    );
    s.wal_path_len = 0;
    s.boot = BOOT_READY;
    s.boot_reported = 0;
    s.replay_errors = 0;
    // Zeroed is a valid idle opener and an unstarted replay.
    core::ptr::write_bytes(
        core::ptr::addr_of_mut!(s.opener) as *mut u8,
        0,
        core::mem::size_of::<super::wal::WalOpener>(),
    );
    core::ptr::write_bytes(
        core::ptr::addr_of_mut!(s.replay) as *mut u8,
        0,
        core::mem::size_of::<super::wal::WalReplay>(),
    );
    0
}

/// Staged-record buffer. Sized by what the appender can hold, NOT by
/// `READ_BUF` — that is the channel-read chunk size, and a record
/// reassembled across chunks is legitimately larger. Undersizing here
/// refuses a record the WAL already made durable, so the requester is
/// told it failed and replay applies it anyway.
const STAGED_REC: usize = super::wal::MAX_WAL_REC;

/// Resolve the record a staged append took off `requests`. `durable`
/// licenses the arena mutation and the success ack; without it the
/// record is refused, because a refusal the requester can see is the
/// only honest answer to a durability failure.
unsafe fn resolve_staged(s: &mut ModuleState, syscalls: &super::SyscallTable, durable: bool) {
    s.wal_staged = 0;
    let mut payload = [0u8; STAGED_REC];
    let n = s.appender.payload().len();
    let ok = durable && n != 0 && n <= payload.len();
    if ok {
        payload[..n].copy_from_slice(s.appender.payload());
    }
    let op = if ok {
        super::wire::peek_opcode(&payload[..n])
    } else {
        None
    };
    let outcome = match (op, ok) {
        (Some(op), true) => match apply_to_arena(&mut s.objects, &payload[..n]) {
            Ok(_) => Ok(op),
            Err(fault) => Err(fault),
        },
        _ => Err(ApplyFault::Rejected),
    };
    let ack_byte = match outcome {
        Ok(op) => {
            s.ops_applied = s.ops_applied.wrapping_add(1);
            op
        }
        Err(fault) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            reply_for(fault)
        }
    };
    let _ = s
        .reply
        .send(syscalls.channel_write, s.out_chan, &[ack_byte]);
}

/// The one-byte answer a fault produces on `responses`.
pub(super) fn reply_for(fault: ApplyFault) -> u8 {
    match fault {
        ApplyFault::Absent => super::wire::ACK_ABSENT,
        ApplyFault::Quota => super::wire::ACK_QUOTA,
        ApplyFault::Rejected => 0xFF,
    }
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

    // The WAL's boot owns the step until it is done: a request taken
    // before the replay finishes would be applied against an arena
    // still missing the log's state. Nothing is read meanwhile.
    if !boot(s, syscalls) {
        return 0;
    }
    if s.boot == BOOT_FAILED && s.boot_reported == 0 {
        s.boot_reported = 1;
        return BOOT_FAILED_RC;
    }

    // An owed answer owns the step until the channel takes it. The
    // record it answers has already left `requests` and changed the
    // arena, so letting new work overtake it would leave a requester
    // with a mutation and no reply.
    if !s.reply.flush(syscalls.channel_write, s.out_chan) {
        return 0;
    }

    // A staged append owns the step until it resolves: the record it
    // describes has left `requests` and no other work may overtake
    // it, reuse the frame buffer, or acknowledge ahead of it.
    if s.wal_staged != 0 {
        match s.appender.poll(syscalls, s.wal_fd) {
            super::wal::AppendState::Pending => return 0,
            super::wal::AppendState::Durable => resolve_staged(s, syscalls, true),
            _ => resolve_staged(s, syscalls, false),
        }
    }

    // `requests` is a byte stream. Refill a reassembly buffer, then
    // take whole records off the front of it — up to the step budget,
    // leaving the rest for the next step rather than discarding it.
    if s.in_chan >= 0 {
        loop {
            let space = REQ_ASM - s.req_asm_len;
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
            s.req_asm_len += n as usize;
        }
    }

    let mut handled: u32 = 0;
    let mut req_off: usize = 0;
    while handled < super::limits::OPS_PER_STEP {
        // An answer still owed for the previous record means the
        // channel is not draining. Taking another record would either
        // overwrite that answer or mutate the arena for a request that
        // cannot be answered either.
        if s.reply.owed() {
            break;
        }
        let rec_len = match super::wire::request_record_len(&s.req_asm[req_off..s.req_asm_len]) {
            Ok(Some(len)) => len,
            // Nothing, or an incomplete tail: keep it and wait.
            Ok(None) => break,
            // Not a request record. NAK the episode once and skip a
            // byte to resync — a byte stream offers no frame to skip
            // to, and silence would leave the producer waiting.
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                if s.req_resyncing == 0 {
                    s.req_resyncing = 1;
                    let nak = [0xFFu8];
                    let _ = s.reply.send(syscalls.channel_write, s.out_chan, &nak);
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

        let op = match super::wire::peek_opcode(bytes) {
            Some(
                op @ (super::wire::OP_OBJ_PUT
                | super::wire::OP_OBJ_UPDATE
                | super::wire::OP_OBJ_REMOVE
                | super::wire::OP_OBJ_GET
                | super::wire::OP_OBJ_SCAN),
            ) => op,
            _ => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                let nak = [0xFFu8];
                let _ = s.reply.send(syscalls.channel_write, s.out_chan, &nak);
                handled = handled.wrapping_add(1);
                continue;
            }
        };

        // Read ops bypass the WAL + arena-mutation flow.
        if op == super::wire::OP_OBJ_GET {
            handle_get(s, syscalls, bytes);
            handled = handled.wrapping_add(1);
            continue;
        }
        if op == super::wire::OP_OBJ_SCAN {
            handle_scan(s, syscalls, bytes);
            handled = handled.wrapping_add(1);
            continue;
        }

        // A WAL that was configured and is now gone is not the same
        // as never having had one: the arena would mutate with no
        // durable backing while the ack claimed otherwise. Refuse
        // until an open succeeds again.
        if s.wal_fd < 0 && s.wal_path_len > 0 {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            let nak = [0xFFu8];
            let _ = s.reply.send(syscalls.channel_write, s.out_chan, &nak);
            continue;
        }

        // Durability first: the append is staged, not completed here.
        // A device that has accepted the frame but not finished it
        // leaves the record staged and the step returns; the arena
        // and the ack wait for the fence.
        if s.wal_fd >= 0 {
            match s.appender.begin(syscalls, s.wal_fd, bytes) {
                super::wal::AppendState::Durable => {}
                super::wal::AppendState::Pending => {
                    s.wal_staged = 1;
                    break;
                }
                _ => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    let nak = [0xFFu8];
                    let _ = s.reply.send(syscalls.channel_write, s.out_chan, &nak);
                    handled = handled.wrapping_add(1);
                    continue;
                }
            }
        }

        match apply_to_arena(&mut s.objects, bytes) {
            Ok(_) => {
                s.ops_applied = s.ops_applied.wrapping_add(1);
                let _ = s.reply.send(syscalls.channel_write, s.out_chan, &[op]);
            }
            Err(fault) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                let nak = [reply_for(fault)];
                let _ = s.reply.send(syscalls.channel_write, s.out_chan, &nak);
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
    0
}

/// Serve an OP_OBJ_GET request: look up the slot by id, encode
/// Found/NotFound, write to out_chan. No WAL touch, no arena
/// mutation.
unsafe fn handle_get(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let id = match super::wire::decode_get_req(bytes) {
        Ok(id) => id,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            let nak = [0xFFu8];
            let _ = s.reply.send(syscalls.channel_write, s.out_chan, &nak);
            return;
        }
    };
    let slot = s.objects.lookup(id);
    let n = match slot {
        Some(slot) => super::wire::encode_get_found(
            &mut s.append_scratch,
            slot.size_bytes,
            slot.revision,
            slot.data_class,
            slot.replica_count,
            slot.erasure,
        ),
        None => super::wire::encode_get_not_found(&mut s.append_scratch),
    };
    match n {
        Ok(n) => {
            let _ = s
                .reply
                .send(syscalls.channel_write, s.out_chan, &s.append_scratch[..n]);
        }
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            let nak = [0xFFu8];
            let _ = s.reply.send(syscalls.channel_write, s.out_chan, &nak);
        }
    }
}

/// Serve an OP_OBJ_SCAN request: one bounded page of the descriptor
/// inventory. No WAL touch, no arena mutation.
unsafe fn handle_scan(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let (cursor, max) = match super::wire::decode_scan_req(bytes) {
        Ok(v) => v,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            let nak = [0xFFu8];
            let _ = s.reply.send(syscalls.channel_write, s.out_chan, &nak);
            return;
        }
    };
    let take = (max as usize).min(super::wire::MAX_OBJ_SCAN);
    let mut digests = [[0u8; super::wire::DIGEST_LEN]; super::wire::MAX_OBJ_SCAN];
    let (next, count) = s.objects.scan(cursor, &mut digests[..take]);
    match super::wire::encode_scan_resp(&mut s.append_scratch, next, &digests[..count]) {
        Ok(n) => {
            let _ = s
                .reply
                .send(syscalls.channel_write, s.out_chan, &s.append_scratch[..n]);
        }
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            let nak = [0xFFu8];
            let _ = s.reply.send(syscalls.channel_write, s.out_chan, &nak);
        }
    }
}

/// Why an apply produced no state change. `Absent` is a definite
/// answer about the arena; `Rejected` means the record could not be
/// applied at all, and a caller must not read absence into it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ApplyFault {
    Absent,
    /// The root's quota would be crossed. Carried separately all the
    /// way out so the gateway can answer 507 rather than a generic
    /// failure — see `loam_object_wire::ACK_QUOTA`.
    Quota,
    Rejected,
}

pub(super) fn apply_to_arena(
    objects: &mut super::state::PicObjectState<ARENA_CAPACITY>,
    payload: &[u8],
) -> Result<u8, ApplyFault> {
    let op = super::wire::peek_opcode(payload).ok_or(ApplyFault::Rejected)?;
    match op {
        super::wire::OP_OBJ_PUT => {
            let p = super::wire::decode_put(payload).map_err(|_| ApplyFault::Rejected)?;
            objects
                .put_new(
                    p.id,
                    p.namespace,
                    p.size_bytes,
                    p.revision,
                    p.data_class,
                    p.replica_count,
                    p.erasure,
                )
                .map_err(|e| match e {
                    super::state::ApplyError::QuotaExceeded => ApplyFault::Quota,
                    _ => ApplyFault::Rejected,
                })?;
            Ok(super::wire::OP_OBJ_PUT)
        }
        super::wire::OP_OBJ_UPDATE => {
            let p = super::wire::decode_update(payload).map_err(|_| ApplyFault::Rejected)?;
            objects
                .update(
                    p.id,
                    p.namespace,
                    p.size_bytes,
                    p.revision,
                    p.data_class,
                    p.replica_count,
                    p.erasure,
                )
                .map_err(|_| ApplyFault::Rejected)?;
            Ok(super::wire::OP_OBJ_UPDATE)
        }
        super::wire::OP_OBJ_REMOVE => {
            let d = super::wire::decode_remove(payload).map_err(|_| ApplyFault::Rejected)?;
            objects.remove(d.id).map_err(|e| match e {
                super::state::ApplyError::NotPresent => ApplyFault::Absent,
                _ => ApplyFault::Rejected,
            })?;
            Ok(super::wire::OP_OBJ_REMOVE)
        }
        _ => Err(ApplyFault::Rejected),
    }
}
