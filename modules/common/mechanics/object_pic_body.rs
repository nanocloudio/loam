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
const READ_BUF: usize = 1024;
/// Reassembly capacity for `requests`. Sized to hold a full step's
/// budget plus one more read, so refilling never starves the step.
const REQ_ASM: usize = READ_BUF * (super::limits::OPS_PER_STEP as usize + 1);

/// Inline WAL-path buffer size; see `namespace_pic_body.rs`.
pub const WAL_PATH_BUF: usize = 256;

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
}

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

/// WAL-backed init. Opens a pre-existing WAL via the fluxor `fs`
/// contract, replays its records into the arena, then leaves the
/// step body in durable-log mode.
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

/// See `namespace_pic_body::open_and_replay_wal`.
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
        Err(_) => return -3,
    };
    s.wal_fd = fd;
    // The appender's tail knowledge belongs to the previous fd.
    s.appender.reset();
    s.wal_staged = 0;

    let mut scratch = [0u8; super::wal::MAX_WAL_REC];
    let objects_ptr: *mut super::state::PicObjectState<ARENA_CAPACITY> = &mut s.objects;
    let mut replay_errors: u32 = 0;
    let replay_rc = super::wal::wal_replay(sys, fd, &mut scratch, |payload| {
        let objects = &mut *objects_ptr;
        if apply_to_arena(objects, payload).is_err() {
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

/// See `namespace_pic_body::decode_wal_path_params`.
pub unsafe fn decode_wal_path_params(state_ptr: *mut u8, params: *const u8, params_len: usize) {
    if state_ptr.is_null() {
        return;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    // The TLV/raw ambiguity lives in one place — `wal_io` — so the
    // four modules that take a WAL path cannot drift apart on it.
    if let Some(n) = super::wal::decode_wal_path(params, params_len, &mut s.wal_path) {
        s.wal_path_len = n as u16;
    }
}

/// See `namespace_pic_body::open_wal_from_state`.
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
