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
#[cfg(target_os = "none")]
const ARENA_CAPACITY: usize = 256;
#[cfg(not(target_os = "none"))]
const ARENA_CAPACITY: usize = 8192;
const MAX_OPS_PER_STEP: u32 = 4;
const READ_BUF: usize = 1024;
/// Reassembly capacity for `requests`. Sized to hold a full step's
/// budget plus one more read, so refilling never starves the step.
const REQ_ASM: usize = READ_BUF * (MAX_OPS_PER_STEP as usize + 1);

/// Inline WAL-path buffer size; see `namespace_pic_body.rs`.
pub const WAL_PATH_BUF: usize = 256;

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
    pub objects: super::state::PicObjectState<ARENA_CAPACITY>,
    pub ticks: u32,
    pub ops_applied: u32,
    pub apply_errors: u32,
    pub wal_fd: i32,
    pub append_scratch: [u8; super::wal::APPEND_SCRATCH],
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
    s.wal_path_len = 0;
    0
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
    while handled < MAX_OPS_PER_STEP {
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
                    let _ = (syscalls.channel_write)(s.out_chan, nak.as_ptr(), 1);
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
                | super::wire::OP_OBJ_GET),
            ) => op,
            _ => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                let nak = [0xFFu8];
                let _ = (syscalls.channel_write)(s.out_chan, nak.as_ptr(), 1);
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

        if s.wal_fd >= 0 {
            let wal_rc = super::wal::wal_append(syscalls, s.wal_fd, bytes, &mut s.append_scratch);
            if wal_rc.is_err() {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                let nak = [0xFFu8];
                let _ = (syscalls.channel_write)(s.out_chan, nak.as_ptr(), 1);
                handled = handled.wrapping_add(1);
                continue;
            }
        }

        match apply_to_arena(&mut s.objects, bytes) {
            Ok(_) => {
                s.ops_applied = s.ops_applied.wrapping_add(1);
                let ack = [op];
                let wrote = (syscalls.channel_write)(s.out_chan, ack.as_ptr(), 1);
                if wrote < 0 {
                    break;
                }
            }
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                let nak = [0xFFu8];
                let _ = (syscalls.channel_write)(s.out_chan, nak.as_ptr(), 1);
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
            let _ = (syscalls.channel_write)(s.out_chan, nak.as_ptr(), 1);
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
            let _ = (syscalls.channel_write)(s.out_chan, s.append_scratch.as_ptr(), n);
        }
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            let nak = [0xFFu8];
            let _ = (syscalls.channel_write)(s.out_chan, nak.as_ptr(), 1);
        }
    }
}

pub(super) fn apply_to_arena(
    objects: &mut super::state::PicObjectState<ARENA_CAPACITY>,
    payload: &[u8],
) -> Result<u8, ()> {
    let op = super::wire::peek_opcode(payload).ok_or(())?;
    match op {
        super::wire::OP_OBJ_PUT => {
            let p = super::wire::decode_put(payload).map_err(|_| ())?;
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
                .map_err(|_| ())?;
            Ok(super::wire::OP_OBJ_PUT)
        }
        super::wire::OP_OBJ_UPDATE => {
            let p = super::wire::decode_update(payload).map_err(|_| ())?;
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
                .map_err(|_| ())?;
            Ok(super::wire::OP_OBJ_UPDATE)
        }
        super::wire::OP_OBJ_REMOVE => {
            let d = super::wire::decode_remove(payload).map_err(|_| ())?;
            objects.remove(d.id).map_err(|_| ())?;
            Ok(super::wire::OP_OBJ_REMOVE)
        }
        _ => Err(()),
    }
}
