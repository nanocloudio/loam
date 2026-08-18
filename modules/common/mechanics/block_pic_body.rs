// Shared step-body implementation for block_allocator. Path-included
// by both the embedded PIC module (modules/block_allocator/mod.rs)
// and the host test harness (tests/pic_block.rs).
//
// Same log-then-arena structure as namespace_pic_body / object_pic_body.
// Tracks volume create + per-volume allocation high-water marks in a
// 16-slot in-arena table; the WAL is the durable record of every
// CreateVolume/Allocate/Release event.

// Arena cap = total live volumes per PIC instance after WAL replay.
// Volumes are coarse-grained (one per logical disk / image), so the
// budget is much smaller than the per-binding/per-object PICs.
// ModuleState size: VolumeSlot(~48B) × 64 + 4 KiB scratch ≈ 7 KiB.
// Capacity profile — see namespace_pic_body.rs.
#[cfg(target_os = "none")]
const ARENA_CAPACITY: usize = 64;
#[cfg(not(target_os = "none"))]
const ARENA_CAPACITY: usize = 1024;
const MAX_OPS_PER_STEP: u32 = 4;
const READ_BUF: usize = 256;
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
    pub volumes: super::state::PicBlockState<ARENA_CAPACITY>,
    pub ticks: u32,
    pub ops_applied: u32,
    pub apply_errors: u32,
    pub wal_fd: i32,
    pub append_scratch: [u8; super::wal::APPEND_SCRATCH],
    pub wal_path: [u8; WAL_PATH_BUF],
    pub wal_path_len: u16,
}

pub unsafe fn module_new_impl(
    in_chan: i32,
    out_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(in_chan, out_chan, state_ptr, state_size, syscalls)
}

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
    let volumes_ptr: *mut super::state::PicBlockState<ARENA_CAPACITY> = &mut s.volumes;
    let mut replay_errors: u32 = 0;
    let replay_rc = super::wal::wal_replay(sys, fd, &mut scratch, |payload| {
        let volumes = &mut *volumes_ptr;
        if apply_to_arena(volumes, payload).is_err() {
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
        core::ptr::addr_of_mut!(s.volumes) as *mut u8,
        0,
        core::mem::size_of::<super::state::PicBlockState<ARENA_CAPACITY>>(),
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
                op @ (super::wire::OP_CREATE_VOLUME
                | super::wire::OP_ALLOCATE
                | super::wire::OP_RELEASE),
            ) => op,
            _ => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                let nak = [0xFFu8];
                let _ = (syscalls.channel_write)(s.out_chan, nak.as_ptr(), 1);
                handled = handled.wrapping_add(1);
                continue;
            }
        };

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

        match apply_to_arena(&mut s.volumes, bytes) {
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

pub(super) fn apply_to_arena(
    volumes: &mut super::state::PicBlockState<ARENA_CAPACITY>,
    payload: &[u8],
) -> Result<u8, ()> {
    let op = super::wire::peek_opcode(payload).ok_or(())?;
    match op {
        super::wire::OP_CREATE_VOLUME => {
            let d = super::wire::decode_create_volume(payload).map_err(|_| ())?;
            volumes
                .create_volume(
                    d.volume_id,
                    d.class,
                    d.logical_bytes,
                    d.block_size,
                    d.thin_provisioned,
                )
                .map_err(|_| ())?;
            Ok(super::wire::OP_CREATE_VOLUME)
        }
        super::wire::OP_ALLOCATE => {
            let d = super::wire::decode_allocate(payload).map_err(|_| ())?;
            volumes.allocate(d.volume_id, d.count).map_err(|_| ())?;
            Ok(super::wire::OP_ALLOCATE)
        }
        super::wire::OP_RELEASE => {
            let d = super::wire::decode_release(payload).map_err(|_| ())?;
            volumes.release(d.volume_id, d.count).map_err(|_| ())?;
            Ok(super::wire::OP_RELEASE)
        }
        _ => Err(()),
    }
}
