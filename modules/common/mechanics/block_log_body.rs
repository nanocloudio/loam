// Step body for `block_log` — a channel-fronted append-only log
// PIC. Loam's WAL-using PICs (namespace_router, object_index,
// block_allocator, raft_metadata_client) can migrate from
// inline `wal_io.rs` fs syscalls to talking to a sibling
// block_log PIC over a channel pair. This preserves the mesh
// discipline (channels-as-state-surface) and lets the bare-metal
// build swap in a block-device backing without touching the
// consumer PICs.
//
// This first cut uses the same fs-contract backing as wal_io
// (FS_OPEN_CREATE + FS_WRITE + FS_FSYNC + FS_READ + FS_SEEK),
// just ENCAPSULATED inside the block_log PIC rather than each
// consumer poking at fs directly. The on-disk format is
// `[crc32:u32][len:u32][payload:len]` per record — same shape as
// `wal_io`. Replay validates CRCs and stops on a torn tail.
//
// Append: cap one per step (bounded work). Replay: cap one
// record per step. Producer/consumer backpressure flows through
// the channels naturally.

const MAX_OPS_PER_STEP: u32 = 4;
const READ_BUF: usize = 4200;
const SCRATCH: usize = 4200;
pub const LOG_PATH_BUF: usize = 256;

// fluxor fs-contract opcodes — duplicated to keep this body
// path-includable into multiple consumers.
const FS_OPEN_CREATE: u32 = 0x0909;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    pub log_path: [u8; LOG_PATH_BUF],
    pub log_path_len: u16,
    pub log_fd: i32,
    pub current_offset: u64,
    pub scratch: [u8; SCRATCH],
    pub ticks: u32,
    pub appends: u32,
    pub replays: u32,
    pub append_errors: u32,
}

pub unsafe fn module_new_impl(
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
    core::ptr::write_bytes(state_ptr, 0u8, state_size);
    let s = &mut *(state_ptr as *mut ModuleState);
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.log_fd = -1;
    0
}

/// Set the log file path after init. Bytes are copied into the
/// inline buffer; subsequent `open_log_from_state` opens or
/// creates the file via FS_OPEN_CREATE.
pub unsafe fn set_log_path(state_ptr: *mut u8, path: &[u8]) -> bool {
    if state_ptr.is_null() || path.is_empty() || path.len() > LOG_PATH_BUF {
        return false;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    s.log_path[..path.len()].copy_from_slice(path);
    s.log_path_len = path.len() as u16;
    true
}

/// Open the log file (creating it on first boot) and scan to the
/// end to set `current_offset`. Torn-tail tolerant.
pub unsafe fn open_log_from_state(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    let len = s.log_path_len as usize;
    if len == 0 || len > LOG_PATH_BUF {
        return -3;
    }
    let path = core::slice::from_raw_parts(s.log_path.as_ptr(), len);
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return -1,
    };
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_ptr() as *mut u8, path.len());
    if fd < 0 {
        return -4;
    }
    s.log_fd = fd;

    // Scan forward to find current_offset (end of last clean record).
    if let Some(off) = scan_clean_tail(sys, fd) {
        s.current_offset = off;
    }
    0
}

unsafe fn scan_clean_tail(sys: &super::SyscallTable, fd: i32) -> Option<u64> {
    // Seek to 0.
    let zero: [u8; 4] = 0u32.to_le_bytes();
    let rc = (sys.provider_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4);
    if rc < 0 {
        return None;
    }
    let mut offset: u64 = 0;
    let mut hdr = [0u8; 8];
    let mut payload_scratch = [0u8; super::wire::MAX_RECORD];
    loop {
        let n = read_exact(sys, fd, &mut hdr);
        if n < 8 {
            break;
        }
        let expected_crc = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        if len == 0 || len > super::wire::MAX_RECORD {
            break;
        }
        let pn = read_exact(sys, fd, &mut payload_scratch[..len]);
        if pn < len {
            break;
        }
        if crc32(&payload_scratch[..len]) != expected_crc {
            break;
        }
        offset = offset.wrapping_add((8 + len) as u64);
    }
    Some(offset)
}

unsafe fn read_exact(sys: &super::SyscallTable, fd: i32, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        let n = (sys.provider_call)(
            fd,
            FS_READ,
            buf.as_mut_ptr().add(filled),
            buf.len() - filled,
        );
        if n <= 0 {
            break;
        }
        filled += n as usize;
    }
    filled
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

    let mut handled: u32 = 0;
    while handled < MAX_OPS_PER_STEP {
        let mut buf = [0u8; READ_BUF];
        let n = (syscalls.channel_read)(s.in_chan, buf.as_mut_ptr(), READ_BUF);
        if n <= 0 {
            break;
        }
        let bytes = &buf[..n as usize];
        match super::wire::peek_opcode(bytes) {
            Some(super::wire::OP_APPEND_REQ) => handle_append(s, syscalls, bytes),
            Some(super::wire::OP_REPLAY_REQ) => handle_replay(s, syscalls, bytes),
            _ => {
                s.append_errors = s.append_errors.wrapping_add(1);
            }
        }
        handled = handled.wrapping_add(1);
    }
    0
}

unsafe fn handle_append(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) {
    let (cid, payload) = match super::wire::decode_append_req(bytes) {
        Ok(d) => d,
        Err(_) => {
            s.append_errors = s.append_errors.wrapping_add(1);
            return;
        }
    };
    if s.log_fd < 0 {
        emit_append_nak(s, sys, cid);
        return;
    }

    // Seek to end (current_offset).
    let off_bytes = (s.current_offset as i32).to_le_bytes();
    let seek_rc = (sys.provider_call)(s.log_fd, FS_SEEK, off_bytes.as_ptr() as *mut u8, 4);
    if seek_rc < 0 {
        emit_append_nak(s, sys, cid);
        return;
    }

    let crc = crc32(payload);
    let frame_len = 8 + payload.len();
    if frame_len > s.scratch.len() {
        emit_append_nak(s, sys, cid);
        return;
    }
    s.scratch[0..4].copy_from_slice(&crc.to_le_bytes());
    s.scratch[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    s.scratch[8..frame_len].copy_from_slice(payload);

    let wrote = (sys.provider_call)(s.log_fd, FS_WRITE, s.scratch.as_mut_ptr(), frame_len);
    if wrote < 0 || (wrote as usize) != frame_len {
        emit_append_nak(s, sys, cid);
        return;
    }
    if (sys.provider_call)(s.log_fd, FS_FSYNC, core::ptr::null_mut(), 0) < 0 {
        emit_append_nak(s, sys, cid);
        return;
    }

    let record_offset = s.current_offset;
    s.current_offset = s.current_offset.wrapping_add(frame_len as u64);
    s.appends = s.appends.wrapping_add(1);

    // Emit AppendResp via scratch (overwriting the frame we just
    // wrote — already on disk).
    let n = match super::wire::encode_append_resp(&mut s.scratch, cid, Some(record_offset)) {
        Ok(n) => n,
        Err(_) => {
            s.append_errors = s.append_errors.wrapping_add(1);
            return;
        }
    };
    let _ = (sys.channel_write)(s.out_chan, s.scratch.as_ptr(), n);
}

unsafe fn emit_append_nak(s: &mut ModuleState, sys: &super::SyscallTable, cid: u32) {
    let mut buf = [0u8; 16];
    if let Ok(n) = super::wire::encode_append_resp(&mut buf, cid, None) {
        let _ = (sys.channel_write)(s.out_chan, buf.as_ptr(), n);
    }
    s.append_errors = s.append_errors.wrapping_add(1);
}

unsafe fn handle_replay(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) {
    let cid = match super::wire::decode_replay_req(bytes) {
        Ok(c) => c,
        Err(_) => {
            s.append_errors = s.append_errors.wrapping_add(1);
            return;
        }
    };
    if s.log_fd < 0 {
        let _ = emit_replay_end(s, sys, cid, 0);
        return;
    }

    // Seek to 0 and stream every clean record.
    let zero: [u8; 4] = 0u32.to_le_bytes();
    let seek_rc = (sys.provider_call)(s.log_fd, FS_SEEK, zero.as_ptr() as *mut u8, 4);
    if seek_rc < 0 {
        let _ = emit_replay_end(s, sys, cid, 0);
        return;
    }

    let mut offset: u64 = 0;
    let mut total: u32 = 0;
    let mut hdr = [0u8; 8];
    let mut payload = [0u8; super::wire::MAX_RECORD];
    loop {
        let n = read_exact(sys, s.log_fd, &mut hdr);
        if n < 8 {
            break;
        }
        let expected_crc = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        if len == 0 || len > super::wire::MAX_RECORD {
            break;
        }
        let pn = read_exact(sys, s.log_fd, &mut payload[..len]);
        if pn < len {
            break;
        }
        if crc32(&payload[..len]) != expected_crc {
            break;
        }
        let n_resp =
            match super::wire::encode_replay_record(&mut s.scratch, cid, offset, &payload[..len]) {
                Ok(n) => n,
                Err(_) => {
                    s.append_errors = s.append_errors.wrapping_add(1);
                    break;
                }
            };
        let _ = (sys.channel_write)(s.out_chan, s.scratch.as_ptr(), n_resp);
        offset = offset.wrapping_add((8 + len) as u64);
        total = total.wrapping_add(1);
    }
    // Seek file pointer back to end so subsequent appends work.
    let off_bytes = (s.current_offset as i32).to_le_bytes();
    let _ = (sys.provider_call)(s.log_fd, FS_SEEK, off_bytes.as_ptr() as *mut u8, 4);

    s.replays = s.replays.wrapping_add(1);
    let _ = emit_replay_end(s, sys, cid, total);
}

unsafe fn emit_replay_end(
    s: &mut ModuleState,
    sys: &super::SyscallTable,
    cid: u32,
    total: u32,
) -> i32 {
    let n = match super::wire::encode_replay_end(&mut s.scratch, cid, total) {
        Ok(n) => n,
        Err(_) => return -1,
    };
    (sys.channel_write)(s.out_chan, s.scratch.as_ptr(), n)
}

// ── CRC32 (IEEE 802.3) — same table as wal_io ─────────────────────

const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC32_TABLE: [u32; 256] = build_crc32_table();

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    crc ^ 0xFFFF_FFFF
}
