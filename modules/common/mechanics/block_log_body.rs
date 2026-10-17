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
// (FS_OPEN_CREATE + FS_FSYNC_NAME + FS_WRITE + FS_FSYNC + FS_READ +
// FS_SEEK), just ENCAPSULATED inside the block_log PIC rather than
// each consumer poking at fs directly. The on-disk format is
// `[crc32:u32][len:u32][payload:len]` per record — same shape as
// `wal_io`. Replay validates CRCs and stops on a torn tail.
//
// No `fs` call waits on the device: `OPEN_CREATE`, `FSYNC_NAME` and
// `FSYNC` may answer `EINPROGRESS` (taken, not decided — re-asked
// byte-identically on a later step), `CAPS`, `SEEK` and `READ` may
// answer `EAGAIN` (nothing consumed — asked again later), and `WRITE` /
// `READ` move short counts. So opening the log, each append and each
// replay are step machines held in the state, resumed where they
// stopped. One job runs at a time; while it is undecided no further
// request is read, and the producer's backpressure flows through the
// channel.
//
// `OPEN_CREATE` mints a directory entry that stays volatile until
// `FSYNC_NAME` covers it, and a file `FSYNC` never publishes it. An
// append acknowledged over an unfenced name is a durability claim a
// power cut can void — the record's bytes are durable, the name that
// finds them is not. So the open is not finished, and no append is
// read, until the name fence has answered 0; a provider that cannot
// fence a name fails the open closed, as `wal_io`'s opener does.

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

/// `EAGAIN`: not now, nothing consumed. `EINPROGRESS`: taken, not yet
/// decided. Neither is ever a failure, an end of data or an absence.
const EAGAIN: i32 = -11;
const EINPROGRESS: i32 = -36;

const fn pending(rc: i32) -> bool {
    rc == EAGAIN || rc == EINPROGRESS
}

/// Boot: the log is being opened, then scanned for its clean tail.
const PHASE_OPEN: u8 = 0;
const PHASE_SCAN: u8 = 1;
const PHASE_READY: u8 = 2;
/// The log could not be opened: appends are refused, replays are empty.
const PHASE_FAILED: u8 = 3;
/// The log is open; whether the provider can fence its name is asked.
const PHASE_CAPS: u8 = 4;
/// The log's name is being fenced (`FSYNC_NAME`, re-asked until it
/// decides).
const PHASE_NAME: u8 = 5;

/// `fail_rc` for a log that did not open.
const FAIL_OPEN: i32 = -4;
/// `fail_rc` for a log whose name cannot be made durable.
const FAIL_NAME: i32 = -5;

const JOB_NONE: u8 = 0;
const JOB_APPEND: u8 = 1;
const JOB_REPLAY: u8 = 2;

// Append stages.
const AP_SEEK: u8 = 0;
const AP_WRITE: u8 = 1;
const AP_FSYNC: u8 = 2;

// Record-reader stages, shared by the boot scan and a replay.
const RD_SEEK: u8 = 0;
const RD_HDR: u8 = 1;
const RD_BODY: u8 = 2;
/// The clean tail is reached; a replay seeks back to the append tail.
const RD_REWIND: u8 = 3;

/// Records the boot scan or a replay reads per step.
const RECORDS_PER_STEP: u32 = 64;

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
    /// `PHASE_*`.
    pub phase: u8,
    /// The job in flight (`JOB_*`) and its stage.
    pub job: u8,
    pub stage: u8,
    /// The open's refusal, reported from the first step after it.
    pub fail_reported: u8,
    pub fail_rc: i32,
    /// The request the job answers.
    pub cid: u32,
    /// The append frame in `scratch`, and how much the provider took.
    pub frame_len: u32,
    pub written: u32,
    /// The record reader: the current record's header and the bytes of
    /// it (header or payload) read so far, its payload length, where it
    /// starts in the file, and how many records a replay has streamed.
    pub rd_hdr: [u8; 8],
    pub rd_filled: u32,
    pub rd_len: u32,
    pub rd_offset: u64,
    pub rd_total: u32,
    /// The payload being read, kept across steps.
    pub rd_buf: [u8; super::wire::MAX_RECORD],
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

/// Arm the log's open (creating it on first boot) and the scan to the
/// end that sets `current_offset`. Torn-tail tolerant. Neither is done
/// here: both may take the provider several steps, so the module's
/// steps drive them, and no request is read until they are done.
pub unsafe fn open_log_from_state(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    let len = s.log_path_len as usize;
    if len == 0 || len > LOG_PATH_BUF {
        return -3;
    }
    s.log_fd = -1;
    s.phase = PHASE_OPEN;
    s.job = JOB_NONE;
    0
}

/// Drive the open and the tail scan. True once the log is ready (or
/// failed to open, which answers requests rather than holding them).
unsafe fn boot(s: &mut ModuleState, sys: &super::SyscallTable) -> bool {
    if s.phase == PHASE_OPEN {
        let len = (s.log_path_len as usize).min(LOG_PATH_BUF);
        let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, s.log_path.as_mut_ptr(), len);
        if pending(fd) {
            return false;
        }
        if fd < 0 {
            s.fail_rc = FAIL_OPEN;
            s.phase = PHASE_FAILED;
            return true;
        }
        s.log_fd = fd;
        s.phase = PHASE_CAPS;
    }
    if s.phase == PHASE_CAPS {
        // An unanswered query is not "cannot": ask again on a later
        // step, and record nothing.
        let caps = match super::fs_names::caps(sys.provider_call) {
            Some(c) => c,
            None => return false,
        };
        if caps & super::fs_names::CAP_FSYNC_NAME == 0 {
            return name_unfenceable(s, sys);
        }
        s.phase = PHASE_NAME;
    }
    if s.phase == PHASE_NAME {
        // Fenced on every boot, not only the one that created the file:
        // `OPEN_CREATE` does not say whether it minted the entry, and a
        // boot after a crash may be the first to see one minted by a
        // process that never fenced it. Fencing a durable entry is a
        // no-op. The path is the same held bytes on every ask.
        let len = (s.log_path_len as usize).min(LOG_PATH_BUF);
        let path: &[u8] = s.log_path.get(..len).unwrap_or(&[]);
        let rc = super::fs_names::fsync_name(sys.provider_call, path);
        if pending(rc) {
            return false;
        }
        if rc < 0 {
            return name_unfenceable(s, sys);
        }
        s.stage = RD_SEEK;
        s.phase = PHASE_SCAN;
    }
    if s.phase == PHASE_SCAN {
        match read_records(s, sys, false) {
            Some(()) => {
                // The clean tail: where the next append lands.
                s.current_offset = s.rd_offset;
                s.phase = PHASE_READY;
            }
            None => return false,
        }
    }
    true
}

/// The log's name cannot be made durable, so no append over it may be
/// acknowledged: close it and fail the open closed.
unsafe fn name_unfenceable(s: &mut ModuleState, sys: &super::SyscallTable) -> bool {
    if s.log_fd >= 0 {
        let _ = (sys.provider_call)(s.log_fd, FS_CLOSE, core::ptr::null_mut(), 0);
    }
    s.log_fd = -1;
    s.fail_rc = FAIL_NAME;
    s.phase = PHASE_FAILED;
    true
}

/// What one `read_some` left.
enum ReadSome {
    /// `[..end]` is filled.
    Full,
    /// The provider has no more for now; this many bytes are filled.
    Pending(usize),
    /// End of file, or a read error: the clean records end here.
    End,
}

/// Fill `buf[at..end]` with `READ`s while bytes keep moving. Stops at
/// the first `EAGAIN` (resume later from the count it answers), at EOF
/// or an error, or once full. Bounded: every further call has moved at
/// least one byte.
unsafe fn read_some(
    sys: &super::SyscallTable,
    fd: i32,
    buf: *mut u8,
    at: usize,
    end: usize,
) -> ReadSome {
    let mut filled = at;
    while filled < end {
        let want = end - filled;
        let n = (sys.provider_call)(fd, FS_READ, buf.add(filled), want);
        if pending(n) {
            return ReadSome::Pending(filled);
        }
        if n <= 0 {
            return ReadSome::End;
        }
        // Clamped: a provider reporting more than it was offered must
        // not walk the cursor past the buffer.
        filled += (n as usize).min(want);
    }
    ReadSome::Full
}

/// Read clean records from the head of the log, up to
/// `RECORDS_PER_STEP` this call, streaming each to the out channel when
/// `emit`. `Some` once the clean tail is reached (`rd_offset` is it, and
/// for `emit` the descriptor is back at the append tail); `None` while
/// more remains for a later step.
unsafe fn read_records(s: &mut ModuleState, sys: &super::SyscallTable, emit: bool) -> Option<()> {
    let fd = s.log_fd;
    let mut records = 0u32;
    loop {
        match s.stage {
            RD_SEEK => {
                let zero: [u8; 4] = 0u32.to_le_bytes();
                let rc = (sys.provider_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4);
                if pending(rc) {
                    return None;
                }
                s.rd_offset = 0;
                s.rd_total = 0;
                s.rd_filled = 0;
                // A log that cannot be positioned holds no clean record.
                s.stage = if rc < 0 { RD_REWIND } else { RD_HDR };
            }
            RD_HDR => {
                if records >= RECORDS_PER_STEP {
                    return None;
                }
                let at = (s.rd_filled as usize).min(8);
                match read_some(sys, fd, s.rd_hdr.as_mut_ptr(), at, 8) {
                    ReadSome::Pending(n) => {
                        s.rd_filled = n as u32;
                        return None;
                    }
                    ReadSome::End => {
                        s.stage = RD_REWIND;
                        continue;
                    }
                    ReadSome::Full => {}
                }
                let h = s.rd_hdr;
                let len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
                if len == 0 || len > super::wire::MAX_RECORD {
                    s.stage = RD_REWIND;
                    continue;
                }
                s.rd_len = len as u32;
                s.rd_filled = 0;
                s.stage = RD_BODY;
            }
            RD_BODY => {
                let len = (s.rd_len as usize).min(super::wire::MAX_RECORD);
                let at = (s.rd_filled as usize).min(len);
                match read_some(sys, fd, s.rd_buf.as_mut_ptr(), at, len) {
                    ReadSome::Pending(n) => {
                        s.rd_filled = n as u32;
                        return None;
                    }
                    ReadSome::End => {
                        s.stage = RD_REWIND;
                        continue;
                    }
                    ReadSome::Full => {}
                }
                let h = s.rd_hdr;
                let expected_crc = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
                let payload: &[u8] = match s.rd_buf.get(..len) {
                    Some(p) => &*(p as *const [u8]),
                    None => {
                        s.stage = RD_REWIND;
                        continue;
                    }
                };
                if crc32(payload) != expected_crc {
                    s.stage = RD_REWIND;
                    continue;
                }
                if emit {
                    let n_resp = match super::wire::encode_replay_record(
                        &mut s.scratch,
                        s.cid,
                        s.rd_offset,
                        payload,
                    ) {
                        Ok(n) => n,
                        Err(_) => {
                            s.append_errors = s.append_errors.wrapping_add(1);
                            s.stage = RD_REWIND;
                            continue;
                        }
                    };
                    let _ = (sys.channel_write)(s.out_chan, s.scratch.as_ptr(), n_resp);
                    s.rd_total = s.rd_total.wrapping_add(1);
                }
                s.rd_offset = s.rd_offset.wrapping_add((8 + len) as u64);
                s.rd_filled = 0;
                s.stage = RD_HDR;
                records = records.wrapping_add(1);
            }
            _ => {
                if !emit {
                    return Some(());
                }
                // Seek file pointer back to end so subsequent appends work.
                let off_bytes = (s.current_offset as i32).to_le_bytes();
                let rc = (sys.provider_call)(fd, FS_SEEK, off_bytes.as_ptr() as *mut u8, 4);
                if pending(rc) {
                    return None;
                }
                return Some(());
            }
        }
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

    if !boot(s, syscalls) {
        return 0;
    }
    if s.phase == PHASE_FAILED && s.fail_reported == 0 {
        s.fail_reported = 1;
        return s.fail_rc;
    }

    if s.job != JOB_NONE {
        drive_job(s, syscalls);
        if s.job != JOB_NONE {
            // Undecided: the requests behind it wait for a later step.
            return 0;
        }
    }
    let mut handled: u32 = 0;
    while handled < super::limits::OPS_PER_STEP {
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
        if s.job != JOB_NONE {
            // The request just read is undecided: it resumes next step.
            break;
        }
    }
    0
}

unsafe fn drive_job(s: &mut ModuleState, sys: &super::SyscallTable) {
    match s.job {
        JOB_APPEND => drive_append(s, sys),
        JOB_REPLAY => {
            if read_records(s, sys, true).is_some() {
                s.job = JOB_NONE;
                s.replays = s.replays.wrapping_add(1);
                let (cid, total) = (s.cid, s.rd_total);
                let _ = emit_replay_end(s, sys, cid, total);
            }
        }
        _ => s.job = JOB_NONE,
    }
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

    let crc = crc32(payload);
    let frame_len = 8 + payload.len();
    if frame_len > s.scratch.len() {
        emit_append_nak(s, sys, cid);
        return;
    }
    // The frame stays in `scratch` until the provider has taken all of
    // it and the fence is down: the append may span steps.
    s.scratch[0..4].copy_from_slice(&crc.to_le_bytes());
    s.scratch[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    s.scratch[8..frame_len].copy_from_slice(payload);
    s.cid = cid;
    s.frame_len = frame_len as u32;
    s.written = 0;
    s.stage = AP_SEEK;
    s.job = JOB_APPEND;
    drive_append(s, sys);
}

/// Drive the append in flight: seek to the tail, write the frame (short
/// counts advance), fence it, answer. A refusal NAKs and leaves
/// `current_offset` where it was, so the next append overwrites whatever
/// part of this frame landed.
unsafe fn drive_append(s: &mut ModuleState, sys: &super::SyscallTable) {
    let cid = s.cid;
    loop {
        match s.stage {
            AP_SEEK => {
                // Seek to end (current_offset).
                let off_bytes = (s.current_offset as i32).to_le_bytes();
                let seek_rc =
                    (sys.provider_call)(s.log_fd, FS_SEEK, off_bytes.as_ptr() as *mut u8, 4);
                if pending(seek_rc) {
                    return;
                }
                if seek_rc < 0 {
                    return append_refused(s, sys, cid);
                }
                s.stage = AP_WRITE;
            }
            AP_WRITE => {
                let end = (s.frame_len as usize).min(s.scratch.len());
                let off = (s.written as usize).min(end);
                if off >= end {
                    s.stage = AP_FSYNC;
                    continue;
                }
                let want = end - off;
                let wrote =
                    (sys.provider_call)(s.log_fd, FS_WRITE, s.scratch.as_mut_ptr().add(off), want);
                if pending(wrote) {
                    return;
                }
                if wrote <= 0 {
                    return append_refused(s, sys, cid);
                }
                // The prefix is the provider's now; offer the rest from
                // where it stopped while bytes keep moving.
                s.written = (off + (wrote as usize).min(want)) as u32;
            }
            _ => {
                // Re-asked byte-identically until it decides.
                let rc = (sys.provider_call)(s.log_fd, FS_FSYNC, core::ptr::null_mut(), 0);
                if pending(rc) {
                    return;
                }
                if rc < 0 {
                    return append_refused(s, sys, cid);
                }
                break;
            }
        }
    }
    s.job = JOB_NONE;
    let record_offset = s.current_offset;
    s.current_offset = s.current_offset.wrapping_add(s.frame_len as u64);
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

unsafe fn append_refused(s: &mut ModuleState, sys: &super::SyscallTable, cid: u32) {
    s.job = JOB_NONE;
    emit_append_nak(s, sys, cid);
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

    // Seek to 0 and stream every clean record, over as many steps as
    // the reads take.
    s.cid = cid;
    s.stage = RD_SEEK;
    s.job = JOB_REPLAY;
    drive_job(s, sys);
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
