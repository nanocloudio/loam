// Append-only WAL primitives for Loam PICs over the Fluxor `fs`
// contract. no_std. Used by `namespace_pic_body.rs` (and, in time,
// the other public-surface bodies) to make each successful apply
// durable before the ack ships.
//
// Record layout (all multi-byte ints are LE):
//
//   [len:   u32]   payload byte length (1..=MAX_WAL_REC)
//   [crc32: u32]   crc32 over the payload bytes
//   [payload: len bytes]
//
// No file header. Records self-validate via CRC; a torn tail trips
// the CRC and replay stops cleanly there. Same scheme as
// `src/wal.rs`, simplified for a fixed binary payload schema.
//
// `FS_OPEN` does not create a file. `wal_open_create` uses
// `FS_OPEN_CREATE` for that and is what a PIC lands its WAL with on
// first boot; `wal_open` returns `None` when the path is missing.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use super::abi::SyscallTable;

// fluxor fs-contract opcodes — duplicated here (rather than imported
// from target/fluxor/fluxor-abi/sdk/contracts/storage/fs.rs) so `wal_io` keeps the same #[path]-
// inclusion shape every PIC common-body file uses.
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_UNLINK: u32 = 0x090A;
const FS_STAT: u32 = 0x0904;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_OPEN_CREATE: u32 = 0x0909;
const FS_WRITE_ASYNC: u32 = 0x090F;
const FS_FSYNC_SUBMIT: u32 = 0x0910;
const FS_FSYNC_POLL: u32 = 0x0911;
const FS_CAPS: u32 = 0x09FF;

/// `caps::FSYNC_ASYNC` — the provider implements the pipelined
/// `WRITE_ASYNC` + `FSYNC_SUBMIT` + `FSYNC_POLL` tier.
const CAP_FSYNC_ASYNC: u32 = 1 << 10;

/// Per-record cap. Matches `loam_wire::MAX_STRING`-bounded events
/// plus their 16-byte fixed prefix, with headroom.
pub const MAX_WAL_REC: usize = 4096;

/// Combined record-header + payload frame. Sized so a single
/// FS_WRITE can land both the header and the payload atomically from
/// the provider's point of view — one write, not two.
pub const APPEND_SCRATCH: usize = 8 + MAX_WAL_REC;

/// The provider's "accepted, not finished" code.
const E_AGAIN: i32 = -11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalOpenError {
    NotFound,
    /// The provider accepted the request but has not finished it. On a
    /// profile where the filesystem sits over a real device, creating a
    /// file needs device I/O that cannot complete inside one bounded
    /// step, so the provider says "again" and the caller retries on a
    /// later step. This is not a failure and must not be treated as
    /// one.
    Again,
    OpenFailed(i32),
    /// The WAL's own name could not be made durable. `FSYNC` fences a
    /// file's bytes and its own size, never the directory entry that
    /// finds them, so without a name fence a crash can leave records
    /// acknowledged durable in a file no later mount can open. A WAL
    /// that cannot publish its name carries no durability claim, so it
    /// refuses to open rather than pretend.
    NameUnfenceable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalAppendError {
    PayloadTooLarge,
    /// A zero-length record. Indistinguishable from padding on
    /// replay, so it is refused rather than written.
    EmptyPayload,
    /// An append is already staged on this appender.
    Busy,
    /// A partial frame sits at the tail, so this WAL can carry no
    /// further durability claim. Latched until the WAL is re-opened.
    Broken,
    SeekFailed(i32),
    WriteFailed(i32),
    ShortWrite {
        wrote: i32,
        wanted: usize,
    },
    FsyncFailed(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "the Failed postfix is the information: each variant names WHICH fs op failed"
)]
pub enum WalReplayError {
    SeekFailed(i32),
    ReadFailed(i32),
    StatFailed(i32),
}

/// Open a WAL at `path`. The file must already exist; fluxor's
/// `FS_OPEN` does not auto-create. On success the returned fd is
/// suitable for `WalAppender` / `wal_replay` / `wal_close`.
///
/// For callers that want create-on-missing semantics — typically
/// per-PIC WALs on first boot — use `wal_open_or_create` instead.
///
/// # Safety
/// `syscalls` must point at a live `SyscallTable`. `path` is read
/// up to its slice length; no NUL termination required.
pub unsafe fn wal_open(syscalls: &SyscallTable, path: &[u8]) -> Result<i32, WalOpenError> {
    wal_open_opcode(syscalls, path, FS_OPEN)
}

/// Open a WAL at `path`, creating it (zero-length) if it doesn't
/// exist. Requires the `fs` provider to implement `FS_OPEN_CREATE`,
/// which both profiles do.
///
/// On platforms where `FS_OPEN_CREATE` is unsupported the
/// underlying syscall returns a negative errno; this function
/// surfaces it as `OpenFailed(errno)` so callers can detect and
/// either fall back to `wal_open` (which requires a pre-touched
/// file) or fail loud.
pub unsafe fn wal_open_or_create(
    syscalls: &SyscallTable,
    path: &[u8],
) -> Result<i32, WalOpenError> {
    let fd = wal_open_opcode(syscalls, path, FS_OPEN_CREATE)?;
    // `OPEN_CREATE` mints a directory entry; the entry is volatile
    // until it is fenced. Publish it before the WAL carries a single
    // record, and fail closed when the provider cannot — proceeding on
    // file `FSYNC` alone would acknowledge records into a file whose
    // name a power cut can erase.
    if !name_is_fenceable(syscalls) || !fsync_name(syscalls, path) {
        let _ = wal_close(syscalls, fd);
        return Err(WalOpenError::NameUnfenceable);
    }
    Ok(fd)
}

/// True when the provider can durably publish a directory entry.
///
/// An unanswered query reads as "cannot", which is the safe answer for a
/// decision taken per call: the open is refused and retried, rather than a
/// name being certified that nothing can fence. Nothing is recorded, so the
/// next attempt asks again.
unsafe fn name_is_fenceable(syscalls: &SyscallTable) -> bool {
    super::fs_names::caps(syscalls.provider_call).unwrap_or(0) & super::fs_names::CAP_FSYNC_NAME
        != 0
}

/// Fence the directory entry the provider last minted for `path`.
unsafe fn fsync_name(syscalls: &SyscallTable, path: &[u8]) -> bool {
    super::fs_names::fsync_name(syscalls.provider_call, path)
}

unsafe fn wal_open_opcode(
    syscalls: &SyscallTable,
    path: &[u8],
    opcode: u32,
) -> Result<i32, WalOpenError> {
    let fd = (syscalls.provider_call)(-1, opcode, path.as_ptr() as *mut u8, path.len());
    if fd >= 0 {
        Ok(fd)
    } else if fd == E_AGAIN {
        Err(WalOpenError::Again)
    } else if fd == -19 {
        // ENODEV is the provider's "file missing" mapping.
        Err(WalOpenError::NotFound)
    } else {
        Err(WalOpenError::OpenFailed(fd))
    }
}

/// FS_STAT into a transient 8-byte buffer; returns the file size
/// in bytes. Layout per `target/fluxor/fluxor-abi/sdk/contracts/storage/fs.rs:13`:
/// `[size: u32 LE, mtime: u32 LE]`.
unsafe fn wal_size(syscalls: &SyscallTable, fd: i32) -> Result<u32, WalReplayError> {
    let mut buf = [0u8; 8];
    let rc = (syscalls.provider_call)(fd, FS_STAT, buf.as_mut_ptr(), buf.len());
    if rc < 0 {
        return Err(WalReplayError::StatFailed(rc));
    }
    Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

unsafe fn fs_seek(syscalls: &SyscallTable, fd: i32, offset: i32) -> i32 {
    let bytes = offset.to_le_bytes();
    (syscalls.provider_call)(fd, FS_SEEK, bytes.as_ptr() as *mut u8, bytes.len())
}

// ── Resumable append ──────────────────────────────────────────────
//
// A provider over a real device answers `E_AGAIN` for any stage of an
// append it accepted but has not finished. An append that collapses
// that into a failure turns transient device latency into operation
// refusal, so the append is a state machine instead: `begin` stages
// one frame, `poll` drives it, and only `Durable` licenses the caller
// to mutate state or acknowledge.
//
// Two device tiers, selected once per WAL from the provider's `CAPS`
// bitmap:
//
//   `FSYNC_ASYNC` set — `WRITE_ASYNC` submits the frame, `FSYNC_SUBMIT`
//     opens a fence ticket, `FSYNC_POLL` reports when the fence is on
//     non-volatile media.
//   otherwise        — checked `WRITE` + `FSYNC`, each retried across
//     steps on `E_AGAIN`.
//
// A hard (non-`E_AGAIN`) error after any frame byte reached the file
// leaves a partial frame at the tail. Replay stops cleanly there, but
// a later frame appended past it would be unreachable — silently
// dropped on the next replay. The FS contract has no truncate, so the
// appender latches `broken` instead and refuses every subsequent
// append. Callers must treat that as "this WAL can no longer carry a
// durability claim" and fail closed.

/// Outcome of one `poll` of a `WalAppender`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendState {
    /// No append staged.
    Idle,
    /// Accepted by the provider, not yet durable. Poll again on a
    /// later step. No caller state may change.
    Pending,
    /// The frame is on non-volatile media.
    Durable,
    /// The append failed. The WAL carries no claim for this record.
    Failed(WalAppendError),
}

const PHASE_IDLE: u8 = 0;
const PHASE_SEEK: u8 = 1;
const PHASE_WRITE: u8 = 2;
const PHASE_SUBMIT: u8 = 3;
const PHASE_POLL: u8 = 4;
const PHASE_FSYNC: u8 = 5;

/// One WAL's append state machine. Owns the frame buffer so the bytes
/// handed to an async provider stay valid until the fence completes;
/// nothing else may reuse them mid-append.
#[repr(C)]
pub struct WalAppender {
    phase: u8,
    /// `CAPS` has been queried for this WAL's provider.
    caps_known: u8,
    /// The provider left a partial frame at the tail; see the module
    /// note above. Latched; only re-opening the WAL clears it.
    broken: u8,
    caps: u32,
    frame_len: u32,
    written: u32,
    ticket: [u8; 8],
    frame: [u8; APPEND_SCRATCH],
}

impl WalAppender {
    pub const fn new() -> Self {
        Self {
            phase: PHASE_IDLE,
            caps_known: 0,
            broken: 0,
            caps: 0,
            frame_len: 0,
            written: 0,
            ticket: [0u8; 8],
            frame: [0u8; APPEND_SCRATCH],
        }
    }

    /// True while a staged frame is neither durable nor failed. The
    /// caller must not consume new work, reuse the frame buffer, or
    /// acknowledge anything while this holds.
    pub fn busy(&self) -> bool {
        self.phase != PHASE_IDLE
    }

    /// True once a partial frame has been left at the tail. Every
    /// further append is refused.
    pub fn broken(&self) -> bool {
        self.broken != 0
    }

    /// Re-arm after the WAL has been re-opened at a known-good tail.
    pub fn reset(&mut self) {
        self.phase = PHASE_IDLE;
        self.broken = 0;
        self.frame_len = 0;
        self.written = 0;
    }

    /// Stage one record. Returns the first `poll` outcome, so a
    /// provider that completes synchronously needs no second step.
    ///
    /// # Safety
    /// `syscalls` must point at a live `SyscallTable` and `fd` at a
    /// WAL opened for writing.
    pub unsafe fn begin(
        &mut self,
        syscalls: &SyscallTable,
        fd: i32,
        payload: &[u8],
    ) -> AppendState {
        if self.broken != 0 {
            return AppendState::Failed(WalAppendError::Broken);
        }
        if self.phase != PHASE_IDLE {
            return AppendState::Failed(WalAppendError::Busy);
        }
        if payload.is_empty() {
            return AppendState::Failed(WalAppendError::EmptyPayload);
        }
        if payload.len() > MAX_WAL_REC {
            return AppendState::Failed(WalAppendError::PayloadTooLarge);
        }
        let frame_len = 8 + payload.len();
        let crc = crc32(payload);
        self.frame[0..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        self.frame[4..8].copy_from_slice(&crc.to_le_bytes());
        self.frame[8..frame_len].copy_from_slice(payload);
        self.frame_len = frame_len as u32;
        self.written = 0;
        self.phase = PHASE_SEEK;
        self.poll(syscalls, fd)
    }

    /// Drive the staged frame one step further.
    ///
    /// # Safety
    /// Same constraints as `begin`, with the same `fd`.
    pub unsafe fn poll(&mut self, syscalls: &SyscallTable, fd: i32) -> AppendState {
        loop {
            match self.phase {
                PHASE_IDLE => return AppendState::Idle,
                PHASE_SEEK => {
                    // FS_SEEK is SEEK_SET-only, so the tail comes from
                    // a stat. Re-stating per append also keeps the WAL
                    // correct if anything else moved the descriptor.
                    let size = match wal_size(syscalls, fd) {
                        Ok(s) => s,
                        Err(WalReplayError::StatFailed(E_AGAIN)) => return AppendState::Pending,
                        Err(WalReplayError::StatFailed(rc)) => {
                            return self.fail(WalAppendError::SeekFailed(rc))
                        }
                        Err(_) => return self.fail(WalAppendError::SeekFailed(-22)),
                    };
                    if size > i32::MAX as u32 {
                        return self.fail(WalAppendError::SeekFailed(-22));
                    }
                    let rc = fs_seek(syscalls, fd, size as i32);
                    if rc == E_AGAIN {
                        return AppendState::Pending;
                    }
                    if rc < 0 {
                        return self.fail(WalAppendError::SeekFailed(rc));
                    }
                    self.phase = PHASE_WRITE;
                }
                PHASE_WRITE => {
                    let off = self.written as usize;
                    let want = self.frame_len as usize - off;
                    let opcode = if self.async_tier(syscalls, fd) {
                        FS_WRITE_ASYNC
                    } else {
                        FS_WRITE
                    };
                    let rc = (syscalls.provider_call)(
                        fd,
                        opcode,
                        self.frame.as_mut_ptr().add(off),
                        want,
                    );
                    if rc == E_AGAIN {
                        return AppendState::Pending;
                    }
                    if rc < 0 {
                        return self.fail(WalAppendError::WriteFailed(rc));
                    }
                    if rc == 0 {
                        // No progress and no error: the provider is
                        // refusing without saying why. Treat as a
                        // short write rather than spinning.
                        return self.fail(WalAppendError::ShortWrite {
                            wrote: 0,
                            wanted: want,
                        });
                    }
                    self.written = self.written.wrapping_add(rc as u32);
                    if (self.written as usize) < self.frame_len as usize {
                        // Partial frame: the rest lands on a later
                        // step, from the position the write left.
                        return AppendState::Pending;
                    }
                    self.phase = if self.async_tier(syscalls, fd) {
                        PHASE_SUBMIT
                    } else {
                        PHASE_FSYNC
                    };
                }
                PHASE_SUBMIT => {
                    let rc = (syscalls.provider_call)(
                        fd,
                        FS_FSYNC_SUBMIT,
                        self.ticket.as_mut_ptr(),
                        self.ticket.len(),
                    );
                    if rc == E_AGAIN {
                        return AppendState::Pending;
                    }
                    if rc < 0 {
                        return self.fail(WalAppendError::FsyncFailed(rc));
                    }
                    self.phase = PHASE_POLL;
                }
                PHASE_POLL => {
                    let rc = (syscalls.provider_call)(
                        fd,
                        FS_FSYNC_POLL,
                        self.ticket.as_mut_ptr(),
                        self.ticket.len(),
                    );
                    if rc < 0 {
                        return self.fail(WalAppendError::FsyncFailed(rc));
                    }
                    if rc != 0 {
                        return AppendState::Pending;
                    }
                    return self.finish();
                }
                _ => {
                    let rc = (syscalls.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
                    if rc == E_AGAIN {
                        return AppendState::Pending;
                    }
                    if rc < 0 {
                        return self.fail(WalAppendError::FsyncFailed(rc));
                    }
                    return self.finish();
                }
            }
        }
    }

    /// Query the provider's capability bitmap once per WAL. A provider
    /// that does not answer keeps the synchronous tier.
    unsafe fn async_tier(&mut self, syscalls: &SyscallTable, fd: i32) -> bool {
        if self.caps_known == 0 {
            let mut out = [0u8; 4];
            let rc = (syscalls.provider_call)(fd, FS_CAPS, out.as_mut_ptr(), out.len());
            // Only a real answer is recorded. A provider still attaching its
            // volume refuses the query, and latching that refusal would hold
            // this appender on the blocking fence tier for good — on a
            // provider that implements the pipelined one.
            if rc >= 4 {
                self.caps = u32::from_le_bytes(out);
                self.caps_known = 1;
            }
        }
        self.caps & CAP_FSYNC_ASYNC != 0
    }

    /// The payload of the most recently staged frame. Valid from
    /// `begin` until the next `begin`, so a caller that stages a
    /// record and resolves it on a later step needs no copy of its
    /// own.
    pub fn payload(&self) -> &[u8] {
        let end = (self.frame_len as usize).min(self.frame.len());
        if end < 8 {
            return &[];
        }
        &self.frame[8..end]
    }

    fn finish(&mut self) -> AppendState {
        self.phase = PHASE_IDLE;
        self.written = 0;
        AppendState::Durable
    }

    fn fail(&mut self, err: WalAppendError) -> AppendState {
        // Frame bytes reached the file: the tail is either a partial
        // record, or a whole record whose fence failed. Neither can
        // carry a further append — a later frame written past a
        // partial one is unreachable on replay, and a later fsync
        // would silently publish the record this one refused.
        if self.written > 0 || self.phase > PHASE_WRITE {
            self.broken = 1;
        }
        self.phase = PHASE_IDLE;
        self.written = 0;
        AppendState::Failed(err)
    }
}

impl Default for WalAppender {
    fn default() -> Self {
        Self::new()
    }
}

/// Replay the WAL: seek to 0, then for each record call `cb` with
/// the payload bytes. Stops on EOF, a CRC mismatch (torn tail),
/// an oversize-length-prefix (corrupt tail), or when `cb` returns
/// `false`. Returns the number of records successfully replayed.
///
/// `scratch` is a per-record decode buffer; size it to
/// `MAX_WAL_REC`. The buffer's lifetime is just the callback call.
pub unsafe fn wal_replay<F: FnMut(&[u8]) -> bool>(
    syscalls: &SyscallTable,
    fd: i32,
    scratch: &mut [u8],
    mut cb: F,
) -> Result<u32, WalReplayError> {
    let seek_rc = fs_seek(syscalls, fd, 0);
    if seek_rc < 0 {
        return Err(WalReplayError::SeekFailed(seek_rc));
    }

    let mut applied: u32 = 0;
    loop {
        let mut hdr = [0u8; 8];
        let n = read_exact(syscalls, fd, &mut hdr)?;
        if n == 0 {
            // Clean EOF on a record boundary.
            break;
        }
        if n < 8 {
            // Torn header — last record didn't finish landing.
            break;
        }
        let len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let expected_crc = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        if len == 0 {
            // Zero-length record is meaningless — treat as torn.
            break;
        }
        if len > MAX_WAL_REC || len > scratch.len() {
            // Torn-tail with high-bit garbage in the length prefix
            // is indistinguishable from real corruption; either way
            // the rest of the file isn't a clean record, so stop
            // here and accept whatever already replayed.
            break;
        }
        let payload = &mut scratch[..len];
        let pn = read_exact(syscalls, fd, payload)?;
        if pn < len {
            // Header survived but payload didn't — torn tail.
            break;
        }
        if crc32(payload) != expected_crc {
            // CRC mismatch — torn tail.
            break;
        }
        if !cb(payload) {
            applied = applied.wrapping_add(1);
            break;
        }
        applied = applied.wrapping_add(1);
    }
    Ok(applied)
}

/// FS_READ loop that fills `buf` or stops at the first short read /
/// EOF. Returns total bytes read (may be < `buf.len()` at EOF).
unsafe fn read_exact(
    syscalls: &SyscallTable,
    fd: i32,
    buf: &mut [u8],
) -> Result<usize, WalReplayError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let want = buf.len() - filled;
        let n = (syscalls.provider_call)(fd, FS_READ, buf.as_mut_ptr().add(filled), want);
        if n < 0 {
            return Err(WalReplayError::ReadFailed(n));
        }
        if n == 0 {
            // EOF.
            break;
        }
        filled = filled.wrapping_add(n as usize);
    }
    Ok(filled)
}

pub unsafe fn wal_close(syscalls: &SyscallTable, fd: i32) -> i32 {
    (syscalls.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0)
}

/// Outcome of a rotation attempt.
pub enum RotateOutcome {
    /// The log was replaced by a fresh empty one. The old fd is
    /// closed; this is the fd to use from here.
    Rotated(i32),
    /// The provider cannot replace a name atomically, so the log was
    /// left alone and the caller's existing fd is still valid.
    /// Rotation only bounds replay work — a longer log is a cost,
    /// losing one is not — so declining is the safe direction.
    Skipped,
}

/// Rotate a WAL by atomic replacement: stage an empty log beside it,
/// fence it, then rename it over the live path.
///
/// For WALs whose records are DELIVERY buffers — safe to discard once
/// every logged entry has been acknowledged durable downstream — this
/// bounds replay work at the last unacknowledged tail instead of the
/// full history.
///
/// The replacement has to be atomic. Unlinking and recreating leaves a
/// window with no log at all, and a crash inside it loses every record
/// the caller still expected to replay; the FS contract has no
/// truncate, so there is no in-place way to empty a file either.
/// `RENAME` publishes the new name and its parents durably, which
/// makes the crash-visible outcomes exactly two: the old log, or the
/// new empty one.
///
/// `Err` means the log was replaced but could not be reopened — the
/// caller holds no usable WAL and must fail closed.
pub unsafe fn wal_rotate(
    syscalls: &SyscallTable,
    fd: i32,
    path: &[u8],
) -> Result<RotateOutcome, i32> {
    // Per-call, and nothing is recorded: an unanswered query skips this
    // rotation and the next one asks again.
    if super::fs_names::caps(syscalls.provider_call).unwrap_or(0) & super::fs_names::CAP_RENAME == 0
    {
        return Ok(RotateOutcome::Skipped);
    }
    let mut staging = [0u8; ROTATE_PATH_BUF];
    const SUFFIX: &[u8] = b".rot";
    if path.len() + SUFFIX.len() > staging.len() {
        return Ok(RotateOutcome::Skipped);
    }
    staging[..path.len()].copy_from_slice(path);
    staging[path.len()..path.len() + SUFFIX.len()].copy_from_slice(SUFFIX);
    let slen = path.len() + SUFFIX.len();
    let stage = &staging[..slen];

    // A crashed attempt can leave staging behind, and `OPEN_CREATE`
    // does not truncate — a surviving file would be renamed into place
    // still carrying its records.
    let _ = super::fs_names::unlink(syscalls.provider_call, stage);
    let sfd = (syscalls.provider_call)(-1, FS_OPEN_CREATE, stage.as_ptr() as *mut u8, slen);
    if sfd < 0 {
        return Ok(RotateOutcome::Skipped);
    }
    let fenced = (syscalls.provider_call)(sfd, FS_FSYNC, core::ptr::null_mut(), 0) >= 0;
    let _ = wal_close(syscalls, sfd);
    if !fenced || !super::fs_names::rename(syscalls.provider_call, stage, path) {
        let _ = super::fs_names::unlink(syscalls.provider_call, stage);
        return Ok(RotateOutcome::Skipped);
    }
    // The old log is unreachable from here; only now is the caller's
    // fd spent.
    let _ = wal_close(syscalls, fd);
    match wal_open_or_create(syscalls, path) {
        Ok(new_fd) => Ok(RotateOutcome::Rotated(new_fd)),
        Err(_) => Err(-1),
    }
}

/// Room for a WAL path plus the rotation suffix.
const ROTATE_PATH_BUF: usize = 288;

/// True when `path` still resolves. Distinguishes "already gone" from
/// "could not remove" without depending on a provider's errno mapping.
unsafe fn name_present(syscalls: &SyscallTable, path: &[u8]) -> bool {
    super::fs_names::name_present(syscalls.provider_call, path)
}

// ── CRC32 (IEEE 802.3 polynomial, table-based, no_std) ────────────
//
// Mirror of `src/wal.rs:292`. Kept inline here so PIC builds don't
// pick up any std-only deps.

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

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    crc ^ 0xFFFF_FFFF
}
