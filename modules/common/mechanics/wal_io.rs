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
// the CRC and replay stops cleanly there.
//
// `FS_OPEN` does not create a file. `WalOpener` with `create` uses
// `FS_OPEN_CREATE` for that and is what a PIC lands its WAL with on
// first boot; without it a missing path answers `NotFound`.
//
// No `fs` call waits on the device, so opening, appending, replaying
// and rotating are each a step machine (`WalOpener`, `WalAppender`,
// `WalReplay`, `WalRotator`) polled once per step until it decides.
// `EAGAIN` and `EINPROGRESS` are never a failure, an end of data or an
// absence; an `EINPROGRESS` is collected by re-asking the
// byte-identical request.

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

/// `EAGAIN`: not now, nothing consumed — ask again on a later step.
const E_AGAIN: i32 = -11;
/// `EINPROGRESS`: taken, not yet decided — re-ask the byte-identical
/// request on a later step.
const E_INPROGRESS: i32 = -36;

/// Neither answer is a result yet; see `fs_names::pending`.
const fn pending(rc: i32) -> bool {
    rc == E_AGAIN || rc == E_INPROGRESS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalOpenError {
    NotFound,
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

// ── Resumable open ────────────────────────────────────────────────
//
// No `fs` call waits on the device. `OPEN_CREATE` and `FSYNC_NAME` may
// answer `EINPROGRESS` and decide on a later ask; `OPEN` and `CAPS` may
// answer `EAGAIN`. Opening a WAL is therefore a step machine like an
// append: the caller polls a `WalOpener` once per step, with the same
// path every time, until it answers `Ready` or `Failed`.
//
// `create` selects `OPEN_CREATE` and the name fence that must follow
// it: `OPEN_CREATE` mints a directory entry that stays volatile until
// `FSYNC_NAME` covers it, so the open is not finished — and the WAL
// carries no record — until that fence answers 0. A provider that
// cannot fence a name fails the open closed (`NameUnfenceable`):
// proceeding on file `FSYNC` alone would acknowledge records into a
// file whose name a power cut can erase. Without `create` the file
// must already exist; `OPEN` does not auto-create.

/// Outcome of one `WalOpener::poll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenPoll {
    /// Not decided yet. Poll again on a later step, with the same path.
    Pending,
    /// Open, and for `create` its name is durable. The fd is suitable
    /// for `WalAppender` / `WalReplay` / `wal_close`.
    Ready(i32),
    /// Refused. Any fd the opener held is closed.
    Failed(WalOpenError),
}

const OPEN_IDLE: u8 = 0;
const OPEN_FILE: u8 = 1;
const OPEN_CAPS: u8 = 2;
const OPEN_NAME: u8 = 3;

/// One WAL open in flight. Zeroed memory is a valid idle opener.
#[repr(C)]
pub struct WalOpener {
    phase: u8,
    create: u8,
    fd: i32,
}

impl WalOpener {
    pub const fn new() -> Self {
        Self {
            phase: OPEN_IDLE,
            create: 0,
            fd: -1,
        }
    }

    /// True while an open is staged and undecided.
    pub fn busy(&self) -> bool {
        self.phase != OPEN_IDLE
    }

    /// Drive the open one step further, starting one when idle.
    ///
    /// `path` and `create` must be the same on every poll of one open:
    /// an `EINPROGRESS` answer is collected only by re-asking the
    /// byte-identical request.
    ///
    /// # Safety
    /// `syscalls` must point at a live `SyscallTable`. `path` is read up
    /// to its slice length; no NUL termination required.
    pub unsafe fn poll(&mut self, syscalls: &SyscallTable, path: &[u8], create: bool) -> OpenPoll {
        if self.phase == OPEN_IDLE {
            self.phase = OPEN_FILE;
            self.create = u8::from(create);
            self.fd = -1;
        }
        loop {
            match self.phase {
                OPEN_FILE => {
                    let opcode = if self.create != 0 {
                        FS_OPEN_CREATE
                    } else {
                        FS_OPEN
                    };
                    let fd =
                        (syscalls.provider_call)(-1, opcode, path.as_ptr() as *mut u8, path.len());
                    if pending(fd) {
                        return OpenPoll::Pending;
                    }
                    if fd < 0 {
                        self.phase = OPEN_IDLE;
                        // ENOENT is the contract's "no such entry"; ENODEV is
                        // the mapping older providers answer a missing file
                        // with.
                        return OpenPoll::Failed(if fd == -2 || fd == -19 {
                            WalOpenError::NotFound
                        } else {
                            WalOpenError::OpenFailed(fd)
                        });
                    }
                    self.fd = fd;
                    if self.create == 0 {
                        return self.ready();
                    }
                    self.phase = OPEN_CAPS;
                }
                OPEN_CAPS => {
                    // An unanswered query is not "cannot": ask again on a
                    // later step, and record nothing.
                    let caps = match super::fs_names::caps(syscalls.provider_call) {
                        Some(c) => c,
                        None => return OpenPoll::Pending,
                    };
                    if caps & super::fs_names::CAP_FSYNC_NAME == 0 {
                        return self.fail(syscalls, WalOpenError::NameUnfenceable);
                    }
                    self.phase = OPEN_NAME;
                }
                _ => {
                    let rc = super::fs_names::fsync_name(syscalls.provider_call, path);
                    if pending(rc) {
                        return OpenPoll::Pending;
                    }
                    if rc < 0 {
                        return self.fail(syscalls, WalOpenError::NameUnfenceable);
                    }
                    return self.ready();
                }
            }
        }
    }

    /// Abandon an open in flight, closing any fd it holds. An
    /// undecided `OPEN_CREATE` or name fence still completes in the
    /// provider's own step; only its answer goes uncollected.
    ///
    /// # Safety
    /// As for `poll`.
    pub unsafe fn abandon(&mut self, syscalls: &SyscallTable) {
        if self.fd >= 0 {
            let _ = wal_close(syscalls, self.fd);
        }
        self.fd = -1;
        self.phase = OPEN_IDLE;
    }

    fn ready(&mut self) -> OpenPoll {
        let fd = self.fd;
        self.fd = -1;
        self.phase = OPEN_IDLE;
        OpenPoll::Ready(fd)
    }

    unsafe fn fail(&mut self, syscalls: &SyscallTable, err: WalOpenError) -> OpenPoll {
        self.abandon(syscalls);
        OpenPoll::Failed(err)
    }
}

impl Default for WalOpener {
    fn default() -> Self {
        Self::new()
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
// No stage of an append decides on the device inside a call: `WRITE`
// moves a short count or answers `EAGAIN`, `FSYNC` answers
// `EINPROGRESS` until the fence is down. An append that collapses
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
//   otherwise        — checked `WRITE` + `FSYNC`, each re-asked across
//     steps while it answers `EAGAIN` / `EINPROGRESS`.
//
// A hard (not `EAGAIN` / `EINPROGRESS`) error after any frame byte reached the file
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
                        Err(WalReplayError::StatFailed(rc)) if pending(rc) => {
                            return AppendState::Pending
                        }
                        Err(WalReplayError::StatFailed(rc)) => {
                            return self.fail(WalAppendError::SeekFailed(rc))
                        }
                        Err(_) => return self.fail(WalAppendError::SeekFailed(-22)),
                    };
                    if size > i32::MAX as u32 {
                        return self.fail(WalAppendError::SeekFailed(-22));
                    }
                    let rc = fs_seek(syscalls, fd, size as i32);
                    if pending(rc) {
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
                    // `EAGAIN` only when nothing moved: nothing was taken,
                    // and the same tail is offered again on a later step.
                    if pending(rc) {
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
                    // Clamped: a provider reporting more than it was
                    // offered must not walk the cursor past the frame.
                    self.written = self.written.wrapping_add((rc as usize).min(want) as u32);
                    if (self.written as usize) < self.frame_len as usize {
                        // Short count: the prefix is the provider's now.
                        // Offer the rest from where it stopped, while
                        // bytes keep moving; an `EAGAIN` defers it to a
                        // later step.
                        continue;
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
                    if pending(rc) {
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
                    if pending(rc) {
                        return AppendState::Pending;
                    }
                    if rc < 0 {
                        return self.fail(WalAppendError::FsyncFailed(rc));
                    }
                    if rc != 0 {
                        return AppendState::Pending;
                    }
                    return self.finish();
                }
                _ => {
                    // Re-asked byte-identically (same fd, no arg) until it
                    // decides: `EINPROGRESS` is taken-not-decided.
                    let rc = (syscalls.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
                    if pending(rc) {
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

    /// The frame buffer, lent out while no append is staged — the
    /// replay buffer a boot passes `WalReplay::poll`, which needs one
    /// that outlives a step. Empty while an append is staged, since the
    /// staged bytes must stay put until their fence completes.
    pub fn idle_buffer(&mut self) -> &mut [u8] {
        if self.phase != PHASE_IDLE {
            return &mut [];
        }
        &mut self.frame
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

// ── Resumable replay ──────────────────────────────────────────────
//
// A `READ` over sectors the provider has not cached starts fetching
// them and answers `EAGAIN`, or the short count of what was cached. So
// a replay is a step machine too: `WalReplay::poll` reads what it can,
// hands each whole record to the callback, and on `EAGAIN` stops with
// its place kept — the partial header or payload already read stays in
// the replay and in the caller's buffer, and the descriptor's offset is
// exactly where the next read resumes (an `EAGAIN` consumes nothing).
// Only a `READ` answering 0 is the end of the file.

/// Outcome of one `WalReplay::poll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayPoll {
    /// More to read. Poll again on a later step with the same fd and
    /// buffer.
    Pending,
    /// The log is replayed: EOF, a torn tail, or the callback stopping
    /// it. Carries the number of records handed to the callback.
    Done(u32),
    Failed(WalReplayError),
}

const REPLAY_SEEK: u8 = 0;
const REPLAY_HDR: u8 = 1;
const REPLAY_BODY: u8 = 2;
const REPLAY_DONE: u8 = 3;

/// One WAL replay in flight. Zeroed memory is a valid replay that has
/// not started.
#[repr(C)]
pub struct WalReplay {
    phase: u8,
    hdr: [u8; 8],
    /// Bytes of the current header or payload read so far.
    filled: u32,
    /// The current record's payload length, once its header is in.
    len: u32,
    applied: u32,
}

impl WalReplay {
    pub const fn new() -> Self {
        Self {
            phase: REPLAY_SEEK,
            hdr: [0u8; 8],
            filled: 0,
            len: 0,
            applied: 0,
        }
    }

    /// Start over from the head of the log, for a newly opened fd.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Replay from the head of the log: seek to 0, then for each record
    /// call `cb` with the payload bytes, at most `budget` records in this
    /// call. Stops on EOF, a CRC mismatch (torn tail), an oversize length
    /// prefix (corrupt tail), or when `cb` returns `false`.
    ///
    /// `scratch` holds a partly read payload across polls, so it must be
    /// the same buffer, unchanged, on every poll of one replay; size it to
    /// `MAX_WAL_REC` (an idle appender's `idle_buffer` serves).
    ///
    /// # Safety
    /// `syscalls` must point at a live `SyscallTable`, and `fd` at the
    /// WAL, untouched by anything else until the replay is done.
    pub unsafe fn poll<F: FnMut(&[u8]) -> bool>(
        &mut self,
        syscalls: &SyscallTable,
        fd: i32,
        scratch: &mut [u8],
        budget: u32,
        mut cb: F,
    ) -> ReplayPoll {
        let mut handed = 0u32;
        loop {
            match self.phase {
                REPLAY_SEEK => {
                    let rc = fs_seek(syscalls, fd, 0);
                    if pending(rc) {
                        return ReplayPoll::Pending;
                    }
                    if rc < 0 {
                        return self.fail(WalReplayError::SeekFailed(rc));
                    }
                    self.phase = REPLAY_HDR;
                    self.filled = 0;
                }
                REPLAY_HDR => {
                    if handed >= budget {
                        return ReplayPoll::Pending;
                    }
                    let at = (self.filled as usize).min(self.hdr.len());
                    let hdr_ptr = self.hdr.as_mut_ptr();
                    match read_some(syscalls, fd, hdr_ptr, at, self.hdr.len()) {
                        ReadSome::Pending(n) => {
                            self.filled = n as u32;
                            return ReplayPoll::Pending;
                        }
                        ReadSome::Failed(rc) => return self.fail(WalReplayError::ReadFailed(rc)),
                        // A clean EOF on a record boundary, or a torn
                        // header: the last record did not finish landing.
                        ReadSome::Eof(_) => return self.done(),
                        ReadSome::Full => {}
                    }
                    let h = self.hdr;
                    let len = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as usize;
                    if len == 0 {
                        // Zero-length record is meaningless — treat as torn.
                        return self.done();
                    }
                    if len > MAX_WAL_REC || len > scratch.len() {
                        // Torn-tail with high-bit garbage in the length
                        // prefix is indistinguishable from real corruption;
                        // either way the rest of the file isn't a clean
                        // record, so stop here and accept whatever already
                        // replayed.
                        return self.done();
                    }
                    self.len = len as u32;
                    self.filled = 0;
                    self.phase = REPLAY_BODY;
                }
                REPLAY_BODY => {
                    let len = (self.len as usize).min(scratch.len());
                    let at = (self.filled as usize).min(len);
                    match read_some(syscalls, fd, scratch.as_mut_ptr(), at, len) {
                        ReadSome::Pending(n) => {
                            self.filled = n as u32;
                            return ReplayPoll::Pending;
                        }
                        ReadSome::Failed(rc) => return self.fail(WalReplayError::ReadFailed(rc)),
                        // Header survived but payload didn't — torn tail.
                        ReadSome::Eof(_) => return self.done(),
                        ReadSome::Full => {}
                    }
                    let h = self.hdr;
                    let expected_crc = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
                    let payload = match scratch.get(..len) {
                        Some(p) => p,
                        None => return self.done(),
                    };
                    if crc32(payload) != expected_crc {
                        // CRC mismatch — torn tail.
                        return self.done();
                    }
                    self.applied = self.applied.wrapping_add(1);
                    handed = handed.wrapping_add(1);
                    if !cb(payload) {
                        return self.done();
                    }
                    self.filled = 0;
                    self.phase = REPLAY_HDR;
                }
                _ => return ReplayPoll::Done(self.applied),
            }
        }
    }

    fn done(&mut self) -> ReplayPoll {
        self.phase = REPLAY_DONE;
        ReplayPoll::Done(self.applied)
    }

    fn fail(&mut self, err: WalReplayError) -> ReplayPoll {
        self.phase = REPLAY_DONE;
        ReplayPoll::Failed(err)
    }
}

impl Default for WalReplay {
    fn default() -> Self {
        Self::new()
    }
}

/// What one `read_some` left.
enum ReadSome {
    /// `[..end]` is filled.
    Full,
    /// The provider has no more for now (`EAGAIN`); this many bytes are
    /// filled. Resume from there on a later step.
    Pending(usize),
    /// End of file with this many bytes filled.
    Eof(usize),
    Failed(i32),
}

/// Fill `buf[at..end]` with `READ`s while bytes keep moving. Stops at
/// the first `EAGAIN` (nothing consumed: resume later from the count it
/// answers), at EOF (`READ` answers 0), or once full. Bounded: every
/// further call has moved at least one byte.
unsafe fn read_some(
    syscalls: &SyscallTable,
    fd: i32,
    buf: *mut u8,
    at: usize,
    end: usize,
) -> ReadSome {
    let mut filled = at;
    while filled < end {
        let want = end - filled;
        let n = (syscalls.provider_call)(fd, FS_READ, buf.add(filled), want);
        if pending(n) {
            return ReadSome::Pending(filled);
        }
        if n < 0 {
            return ReadSome::Failed(n);
        }
        if n == 0 {
            return ReadSome::Eof(filled);
        }
        // Clamped: a provider reporting more than it was offered must
        // not walk the cursor past the buffer.
        filled += (n as usize).min(want);
    }
    ReadSome::Full
}

pub unsafe fn wal_close(syscalls: &SyscallTable, fd: i32) -> i32 {
    (syscalls.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0)
}

// ── Resumable rotation ────────────────────────────────────────────
//
// Rotate a WAL by atomic replacement: stage an empty log beside it,
// fence it, then rename it over the live path.
//
// For WALs whose records are DELIVERY buffers — safe to discard once
// every logged entry has been acknowledged durable downstream — this
// bounds replay work at the last unacknowledged tail instead of the
// full history.
//
// The replacement has to be atomic. Unlinking and recreating leaves a
// window with no log at all, and a crash inside it loses every record
// the caller still expected to replay; the FS contract has no
// truncate, so there is no in-place way to empty a file either.
// `RENAME` publishes the new name and its parents durably, which
// makes the crash-visible outcomes exactly two: the old log, or the
// new empty one.
//
// Every stage of it may be undecided inside a call — `UNLINK`,
// `OPEN_CREATE`, `FSYNC` and `RENAME` answer `EINPROGRESS`, `WRITE`
// moves a short count or answers `EAGAIN` — so the rotation is a step
// machine. The caller polls a `WalRotator` once per step with the same
// path, seed count and seed buffer until it answers `Rotated`,
// `Skipped` or `Lost`, and resumes where it stopped, never from the
// top.
//
// While it runs the caller must append nothing to the live log: the
// rename discards the old file, and any record appended to it after the
// staging copy was seeded would be lost with it. `busy()` is the gate.

/// Outcome of one `WalRotator::poll`.
pub enum RotateOutcome {
    /// Not decided yet. Poll again on a later step; append nothing to
    /// the live log meanwhile.
    Pending,
    /// The log was replaced by a fresh one (holding the seed records).
    /// The old fd is closed; this is the fd to use from here.
    Rotated(i32),
    /// The provider cannot replace a name atomically, or the staging log
    /// could not be built, so the log was left alone and the caller's
    /// existing fd is still valid. Rotation only bounds replay work — a
    /// longer log is a cost, losing one is not — so declining is the safe
    /// direction.
    Skipped,
    /// The log was replaced but could not be reopened: the caller's fd
    /// is closed and it holds no usable WAL, so it must fail closed.
    Lost,
}

const ROT_IDLE: u8 = 0;
const ROT_CAPS: u8 = 1;
const ROT_CLEAR: u8 = 2;
const ROT_CREATE: u8 = 3;
const ROT_SEED: u8 = 4;
const ROT_FSYNC: u8 = 5;
const ROT_RENAME: u8 = 6;
const ROT_REOPEN: u8 = 7;
/// Abandoning: remove the staging log, then answer `Skipped`.
const ROT_DISCARD: u8 = 8;

/// The rotation's staging suffix. Typed by the register's length, so a
/// suffix that grew past what `RENAME` is sized for does not compile.
const ROT_SUFFIX: [u8; super::fs_names::WAL_STAGE_SUFFIX_LEN] = *b".rot";

/// Room for the longest WAL path plus the rotation suffix.
const ROTATE_PATH_BUF: usize = super::limits::WAL_PATH_BUF + ROT_SUFFIX.len();

// Every rotation's rename fits the frame `fs_names::rename` builds: the
// longest staging name onto the longest WAL path.
const _: () = assert!(
    ROTATE_PATH_BUF + super::limits::WAL_PATH_BUF <= super::fs_names::RENAME_PATHS_MAX,
    "a WAL at its longest path could not be rotated"
);

/// One WAL rotation in flight. Zeroed memory is a valid idle rotator.
#[repr(C)]
pub struct WalRotator {
    phase: u8,
    /// The current seed record is framed in the caller's buffer.
    framed: u8,
    stage_len: u16,
    stage_fd: i32,
    /// The next seed record to frame.
    seed_at: u32,
    frame_len: u32,
    written: u32,
    stage: [u8; ROTATE_PATH_BUF],
    opener: WalOpener,
}

impl WalRotator {
    pub const fn new() -> Self {
        Self {
            phase: ROT_IDLE,
            framed: 0,
            stage_len: 0,
            stage_fd: -1,
            seed_at: 0,
            frame_len: 0,
            written: 0,
            stage: [0u8; ROTATE_PATH_BUF],
            opener: WalOpener::new(),
        }
    }

    /// True while a rotation is undecided. The caller appends nothing to
    /// the live log while this holds.
    pub fn busy(&self) -> bool {
        self.phase != ROT_IDLE
    }

    /// `rotate_seeded` with no seed records.
    ///
    /// # Safety
    /// As for `rotate_seeded`.
    pub unsafe fn rotate(
        &mut self,
        syscalls: &SyscallTable,
        fd: i32,
        path: &[u8],
    ) -> RotateOutcome {
        let mut none = [0u8; 0];
        self.rotate_seeded(syscalls, fd, path, 0, &mut none, |_, _| Some(0))
    }

    /// Drive a rotation of the log at `path` (open as `fd`) one step
    /// further, starting one when idle.
    ///
    /// For a log that carries state no snapshot holds, the replacement is
    /// written with `seed_count` records before it is fenced and renamed
    /// into place, so the crash-visible outcomes stay exactly two — the
    /// old log, or the new one already holding them. Seeding after the
    /// rename instead would open a window in which a crash boots from a
    /// log that has lost that state.
    ///
    /// `seed(i, payload)` writes record `i` into `payload` and answers
    /// its length: `Some(0)` skips it, `None` abandons the rotation (the
    /// old log stays in service, as for any other `Skipped`). It is asked
    /// for each record once, when the record is framed. `scratch` holds
    /// one framed record across polls — the same buffer, unchanged, on
    /// every poll of one rotation; `seed` receives it past the 8-byte
    /// header.
    ///
    /// # Safety
    /// `syscalls` must point at a live `SyscallTable` and `fd` at the
    /// WAL. `path`, `seed_count` and `scratch` are the same on every poll
    /// of one rotation.
    pub unsafe fn rotate_seeded<F: FnMut(usize, &mut [u8]) -> Option<usize>>(
        &mut self,
        syscalls: &SyscallTable,
        fd: i32,
        path: &[u8],
        seed_count: usize,
        scratch: &mut [u8],
        mut seed: F,
    ) -> RotateOutcome {
        if self.phase == ROT_IDLE {
            let suffix = ROT_SUFFIX;
            // A path past `WAL_PATH_BUF` is one no WAL module holds.
            if path.len() + suffix.len() > self.stage.len() {
                return RotateOutcome::Skipped;
            }
            let slen = path.len() + suffix.len();
            for (d, b) in self.stage.iter_mut().zip(path.iter().chain(suffix.iter())) {
                *d = *b;
            }
            self.stage_len = slen as u16;
            self.stage_fd = -1;
            self.seed_at = 0;
            self.framed = 0;
            self.frame_len = 0;
            self.written = 0;
            self.phase = ROT_CAPS;
        }
        let slen = (self.stage_len as usize).min(self.stage.len());
        loop {
            // Re-borrowed per stage: the stage path is fixed for the
            // rotation, so every re-ask frames the same bytes.
            let stage: &[u8] = &*(&self.stage[..slen] as *const [u8]);
            match self.phase {
                ROT_CAPS => {
                    // An unanswered query is not "cannot": ask again on a
                    // later step, and record nothing.
                    let caps = match super::fs_names::caps(syscalls.provider_call) {
                        Some(c) => c,
                        None => return RotateOutcome::Pending,
                    };
                    if caps & super::fs_names::CAP_RENAME == 0 {
                        return self.skipped();
                    }
                    self.phase = ROT_CLEAR;
                }
                ROT_CLEAR => {
                    // A crashed attempt can leave staging behind, and
                    // `OPEN_CREATE` does not truncate — a surviving file
                    // would be renamed into place still carrying its
                    // records. Gone already is as good as removed.
                    let rc = super::fs_names::unlink(syscalls.provider_call, stage);
                    if pending(rc) {
                        return RotateOutcome::Pending;
                    }
                    if rc < 0 && rc != super::fs_names::ENOENT {
                        return self.skipped();
                    }
                    self.phase = ROT_CREATE;
                }
                ROT_CREATE => {
                    let sfd = (syscalls.provider_call)(
                        -1,
                        FS_OPEN_CREATE,
                        stage.as_ptr() as *mut u8,
                        stage.len(),
                    );
                    if pending(sfd) {
                        return RotateOutcome::Pending;
                    }
                    if sfd < 0 {
                        return self.skipped();
                    }
                    self.stage_fd = sfd;
                    self.phase = ROT_SEED;
                }
                ROT_SEED => {
                    if self.framed == 0 {
                        if self.seed_at as usize >= seed_count {
                            self.phase = ROT_FSYNC;
                            continue;
                        }
                        match frame_seed_record(scratch, &mut seed, self.seed_at as usize) {
                            Some(0) => {
                                self.seed_at = self.seed_at.wrapping_add(1);
                                continue;
                            }
                            Some(n) => {
                                self.frame_len = n as u32;
                                self.written = 0;
                                self.framed = 1;
                            }
                            None => {
                                self.phase = ROT_DISCARD;
                                continue;
                            }
                        }
                    }
                    let end = (self.frame_len as usize).min(scratch.len());
                    let off = (self.written as usize).min(end);
                    let want = end - off;
                    let rc = (syscalls.provider_call)(
                        self.stage_fd,
                        FS_WRITE,
                        scratch.as_mut_ptr().add(off),
                        want,
                    );
                    if pending(rc) {
                        return RotateOutcome::Pending;
                    }
                    if rc <= 0 {
                        self.phase = ROT_DISCARD;
                        continue;
                    }
                    // Clamped: a provider reporting more than it was
                    // offered must not walk the cursor past the frame.
                    self.written = self.written.wrapping_add((rc as usize).min(want) as u32);
                    if self.written as usize >= end {
                        self.framed = 0;
                        self.seed_at = self.seed_at.wrapping_add(1);
                    }
                }
                ROT_FSYNC => {
                    // Fence before close: `CLOSE` reports no writeback
                    // failure, so durability comes only from here.
                    let rc =
                        (syscalls.provider_call)(self.stage_fd, FS_FSYNC, core::ptr::null_mut(), 0);
                    if pending(rc) {
                        return RotateOutcome::Pending;
                    }
                    if rc < 0 {
                        self.phase = ROT_DISCARD;
                        continue;
                    }
                    let _ = wal_close(syscalls, self.stage_fd);
                    self.stage_fd = -1;
                    self.phase = ROT_RENAME;
                }
                ROT_RENAME => {
                    let rc = super::fs_names::rename(syscalls.provider_call, stage, path);
                    if pending(rc) {
                        return RotateOutcome::Pending;
                    }
                    if rc < 0 {
                        self.phase = ROT_DISCARD;
                        continue;
                    }
                    // The old log is unreachable from here; only now is
                    // the caller's fd spent.
                    let _ = wal_close(syscalls, fd);
                    self.phase = ROT_REOPEN;
                }
                ROT_REOPEN => match self.opener.poll(syscalls, path, true) {
                    OpenPoll::Pending => return RotateOutcome::Pending,
                    OpenPoll::Ready(new_fd) => {
                        self.phase = ROT_IDLE;
                        return RotateOutcome::Rotated(new_fd);
                    }
                    OpenPoll::Failed(_) => {
                        self.phase = ROT_IDLE;
                        return RotateOutcome::Lost;
                    }
                },
                ROT_DISCARD => {
                    if self.stage_fd >= 0 {
                        let _ = wal_close(syscalls, self.stage_fd);
                        self.stage_fd = -1;
                    }
                    // Leftover staging is harmless — the next rotation
                    // clears it first — so only an undecided removal is
                    // waited for.
                    let rc = super::fs_names::unlink(syscalls.provider_call, stage);
                    if pending(rc) {
                        return RotateOutcome::Pending;
                    }
                    return self.skipped();
                }
                _ => return self.skipped(),
            }
        }
    }

    fn skipped(&mut self) -> RotateOutcome {
        self.phase = ROT_IDLE;
        RotateOutcome::Skipped
    }
}

impl Default for WalRotator {
    fn default() -> Self {
        Self::new()
    }
}

/// Frame seed record `i` into `scratch`: `Some(frame_len)`, `Some(0)`
/// when the seed skips it, `None` to abandon the rotation — the seed
/// refused, or the record does not fit a frame.
fn frame_seed_record<F: FnMut(usize, &mut [u8]) -> Option<usize>>(
    scratch: &mut [u8],
    seed: &mut F,
    i: usize,
) -> Option<usize> {
    let n = match scratch.get_mut(8..) {
        Some(payload) => seed(i, payload)?,
        None => return None,
    };
    if n == 0 {
        return Some(0);
    }
    if n > MAX_WAL_REC {
        return None;
    }
    let frame_len = 8 + n;
    let crc = match scratch.get(8..frame_len) {
        Some(payload) => crc32(payload),
        None => return None,
    };
    let len_le = (n as u32).to_le_bytes();
    let crc_le = crc.to_le_bytes();
    let hdr = scratch.get_mut(..8)?;
    for (d, b) in hdr.iter_mut().zip(len_le.iter().chain(crc_le.iter())) {
        *d = *b;
    }
    Some(frame_len)
}

// ── CRC32 (IEEE 802.3 polynomial, table-based, no_std) ────────────
//
// The table is built at compile time, so the module carries it as data
// and computes nothing at load.

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

/// The `wal_path` a module's params blob carries: the TLV block the
/// fluxor build packs from a graph's parameters (`0xFE 0x01` magic, then
/// `[tag][len][bytes]` records, tag 1 = `wal_path`, tag 0xFF = end).
/// Four modules take a WAL path this way, so the parser lives here
/// rather than four times over.
///
/// `Ok(0)` when the blob carries no path: a channel-only module. `Err`
/// when it is not a TLV block, or names a path longer than `out` — a
/// path is never cut short, since a shortened one can name a file that
/// opens, and the module would log somewhere no one configured.
///
/// # Safety
/// `params` must point to `params_len` readable bytes.
pub unsafe fn decode_wal_path(
    params: *const u8,
    params_len: usize,
    out: &mut [u8],
) -> Result<usize, ()> {
    if params.is_null() || params_len == 0 {
        return Ok(0);
    }
    if params_len < 4 || *params != 0xFE || *params.add(1) != 0x01 {
        return Err(());
    }
    let mut off = 4usize;
    while off + 2 <= params_len {
        let tag = *params.add(off);
        let elen = *params.add(off + 1) as usize;
        off += 2;
        if tag == 0xFF {
            break;
        }
        if tag == 1 {
            if off + elen > params_len || elen > out.len() {
                return Err(());
            }
            let src = params.add(off);
            let mut i = 0usize;
            while i < elen {
                out[i] = *src.add(i);
                i += 1;
            }
            return Ok(elen);
        }
        off += elen;
    }
    Ok(0)
}
