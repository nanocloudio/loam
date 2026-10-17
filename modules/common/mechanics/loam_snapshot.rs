// Namespace snapshot file: the durable, binary-searchable record
// of every binding, letting the PIC arena be a HOT CACHE instead
// of the whole set. Consumed by namespace_pic_body.
//
// Layout: 16-byte header + `count` fixed-size records sorted by key —
// the root's bytes, then the path's — so a lookup is a binary search
// and a listing in name order is a search to its cursor and a
// sequential read from there:
//
//   header  [magic u32 "LSNP"][count u32][generation u64]
//   record  [root_len u8][root MAX_ROOT][path_len u16][path MAX_PATH]
//           [revision u64][kind u8][oid_len u8][oid MAX_OID]
//           [stamp_ms u64][size u64][ctype_len u8][ctype CONTENT_TYPE_MAX]
//
// The key and metadata ceilings come from `loam_limits.rs`, so
// REC_SIZE is per capacity profile rather than a number stated here. A snapshot is therefore a node-local artefact
// of one profile: a file written by the other profile fails the
// `size == SNAP_HDR + count * REC_SIZE` validity check on open and
// is treated as the invalid generation, which is the same path a
// torn write takes. That is deliberate — silently reinterpreting
// another profile's records would mispair keys with revisions.
//
// Crash safety via ALTERNATING GENERATIONS: compaction writes to
// whichever of `<wal>.snapA` / `<wal>.snapB` holds the OLDER
// generation; open picks the valid file (size == 16 + count*348)
// with the higher generation. A torn write leaves the other
// generation intact, and WAL replay is revision-gated, so any
// (snapshot, wal-tail) pairing replays to a correct arena.
//
// Same include discipline as wal_io.rs: raw fs-contract calls via
// the module's SyscallTable, and the same non-blocking rule — no call
// here waits on the device, so opening, reading and writing a
// generation are each resumable across steps (see the sections below).
// `fs_names` is mounted beside this file by every includer.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use core::convert::TryInto;

const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_OPEN_CREATE: u32 = 0x0909;

pub const SNAP_MAGIC: u32 = u32::from_le_bytes(*b"LSNP");
pub const SNAP_HDR: usize = 16;
/// Key and metadata ceilings, from the single register in `loam_limits.rs`.
pub use super::limits::{CONTENT_TYPE_MAX, MAX_OBJECT_ID as MAX_OID, MAX_PATH, MAX_ROOT};

/// Derived, not chosen: the fixed record width that makes the file
/// binary-searchable. Moves when any ceiling above moves.
pub const REC_SIZE: usize =
    1 + MAX_ROOT + 2 + MAX_PATH + 8 + 1 + 1 + MAX_OID + 8 + 8 + 1 + CONTENT_TYPE_MAX;

pub use super::hash::key_cmp;

/// `kind` value marking a tombstone: a deleted key, kept in the arena
/// and in the snapshot at the revision it was deleted at, which is what
/// a later bind of the key must exceed. Snapshot readers treat it as
/// absent.
pub const KIND_TOMBSTONE: u8 = 0xFE;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SnapRecord {
    pub root_len: u8,
    pub root: [u8; MAX_ROOT],
    pub path_len: u16,
    pub path: [u8; MAX_PATH],
    pub revision: u64,
    pub kind: u8,
    pub oid_len: u8,
    pub oid: [u8; MAX_OID],
    pub stamp_ms: u64,
    pub size: u64,
    pub ctype_len: u8,
    pub ctype: [u8; CONTENT_TYPE_MAX],
}

impl SnapRecord {
    pub const fn empty() -> Self {
        Self {
            root_len: 0,
            root: [0; MAX_ROOT],
            path_len: 0,
            path: [0; MAX_PATH],
            revision: 0,
            kind: 0,
            oid_len: 0,
            oid: [0; MAX_OID],
            stamp_ms: 0,
            size: 0,
            ctype_len: 0,
            ctype: [0; CONTENT_TYPE_MAX],
        }
    }

    pub fn root(&self) -> &[u8] {
        &self.root[..(self.root_len as usize).min(MAX_ROOT)]
    }

    pub fn path(&self) -> &[u8] {
        &self.path[..(self.path_len as usize).min(MAX_PATH)]
    }

    pub fn oid(&self) -> &[u8] {
        &self.oid[..(self.oid_len as usize).min(MAX_OID)]
    }

    pub fn content_type(&self) -> &[u8] {
        &self.ctype[..(self.ctype_len as usize).min(CONTENT_TYPE_MAX)]
    }

    /// This record's key against `(root, path)`.
    pub fn cmp_key(&self, root: &[u8], path: &[u8]) -> core::cmp::Ordering {
        key_cmp(self.root(), self.path(), root, path)
    }

    pub fn encode(&self, out: &mut [u8]) -> bool {
        if out.len() < REC_SIZE {
            return false;
        }
        let mut o = 0;
        out[o] = self.root_len;
        out[o + 1..o + 1 + MAX_ROOT].copy_from_slice(&self.root);
        o += 1 + MAX_ROOT;
        out[o..o + 2].copy_from_slice(&self.path_len.to_le_bytes());
        out[o + 2..o + 2 + MAX_PATH].copy_from_slice(&self.path);
        o += 2 + MAX_PATH;
        out[o..o + 8].copy_from_slice(&self.revision.to_le_bytes());
        o += 8;
        out[o] = self.kind;
        out[o + 1] = self.oid_len;
        out[o + 2..o + 2 + MAX_OID].copy_from_slice(&self.oid);
        o += 2 + MAX_OID;
        out[o..o + 8].copy_from_slice(&self.stamp_ms.to_le_bytes());
        out[o + 8..o + 16].copy_from_slice(&self.size.to_le_bytes());
        o += 16;
        out[o] = self.ctype_len;
        out[o + 1..o + 1 + CONTENT_TYPE_MAX].copy_from_slice(&self.ctype);
        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() < REC_SIZE {
            return None;
        }
        let mut r = Self::empty();
        let mut o = 0;
        r.root_len = src[o];
        r.root.copy_from_slice(&src[o + 1..o + 1 + MAX_ROOT]);
        o += 1 + MAX_ROOT;
        r.path_len = u16::from_le_bytes(src[o..o + 2].try_into().ok()?);
        r.path.copy_from_slice(&src[o + 2..o + 2 + MAX_PATH]);
        o += 2 + MAX_PATH;
        r.revision = u64::from_le_bytes(src[o..o + 8].try_into().ok()?);
        o += 8;
        r.kind = src[o];
        r.oid_len = src[o + 1];
        r.oid.copy_from_slice(&src[o + 2..o + 2 + MAX_OID]);
        o += 2 + MAX_OID;
        r.stamp_ms = u64::from_le_bytes(src[o..o + 8].try_into().ok()?);
        r.size = u64::from_le_bytes(src[o + 8..o + 16].try_into().ok()?);
        o += 16;
        r.ctype_len = src[o];
        r.ctype
            .copy_from_slice(&src[o + 1..o + 1 + CONTENT_TYPE_MAX]);
        if r.root_len as usize > MAX_ROOT
            || r.path_len as usize > MAX_PATH
            || r.oid_len as usize > MAX_OID
            || r.ctype_len as usize > CONTENT_TYPE_MAX
        {
            return None;
        }
        Some(r)
    }
}

/// A generation file's suffix after its WAL path: `.snapA` / `.snapB`.
const SNAP_SUFFIX_LEN: usize = 6;

/// Longest generation-file path: the longest WAL path plus its `.snapA`
/// suffix. Derived, so every WAL path a module accepts has both of its
/// generation names.
pub const SNAP_PATH_MAX: usize = super::limits::WAL_PATH_BUF + SNAP_SUFFIX_LEN;

/// Build `<wal_path>.snapA` / `.snapB` into `out`; returns len, or 0
/// when it does not fit.
///
/// The suffix is built a byte at a time rather than chosen between two
/// literals: a selection of `&'static [u8]` literals can land in
/// `.rodata` as a table of pointers the PIC loader never relocates.
pub fn snap_path(wal_path: &[u8], which: u8, out: &mut [u8]) -> usize {
    let n = wal_path.len() + SNAP_SUFFIX_LEN;
    if out.len() < n {
        return 0;
    }
    for (d, b) in out.iter_mut().zip(wal_path.iter()) {
        *d = *b;
    }
    let tag = if which == 0 { b'A' } else { b'B' };
    let suffix: [u8; SNAP_SUFFIX_LEN] = [b'.', b's', b'n', b'a', b'p', tag];
    if let Some(tail) = out.get_mut(wal_path.len()..n) {
        for (d, b) in tail.iter_mut().zip(suffix.iter()) {
            *d = *b;
        }
    }
    n
}

// ── Non-blocking reads ─────────────────────────────────────────────
//
// No `fs` call waits on the device. A `READ` over sectors the provider
// has not cached starts fetching them and answers `EAGAIN` (or the
// short count of what it had), and `SEEK` / `STAT` / `OPEN` answer
// `EAGAIN` while what they need is being fetched. So every read here is
// tri-state: a result, `Pending` (ask again on a later step — the
// provider is fetching meanwhile), or `Failed`. `Pending` is never an
// absence and never a failure: a lookup that met it is deferred by its
// caller, not answered.
//
// Reads keep no state across steps. A record read that stops short is
// started again from its seek on the next ask, which costs a re-read
// of bytes the provider now has cached and nothing else.

/// Outcome of one snapshot read.
#[derive(Clone, Copy)]
pub enum SnapRead<T> {
    Ready(T),
    /// Not decided yet: the provider is fetching. Ask again on a later
    /// step. Nothing may be concluded from it.
    Pending,
    /// The read failed, or the file no longer matches its header.
    Failed,
}

/// SAFETY: `syscalls` must be a valid provider table.
unsafe fn seek(syscalls: &super::SyscallTable, fd: i32, off: u32) -> SnapRead<()> {
    let b = off.to_le_bytes();
    let rc = (syscalls.provider_call)(fd, FS_SEEK, b.as_ptr() as *mut u8, 4);
    if super::fs_names::pending(rc) {
        return SnapRead::Pending;
    }
    if rc < 0 {
        return SnapRead::Failed;
    }
    SnapRead::Ready(())
}

/// Fill `buf` from the descriptor's offset, while bytes keep moving.
/// Bounded: every further call has moved at least one byte. A `READ`
/// answering 0 before `buf` is full is the end of a file that its own
/// header says is longer — a torn or replaced file, so a failure.
///
/// SAFETY: `syscalls` must be a valid provider table.
unsafe fn read_exact(syscalls: &super::SyscallTable, fd: i32, buf: &mut [u8]) -> SnapRead<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let want = buf.len() - filled;
        let n = (syscalls.provider_call)(fd, FS_READ, buf.as_mut_ptr().add(filled), want);
        if super::fs_names::pending(n) {
            return SnapRead::Pending;
        }
        if n <= 0 {
            return SnapRead::Failed;
        }
        // Clamped: a provider reporting more than it was offered must
        // not walk the cursor past the buffer.
        filled += (n as usize).min(want);
    }
    SnapRead::Ready(())
}

/// An open, validated snapshot: fd + record count + generation.
#[derive(Clone, Copy)]
pub struct OpenSnapshot {
    pub fd: i32,
    pub count: u32,
    pub generation: u64,
}

impl OpenSnapshot {
    pub const fn none() -> Self {
        Self {
            fd: -1,
            count: 0,
            generation: 0,
        }
    }
}

/// Outcome of one `SnapOpener::poll`.
#[derive(Clone, Copy)]
pub enum SnapOpenPoll {
    /// Not decided yet. Poll again on a later step, with the same path.
    Pending,
    /// Open and validated.
    Opened(OpenSnapshot),
    /// Missing, torn, of another capacity profile, or unreadable. Any
    /// fd the opener held is closed.
    Invalid,
}

const SO_OPEN: u8 = 0;
const SO_SEEK: u8 = 1;
const SO_HDR: u8 = 2;
const SO_STAT: u8 = 3;

/// One generation file being opened and validated. Zeroed memory is a
/// valid opener that has not started.
///
/// `OPEN`, `SEEK`, `READ` and `STAT` may each answer `EAGAIN`; the
/// opener stops there with its place kept and resumes on the next poll.
/// Only a decided answer moves it on, so a provider still fetching is
/// never read as a missing file.
#[repr(C)]
pub struct SnapOpener {
    phase: u8,
    /// The descriptor, biased by one so zeroed memory holds none.
    fd_plus1: i32,
    /// The header, once read whole; validated against the size.
    hdr: [u8; SNAP_HDR],
}

impl SnapOpener {
    pub const fn new() -> Self {
        Self {
            phase: SO_OPEN,
            fd_plus1: 0,
            hdr: [0u8; SNAP_HDR],
        }
    }

    /// Drive the open of `path` one step further.
    ///
    /// SAFETY: valid syscalls table; `path` is the same on every poll of
    /// one open.
    pub unsafe fn poll(&mut self, syscalls: &super::SyscallTable, path: &[u8]) -> SnapOpenPoll {
        loop {
            match self.phase {
                SO_OPEN => {
                    let fd =
                        (syscalls.provider_call)(-1, FS_OPEN, path.as_ptr() as *mut u8, path.len());
                    if super::fs_names::pending(fd) {
                        return SnapOpenPoll::Pending;
                    }
                    if fd < 0 {
                        // A decided refusal: the generation is absent.
                        *self = Self::new();
                        return SnapOpenPoll::Invalid;
                    }
                    self.fd_plus1 = fd + 1;
                    self.phase = SO_SEEK;
                }
                SO_SEEK => match seek(syscalls, self.fd_plus1 - 1, 0) {
                    SnapRead::Ready(()) => self.phase = SO_HDR,
                    SnapRead::Pending => return SnapOpenPoll::Pending,
                    SnapRead::Failed => return self.invalid(syscalls),
                },
                SO_HDR => {
                    // An `EAGAIN` consumed nothing, but a short count
                    // before it moved the offset, so a re-ask starts
                    // again from the seek.
                    let mut hdr = [0u8; SNAP_HDR];
                    match read_exact(syscalls, self.fd_plus1 - 1, &mut hdr) {
                        SnapRead::Ready(()) => {}
                        SnapRead::Pending => {
                            self.phase = SO_SEEK;
                            return SnapOpenPoll::Pending;
                        }
                        SnapRead::Failed => return self.invalid(syscalls),
                    }
                    self.hdr = hdr;
                    self.phase = SO_STAT;
                }
                _ => {
                    let h = self.hdr;
                    let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
                    let count = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
                    let generation =
                        u64::from_le_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]);
                    if magic != SNAP_MAGIC {
                        return self.invalid(syscalls);
                    }
                    let mut stat = [0u8; 8];
                    let rc = (syscalls.provider_call)(
                        self.fd_plus1 - 1,
                        FS_STAT,
                        stat.as_mut_ptr(),
                        stat.len(),
                    );
                    if super::fs_names::pending(rc) {
                        return SnapOpenPoll::Pending;
                    }
                    if rc < 0 {
                        return self.invalid(syscalls);
                    }
                    let size = u32::from_le_bytes([stat[0], stat[1], stat[2], stat[3]]) as u64;
                    let expect = SNAP_HDR as u64 + count as u64 * REC_SIZE as u64;
                    if size != expect {
                        return self.invalid(syscalls);
                    }
                    let snap = OpenSnapshot {
                        fd: self.fd_plus1 - 1,
                        count,
                        generation,
                    };
                    *self = Self::new();
                    return SnapOpenPoll::Opened(snap);
                }
            }
        }
    }

    unsafe fn invalid(&mut self, syscalls: &super::SyscallTable) -> SnapOpenPoll {
        self.abandon(syscalls);
        SnapOpenPoll::Invalid
    }

    /// Give up an open in flight, closing any fd it holds. A read-only
    /// descriptor owes no fence.
    ///
    /// SAFETY: valid syscalls table.
    pub unsafe fn abandon(&mut self, syscalls: &super::SyscallTable) {
        if self.fd_plus1 > 0 {
            let _ = (syscalls.provider_call)(self.fd_plus1 - 1, FS_CLOSE, core::ptr::null_mut(), 0);
        }
        *self = Self::new();
    }
}

/// Outcome of one `SnapBestOpener::poll`.
#[derive(Clone, Copy)]
pub enum BestPoll {
    Pending,
    /// Both generations decided: the best valid one and its slot, or
    /// none.
    Done(Option<(OpenSnapshot, u8)>),
}

/// Opens the best (highest-generation valid) snapshot for a WAL path,
/// one generation after the other, across as many steps as the provider
/// needs. Zeroed memory is a valid opener that has not started.
#[repr(C)]
pub struct SnapBestOpener {
    which: u8,
    has_best: u8,
    best_slot: u8,
    best: OpenSnapshot,
    one: SnapOpener,
}

impl SnapBestOpener {
    pub const fn new() -> Self {
        Self {
            which: 0,
            has_best: 0,
            best_slot: 0,
            best: OpenSnapshot::none(),
            one: SnapOpener::new(),
        }
    }

    /// SAFETY: valid syscalls table; `wal_path` is the same on every
    /// poll of one open.
    pub unsafe fn poll(&mut self, syscalls: &super::SyscallTable, wal_path: &[u8]) -> BestPoll {
        let mut path = [0u8; SNAP_PATH_MAX];
        while self.which < 2 {
            let n = snap_path(wal_path, self.which, &mut path);
            let Some(p) = path.get(..n).filter(|p| !p.is_empty()) else {
                self.which += 1;
                continue;
            };
            match self.one.poll(syscalls, p) {
                SnapOpenPoll::Pending => return BestPoll::Pending,
                SnapOpenPoll::Invalid => {}
                SnapOpenPoll::Opened(s) => {
                    if self.has_best != 0 && self.best.generation >= s.generation {
                        let _ = (syscalls.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
                    } else {
                        if self.has_best != 0 {
                            let _ = (syscalls.provider_call)(
                                self.best.fd,
                                FS_CLOSE,
                                core::ptr::null_mut(),
                                0,
                            );
                        }
                        self.best = s;
                        self.best_slot = self.which;
                        self.has_best = 1;
                    }
                }
            }
            self.which += 1;
        }
        let out = if self.has_best != 0 {
            Some((self.best, self.best_slot))
        } else {
            None
        };
        *self = Self::new();
        BestPoll::Done(out)
    }

    /// Give up, closing everything held.
    ///
    /// SAFETY: valid syscalls table.
    pub unsafe fn abandon(&mut self, syscalls: &super::SyscallTable) {
        self.one.abandon(syscalls);
        if self.has_best != 0 {
            let _ = (syscalls.provider_call)(self.best.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        }
        *self = Self::new();
    }
}

/// Read record `idx`. `Failed` for an index past the end.
///
/// SAFETY: valid syscalls table; `snap.fd` open.
pub unsafe fn snap_read_at(
    syscalls: &super::SyscallTable,
    snap: &OpenSnapshot,
    idx: u32,
) -> SnapRead<SnapRecord> {
    if idx >= snap.count {
        return SnapRead::Failed;
    }
    match seek(syscalls, snap.fd, SNAP_HDR as u32 + idx * REC_SIZE as u32) {
        SnapRead::Ready(()) => {}
        SnapRead::Pending => return SnapRead::Pending,
        SnapRead::Failed => return SnapRead::Failed,
    }
    let mut buf = [0u8; REC_SIZE];
    match read_exact(syscalls, snap.fd, &mut buf) {
        SnapRead::Ready(()) => {}
        SnapRead::Pending => return SnapRead::Pending,
        SnapRead::Failed => return SnapRead::Failed,
    }
    match SnapRecord::decode(&buf) {
        Some(r) => SnapRead::Ready(r),
        None => SnapRead::Failed,
    }
}

/// Binary-search for the record keyed `(root, path)`: ~log2(count)
/// seeks. `Ready(None)` is a decided absence; a probe still being
/// fetched answers `Pending` for the whole search, which the caller
/// asks again — the probes before it are cached by then.
///
/// SAFETY: valid syscalls table; `snap.fd` open.
pub unsafe fn snap_search(
    syscalls: &super::SyscallTable,
    snap: &OpenSnapshot,
    root: &[u8],
    path: &[u8],
) -> SnapRead<Option<SnapRecord>> {
    let (mut lo, mut hi) = (0u32, snap.count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let rec = match snap_read_at(syscalls, snap, mid) {
            SnapRead::Ready(r) => r,
            SnapRead::Pending => return SnapRead::Pending,
            SnapRead::Failed => return SnapRead::Failed,
        };
        match rec.cmp_key(root, path) {
            core::cmp::Ordering::Equal => return SnapRead::Ready(Some(rec)),
            core::cmp::Ordering::Less => lo = mid + 1,
            core::cmp::Ordering::Greater => hi = mid,
        }
    }
    SnapRead::Ready(None)
}

/// Index of the first record whose key sorts strictly after
/// `(root, after)`: where a name-ordered listing resumes.
///
/// SAFETY: valid syscalls table; `snap.fd` open.
pub unsafe fn snap_seek_after(
    syscalls: &super::SyscallTable,
    snap: &OpenSnapshot,
    root: &[u8],
    after: &[u8],
) -> SnapRead<u32> {
    let (mut lo, mut hi) = (0u32, snap.count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let rec = match snap_read_at(syscalls, snap, mid) {
            SnapRead::Ready(r) => r,
            SnapRead::Pending => return SnapRead::Pending,
            SnapRead::Failed => return SnapRead::Failed,
        };
        if rec.cmp_key(root, after) == core::cmp::Ordering::Greater {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    SnapRead::Ready(lo)
}

// ── Resumable writer ───────────────────────────────────────────────
//
// Writing a generation is a sequence of calls none of which decides on
// the device inside the call: `UNLINK`, `OPEN_CREATE`, `FSYNC` and
// `FSYNC_NAME` may answer `EINPROGRESS` (re-asked byte-identically on a
// later step until they decide), `WRITE` moves a short count or answers
// `EAGAIN`, and `SEEK` may answer `EAGAIN`. So the writer is a step
// machine held in the caller's state, and it owns the bytes it has
// staged: a record handed to `WRITE` is the provider's only for the
// prefix it accepted, so the rest stays here until it is taken.
//
//   open    UNLINK → OPEN_CREATE → placeholder header
//   append  one record staged at a time, written across steps
//   finish  FSYNC → SEEK 0 → real header → FSYNC → FSYNC_NAME → CLOSE
//
// `CLOSE` reports no writeback failure, so the generation is durable
// only on the fences before it. `FSYNC` covers the file's bytes and
// size; `FSYNC_NAME` covers the directory entry `OPEN_CREATE` minted,
// without which a power cut could leave the generation's name absent
// after the WAL that held its records has been rotated away.

/// Outcome of one writer poll.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WritePoll {
    /// Not decided yet. Poll again on a later step.
    Pending,
    /// This stage is done.
    Ready,
    /// The generation cannot be written. Abandon it.
    Failed,
}

const W_IDLE: u8 = 0;
const W_UNLINK: u8 = 1;
const W_CREATE: u8 = 2;
const W_PLACEHOLDER: u8 = 3;
const W_RECORDS: u8 = 4;
const W_FSYNC_RECORDS: u8 = 5;
const W_SEEK: u8 = 6;
const W_HEADER: u8 = 7;
const W_FSYNC_HEADER: u8 = 8;
const W_NAME: u8 = 9;
const W_DONE: u8 = 10;

/// Streaming snapshot writer (used by the incremental compactor).
/// Zeroed memory is a valid idle writer.
#[repr(C)]
pub struct SnapWriter {
    /// The generation file's descriptor, biased by one so zeroed memory
    /// holds none.
    fd_plus1: i32,
    /// Records staged so far, the one in `stage` included.
    pub count: u32,
    pub generation: u64,
    phase: u8,
    path_len: u16,
    path: [u8; SNAP_PATH_MAX],
    /// Bytes owed to the file: `stage[written..len]` is not yet taken.
    stage_len: u32,
    stage_written: u32,
    stage: [u8; REC_SIZE],
}

impl SnapWriter {
    pub const fn new() -> Self {
        Self {
            fd_plus1: 0,
            count: 0,
            generation: 0,
            phase: W_IDLE,
            path_len: 0,
            path: [0u8; SNAP_PATH_MAX],
            stage_len: 0,
            stage_written: 0,
            stage: [0u8; REC_SIZE],
        }
    }

    /// True from `start` until the writer finishes or is abandoned.
    pub fn busy(&self) -> bool {
        self.phase != W_IDLE
    }

    /// Arm a new generation at `path`. Nothing is asked of the
    /// provider until `poll_open`. False when `path` does not fit or a
    /// generation is already in flight.
    pub fn start(&mut self, path: &[u8], generation: u64) -> bool {
        if self.phase != W_IDLE || path.is_empty() || path.len() > SNAP_PATH_MAX {
            return false;
        }
        for (d, b) in self.path.iter_mut().zip(path.iter()) {
            *d = *b;
        }
        self.path_len = path.len() as u16;
        self.fd_plus1 = 0;
        self.count = 0;
        self.generation = generation;
        self.stage_len = 0;
        self.stage_written = 0;
        self.phase = W_UNLINK;
        true
    }

    fn path(&self) -> &[u8] {
        let n = (self.path_len as usize).min(SNAP_PATH_MAX);
        self.path.get(..n).unwrap_or(&[])
    }

    /// Stage `bytes` (at most `REC_SIZE`) as the next bytes owed.
    fn stage_bytes(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(REC_SIZE);
        for (d, b) in self.stage.iter_mut().zip(bytes.iter()) {
            *d = *b;
        }
        self.stage_len = n as u32;
        self.stage_written = 0;
    }

    /// Hand the provider what it has not taken of the staged bytes,
    /// while bytes keep moving. `Ready` once all of them are taken.
    unsafe fn drain_stage(&mut self, syscalls: &super::SyscallTable) -> WritePoll {
        let len = (self.stage_len as usize).min(REC_SIZE);
        while (self.stage_written as usize) < len {
            let off = self.stage_written as usize;
            let want = len - off;
            let rc = (syscalls.provider_call)(
                self.fd_plus1 - 1,
                FS_WRITE,
                self.stage.as_mut_ptr().add(off),
                want,
            );
            // `EAGAIN` only when nothing moved: offer the same tail on a
            // later step.
            if super::fs_names::pending(rc) {
                return WritePoll::Pending;
            }
            if rc <= 0 {
                // An error, or a provider refusing without saying why:
                // nothing to wait for either way.
                return WritePoll::Failed;
            }
            // Clamped: a provider reporting more than it was offered
            // must not walk the cursor past the stage.
            self.stage_written += (rc as usize).min(want) as u32;
        }
        self.stage_len = 0;
        self.stage_written = 0;
        WritePoll::Ready
    }

    /// Create (or recreate) the generation file and write its
    /// placeholder header. `Ready` once records may be appended.
    ///
    /// SAFETY: valid syscalls table.
    pub unsafe fn poll_open(&mut self, syscalls: &super::SyscallTable) -> WritePoll {
        loop {
            match self.phase {
                W_UNLINK => {
                    // Truncate-by-recreate: `OPEN_CREATE` does not
                    // truncate, and a stale longer file would fail the
                    // size validation later. A decided refusal — gone
                    // already, or a provider that cannot unlink — is
                    // not fatal: validation catches a stale tail.
                    let rc = super::fs_names::unlink(syscalls.provider_call, self.path());
                    if super::fs_names::pending(rc) {
                        return WritePoll::Pending;
                    }
                    self.phase = W_CREATE;
                }
                W_CREATE => {
                    let p = self.path();
                    let fd = (syscalls.provider_call)(
                        -1,
                        FS_OPEN_CREATE,
                        p.as_ptr() as *mut u8,
                        p.len(),
                    );
                    if super::fs_names::pending(fd) {
                        return WritePoll::Pending;
                    }
                    if fd < 0 {
                        self.phase = W_IDLE;
                        return WritePoll::Failed;
                    }
                    self.fd_plus1 = fd + 1;
                    // Placeholder header with an INVALID magic: an
                    // unfinished generation must never be openable — a
                    // crash right after start would otherwise leave a
                    // byte-valid EMPTY snapshot whose higher generation
                    // outranks the real one. The true header (magic +
                    // count + generation) lands only in `poll_finish`,
                    // after the records are fsynced.
                    self.stage_bytes(&[0u8; SNAP_HDR]);
                    self.phase = W_PLACEHOLDER;
                }
                W_PLACEHOLDER => match self.drain_stage(syscalls) {
                    WritePoll::Ready => {
                        self.phase = W_RECORDS;
                        return WritePoll::Ready;
                    }
                    other => return other,
                },
                W_RECORDS => return WritePoll::Ready,
                _ => return WritePoll::Failed,
            }
        }
    }

    /// Whether a record can be staged now: the file is open and the
    /// previous record has been taken whole.
    pub fn can_stage(&self) -> bool {
        self.phase == W_RECORDS && self.stage_len == 0
    }

    /// Stage one record. The bytes are the writer's until the provider
    /// takes them; `flush` hands them over. False when `can_stage` is
    /// not true or the record does not encode.
    pub fn stage_record(&mut self, rec: &SnapRecord) -> bool {
        if !self.can_stage() {
            return false;
        }
        if !rec.encode(&mut self.stage) {
            return false;
        }
        self.stage_len = REC_SIZE as u32;
        self.stage_written = 0;
        self.count += 1;
        true
    }

    /// Drive a staged record into the file. `Ready` when nothing is
    /// owed.
    ///
    /// SAFETY: valid syscalls table.
    pub unsafe fn flush(&mut self, syscalls: &super::SyscallTable) -> WritePoll {
        if self.phase != W_RECORDS {
            return WritePoll::Failed;
        }
        self.drain_stage(syscalls)
    }

    /// Finalize: fsync records, write the real header (count), fsync,
    /// fence the name, close. `Ready` means the generation is durable
    /// under its name and the file is closed.
    ///
    /// SAFETY: valid syscalls table.
    pub unsafe fn poll_finish(&mut self, syscalls: &super::SyscallTable) -> WritePoll {
        loop {
            match self.phase {
                W_RECORDS => {
                    match self.drain_stage(syscalls) {
                        WritePoll::Ready => {}
                        other => return other,
                    }
                    self.phase = W_FSYNC_RECORDS;
                }
                W_FSYNC_RECORDS | W_FSYNC_HEADER => {
                    // Re-asked byte-identically (same fd, no arg) until
                    // it decides.
                    let rc = (syscalls.provider_call)(
                        self.fd_plus1 - 1,
                        FS_FSYNC,
                        core::ptr::null_mut(),
                        0,
                    );
                    if super::fs_names::pending(rc) {
                        return WritePoll::Pending;
                    }
                    if rc < 0 {
                        return WritePoll::Failed;
                    }
                    self.phase = if self.phase == W_FSYNC_RECORDS {
                        W_SEEK
                    } else {
                        W_NAME
                    };
                }
                W_SEEK => {
                    match seek(syscalls, self.fd_plus1 - 1, 0) {
                        SnapRead::Ready(()) => {}
                        SnapRead::Pending => return WritePoll::Pending,
                        SnapRead::Failed => return WritePoll::Failed,
                    }
                    let mut hdr = [0u8; SNAP_HDR];
                    let magic = SNAP_MAGIC.to_le_bytes();
                    let count = self.count.to_le_bytes();
                    let generation = self.generation.to_le_bytes();
                    for (d, b) in hdr
                        .iter_mut()
                        .zip(magic.iter().chain(count.iter()).chain(generation.iter()))
                    {
                        *d = *b;
                    }
                    self.stage_bytes(&hdr);
                    self.phase = W_HEADER;
                }
                W_HEADER => {
                    match self.drain_stage(syscalls) {
                        WritePoll::Ready => {}
                        other => return other,
                    }
                    self.phase = W_FSYNC_HEADER;
                }
                W_NAME => {
                    let rc = super::fs_names::fsync_name(syscalls.provider_call, self.path());
                    if super::fs_names::pending(rc) {
                        return WritePoll::Pending;
                    }
                    if rc < 0 {
                        return WritePoll::Failed;
                    }
                    // Every fence is down; closing owes nothing now.
                    let _ = (syscalls.provider_call)(
                        self.fd_plus1 - 1,
                        FS_CLOSE,
                        core::ptr::null_mut(),
                        0,
                    );
                    self.fd_plus1 = 0;
                    self.phase = W_DONE;
                }
                W_DONE => {
                    self.phase = W_IDLE;
                    return WritePoll::Ready;
                }
                _ => return WritePoll::Failed,
            }
        }
    }

    /// Give up on the generation, closing its file. Nothing durable is
    /// claimed for it: its placeholder header keeps it unopenable.
    ///
    /// SAFETY: valid syscalls table.
    pub unsafe fn abandon(&mut self, syscalls: &super::SyscallTable) {
        if self.fd_plus1 > 0 {
            let _ = (syscalls.provider_call)(self.fd_plus1 - 1, FS_CLOSE, core::ptr::null_mut(), 0);
        }
        self.fd_plus1 = 0;
        self.stage_len = 0;
        self.stage_written = 0;
        self.phase = W_IDLE;
    }
}
