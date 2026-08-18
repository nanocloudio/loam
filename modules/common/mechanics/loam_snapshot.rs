// Namespace snapshot file: the durable, binary-searchable record
// of every binding, letting the PIC arena be a HOT CACHE instead
// of the whole set. Consumed by namespace_pic_body.
//
// Layout: 16-byte header + `count` fixed-size records sorted by
// (namespace_hash, path_hash):
//
//   header  [magic u32 "LSNP"][count u32][generation u64]
//   record  [ns_hash u64][path_hash u64][revision u64][kind u8]
//           [oid_len u8][oid 96][root_len u8][root 64]
//           [path_len u8][path 160]                       = 348 B
//
// Crash safety via ALTERNATING GENERATIONS: compaction writes to
// whichever of `<wal>.snapA` / `<wal>.snapB` holds the OLDER
// generation; open picks the valid file (size == 16 + count*348)
// with the higher generation. A torn write leaves the other
// generation intact, and WAL replay is revision-gated, so any
// (snapshot, wal-tail) pairing replays to a correct arena.
//
// Same include discipline as wal_io.rs: raw fs-contract calls via
// the module's SyscallTable.

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
const FS_UNLINK: u32 = 0x090A;

pub const SNAP_MAGIC: u32 = u32::from_le_bytes(*b"LSNP");
pub const SNAP_HDR: usize = 16;
pub const REC_SIZE: usize = 8 + 8 + 8 + 1 + 1 + 96 + 1 + 64 + 1 + 160; // 348
pub const MAX_OID: usize = 96;
pub const MAX_ROOT: usize = 64;
pub const MAX_PATH: usize = 160;

/// `kind` value marking a tombstone in ARENA slots (never written
/// to a snapshot — compaction drops the record entirely).
pub const KIND_TOMBSTONE: u8 = 0xFE;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SnapRecord {
    pub ns_hash: u64,
    pub path_hash: u64,
    pub revision: u64,
    pub kind: u8,
    pub oid_len: u8,
    pub oid: [u8; MAX_OID],
    pub root_len: u8,
    pub root: [u8; MAX_ROOT],
    pub path_len: u8,
    pub path: [u8; MAX_PATH],
}

impl SnapRecord {
    pub const fn empty() -> Self {
        Self {
            ns_hash: 0,
            path_hash: 0,
            revision: 0,
            kind: 0,
            oid_len: 0,
            oid: [0; MAX_OID],
            root_len: 0,
            root: [0; MAX_ROOT],
            path_len: 0,
            path: [0; MAX_PATH],
        }
    }

    pub fn key(&self) -> (u64, u64) {
        (self.ns_hash, self.path_hash)
    }

    pub fn encode(&self, out: &mut [u8]) -> bool {
        if out.len() < REC_SIZE {
            return false;
        }
        out[0..8].copy_from_slice(&self.ns_hash.to_le_bytes());
        out[8..16].copy_from_slice(&self.path_hash.to_le_bytes());
        out[16..24].copy_from_slice(&self.revision.to_le_bytes());
        out[24] = self.kind;
        out[25] = self.oid_len;
        out[26..26 + MAX_OID].copy_from_slice(&self.oid);
        let mut o = 26 + MAX_OID;
        out[o] = self.root_len;
        out[o + 1..o + 1 + MAX_ROOT].copy_from_slice(&self.root);
        o += 1 + MAX_ROOT;
        out[o] = self.path_len;
        out[o + 1..o + 1 + MAX_PATH].copy_from_slice(&self.path);
        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() < REC_SIZE {
            return None;
        }
        let mut r = Self::empty();
        r.ns_hash = u64::from_le_bytes(src[0..8].try_into().ok()?);
        r.path_hash = u64::from_le_bytes(src[8..16].try_into().ok()?);
        r.revision = u64::from_le_bytes(src[16..24].try_into().ok()?);
        r.kind = src[24];
        r.oid_len = src[25];
        r.oid.copy_from_slice(&src[26..26 + MAX_OID]);
        let mut o = 26 + MAX_OID;
        r.root_len = src[o];
        r.root.copy_from_slice(&src[o + 1..o + 1 + MAX_ROOT]);
        o += 1 + MAX_ROOT;
        r.path_len = src[o];
        r.path.copy_from_slice(&src[o + 1..o + 1 + MAX_PATH]);
        Some(r)
    }
}

/// Build `<wal_path>.snapA` / `.snapB` into `out`; returns len.
pub fn snap_path(wal_path: &[u8], which: u8, out: &mut [u8]) -> usize {
    let suffix: &[u8] = if which == 0 { b".snapA" } else { b".snapB" };
    let n = wal_path.len() + suffix.len();
    if out.len() < n {
        return 0;
    }
    out[..wal_path.len()].copy_from_slice(wal_path);
    out[wal_path.len()..n].copy_from_slice(suffix);
    n
}

/// SAFETY: `syscalls` must be a valid provider table.
unsafe fn stat_size(syscalls: &super::SyscallTable, fd: i32) -> Option<u64> {
    let mut stat = [0u8; 8];
    if (syscalls.provider_call)(fd, FS_STAT, stat.as_mut_ptr(), stat.len()) < 0 {
        return None;
    }
    Some(u32::from_le_bytes([stat[0], stat[1], stat[2], stat[3]]) as u64)
}

unsafe fn seek(syscalls: &super::SyscallTable, fd: i32, off: u32) {
    let b = off.to_le_bytes();
    let _ = (syscalls.provider_call)(fd, FS_SEEK, b.as_ptr() as *mut u8, 4);
}

unsafe fn read_exact(syscalls: &super::SyscallTable, fd: i32, buf: &mut [u8]) -> bool {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = (syscalls.provider_call)(
            fd,
            FS_READ,
            buf.as_mut_ptr().add(filled),
            buf.len() - filled,
        );
        if n <= 0 {
            return false;
        }
        filled += n as usize;
    }
    true
}

/// An open, validated snapshot: fd + record count + generation.
#[derive(Clone, Copy)]
pub struct OpenSnapshot {
    pub fd: i32,
    pub count: u32,
    pub generation: u64,
}

/// Open ONE generation file and validate header vs size. Returns
/// None (fd closed) if missing or torn.
///
/// SAFETY: valid syscalls table; path is a live byte slice.
pub unsafe fn snap_open_one(syscalls: &super::SyscallTable, path: &[u8]) -> Option<OpenSnapshot> {
    let fd = (syscalls.provider_call)(-1, FS_OPEN, path.as_ptr() as *mut u8, path.len());
    if fd < 0 {
        return None;
    }
    let mut hdr = [0u8; SNAP_HDR];
    seek(syscalls, fd, 0);
    if !read_exact(syscalls, fd, &mut hdr) {
        let _ = (syscalls.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        return None;
    }
    let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let count = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
    let generation = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
    let expect = SNAP_HDR as u64 + count as u64 * REC_SIZE as u64;
    if magic != SNAP_MAGIC || stat_size(syscalls, fd) != Some(expect) {
        let _ = (syscalls.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        return None;
    }
    Some(OpenSnapshot {
        fd,
        count,
        generation,
    })
}

/// Open the best (highest-generation valid) snapshot for
/// `wal_path`, returning it plus which slot (0/1) it lives in.
///
/// SAFETY: valid syscalls table.
pub unsafe fn snap_open_best(
    syscalls: &super::SyscallTable,
    wal_path: &[u8],
) -> Option<(OpenSnapshot, u8)> {
    let mut path = [0u8; 300];
    let mut best: Option<(OpenSnapshot, u8)> = None;
    for which in 0..2u8 {
        let n = snap_path(wal_path, which, &mut path);
        if n == 0 {
            continue;
        }
        if let Some(s) = snap_open_one(syscalls, &path[..n]) {
            match best {
                Some((b, _)) if b.generation >= s.generation => {
                    let _ = (syscalls.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
                }
                Some((b, _)) => {
                    let _ = (syscalls.provider_call)(b.fd, FS_CLOSE, core::ptr::null_mut(), 0);
                    best = Some((s, which));
                }
                None => best = Some((s, which)),
            }
        }
    }
    best
}

/// Read record `idx`.
///
/// SAFETY: valid syscalls table; `snap.fd` open.
pub unsafe fn snap_read_at(
    syscalls: &super::SyscallTable,
    snap: &OpenSnapshot,
    idx: u32,
) -> Option<SnapRecord> {
    if idx >= snap.count {
        return None;
    }
    seek(syscalls, snap.fd, SNAP_HDR as u32 + idx * REC_SIZE as u32);
    let mut buf = [0u8; REC_SIZE];
    if !read_exact(syscalls, snap.fd, &mut buf) {
        return None;
    }
    SnapRecord::decode(&buf)
}

/// Binary-search for (ns_hash, path_hash): ~log2(count) seeks.
///
/// SAFETY: valid syscalls table; `snap.fd` open.
pub unsafe fn snap_search(
    syscalls: &super::SyscallTable,
    snap: &OpenSnapshot,
    ns_hash: u64,
    path_hash: u64,
) -> Option<SnapRecord> {
    let key = (ns_hash, path_hash);
    let (mut lo, mut hi) = (0u32, snap.count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let rec = snap_read_at(syscalls, snap, mid)?;
        match rec.key().cmp(&key) {
            core::cmp::Ordering::Equal => return Some(rec),
            core::cmp::Ordering::Less => lo = mid + 1,
            core::cmp::Ordering::Greater => hi = mid,
        }
    }
    None
}

/// Streaming snapshot writer (used by the incremental compactor).
#[derive(Clone, Copy)]
pub struct SnapWriter {
    pub fd: i32,
    pub count: u32,
    pub generation: u64,
}

/// Create/truncate the target generation file and write a
/// placeholder header (finalized by `snap_writer_finish`).
///
/// SAFETY: valid syscalls table.
pub unsafe fn snap_writer_start(
    syscalls: &super::SyscallTable,
    path: &[u8],
    generation: u64,
) -> Option<SnapWriter> {
    // Truncate-by-recreate: a stale longer file would fail the
    // size validation later, but start clean anyway.
    let _ = (syscalls.provider_call)(-1, FS_UNLINK, path.as_ptr() as *mut u8, path.len());
    let fd = (syscalls.provider_call)(-1, FS_OPEN_CREATE, path.as_ptr() as *mut u8, path.len());
    if fd < 0 {
        return None;
    }
    // Placeholder header with an INVALID magic: an unfinished
    // generation must never be openable — a crash right after
    // start would otherwise leave a byte-valid EMPTY snapshot
    // whose higher generation outranks the real one. The true
    // header (magic + count + generation) lands only in
    // `snap_writer_finish`, after the records are fsynced.
    let mut hdr = [0u8; SNAP_HDR];
    let w = (syscalls.provider_call)(fd, FS_WRITE, hdr.as_mut_ptr(), SNAP_HDR);
    if w != SNAP_HDR as i32 {
        let _ = (syscalls.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        return None;
    }
    Some(SnapWriter {
        fd,
        count: 0,
        generation,
    })
}

/// SAFETY: valid syscalls table; writer started.
pub unsafe fn snap_writer_append(
    syscalls: &super::SyscallTable,
    w: &mut SnapWriter,
    rec: &SnapRecord,
) -> bool {
    let mut buf = [0u8; REC_SIZE];
    if !rec.encode(&mut buf) {
        return false;
    }
    let n = (syscalls.provider_call)(w.fd, FS_WRITE, buf.as_mut_ptr(), REC_SIZE);
    if n != REC_SIZE as i32 {
        return false;
    }
    w.count += 1;
    true
}

/// Finalize: fsync records, write the real header (count), fsync,
/// close. After this returns true the generation is durable.
///
/// SAFETY: valid syscalls table; writer started.
pub unsafe fn snap_writer_finish(syscalls: &super::SyscallTable, w: &mut SnapWriter) -> bool {
    if (syscalls.provider_call)(w.fd, FS_FSYNC, core::ptr::null_mut(), 0) < 0 {
        let _ = (syscalls.provider_call)(w.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        return false;
    }
    seek(syscalls, w.fd, 0);
    let mut hdr = [0u8; SNAP_HDR];
    hdr[0..4].copy_from_slice(&SNAP_MAGIC.to_le_bytes());
    hdr[4..8].copy_from_slice(&w.count.to_le_bytes());
    hdr[8..16].copy_from_slice(&w.generation.to_le_bytes());
    let ok = (syscalls.provider_call)(w.fd, FS_WRITE, hdr.as_mut_ptr(), SNAP_HDR)
        == SNAP_HDR as i32
        && (syscalls.provider_call)(w.fd, FS_FSYNC, core::ptr::null_mut(), 0) >= 0;
    let _ = (syscalls.provider_call)(w.fd, FS_CLOSE, core::ptr::null_mut(), 0);
    ok
}
