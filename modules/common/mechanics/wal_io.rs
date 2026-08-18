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

/// Per-record cap. Matches `loam_wire::MAX_STRING`-bounded events
/// plus their 16-byte fixed prefix, with headroom.
pub const MAX_WAL_REC: usize = 4096;

/// Combined record-header + payload scratch. Sized so a single
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalAppendError {
    PayloadTooLarge,
    SeekFailed(i32),
    WriteFailed(i32),
    ShortWrite { wrote: i32, wanted: usize },
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
/// suitable for `wal_append` / `wal_replay` / `wal_close`.
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
    wal_open_opcode(syscalls, path, FS_OPEN_CREATE)
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

/// Append one record. `payload` is written verbatim after an
/// 8-byte `[len, crc32]` header, then the file is fsynced. Returns
/// only after the bytes are durable.
///
/// `scratch` must be at least `8 + payload.len()`; pass a fixed
/// `[u8; APPEND_SCRATCH]` from the module's `ModuleState`.
pub unsafe fn wal_append(
    syscalls: &SyscallTable,
    fd: i32,
    payload: &[u8],
    scratch: &mut [u8],
) -> Result<(), WalAppendError> {
    if payload.len() > MAX_WAL_REC {
        return Err(WalAppendError::PayloadTooLarge);
    }
    let frame_len = 8 + payload.len();
    if scratch.len() < frame_len {
        return Err(WalAppendError::PayloadTooLarge);
    }

    // Position at end-of-file before each append. Fluxor's FS_SEEK
    // is SEEK_SET-only (providers.rs:208); stat the file to find
    // its tail. Doing this every append is cheap (one syscall) and
    // means the WAL is robust against any other writer that may
    // have moved the file pointer.
    let size = match wal_size(syscalls, fd) {
        Ok(s) => s,
        Err(WalReplayError::StatFailed(rc)) => {
            return Err(WalAppendError::SeekFailed(rc));
        }
        Err(_) => return Err(WalAppendError::SeekFailed(-22)),
    };
    if size > i32::MAX as u32 {
        return Err(WalAppendError::SeekFailed(-22));
    }
    let seek_rc = fs_seek(syscalls, fd, size as i32);
    if seek_rc < 0 {
        return Err(WalAppendError::SeekFailed(seek_rc));
    }

    let crc = crc32(payload);
    scratch[0..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    scratch[4..8].copy_from_slice(&crc.to_le_bytes());
    scratch[8..frame_len].copy_from_slice(payload);

    // A provider over a real device can answer E_AGAIN here too. It
    // surfaces as an append failure, which the caller must treat as
    // "not durable" and refuse the operation — never as "written".
    // Refusing is safe but pessimistic: the write would likely have
    // completed on a later step. Turning that into a retry needs the
    // append itself to span steps, which is what the provider's
    // `FS_WRITE_ASYNC` / `FS_FSYNC_SUBMIT` / `FS_FSYNC_POLL` pair
    // exists for — tracked as RFC 0005 P4.6.
    let wrote = (syscalls.provider_call)(fd, FS_WRITE, scratch.as_mut_ptr(), frame_len);
    if wrote < 0 {
        return Err(WalAppendError::WriteFailed(wrote));
    }
    if (wrote as usize) != frame_len {
        return Err(WalAppendError::ShortWrite {
            wrote,
            wanted: frame_len,
        });
    }

    let fsync_rc = (syscalls.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
    if fsync_rc < 0 {
        return Err(WalAppendError::FsyncFailed(fsync_rc));
    }
    Ok(())
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

/// Rotate a WAL: close the fd, unlink the file, recreate it empty.
/// For WALs whose records are DELIVERY buffers (safe to discard once
/// every logged entry has been acknowledged durable downstream), this
/// bounds replay work at the last unacknowledged tail instead of the
/// full history. Returns the fresh fd or a negative errno.
pub unsafe fn wal_rotate(syscalls: &SyscallTable, fd: i32, path: &[u8]) -> Result<i32, i32> {
    let _ = wal_close(syscalls, fd);
    let rc = (syscalls.provider_call)(-1, FS_UNLINK, path.as_ptr() as *mut u8, path.len());
    if rc < 0 {
        // Unlink failing is not fatal — recreate truncates logically
        // on replay only if the create below also fails.
        let _ = rc;
    }
    wal_open_or_create(syscalls, path).map_err(|_| -1)
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
