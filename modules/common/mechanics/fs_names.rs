// Durable name publication over the fluxor `fs` contract. no_std.
//
// `FSYNC` fences a file's bytes and its own size metadata. It never
// publishes the directory entry that lets a later mount FIND the file,
// so an artefact fsynced through its FD alone has durable bytes
// reachable by no durable name: after a power cut it may be absent, or
// present with its old contents. Closing that gap is a separate fence,
// and the contract offers two shapes for it —
//
//   `OPEN_CREATE`(final) → write → `FSYNC` → `FSYNC_NAME`(final)
//     for a self-describing artefact, where a truncated tail is
//     recoverable. The crash-visible outcomes are name absent, or name
//     present over a prefix of the bytes.
//   `OPEN_CREATE`(temp) → write → `FSYNC` → `RENAME`(temp → final)
//     for an artefact that must be all-or-nothing. The crash-visible
//     outcomes are the old name, or the new complete artefact.
//
// Both are optional provider capabilities. A caller that needs
// crash-safe publication queries `CAPS` and fails closed when the bit
// it needs is clear, rather than treating file `FSYNC` as name
// publication — it is not.
//
// This file is `#[path]`-mounted by the modules that publish names.
// It takes the raw `provider_call` pointer rather than a
// `SyscallTable` reference so the same source works at any mount
// depth: some includers mount it beside themselves, others mount it
// from inside another shared file.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

/// The kernel's provider dispatch entry point, taken by pointer so
/// this file names no type from its includer's module tree.
pub type ProviderCall = unsafe extern "C" fn(i32, u32, *mut u8, usize) -> i32;

pub const FS_OPEN: u32 = 0x0900;
pub const FS_CLOSE: u32 = 0x0903;
pub const FS_UNLINK: u32 = 0x090A;
pub const FS_RENAME: u32 = 0x090D;
pub const FS_FSYNC_NAME: u32 = 0x0912;
pub const FS_CAPS: u32 = 0x09FF;

/// `caps::RENAME` — atomic replace, both parent directories durable on
/// return.
pub const CAP_RENAME: u32 = 1 << 8;
/// `caps::FSYNC_NAME` — durable publication of a parent-directory
/// entry the provider last minted for a path.
pub const CAP_FSYNC_NAME: u32 = 1 << 11;

/// The provider's capability bitmap, or `None` when it did not answer.
///
/// The two must not be conflated. A provider whose backing volume has not
/// finished attaching answers `EAGAIN`, because a capability can depend on
/// the volume rather than the provider — `fat32` derives `RENAME` from the
/// mounted volume's reserved-sector geometry. Reading that as an empty
/// bitmap is fail-closed for one call and a permanent downgrade for a caller
/// that remembers it: the store would run its weakest publication recipe for
/// the life of the process, on a provider that supports the strongest, with
/// nothing to distinguish that from a backend which genuinely cannot.
///
/// So: `None` means ask again, and a caller must not record it.
pub unsafe fn caps(call: ProviderCall) -> Option<u32> {
    let mut out = [0u8; 4];
    if call(-1, FS_CAPS, out.as_mut_ptr(), out.len()) >= 4 {
        Some(u32::from_le_bytes(out))
    } else {
        None
    }
}

/// `EAGAIN`: not now, nothing consumed — ask again on a later step,
/// with any arguments.
pub const EAGAIN: i32 = -11;
/// `EINPROGRESS`: taken, not yet decided — re-ask on a later step with
/// the byte-identical request; that later answer is the decision.
pub const EINPROGRESS: i32 = -36;
/// `ENOENT`: no such entry.
pub const ENOENT: i32 = -2;

/// True when `rc` is not an answer yet: `EAGAIN` or `EINPROGRESS`.
/// Neither is ever a failure, an end of data, or an absence. A caller
/// holding an `EINPROGRESS` keeps its exact request and re-asks it.
pub const fn pending(rc: i32) -> bool {
    rc == EAGAIN || rc == EINPROGRESS
}

/// Fence the directory entry the provider last minted for `path` —
/// a creation, a directory creation, or a removal, whichever the
/// caller last performed on it.
///
/// Answers the provider's rc: `>= 0` once the entry is durable,
/// [`pending`] while it is not decided (re-ask with the same `path` on a
/// later step), any other negative a failure.
pub unsafe fn fsync_name(call: ProviderCall, path: &[u8]) -> i32 {
    call(-1, FS_FSYNC_NAME, path.as_ptr() as *mut u8, path.len())
}

/// `RENAME`'s framing: a `u16` length before each of the two paths.
pub const RENAME_FRAMING: usize = 2 + 2;

/// The longest suffix a caller appends to a path to stage a file it then
/// renames onto that path: the WAL rotation's `.rot`. `wal_io` types its
/// suffix as an array of this length, so the two cannot disagree.
pub const WAL_STAGE_SUFFIX_LEN: usize = 4;

/// Longest `src` + `dst` pair [`rename`] can frame, derived from the
/// longest pair any caller renames: a WAL rotation's staging log onto
/// its WAL, `(WAL_PATH_BUF + WAL_STAGE_SUFFIX_LEN) + WAL_PATH_BUF`.
/// Every renamer asserts at compile time that its own pair fits
/// (`wal_io` for rotation, `body_store_body` for `.pub_` and `.wip_`
/// publication), so a path the module accepted is never refused here.
pub const RENAME_PATHS_MAX: usize = 2 * super::limits::WAL_PATH_BUF + WAL_STAGE_SUFFIX_LEN;

/// The whole `RENAME` argument: framing and the longest pair.
pub const RENAME_ARG_LEN: usize = RENAME_FRAMING + RENAME_PATHS_MAX;

/// `RENAME(src → dst)`. Arg layout is
/// `[src_len:u16][src][dst_len:u16][dst]`.
///
/// Answers the provider's rc, as [`fsync_name`]: `>= 0` once both parent
/// directories are durable, [`pending`] while undecided (re-ask with the
/// same `src` and `dst`, which frame the same bytes), any other negative
/// a failure. A pair longer than [`RENAME_PATHS_MAX`] is `EINVAL`.
pub unsafe fn rename(call: ProviderCall, src: &[u8], dst: &[u8]) -> i32 {
    let mut arg = [0u8; RENAME_ARG_LEN];
    let needed = RENAME_FRAMING + src.len() + dst.len();
    if needed > arg.len() {
        return -22;
    }
    arg[0..2].copy_from_slice(&(src.len() as u16).to_le_bytes());
    arg[2..2 + src.len()].copy_from_slice(src);
    let at = 2 + src.len();
    arg[at..at + 2].copy_from_slice(&(dst.len() as u16).to_le_bytes());
    arg[at + 2..needed].copy_from_slice(dst);
    call(-1, FS_RENAME, arg.as_mut_ptr(), needed)
}

/// Remove `path`. The name is not retired until a `fsync_name` covers
/// it: an unlink whose directory entry is still volatile can come back
/// after a power cut.
///
/// Answers the provider's rc, as [`fsync_name`]: `>= 0` removed,
/// [`pending`] undecided (re-ask with the same `path`), `ENOENT` already
/// gone, any other negative a failure.
pub unsafe fn unlink(call: ProviderCall, path: &[u8]) -> i32 {
    call(-1, FS_UNLINK, path.as_ptr() as *mut u8, path.len())
}

/// Whether `path` still resolves: `Some(true)` it does, `Some(false)` it
/// does not, `None` not known yet — the provider answered `EAGAIN`, and
/// the caller asks again on a later step. Tells "already gone" from
/// "could not remove" without depending on a provider's errno mapping
/// beyond that: a pending answer is never read as absence.
pub unsafe fn name_present(call: ProviderCall, path: &[u8]) -> Option<bool> {
    let fd = call(-1, FS_OPEN, path.as_ptr() as *mut u8, path.len());
    if pending(fd) {
        return None;
    }
    if fd < 0 {
        return Some(false);
    }
    let _ = call(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    Some(true)
}
