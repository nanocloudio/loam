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

/// Fence the directory entry the provider last minted for `path` —
/// a creation, a directory creation, or a removal, whichever the
/// caller last performed on it.
pub unsafe fn fsync_name(call: ProviderCall, path: &[u8]) -> bool {
    call(-1, FS_FSYNC_NAME, path.as_ptr() as *mut u8, path.len()) >= 0
}

/// `RENAME(src → dst)`. Arg layout is
/// `[src_len:u16][src][dst_len:u16][dst]`.
pub unsafe fn rename(call: ProviderCall, src: &[u8], dst: &[u8]) -> bool {
    let mut arg = [0u8; 4 + 512];
    let needed = 4 + src.len() + dst.len();
    if needed > arg.len() {
        return false;
    }
    arg[0..2].copy_from_slice(&(src.len() as u16).to_le_bytes());
    arg[2..2 + src.len()].copy_from_slice(src);
    let at = 2 + src.len();
    arg[at..at + 2].copy_from_slice(&(dst.len() as u16).to_le_bytes());
    arg[at + 2..needed].copy_from_slice(dst);
    call(-1, FS_RENAME, arg.as_mut_ptr(), needed) >= 0
}

/// Remove `path`. The name is not retired until a `fsync_name` covers
/// it: an unlink whose directory entry is still volatile can come back
/// after a power cut.
pub unsafe fn unlink(call: ProviderCall, path: &[u8]) -> bool {
    call(-1, FS_UNLINK, path.as_ptr() as *mut u8, path.len()) >= 0
}

/// True when `path` still resolves. Tells "already gone" from "could
/// not remove" without depending on a provider's errno mapping.
pub unsafe fn name_present(call: ProviderCall, path: &[u8]) -> bool {
    let fd = call(-1, FS_OPEN, path.as_ptr() as *mut u8, path.len());
    if fd < 0 {
        return false;
    }
    let _ = call(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    true
}
