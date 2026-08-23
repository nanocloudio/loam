// Step body for `body_store`. Disk-backed content-addressed
// store. Each PUT writes the body to
// `<root_dir>/<hex(sha256(body))>` via FS_OPEN_CREATE + FS_WRITE
// + FS_FSYNC + FS_CLOSE. The in-arena slot table holds only
// (digest, size) metadata so the PIC's memory footprint stays
// flat regardless of how much body data has been stored.
//
// `<root_dir>` must already exist — this module never creates it.
// The graph profile / launch script is responsible for that; PUT
// against a missing directory fails with ERR_NO_ROOT.
//
// DELETE clears the slot AND unlinks the on-disk file (fs contract
// UNLINK, 0x090A). A DELETE for a digest with no slot still attempts
// the unlink so restarts don't strand orphans: `existed` is true if
// either the slot or the file was present.
//
// GET falls back to DISK when the slot table has no entry (the table
// is in-arena and empty after a restart): the file is opened by its
// content path, read to EOF, digest-verified, and the slot is
// rehydrated. Content addressing makes the verification exact.

const MAX_OPS_PER_STEP: u32 = 4;
const READ_BUF: usize = super::wire::MAX_BODY + 64;
const SCRATCH_OUT: usize = super::wire::MAX_BODY + 64;

// Capacity profile — see namespace_pic_body.rs.
#[cfg(target_os = "none")]
pub const BODY_SLOTS: usize = 64;
#[cfg(not(target_os = "none"))]
pub const BODY_SLOTS: usize = 8192;
pub const ROOT_DIR_BUF: usize = 192;

// fluxor `fs` opcodes — duplicated to avoid pulling in another
// module just for constants.
const FS_OPEN_CREATE: u32 = 0x0909;
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_OPENDIR: u32 = 0x0907;
const FS_READDIR: u32 = 0x0908;
const FS_UNLINK: u32 = 0x090A;

/// How a content-addressed artefact reaches its final name.
///
/// `FSYNC` fences a file's bytes and its own size, never the directory
/// entry that finds it. A blob published without a name fence has
/// durable bytes reachable by no durable name, so the tier is chosen
/// from the provider's capabilities and the weakest tier refuses
/// rather than acknowledging a publication it cannot make.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PublishTier {
    /// Write a temporary, fence its bytes, rename onto the final path.
    /// The rename is atomic and publishes both parents, so no partial
    /// final artefact is ever observable.
    Rename,
    /// Write the final path in place, fence its bytes, then fence the
    /// name. A crash mid-write leaves a short file under a name that
    /// promises whole content; content addressing is what makes that
    /// detectable, and a re-PUT republishes it.
    NameFence,
    /// Neither fence exists. A content-addressed PUT cannot be
    /// acknowledged, because the acknowledgement is a durability
    /// claim.
    Unavailable,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DiskSlot {
    pub digest: [u8; super::wire::DIGEST_LEN],
    pub size: u32,
    pub in_use: u8,
    /// 1 when the blob is stored under an explicit key (volume
    /// extent / EC shard) rather than its content hash. Keyed
    /// blobs' lifecycle belongs to their writers — the orphan GC
    /// must never collect them, so SCAN reports this flag.
    pub keyed: u8,
}

/// Concurrent chunked writes. Each session streams to
/// `<root>/.wip_<wid>` with an incremental hash; COMMIT verifies the
/// declared digest, then publishes under the provider's
/// [`PublishTier`] — see `handle_wcommit`.
pub const WRITE_SESSIONS: usize = 4;
/// Sessions untouched this many ticks are reaped (client died
/// mid-stream) — temp file unlinked, slot freed.
const SESSION_REAP_TICKS: u32 = 120_000;

#[repr(C)]
pub struct WriteSession {
    pub in_use: u8,
    pub fd: i32,
    pub expect: [u8; super::wire::DIGEST_LEN],
    pub total_len: u64,
    pub written: u64,
    pub last_tick: u32,
    pub hasher: super::sha256::Sha256,
}

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    pub root_dir: [u8; ROOT_DIR_BUF],
    pub root_dir_len: u16,
    pub scratch: [u8; SCRATCH_OUT],
    /// The response owed on `body_responses`, held in `scratch`.
    /// `resp_len` is its length and `resp_sent` how much the channel
    /// has taken; both zero means nothing is owed.
    ///
    /// This tracks the existing buffer rather than mounting
    /// `reply_out.rs` as the arena PICs do: a body response is up to
    /// `SCRATCH_OUT`, so a second copy would double the largest
    /// allocation in this module for no gain. The discipline is the
    /// same — an answer refused by the channel is retained, and no new
    /// request is read while one is owed.
    pub resp_len: u32,
    pub resp_sent: u32,
    pub slots: [DiskSlot; BODY_SLOTS],
    pub wsessions: [WriteSession; WRITE_SESSIONS],
    /// Provider capability bitmap, queried once. `caps_known` is what
    /// distinguishes "no capabilities" from "not asked yet".
    pub caps: u32,
    pub caps_known: u8,
    /// Set once the negotiated tier has been reported. Composites that
    /// have a log surface drain this through [`take_tier_report`]; the
    /// mechanics tier keeps no logging of its own, because it is mounted
    /// into host contexts that have none.
    pub tier_reported: u8,
    pub ticks: u32,
    pub stream_opens: u32,
    pub stream_commits: u32,
    pub stream_aborts: u32,
    pub ranges: u32,
    pub puts: u32,
    pub gets: u32,
    pub deletes: u32,
    pub heads: u32,
    pub scans: u32,
    pub rehydrated: u32,
    pub apply_errors: u32,
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
    0
}

/// Set the root directory after init. Bodies will be stored at
/// `<root_dir>/<hex_digest>`. Returns false if `path` is longer
/// than the inline buffer.
pub unsafe fn set_root_dir(state_ptr: *mut u8, path: &[u8]) -> bool {
    if state_ptr.is_null() || path.is_empty() || path.len() > ROOT_DIR_BUF {
        return false;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    s.root_dir[..path.len()].copy_from_slice(path);
    s.root_dir_len = path.len() as u16;
    true
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

    // An owed response owns the step until the channel takes it. It
    // lives in `scratch`, which the next request would overwrite.
    if !flush_resp(s) {
        return 0;
    }

    let mut handled: u32 = 0;
    while handled < MAX_OPS_PER_STEP {
        if s.resp_len != 0 {
            break;
        }
        let mut buf = [0u8; READ_BUF];
        let n = (syscalls.channel_read)(s.in_chan, buf.as_mut_ptr(), READ_BUF);
        if n <= 0 {
            break;
        }
        let bytes = &buf[..n as usize];
        let op = match super::wire::peek_opcode(bytes) {
            Some(op) => op,
            None => {
                nak(s, super::wire::ERR_BAD_REQ);
                handled = handled.wrapping_add(1);
                continue;
            }
        };
        match op {
            super::wire::OP_PUT => handle_put(s, bytes),
            super::wire::OP_GET => handle_get(s, bytes),
            super::wire::OP_HEAD => handle_head(s, bytes),
            super::wire::OP_DELETE => handle_delete(s, bytes),
            super::wire::OP_SCAN => handle_scan(s, bytes),
            super::wire::OP_PUT_KEYED => handle_put_keyed(s, bytes),
            super::wire::OP_WOPEN => handle_wopen(s, bytes),
            super::wire::OP_WAPPEND => handle_wappend(s, bytes),
            super::wire::OP_WCOMMIT => handle_wcommit(s, bytes),
            super::wire::OP_WABORT => handle_wabort(s, bytes),
            super::wire::OP_RANGE => handle_range(s, bytes),
            _ => nak(s, super::wire::ERR_BAD_REQ),
        }
        handled = handled.wrapping_add(1);
    }
    reap_stale_sessions(s);
    0
}

// ── Path building ─────────────────────────────────────────────────
//
// Builds `<root_dir>/<hex(digest)>` into `out`. Returns the
// total byte length, or 0 if root is unset or the buffer is too
// small.

const HEX_DIGEST_LEN: usize = super::wire::DIGEST_LEN * 2;

unsafe fn build_body_path(
    s: &ModuleState,
    digest: &[u8; super::wire::DIGEST_LEN],
    out: &mut [u8],
) -> usize {
    let rl = s.root_dir_len as usize;
    if rl == 0 {
        return 0;
    }
    let needed = rl + 1 + HEX_DIGEST_LEN;
    if out.len() < needed {
        return 0;
    }
    out[..rl].copy_from_slice(&s.root_dir[..rl]);
    out[rl] = b'/';
    super::wire::hex_lower_into(digest, &mut out[rl + 1..rl + 1 + HEX_DIGEST_LEN]);
    needed
}

// ── PUT ───────────────────────────────────────────────────────────

unsafe fn handle_put(s: &mut ModuleState, bytes: &[u8]) {
    if s.root_dir_len == 0 {
        nak(s, super::wire::ERR_NO_ROOT);
        return;
    }
    let body = match super::wire::decode_put_req(bytes) {
        Ok(b) => b,
        Err(super::wire::WireError::BodyTooLarge { .. }) => {
            nak(s, super::wire::ERR_TOO_LARGE);
            return;
        }
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };

    let mut hasher = super::sha256::Sha256::new();
    hasher.update(body);
    let digest = hasher.finalize();

    // If a slot already holds this digest, idempotent ack.
    if find_slot(s, &digest).is_some() {
        respond_put(s, &digest);
        s.puts = s.puts.wrapping_add(1);
        return;
    }

    let slot_ok = write_blob_at(s, &digest, body, 0);
    if !slot_ok {
        nak(s, super::wire::ERR_IO);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }

    respond_put(s, &digest);
    s.puts = s.puts.wrapping_add(1);
}

unsafe fn respond_put(s: &mut ModuleState, digest: &[u8; super::wire::DIGEST_LEN]) {
    let n = match super::wire::encode_put_resp(&mut s.scratch, digest) {
        Ok(n) => n,
        Err(_) => {
            nak(s, super::wire::ERR_IO);
            return;
        }
    };
    write_resp(s, n);
}

/// Which publication recipe this provider supports.
///
/// Queried until it is answered, not once: a probe that lands before the
/// provider's volume has attached is refused, and recording that refusal
/// would pin the store to its weakest recipe for good.
pub unsafe fn publish_tier(s: &mut ModuleState) -> PublishTier {
    if s.caps_known == 0 {
        let probed = match s.syscalls.as_ref() {
            Some(sys) => super::fs_names::caps(sys.provider_call),
            None => None,
        };
        match probed {
            Some(bits) => {
                s.caps = bits;
                s.caps_known = 1;
            }
            // Unanswered. Report the conservative tier for this call and
            // leave the probe open so the next one asks again.
            None => return PublishTier::Unavailable,
        }
    }
    if s.caps & super::fs_names::CAP_RENAME != 0 {
        PublishTier::Rename
    } else if s.caps & super::fs_names::CAP_FSYNC_NAME != 0 {
        PublishTier::NameFence
    } else {
        PublishTier::Unavailable
    }
}

/// The negotiated publication tier as a line to log, returned once and
/// then never again.
///
/// Which recipe a store runs is a property of the provider in front of
/// it, so it is not derivable from the store's own configuration — a
/// composite that can log should say it, or an operator is left
/// inferring the fence from the artefacts it leaves behind. `None`
/// before the first capability query, and after the line has been taken.
pub unsafe fn take_tier_report(state_ptr: *mut u8) -> Option<&'static [u8]> {
    let s = &mut *(state_ptr as *mut ModuleState);
    if s.caps_known == 0 || s.tier_reported != 0 {
        return None;
    }
    s.tier_reported = 1;
    Some(if s.caps & super::fs_names::CAP_RENAME != 0 {
        b"[body_store] publish tier=rename"
    } else if s.caps & super::fs_names::CAP_FSYNC_NAME != 0 {
        b"[body_store] publish tier=name_fence"
    } else {
        b"[body_store] publish tier=unavailable"
    })
}

/// `<root>/.pub_<16 hex>` — the staging name a `Rename` publication
/// writes before it publishes. Derived from the digest so two writers
/// of the same content share it and no counter has to survive a
/// restart; a crash leaves one behind and the boot sweep removes it.
unsafe fn build_pub_path(
    s: &ModuleState,
    digest: &[u8; super::wire::DIGEST_LEN],
    out: &mut [u8],
) -> usize {
    let rl = s.root_dir_len as usize;
    const PREFIX: &[u8] = b"/.pub_";
    const HEX: usize = 16;
    if rl == 0 || out.len() < rl + PREFIX.len() + HEX {
        return 0;
    }
    out[..rl].copy_from_slice(&s.root_dir[..rl]);
    out[rl..rl + PREFIX.len()].copy_from_slice(PREFIX);
    let hex_at = rl + PREFIX.len();
    for i in 0..HEX / 2 {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        out[hex_at + 2 * i] = DIGITS[(digest[i] >> 4) as usize];
        out[hex_at + 2 * i + 1] = DIGITS[(digest[i] & 0x0F) as usize];
    }
    hex_at + HEX
}

/// Write `bytes` to `path` and fence the bytes: create, write, fsync,
/// close. Does not publish a name.
unsafe fn write_and_fence(
    sys: &super::SyscallTable,
    path: &mut [u8],
    plen: usize,
    bytes: &[u8],
) -> bool {
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
    if fd < 0 {
        return false;
    }
    let wrote = (sys.provider_call)(fd, FS_WRITE, bytes.as_ptr() as *mut u8, bytes.len());
    if wrote < 0 || (wrote as usize) != bytes.len() {
        let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        return false;
    }
    let fenced = (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0) >= 0;
    let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    fenced
}

unsafe fn rename_path(sys: &super::SyscallTable, src: &[u8], dst: &[u8]) -> bool {
    super::fs_names::rename(sys.provider_call, src, dst)
}

unsafe fn fsync_name(sys: &super::SyscallTable, path: &mut [u8], plen: usize) -> bool {
    super::fs_names::fsync_name(sys.provider_call, &path[..plen])
}

unsafe fn name_present(sys: &super::SyscallTable, path: &mut [u8], plen: usize) -> bool {
    super::fs_names::name_present(sys.provider_call, &path[..plen])
}

/// Write `bytes` to `<root_dir>/<hex(digest)>` (create + write +
/// fsync + close) and record a slot. Returns false on any disk
/// failure or a full slot table.
unsafe fn write_blob_at(
    s: &mut ModuleState,
    digest: &[u8; super::wire::DIGEST_LEN],
    bytes: &[u8],
    keyed: u8,
) -> bool {
    let mut path = [0u8; 256];
    let plen = build_body_path(s, digest, &mut path);
    if plen == 0 {
        return false;
    }
    let tier = publish_tier(s);
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return false,
    };
    // A file already at the content path is NOT proof that its bytes
    // hash to that path. A crash during an in-place publication can
    // leave a full-length file whose interior was never fenced, and a
    // length comparison accepts it forever without reading it. The
    // supplied bytes are known-good and in hand, so republish them
    // rather than acknowledge bytes nothing has verified. The cost is
    // one rewrite per retried PUT; the alternative is a durability
    // claim over unverified content.
    // Keyed blobs are mutable — last write wins on a derived key — so
    // they take the same recipe as content-addressed ones rather than
    // a weaker one. On `Rename` that makes an overwrite atomic: the
    // crash-visible outcomes are the old extent or the new one, never
    // an absent or half-replaced extent.
    match tier {
        PublishTier::Rename => {
            let mut tmp = [0u8; 256];
            let tlen = build_pub_path(s, digest, &mut tmp);
            if tlen == 0 {
                return false;
            }
            // Staging is transient, and a crashed attempt can leave one
            // behind. `FS_OPEN_CREATE` does not truncate, so a shorter
            // payload would inherit the old tail and rename it into
            // place. Remove it first.
            let _ = (sys.provider_call)(-1, FS_UNLINK, tmp.as_mut_ptr(), tlen);
            if !write_and_fence(sys, &mut tmp, tlen, bytes) {
                let _ = (sys.provider_call)(-1, FS_UNLINK, tmp.as_mut_ptr(), tlen);
                return false;
            }
            if !rename_path(sys, &tmp[..tlen], &path[..plen]) {
                let _ = (sys.provider_call)(-1, FS_UNLINK, tmp.as_mut_ptr(), tlen);
                return false;
            }
        }
        PublishTier::NameFence => {
            // No atomic replace on this tier. A keyed blob may shrink,
            // and `FS_OPEN_CREATE` does not truncate, so the old entry
            // has to go first — which leaves a window where the extent
            // is absent. That window is the cost of the tier, not of
            // the operation.
            if keyed != 0 {
                let _ = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), plen);
            }
            if !write_and_fence(sys, &mut path, plen, bytes) {
                return false;
            }
            if !fsync_name(sys, &mut path, plen) {
                return false;
            }
        }
        // No durable name publication exists on this backend, and the
        // PUT response is a durability claim. Refuse it rather than
        // acknowledge bytes reachable by no durable name.
        PublishTier::Unavailable => return false,
    }
    record_slot(s, digest, bytes.len(), keyed)
}

/// Upsert the slot for a blob now on disk. An overwrite (mutable keyed
/// blob, or identical content re-put) refreshes the existing slot in
/// place.
fn record_slot(
    s: &mut ModuleState,
    digest: &[u8; super::wire::DIGEST_LEN],
    len: usize,
    keyed: u8,
) -> bool {
    if let Some(slot) = s
        .slots
        .iter_mut()
        .find(|sl| sl.in_use != 0 && sl.digest == *digest)
    {
        slot.size = len as u32;
        slot.keyed = keyed;
        return true;
    }
    match find_empty_slot(s) {
        Some(slot) => {
            slot.digest = *digest;
            slot.size = len as u32;
            slot.in_use = 1;
            slot.keyed = keyed;
            true
        }
        None => false,
    }
}

// ── PUT_KEYED ─────────────────────────────────────────────────────

/// Store bytes at an EXPLICIT key rather than the content hash.
/// Used for EC shard blobs (key derives from (body_digest, shard
/// index)) and volume extent blobs (key derives from (volume_id,
/// extent index)); both are self-describing, so disk-fallback
/// reads verify them against the key instead of a content hash.
/// MUTABLE: a re-put of an existing key overwrites — last write
/// wins. (Extents require it; EC shard content is deterministic
/// per key, so an overwrite there is a no-op by value.)
unsafe fn handle_put_keyed(s: &mut ModuleState, bytes: &[u8]) {
    if s.root_dir_len == 0 {
        nak(s, super::wire::ERR_NO_ROOT);
        return;
    }
    let (key_bytes, blob) = match super::wire::decode_put_keyed_req(bytes) {
        Ok(v) => v,
        Err(super::wire::WireError::BodyTooLarge { .. }) => {
            nak(s, super::wire::ERR_TOO_LARGE);
            return;
        }
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };
    let mut key = [0u8; super::wire::DIGEST_LEN];
    key.copy_from_slice(key_bytes);

    if !write_blob_at(s, &key, blob, 1) {
        nak(s, super::wire::ERR_IO);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let n = match super::wire::encode_put_keyed_resp(&mut s.scratch, &key) {
        Ok(n) => n,
        Err(_) => {
            nak(s, super::wire::ERR_IO);
            return;
        }
    };
    write_resp(s, n);
    s.puts = s.puts.wrapping_add(1);
}

// ── GET ───────────────────────────────────────────────────────────

unsafe fn handle_get(s: &mut ModuleState, bytes: &[u8]) {
    if s.root_dir_len == 0 {
        nak(s, super::wire::ERR_NO_ROOT);
        return;
    }
    let digest_bytes = match super::wire::decode_get_req(bytes) {
        Ok(d) => d,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };
    let mut digest = [0u8; super::wire::DIGEST_LEN];
    digest.copy_from_slice(digest_bytes);

    // Slot hit → exact size. Slot miss → DISK FALLBACK: the table is
    // in-arena and empty after a restart, but the content-addressed
    // file may still exist. `size = None` means read-to-EOF + verify.
    let size: Option<usize> = match find_slot(s, &digest) {
        Some(slot) => Some(slot.size as usize),
        None => None,
    };
    if let Some(sz) = size {
        if sz > super::wire::MAX_BODY {
            nak(s, super::wire::ERR_TOO_LARGE);
            return;
        }
    }

    let mut path = [0u8; 256];
    let plen = build_body_path(s, &digest, &mut path);
    if plen == 0 {
        nak(s, super::wire::ERR_IO);
        return;
    }
    let path_slice = &path[..plen];

    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => {
            nak(s, super::wire::ERR_IO);
            return;
        }
    };

    let fd = (sys.provider_call)(
        -1,
        FS_OPEN,
        path_slice.as_ptr() as *mut u8,
        path_slice.len(),
    );
    if fd < 0 {
        nak(s, super::wire::ERR_NOT_FOUND);
        return;
    }
    // Seek to 0 in case the FD was reused (slot table may have
    // been recreated; provider seeks to 0 on open, but be safe).
    let zero: [u8; 4] = 0u32.to_le_bytes();
    let _ = (sys.provider_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4);

    // Read into the scratch buffer past the 5-byte response
    // header, so we can encode in place.
    let read_dst_off = 5;
    let cap = match size {
        Some(sz) => sz,
        None => super::wire::MAX_BODY, // fallback: bounded read-to-EOF
    };
    if read_dst_off + cap > s.scratch.len() {
        let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        nak(s, super::wire::ERR_IO);
        return;
    }
    let mut filled = 0usize;
    while filled < cap {
        let want = cap - filled;
        let n = (sys.provider_call)(
            fd,
            FS_READ,
            s.scratch.as_mut_ptr().add(read_dst_off + filled),
            want,
        );
        if n <= 0 {
            break;
        }
        filled += n as usize;
    }
    let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    let size = match size {
        Some(sz) => {
            if filled != sz {
                nak(s, super::wire::ERR_IO);
                return;
            }
            sz
        }
        None => {
            // Fallback read: verify the bytes really belong to this
            // key before serving. A body blob's key IS its content
            // hash; an EC shard blob's key derives from the header
            // it carries — both checks are exact.
            let (verified, is_keyed) = {
                let bytes = &s.scratch[read_dst_off..read_dst_off + filled];
                let mut hasher = super::sha256::Sha256::new();
                hasher.update(bytes);
                if hasher.finalize() == digest {
                    (true, 0u8)
                } else if super::ec_wire::shard_blob_matches_key(bytes, &digest)
                    || super::extent_wire::extent_blob_matches_key(bytes, &digest)
                {
                    (true, 1u8)
                } else {
                    (false, 0u8)
                }
            };
            if !verified {
                nak(s, super::wire::ERR_NOT_FOUND);
                return;
            }
            if let Some(slot) = find_empty_slot(s) {
                slot.digest = digest;
                slot.size = filled as u32;
                slot.in_use = 1;
                slot.keyed = is_keyed;
            } // full table: fine — next GET re-reads from disk
            filled
        }
    };

    // Write the 5-byte response header in front of the body bytes.
    s.scratch[0] = super::wire::OP_GET;
    s.scratch[1..5].copy_from_slice(&(size as u32).to_le_bytes());
    write_resp(s, 5 + size);
    s.gets = s.gets.wrapping_add(1);
}

// ── HEAD ──────────────────────────────────────────────────────────

unsafe fn handle_head(s: &mut ModuleState, bytes: &[u8]) {
    let digest_bytes = match super::wire::decode_head_req(bytes) {
        Ok(d) => d,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };
    let mut digest = [0u8; super::wire::DIGEST_LEN];
    digest.copy_from_slice(digest_bytes);
    // Slot miss → DISK FALLBACK, same as GET: the slot table is
    // in-arena and empty after a restart, but the file may exist.
    // Size via FS_STAT, keyed-ness via a 4-byte magic sniff; the
    // slot is rehydrated so later ops are table hits. (Unlike the
    // GET fallback this serves without a full-content verify — a
    // HEAD answers existence + size, and the GET that follows any
    // consequential read still verifies.)
    let size = match find_slot(s, &digest) {
        Some(slot) => slot.size as u64,
        None => {
            let sys = match s.syscalls.as_ref() {
                Some(t) => t,
                None => {
                    nak(s, super::wire::ERR_IO);
                    return;
                }
            };
            let mut path = [0u8; 256];
            let plen = build_body_path(s, &digest, &mut path);
            if plen == 0 {
                nak(s, super::wire::ERR_IO);
                return;
            }
            let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
            if fd < 0 {
                nak(s, super::wire::ERR_NOT_FOUND);
                return;
            }
            let mut stat = [0u8; 8];
            let rc = (sys.provider_call)(fd, FS_STAT, stat.as_mut_ptr(), stat.len());
            let mut magic = [0u8; 4];
            let mread = (sys.provider_call)(fd, FS_READ, magic.as_mut_ptr(), magic.len());
            let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            if rc < 0 {
                nak(s, super::wire::ERR_NOT_FOUND);
                return;
            }
            let size = u32::from_le_bytes([stat[0], stat[1], stat[2], stat[3]]);
            if size as usize > super::wire::MAX_BODY {
                nak(s, super::wire::ERR_TOO_LARGE);
                return;
            }
            if let Some(slot) = find_empty_slot(s) {
                slot.digest = digest;
                slot.size = size;
                slot.in_use = 1;
                slot.keyed = if mread >= 4 && super::extent_wire::blob_is_keyed_magic(&magic) {
                    1
                } else {
                    0
                };
            }
            size as u64
        }
    };
    let n = match super::wire::encode_head_resp(&mut s.scratch, size) {
        Ok(n) => n,
        Err(_) => {
            nak(s, super::wire::ERR_IO);
            return;
        }
    };
    write_resp(s, n);
    s.heads = s.heads.wrapping_add(1);
}

// ── DELETE ────────────────────────────────────────────────────────

unsafe fn handle_delete(s: &mut ModuleState, bytes: &[u8]) {
    let digest_bytes = match super::wire::decode_delete_req(bytes) {
        Ok(d) => d,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };
    let mut digest = [0u8; super::wire::DIGEST_LEN];
    digest.copy_from_slice(digest_bytes);
    // Retirement is fail-closed: the slot is the store's record that
    // the blob is reachable, so it is cleared only once the file is
    // provably gone. Clearing first would report a delete that did not
    // happen — the file survives, the next disk sweep rehydrates it,
    // and the caller has already been told it was retired.
    let slot_present = find_slot(s, &digest).is_some();
    let mut file_existed = false;
    let mut retired = true;
    if s.root_dir_len != 0 {
        let mut path = [0u8; 256];
        let plen = build_body_path(s, &digest, &mut path);
        if plen == 0 {
            nak(s, super::wire::ERR_IO);
            return;
        }
        let _ = publish_tier(s); // populates `caps`
        let names_are_fenceable = s.caps & super::fs_names::CAP_FSYNC_NAME != 0;
        match s.syscalls.as_ref() {
            Some(sys) => {
                let rc = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), plen);
                file_existed = rc == 0;
                if rc == 0 {
                    // An unlink whose directory entry is still volatile
                    // can reappear after a power cut, so the removal is
                    // not retired until its name is fenced. Without
                    // that fence the store cannot prove retirement and
                    // must not claim it.
                    retired = names_are_fenceable && fsync_name(sys, &mut path, plen);
                } else {
                    // Unlink failed. Deleting a blob that was never
                    // there is a retirement that has already happened,
                    // so probe the name rather than trust an errno
                    // mapping: absent is success, present is failure.
                    retired = !name_present(sys, &mut path, plen);
                }
            }
            None => retired = false,
        }
    }
    if !retired {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        nak(s, super::wire::ERR_IO);
        return;
    }
    if let Some(slot) = find_slot(s, &digest) {
        slot.in_use = 0;
        slot.size = 0;
        slot.digest = [0u8; super::wire::DIGEST_LEN];
    }
    let existed = slot_present || file_existed;
    let n = match super::wire::encode_delete_resp(&mut s.scratch, existed) {
        Ok(n) => n,
        Err(_) => {
            nak(s, super::wire::ERR_IO);
            return;
        }
    };
    write_resp(s, n);
    s.deletes = s.deletes.wrapping_add(1);
}

// ── SCAN ──────────────────────────────────────────────────────────

/// Page through the store's digest inventory. The cursor is a slot
/// index; next_cursor 0 signals the enumeration wrapped.
///
/// A cursor-0 request (the start of an enumeration round) first
/// rehydrates the slot table from the DISK inventory: the table is
/// in-arena and empty after a restart, but the content-addressed
/// files survive, so the root dir is swept via FS_OPENDIR +
/// FS_READDIR and every 64-hex filename missing from the table gets
/// a slot (size via FS_OPEN + FS_STAT — no body read). This makes
/// scan authoritative for what's on disk, which is what scrub needs
/// after a whole-fleet restart. The sweep is bounded by BODY_SLOTS.
unsafe fn handle_scan(s: &mut ModuleState, bytes: &[u8]) {
    let (cursor, max) = match super::wire::decode_scan_req(bytes) {
        Ok(v) => v,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };
    if cursor == 0 {
        rehydrate_from_disk(s);
    }
    let take = (max as usize).min(super::wire::MAX_SCAN_DIGESTS);
    let mut digests = [[0u8; super::wire::DIGEST_LEN]; super::wire::MAX_SCAN_DIGESTS];
    let mut keyed = [0u8; super::wire::MAX_SCAN_DIGESTS];
    let mut count = 0usize;
    let mut idx = cursor as usize;
    while idx < BODY_SLOTS && count < take {
        if s.slots[idx].in_use != 0 {
            digests[count] = s.slots[idx].digest;
            keyed[count] = s.slots[idx].keyed;
            count += 1;
        }
        idx += 1;
    }
    let next_cursor = if idx >= BODY_SLOTS { 0 } else { idx as u32 };
    let n = match super::wire::encode_scan_resp(
        &mut s.scratch,
        next_cursor,
        &digests[..count],
        &keyed[..count],
    ) {
        Ok(n) => n,
        Err(_) => {
            nak(s, super::wire::ERR_IO);
            return;
        }
    };
    write_resp(s, n);
    s.scans = s.scans.wrapping_add(1);
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Parse a `.wip_<n>` temporary filename back into its session id.
fn wip_id_from_name(name: &[u8]) -> Option<usize> {
    const PREFIX: &[u8] = b".wip_";
    if name.len() != PREFIX.len() + 1 || &name[..PREFIX.len()] != PREFIX {
        return None;
    }
    let d = name[PREFIX.len()];
    if d.is_ascii_digit() {
        Some((d - b'0') as usize)
    } else {
        None
    }
}

/// True for a `.pub_<hex>` publication staging name.
fn is_pub_staging_name(name: &[u8]) -> bool {
    const PREFIX: &[u8] = b".pub_";
    name.len() > PREFIX.len()
        && &name[..PREFIX.len()] == PREFIX
        && name[PREFIX.len()..].iter().all(|c| hex_val(*c).is_some())
}

/// Parse a body filename (64 lowercase hex chars) back into its
/// digest. Anything else in the root dir is not ours — skipped.
fn hex_digest_from_name(name: &[u8]) -> Option<[u8; super::wire::DIGEST_LEN]> {
    if name.len() != HEX_DIGEST_LEN {
        return None;
    }
    let mut d = [0u8; super::wire::DIGEST_LEN];
    for (i, out) in d.iter_mut().enumerate() {
        let hi = hex_val(name[2 * i])?;
        let lo = hex_val(name[2 * i + 1])?;
        *out = (hi << 4) | lo;
    }
    Some(d)
}

/// Sweep the root dir and give every on-disk body missing from the
/// in-arena slot table a slot. Sizes come from FS_OPEN + FS_STAT —
/// no body bytes are read, so the sweep costs three provider calls
/// per missing entry and nothing per already-known entry. Stops
/// early if the slot table fills.
unsafe fn rehydrate_from_disk(s: &mut ModuleState) {
    if s.root_dir_len == 0 {
        return;
    }
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return,
    };
    let dlen = s.root_dir_len as usize;
    let mut dir_path = [0u8; ROOT_DIR_BUF];
    dir_path[..dlen].copy_from_slice(&s.root_dir[..dlen]);
    let dir_fd = (sys.provider_call)(-1, FS_OPENDIR, dir_path.as_mut_ptr(), dlen);
    if dir_fd < 0 {
        return;
    }
    // READDIR output: [count: u16 LE][ [len: u8][is_dir: u8][name] ]*
    // repeated until the provider returns 0 ("drained").
    let mut buf = [0u8; 1024];
    'sweep: loop {
        let n = (sys.provider_call)(dir_fd, FS_READDIR, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        let n = n as usize;
        if n < 2 {
            break;
        }
        let count = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        if count == 0 {
            break;
        }
        let mut pos = 2usize;
        let mut seen = 0usize;
        while seen < count && pos + 2 <= n {
            let name_len = buf[pos] as usize;
            let is_dir = buf[pos + 1];
            pos += 2;
            if pos + name_len > n {
                break;
            }
            let mut name = [0u8; HEX_DIGEST_LEN];
            let take = name_len.min(HEX_DIGEST_LEN);
            name[..take].copy_from_slice(&buf[pos..pos + take]);
            pos += name_len;
            seen += 1;
            if is_dir != 0 {
                continue;
            }
            let raw_name = &buf[pos - name_len..pos];
            // A `.wip_N` file is a streamed write's temporary. One
            // whose session is gone belongs to a stream that died
            // before its commit: no live state names it and no future
            // one will, because the next WOPEN for that id unlinks it
            // first. Remove it so the boot treatment of an interrupted
            // stream is the same every time.
            if let Some(wid) = wip_id_from_name(raw_name) {
                if wid >= WRITE_SESSIONS || s.wsessions[wid].in_use == 0 {
                    let mut wpath = [0u8; 256];
                    let wplen = build_wip_path(s, wid as u8, &mut wpath);
                    if wplen != 0 {
                        let _ = (sys.provider_call)(-1, FS_UNLINK, wpath.as_mut_ptr(), wplen);
                    }
                }
                continue;
            }
            // A `.pub_*` file is a publication that was interrupted
            // before its rename. Its bytes are unreachable by any
            // content path, so a re-PUT stages afresh; leaving it would
            // accumulate one per interrupted write.
            if is_pub_staging_name(raw_name) {
                let rl = s.root_dir_len as usize;
                let mut ppath = [0u8; 256];
                if rl + 1 + name_len <= ppath.len() {
                    ppath[..rl].copy_from_slice(&s.root_dir[..rl]);
                    ppath[rl] = b'/';
                    ppath[rl + 1..rl + 1 + name_len].copy_from_slice(raw_name);
                    let _ =
                        (sys.provider_call)(-1, FS_UNLINK, ppath.as_mut_ptr(), rl + 1 + name_len);
                }
                continue;
            }
            let digest = match hex_digest_from_name(&name[..name_len.min(HEX_DIGEST_LEN)]) {
                Some(d) if name_len == HEX_DIGEST_LEN => d,
                _ => continue,
            };
            if find_slot(s, &digest).is_some() {
                continue;
            }
            let mut path = [0u8; 256];
            let plen = build_body_path(s, &digest, &mut path);
            if plen == 0 {
                continue;
            }
            let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
            if fd < 0 {
                continue;
            }
            let mut stat = [0u8; 8];
            let rc = (sys.provider_call)(fd, FS_STAT, stat.as_mut_ptr(), stat.len());
            // Keyed-ness sniff: keyed blobs (extents, EC shards)
            // open with a known magic; 4 bytes tell them apart
            // from content-addressed bodies without a body read.
            let mut magic = [0u8; 4];
            let mread = (sys.provider_call)(fd, FS_READ, magic.as_mut_ptr(), magic.len());
            let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            if rc < 0 {
                continue;
            }
            let size = u32::from_le_bytes([stat[0], stat[1], stat[2], stat[3]]);
            if size as usize > super::wire::MAX_BODY {
                continue;
            }
            let keyed = if mread >= 4 && super::extent_wire::blob_is_keyed_magic(&magic) {
                1
            } else {
                0
            };
            match find_empty_slot(s) {
                Some(slot) => {
                    slot.digest = digest;
                    slot.size = size;
                    slot.in_use = 1;
                    slot.keyed = keyed;
                }
                None => break 'sweep,
            }
            s.rehydrated = s.rehydrated.wrapping_add(1);
        }
    }
    let _ = (sys.provider_call)(dir_fd, FS_CLOSE, core::ptr::null_mut(), 0);
}

// ── Chunked writes (WOPEN / WAPPEND / WCOMMIT / WABORT) ───────────

/// `<root>/.wip_<wid>` into `out`; returns length or 0.
unsafe fn build_wip_path(s: &ModuleState, wid: u8, out: &mut [u8]) -> usize {
    let rl = s.root_dir_len as usize;
    if rl == 0 || out.len() < rl + 8 {
        return 0;
    }
    out[..rl].copy_from_slice(&s.root_dir[..rl]);
    let suffix = [b'/', b'.', b'w', b'i', b'p', b'_', b'0' + (wid % 10)];
    out[rl..rl + suffix.len()].copy_from_slice(&suffix);
    rl + suffix.len()
}

unsafe fn session_cleanup(s: &mut ModuleState, wid: usize) {
    let fd = s.wsessions[wid].fd;
    if fd >= 0 {
        if let Some(sys) = s.syscalls.as_ref() {
            let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            let mut path = [0u8; 256];
            let plen = build_wip_path(s, wid as u8, &mut path);
            if plen != 0 {
                let _ = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), plen);
            }
        }
    }
    s.wsessions[wid].in_use = 0;
    s.wsessions[wid].fd = -1;
}

unsafe fn reap_stale_sessions(s: &mut ModuleState) {
    for wid in 0..WRITE_SESSIONS {
        if s.wsessions[wid].in_use != 0
            && s.ticks.wrapping_sub(s.wsessions[wid].last_tick) > SESSION_REAP_TICKS
        {
            session_cleanup(s, wid);
            s.stream_aborts = s.stream_aborts.wrapping_add(1);
        }
    }
}

unsafe fn handle_wopen(s: &mut ModuleState, bytes: &[u8]) {
    if s.root_dir_len == 0 {
        nak(s, super::wire::ERR_NO_ROOT);
        return;
    }
    let (digest_bytes, total_len) = match super::wire::decode_wopen_req(bytes) {
        Ok(v) => v,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };
    if total_len == 0 || total_len > super::wire::MAX_STREAM_TOTAL {
        nak(s, super::wire::ERR_TOO_LARGE);
        return;
    }
    let wid = match (0..WRITE_SESSIONS).find(|&i| s.wsessions[i].in_use == 0) {
        Some(i) => i,
        None => {
            nak(s, super::wire::ERR_IO);
            return;
        }
    };
    let mut path = [0u8; 256];
    let plen = build_wip_path(s, wid as u8, &mut path);
    if plen == 0 {
        nak(s, super::wire::ERR_IO);
        return;
    }
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => {
            nak(s, super::wire::ERR_IO);
            return;
        }
    };
    // A leftover temp from a crashed stream must not contribute
    // stale prefix bytes — unlink before create.
    let _ = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), plen);
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
    if fd < 0 {
        nak(s, super::wire::ERR_IO);
        return;
    }
    let sess = &mut s.wsessions[wid];
    sess.in_use = 1;
    sess.fd = fd;
    sess.expect.copy_from_slice(digest_bytes);
    sess.total_len = total_len;
    sess.written = 0;
    sess.last_tick = s.ticks;
    sess.hasher = super::sha256::Sha256::new();
    s.stream_opens = s.stream_opens.wrapping_add(1);
    let n = match super::wire::encode_wopen_resp(&mut s.scratch, wid as u8) {
        Ok(n) => n,
        Err(_) => return,
    };
    write_resp(s, n);
}

unsafe fn handle_wappend(s: &mut ModuleState, bytes: &[u8]) {
    let (wid, chunk) = match super::wire::decode_wappend_req(bytes) {
        Ok(v) => v,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };
    let wid = wid as usize;
    if wid >= WRITE_SESSIONS || s.wsessions[wid].in_use == 0 {
        nak(s, super::wire::ERR_BAD_REQ);
        return;
    }
    if s.wsessions[wid].written + chunk.len() as u64 > s.wsessions[wid].total_len {
        session_cleanup(s, wid);
        nak(s, super::wire::ERR_TOO_LARGE);
        return;
    }
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => {
            nak(s, super::wire::ERR_IO);
            return;
        }
    };
    let fd = s.wsessions[wid].fd;
    let wrote = (sys.provider_call)(fd, FS_WRITE, chunk.as_ptr() as *mut u8, chunk.len());
    if wrote < 0 || (wrote as usize) != chunk.len() {
        session_cleanup(s, wid);
        nak(s, super::wire::ERR_IO);
        return;
    }
    s.wsessions[wid].hasher.update(chunk);
    s.wsessions[wid].written += chunk.len() as u64;
    s.wsessions[wid].last_tick = s.ticks;
    let n = match super::wire::encode_wappend_resp(&mut s.scratch, wid as u8) {
        Ok(n) => n,
        Err(_) => return,
    };
    write_resp(s, n);
}

unsafe fn handle_wcommit(s: &mut ModuleState, bytes: &[u8]) {
    let wid = match super::wire::decode_wid_req(bytes, super::wire::OP_WCOMMIT) {
        Ok(w) => w as usize,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };
    if wid >= WRITE_SESSIONS || s.wsessions[wid].in_use == 0 {
        nak(s, super::wire::ERR_BAD_REQ);
        return;
    }
    // Verify: every declared byte arrived AND hashes to the
    // declared digest. Either failure aborts — nothing publishes.
    let complete = s.wsessions[wid].written == s.wsessions[wid].total_len;
    let digest = {
        let mut h = super::sha256::Sha256::new();
        core::mem::swap(&mut h, &mut s.wsessions[wid].hasher);
        h.finalize()
    };
    if !complete || digest != s.wsessions[wid].expect {
        session_cleanup(s, wid);
        nak(s, super::wire::ERR_BAD_REQ);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let tier = publish_tier(s);
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => {
            session_cleanup(s, wid);
            nak(s, super::wire::ERR_IO);
            return;
        }
    };
    let tmp_fd = s.wsessions[wid].fd;
    let written = s.wsessions[wid].written;
    if (sys.provider_call)(tmp_fd, FS_FSYNC, core::ptr::null_mut(), 0) < 0 {
        session_cleanup(s, wid);
        nak(s, super::wire::ERR_IO);
        return;
    }
    // Publish. The stream has already written every byte to the
    // temporary and verified the digest, and the fsync above fences
    // those bytes; only the name is left.
    //
    // `Rename` publishes it atomically — the temporary IS the artefact,
    // so the commit is one provider call and no partial final artefact
    // is ever observable. `NameFence` has no atomic replace, so the
    // bytes are copied to the content path and the name fenced after;
    // content addressing is what makes an interrupted copy detectable.
    // Without either, the commit cannot claim publication and refuses.
    let mut final_path = [0u8; 256];
    let plen = build_body_path(s, &digest, &mut final_path);
    if plen == 0 {
        session_cleanup(s, wid);
        nak(s, super::wire::ERR_IO);
        return;
    }
    // No short-circuit on an existing same-length file: length is not
    // a digest, and this session holds bytes whose digest is verified.
    // Publishing them is the only path that makes the acknowledgement
    // true.
    if tier == PublishTier::Unavailable {
        session_cleanup(s, wid);
        nak(s, super::wire::ERR_IO);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    if tier == PublishTier::Rename {
        // The temporary already holds the verified, fenced bytes: the
        // publication is the rename of that file onto its content path.
        let mut tmp_path = [0u8; 256];
        let tlen = build_wip_path(s, wid as u8, &mut tmp_path);
        let _ = (sys.provider_call)(tmp_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.wsessions[wid].fd = -1;
        s.wsessions[wid].in_use = 0;
        if tlen == 0 || !rename_path(sys, &tmp_path[..tlen], &final_path[..plen]) {
            if tlen != 0 {
                let _ = (sys.provider_call)(-1, FS_UNLINK, tmp_path.as_mut_ptr(), tlen);
            }
            nak(s, super::wire::ERR_IO);
            return;
        }
        record_slot(s, &digest, written.min(u32::MAX as u64) as usize, 0);
        s.stream_commits = s.stream_commits.wrapping_add(1);
        let n = match super::wire::encode_wcommit_resp(&mut s.scratch, &digest) {
            Ok(n) => n,
            Err(_) => return,
        };
        write_resp(s, n);
        return;
    }
    let out_fd = (sys.provider_call)(-1, FS_OPEN_CREATE, final_path.as_mut_ptr(), plen);
    if out_fd < 0 {
        session_cleanup(s, wid);
        nak(s, super::wire::ERR_IO);
        return;
    }
    let zero: [u8; 4] = 0u32.to_le_bytes();
    let _ = (sys.provider_call)(tmp_fd, FS_SEEK, zero.as_ptr() as *mut u8, 4);
    let mut copied: u64 = 0;
    let mut ok = true;
    while copied < written {
        let n = (sys.provider_call)(
            tmp_fd,
            FS_READ,
            s.scratch.as_mut_ptr(),
            super::wire::MAX_BODY.min((written - copied) as usize),
        );
        if n <= 0 {
            ok = false;
            break;
        }
        let w = (sys.provider_call)(out_fd, FS_WRITE, s.scratch.as_mut_ptr(), n as usize);
        if w != n {
            ok = false;
            break;
        }
        copied += n as u64;
    }
    if ok {
        ok = (sys.provider_call)(out_fd, FS_FSYNC, core::ptr::null_mut(), 0) >= 0;
    }
    let _ = (sys.provider_call)(out_fd, FS_CLOSE, core::ptr::null_mut(), 0);
    // The name is what a later mount finds the bytes by, so it is
    // fenced before the commit is acknowledged.
    if ok {
        ok = fsync_name(sys, &mut final_path, plen);
    }
    session_cleanup(s, wid); // closes + unlinks the temp
    if !ok {
        nak(s, super::wire::ERR_IO);
        return;
    }
    record_slot(s, &digest, written.min(u32::MAX as u64) as usize, 0);
    s.stream_commits = s.stream_commits.wrapping_add(1);
    let n = match super::wire::encode_wcommit_resp(&mut s.scratch, &digest) {
        Ok(n) => n,
        Err(_) => return,
    };
    write_resp(s, n);
}

unsafe fn handle_wabort(s: &mut ModuleState, bytes: &[u8]) {
    let wid = match super::wire::decode_wid_req(bytes, super::wire::OP_WABORT) {
        Ok(w) => w as usize,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };
    if wid < WRITE_SESSIONS && s.wsessions[wid].in_use != 0 {
        session_cleanup(s, wid);
        s.stream_aborts = s.stream_aborts.wrapping_add(1);
    }
    let n = match super::wire::encode_wabort_resp(&mut s.scratch) {
        Ok(n) => n,
        Err(_) => return,
    };
    write_resp(s, n);
}

// ── Ranged reads ──────────────────────────────────────────────────

unsafe fn handle_range(s: &mut ModuleState, bytes: &[u8]) {
    if s.root_dir_len == 0 {
        nak(s, super::wire::ERR_NO_ROOT);
        return;
    }
    let (digest_bytes, off, want) = match super::wire::decode_range_req(bytes) {
        Ok(v) => v,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return;
        }
    };
    let mut digest = [0u8; super::wire::DIGEST_LEN];
    digest.copy_from_slice(digest_bytes);
    let mut path = [0u8; 256];
    let plen = build_body_path(s, &digest, &mut path);
    if plen == 0 {
        nak(s, super::wire::ERR_IO);
        return;
    }
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => {
            nak(s, super::wire::ERR_IO);
            return;
        }
    };
    let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
    if fd < 0 {
        nak(s, super::wire::ERR_NOT_FOUND);
        return;
    }
    // File size via STAT so a past-EOF range answers empty rather
    // than a short read being ambiguous.
    let mut stat = [0u8; 8];
    if (sys.provider_call)(fd, FS_STAT, stat.as_mut_ptr(), stat.len()) < 0 {
        let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        nak(s, super::wire::ERR_IO);
        return;
    }
    let size = u32::from_le_bytes([stat[0], stat[1], stat[2], stat[3]]) as u64;
    if off >= size {
        let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        let n = match super::wire::encode_range_resp(&mut s.scratch, &[]) {
            Ok(n) => n,
            Err(_) => return,
        };
        write_resp(s, n);
        s.ranges = s.ranges.wrapping_add(1);
        return;
    }
    let take = (want as u64)
        .min(super::wire::MAX_BODY as u64)
        .min(size - off) as usize;
    let off32: [u8; 4] = (off as u32).to_le_bytes();
    let _ = (sys.provider_call)(fd, FS_SEEK, off32.as_ptr() as *mut u8, 4);
    // Read into scratch past the 5-byte header, encode in place.
    let mut filled = 0usize;
    while filled < take {
        let n = (sys.provider_call)(
            fd,
            FS_READ,
            s.scratch.as_mut_ptr().add(5 + filled),
            take - filled,
        );
        if n <= 0 {
            break;
        }
        filled += n as usize;
    }
    let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    s.scratch[0] = super::wire::OP_RANGE;
    s.scratch[1..5].copy_from_slice(&(filled as u32).to_le_bytes());
    write_resp(s, 5 + filled);
    s.ranges = s.ranges.wrapping_add(1);
}

unsafe fn nak(s: &mut ModuleState, errno: u8) {
    let n = match super::wire::encode_nak(&mut s.scratch, errno) {
        Ok(n) => n,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    write_resp(s, n);
    s.apply_errors = s.apply_errors.wrapping_add(1);
}

/// Take ownership of the response now in `scratch` and offer it.
unsafe fn write_resp(s: &mut ModuleState, n: usize) {
    if n == 0 || n > s.scratch.len() {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.resp_len = n as u32;
    s.resp_sent = 0;
    let _ = flush_resp(s);
}

/// Offer the owed response. True once every byte has been accepted,
/// and when nothing is owed, so a caller can gate on it directly.
unsafe fn flush_resp(s: &mut ModuleState) -> bool {
    if s.resp_len == 0 {
        return true;
    }
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return false,
    };
    if s.out_chan < 0 {
        return false;
    }
    let at = s.resp_sent as usize;
    let rc = (sys.channel_write)(
        s.out_chan,
        s.scratch.as_ptr().add(at),
        s.resp_len as usize - at,
    );
    if rc <= 0 {
        return false;
    }
    s.resp_sent = (s.resp_sent + rc as u32).min(s.resp_len);
    if s.resp_sent < s.resp_len {
        return false;
    }
    s.resp_len = 0;
    s.resp_sent = 0;
    true
}

fn find_slot<'a>(
    s: &'a mut ModuleState,
    digest: &[u8; super::wire::DIGEST_LEN],
) -> Option<&'a mut DiskSlot> {
    for slot in s.slots.iter_mut() {
        if slot.in_use != 0 && slot.digest == *digest {
            return Some(slot);
        }
    }
    None
}

fn find_empty_slot(s: &mut ModuleState) -> Option<&mut DiskSlot> {
    for slot in s.slots.iter_mut() {
        if slot.in_use == 0 {
            return Some(slot);
        }
    }
    None
}
