// Step body for `body_store`. Disk-backed content-addressed
// store. Each PUT writes the body to
// `<root_dir>/<hex(sha256(body))>` via FS_OPEN_CREATE + FS_WRITE
// + FS_FSYNC + FS_CLOSE. The in-arena slot table holds only
// (digest, size) metadata so the PIC's memory footprint stays
// flat regardless of how much body data has been stored.
//
// `<root_dir>` must already exist (the fluxor fs contract has no
// MKDIR opcode). The graph profile / launch script is responsible
// for creating it; PUT against a missing directory fails with
// ERR_NO_ROOT.
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
/// `<root>/.wip_<wid>` with an incremental hash; COMMIT verifies
/// the declared digest and publishes by copying to the content
/// path (an FS_RENAME fs-contract op is the tracked optimization).
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
    pub slots: [DiskSlot; BODY_SLOTS],
    pub wsessions: [WriteSession; WRITE_SESSIONS],
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

    let mut handled: u32 = 0;
    while handled < MAX_OPS_PER_STEP {
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
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return false,
    };
    // FS_OPEN_CREATE does not truncate: a shorter overwrite
    // (mutable keyed blob) would leave a stale tail that the
    // restart-time disk-fallback read would serve. Unlink first —
    // a crash inside the window is a torn extent write, which is
    // exactly the contract a block device gives its filesystem.
    let _ = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), plen);
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
    if fd < 0 {
        return false;
    }
    let wrote = (sys.provider_call)(fd, FS_WRITE, bytes.as_ptr() as *mut u8, bytes.len());
    if wrote < 0 || (wrote as usize) != bytes.len() {
        let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        return false;
    }
    if (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0) < 0 {
        let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        return false;
    }
    let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    // Upsert: an overwrite (mutable keyed blob, or identical
    // content re-put) refreshes the existing slot in place.
    if let Some(slot) = s
        .slots
        .iter_mut()
        .find(|sl| sl.in_use != 0 && sl.digest == *digest)
    {
        slot.size = bytes.len() as u32;
        slot.keyed = keyed;
        return true;
    }
    match find_empty_slot(s) {
        Some(slot) => {
            slot.digest = *digest;
            slot.size = bytes.len() as u32;
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
    // Clear the slot AND unlink the on-disk file. The unlink is
    // attempted even without a slot (restarts empty the in-arena
    // table but leave files); `existed` reflects either.
    let slot_existed = if let Some(slot) = find_slot(s, &digest) {
        slot.in_use = 0;
        slot.size = 0;
        slot.digest = [0u8; super::wire::DIGEST_LEN];
        true
    } else {
        false
    };
    let mut file_existed = false;
    if s.root_dir_len != 0 {
        let mut path = [0u8; 256];
        let plen = build_body_path(s, &digest, &mut path);
        if plen != 0 {
            if let Some(sys) = s.syscalls.as_ref() {
                let rc = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), plen);
                file_existed = rc == 0;
            }
        }
    }
    let existed = slot_existed || file_existed;
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
    // Publish: copy temp → content path. (FS_RENAME would make
    // this O(1); tracked as the fs-contract optimization.)
    let mut final_path = [0u8; 256];
    let plen = build_body_path(s, &digest, &mut final_path);
    if plen == 0 {
        session_cleanup(s, wid);
        nak(s, super::wire::ERR_IO);
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
    session_cleanup(s, wid); // closes + unlinks the temp
    if !ok {
        nak(s, super::wire::ERR_IO);
        return;
    }
    if find_slot(s, &digest).is_none() {
        if let Some(slot) = find_empty_slot(s) {
            slot.digest = digest;
            slot.size = written.min(u32::MAX as u64) as u32;
            slot.in_use = 1;
            slot.keyed = 0;
        }
    }
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

unsafe fn write_resp(s: &mut ModuleState, n: usize) {
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return,
    };
    let _ = (sys.channel_write)(s.out_chan, s.scratch.as_ptr(), n);
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
