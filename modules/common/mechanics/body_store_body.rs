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
//
// No fs call waits on the device. A call answers now, or `EAGAIN`
// (not now, nothing moved), or `EINPROGRESS` (taken, re-ask the
// identical request for the decision). So every request that touches
// the disk runs as a resumable sequence held in `ModuleState::job`:
// a pending answer parks it, the request record stays held in the
// inbox, and the next step re-enters the same handler at the phase it
// stopped in, re-asking the same call with the same arguments. A
// request is answered only once its sequence has decided, and
// requests are served in arrival order, so a parked one holds the
// requests behind it rather than letting a later answer overtake it.

const SCRATCH_OUT: usize = super::wire::RECORD_MAX;

// Capacity profile — see namespace_pic_body.rs.
pub use super::limits::BODY_SLOTS;
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

/// Every path this module names: the longest root, `/`, and the longest
/// entry name it builds — a body's 64 hex digits. Derived, so a root the
/// module accepts always has room for every name under it.
const PATH_BUF: usize = ROOT_DIR_BUF + 1 + HEX_DIGEST_LEN;
// The staging and temporary names are shorter than a content name:
// `.pub_` and 16 hex digits, `.wip_` and a three-digit id.
const _: () = assert!(5 + 16 <= HEX_DIGEST_LEN && 5 + WIP_ID_DIGITS <= HEX_DIGEST_LEN);
// Both renames this module issues (`.pub_` staging and a streamed
// commit's `.wip_` temporary, each onto its content path) fit the frame
// `fs_names::rename` builds.
const _: () = assert!(
    2 * PATH_BUF <= super::fs_names::RENAME_PATHS_MAX,
    "a body publication's rename would not fit"
);
/// One READDIR answer, held across steps while its entries are
/// worked through: `[count: u16 LE][ [len: u8][is_dir: u8][name] ]*`.
const DIR_BUF: usize = 1024;
/// Directory entries one step's sweep examines before it yields. The
/// sweep's calls are each bounded, but a large root is not, and a step
/// must be.
const SWEEP_ENTRIES_PER_STEP: u32 = 256;
/// Read-then-write rounds one step's commit copy makes before it
/// yields, for the same reason: a streamed body is up to
/// `MAX_STREAM_TOTAL`, far more than one step should move.
const COPY_ROUNDS_PER_STEP: u32 = 8;

/// True when `rc` is not an answer yet — `EAGAIN` or `EINPROGRESS`.
/// Either way the sequence parks and asks again on a later step; it is
/// never a failure, an end of data or an absence.
fn pending(rc: i32) -> bool {
    super::fs_names::pending(rc)
}

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

/// `Job::tier` codes. A tier is held as a byte rather than a
/// [`PublishTier`] because the job lives in zeroed module state, where
/// every byte pattern must already be a valid value.
const TIER_RENAME: u8 = 1;
const TIER_NAME_FENCE: u8 = 2;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DiskSlot {
    pub digest: [u8; super::wire::DIGEST_LEN],
    pub size: u32,
    pub in_use: u8,
    /// 1 when the blob is stored under an explicit key (an EC
    /// shard) rather than its content hash. Keyed
    /// blobs' lifecycle belongs to their writers — the orphan GC
    /// must never collect them, so SCAN reports this flag.
    pub keyed: u8,
}

/// Concurrent chunked writes. Each session streams to
/// `<root>/.wip_<wid>` with an incremental hash; COMMIT verifies the
/// declared digest, then publishes under the provider's
/// [`PublishTier`] — see `handle_wcommit`.
///
/// `<wid>` is the session's full id in decimal, so every live session
/// writes its own temporary: an id is never held by two sessions at
/// once, and is not reused until the removal of its last temporary has
/// been decided (`WriteSession::unlink_owed`).
pub use super::limits::WRITE_SESSIONS;
/// A write id travels in one wire byte, so a temporary's id is at most
/// three decimal digits.
const _: () = assert!(WRITE_SESSIONS <= 256, "a write id is one wire byte");
/// Longest decimal write id a temporary name carries.
const WIP_ID_DIGITS: usize = 3;
/// Sessions untouched this many ticks are reaped (client died
/// mid-stream) — temp file unlinked, slot freed.
const SESSION_REAP_TICKS: u32 = 120_000;

#[repr(C)]
pub struct WriteSession {
    pub in_use: u8,
    /// The session has ended but its temporary's UNLINK has not been
    /// decided yet. The slot is not reusable until it has, because a
    /// new stream on this id would write the same `.wip_<wid>` name the
    /// owed unlink removes. See `retire_sessions`. Every other session
    /// writes a name of its own: `<wid>` is the full id.
    pub unlink_owed: u8,
    pub fd: i32,
    pub expect: [u8; super::wire::DIGEST_LEN],
    pub total_len: u64,
    pub written: u64,
    pub last_tick: u32,
    pub hasher: super::sha256::Sha256,
}

/// A resumable create → write → `FSYNC` → close of one file: the byte
/// fence every publication starts with. It does not hold the bytes:
/// the caller lends the same slice on every poll (the request record,
/// which the inbox keeps until the request is answered), and only the
/// count the provider has accepted is recorded here.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct WriteFence {
    /// `WF_*`. Zeroed is `WF_CREATE`, so a reset job starts here.
    pub phase: u8,
    /// Valid in `WF_WRITE` and `WF_FENCE` only.
    pub fd: i32,
    /// Bytes the provider has accepted. A short count is progress, not
    /// failure: the rest is offered from here on a later poll.
    pub done: u32,
}

const WF_CREATE: u8 = 0;
const WF_WRITE: u8 = 1;
const WF_FENCE: u8 = 2;

/// A resumable open → `STAT` → 4-byte magic read → close of one file:
/// what HEAD's disk fallback and the boot sweep learn about a body
/// without reading it.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Probe {
    /// `PR_*`. Zeroed is `PR_OPEN`.
    pub phase: u8,
    /// Magic bytes read so far.
    pub got: u8,
    pub fd: i32,
    pub stat: [u8; 8],
    pub magic: [u8; 4],
}

const PR_OPEN: u8 = 0;
const PR_STAT: u8 = 1;
const PR_MAGIC: u8 = 2;

/// What one poll of a resumable sequence decided.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Poll {
    /// An answer was `EAGAIN` or `EINPROGRESS`: ask again next step.
    Pending,
    Done,
    Failed,
}

/// What a [`Probe`] decided.
#[derive(Clone, Copy)]
enum ProbePoll {
    Pending,
    /// The file did not open, or would not stat.
    Absent,
    Found {
        size: u32,
        keyed: u8,
    },
}

/// The request in progress: where its fs sequence resumes, and every
/// value a later step needs to re-ask a call byte-for-byte.
///
/// `phase == 0` means no sequence is held, and the next request starts
/// fresh. Each handler gives the other phase values its own meaning;
/// only the handler for the held record (its opcode is in the inbox)
/// reads them.
#[repr(C)]
pub struct Job {
    pub phase: u8,
    /// `TIER_*`, once the publication tier has been resolved.
    pub tier: u8,
    pub keyed: u8,
    /// Per-request booleans (`DEL_*` for DELETE).
    pub flags: u8,
    pub wid: u8,
    /// A file this job opened and must close: the GET / RANGE source,
    /// or a streamed commit's copy target.
    pub fd: i32,
    pub dir_fd: i32,
    /// GET: the read cap. RANGE: the byte count to serve. SCAN: `max`.
    pub size: u32,
    /// Bytes read into `scratch`, or written of a WAPPEND chunk.
    pub filled: u32,
    /// RANGE: the offset. SCAN: the cursor.
    pub off: u64,
    /// Streamed copy: bytes read from the temporary so far.
    pub copied: u64,
    /// Streamed copy: bytes staged in `scratch`, and how many of them
    /// the target has accepted.
    pub copy_len: u32,
    pub copy_at: u32,
    pub digest: [u8; super::wire::DIGEST_LEN],
    pub plen: u16,
    pub tlen: u16,
    /// The final (content or key) path.
    pub path: [u8; PATH_BUF],
    /// A staging, temporary or swept path.
    pub tmp: [u8; PATH_BUF],
    pub stat: [u8; 8],
    pub wf: WriteFence,
    pub probe: Probe,
    pub dir_n: u16,
    pub dir_pos: u16,
    pub dir_count: u16,
    pub dir_seen: u16,
    pub dir: [u8; DIR_BUF],
}

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    pub root_dir: [u8; ROOT_DIR_BUF],
    pub root_dir_len: u16,
    /// The request being assembled from `body_requests`, framed
    /// (`body_frame.rs`).
    pub inbox: super::body_frame::Inbox<{ super::body_frame::RECORD_MAX }>,
    /// The correlation id of the request being answered; its response
    /// echoes it.
    pub cid: u32,
    pub scratch: [u8; SCRATCH_OUT],
    /// The response owed on `body_responses`: its frame header here,
    /// its record in `scratch`.
    ///
    /// An answer refused by the channel is retained, and no new
    /// request is read while one is owed, because the next response
    /// would overwrite `scratch`.
    pub out: super::body_frame::Sender,
    pub slots: [DiskSlot; BODY_SLOTS],
    pub wsessions: [WriteSession; WRITE_SESSIONS],
    /// The held request's fs sequence. While one is parked, `scratch`
    /// may hold its read bytes (GET, RANGE, a streamed copy) — safe,
    /// because no answer is staged until the sequence decides.
    pub job: Job,
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

    // Owed temporary removals progress whatever else the step does:
    // they answer nobody, and they hold their session ids until done.
    retire_sessions(s, syscalls);

    // An owed response owns the step until the channel takes it. Its
    // record lives in `scratch`, which the next request would
    // overwrite.
    if !flush_resp(s) {
        return 0;
    }

    let mut handled: u32 = 0;
    while handled < super::limits::OPS_PER_STEP {
        if !s.out.is_idle() {
            break;
        }
        // A record parked on a pending fs answer is still held, so
        // `pull` hands it back and its handler resumes below.
        match s.inbox.pull(syscalls, s.in_chan) {
            super::body_frame::Pull::Record => {}
            super::body_frame::Pull::Empty => break,
            super::body_frame::Pull::Oversize(cid) => {
                s.cid = cid;
                nak(s, super::wire::ERR_TOO_LARGE);
                handled = handled.wrapping_add(1);
                continue;
            }
            super::body_frame::Pull::Malformed => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                break;
            }
        }
        s.cid = s.inbox.cid();
        // The record is borrowed from the inbox while the handlers
        // mutate the rest of the state; the inbox is not touched
        // until `take` below.
        let bytes: &[u8] = &*(s.inbox.record() as *const [u8]);
        let op = match super::wire::peek_opcode(bytes) {
            Some(op) => op,
            None => {
                nak(s, super::wire::ERR_BAD_REQ);
                reset_job(s);
                s.inbox.take();
                handled = handled.wrapping_add(1);
                continue;
            }
        };
        let answered = match op {
            super::wire::OP_PUT => handle_put(s, syscalls, bytes),
            super::wire::OP_GET => handle_get(s, syscalls, bytes),
            super::wire::OP_HEAD => handle_head(s, syscalls, bytes),
            super::wire::OP_DELETE => handle_delete(s, syscalls, bytes),
            super::wire::OP_SCAN => handle_scan(s, syscalls, bytes),
            super::wire::OP_PUT_KEYED => handle_put_keyed(s, syscalls, bytes),
            super::wire::OP_WOPEN => handle_wopen(s, syscalls, bytes),
            super::wire::OP_WAPPEND => handle_wappend(s, syscalls, bytes),
            super::wire::OP_WCOMMIT => handle_wcommit(s, syscalls, bytes),
            super::wire::OP_WABORT => handle_wabort(s, bytes),
            super::wire::OP_RANGE => handle_range(s, syscalls, bytes),
            _ => {
                nak(s, super::wire::ERR_BAD_REQ);
                true
            }
        };
        if !answered {
            // Parked on an answer the provider has not decided. The
            // record stays held and `job` remembers the phase, so the
            // next step resumes this request; nothing behind it is
            // read meanwhile.
            break;
        }
        reset_job(s);
        s.inbox.take();
        handled = handled.wrapping_add(1);
    }
    reap_stale_sessions(s);
    0
}

/// Forget the finished request's sequence, so the next one starts
/// fresh.
fn reset_job(s: &mut ModuleState) {
    s.job.phase = 0;
    s.job.tier = 0;
    s.job.flags = 0;
    s.job.wf.phase = WF_CREATE;
    s.job.probe.phase = PR_OPEN;
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

/// The first `len` bytes of a held path: the exact bytes a re-ask
/// must repeat. An impossible length reads as empty, which no provider
/// resolves.
fn held(buf: &[u8; PATH_BUF], len: u16) -> &[u8] {
    match buf.get(..len as usize) {
        Some(p) => p,
        None => &[],
    }
}

/// A request's 32-byte digest or key, copied out of the record.
fn digest_from(bytes: &[u8]) -> [u8; super::wire::DIGEST_LEN] {
    let mut d = [0u8; super::wire::DIGEST_LEN];
    for (o, b) in d.iter_mut().zip(bytes.iter()) {
        *o = *b;
    }
    d
}

unsafe fn close_fd(sys: &super::SyscallTable, fd: i32) {
    // CLOSE never waits and always releases the descriptor; it reports
    // no writeback outcome, so every durability claim is fenced before
    // it.
    let _ = (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
}

unsafe fn unlink(sys: &super::SyscallTable, path: &[u8]) -> i32 {
    super::fs_names::unlink(sys.provider_call, path)
}

// ── Resumable file sequences ──────────────────────────────────────

/// Drive a [`WriteFence`] over `path` and `bytes` as far as the
/// provider's answers are decided. `Done` once the bytes and their size
/// are durable and the file is closed; `Failed` with the file closed.
/// Does not publish a name.
unsafe fn poll_write_fence(
    wf: &mut WriteFence,
    sys: &super::SyscallTable,
    path: &[u8],
    bytes: &[u8],
) -> Poll {
    loop {
        match wf.phase {
            WF_CREATE => {
                let fd =
                    (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_ptr() as *mut u8, path.len());
                if pending(fd) {
                    return Poll::Pending;
                }
                if fd < 0 {
                    return Poll::Failed;
                }
                wf.fd = fd;
                wf.done = 0;
                wf.phase = WF_WRITE;
            }
            WF_WRITE => {
                // An empty body is a file with nothing in it: there is
                // nothing to write, and the fs surface refuses a
                // zero-length write. Otherwise offer what the provider
                // has not taken yet, for as long as it keeps taking it.
                let rest = match bytes.get(wf.done as usize..) {
                    Some(r) => r,
                    None => &[],
                };
                if rest.is_empty() {
                    wf.phase = WF_FENCE;
                    continue;
                }
                let n = (sys.provider_call)(wf.fd, FS_WRITE, rest.as_ptr() as *mut u8, rest.len());
                if pending(n) {
                    return Poll::Pending;
                }
                if n <= 0 || n as usize > rest.len() {
                    close_fd(sys, wf.fd);
                    wf.phase = WF_CREATE;
                    return Poll::Failed;
                }
                wf.done = wf.done.wrapping_add(n as u32);
            }
            _ => {
                // The fence is re-asked, identically, until it decides;
                // only then is the file closed.
                let rc = (sys.provider_call)(wf.fd, FS_FSYNC, core::ptr::null_mut(), 0);
                if pending(rc) {
                    return Poll::Pending;
                }
                close_fd(sys, wf.fd);
                wf.phase = WF_CREATE;
                return if rc >= 0 { Poll::Done } else { Poll::Failed };
            }
        }
    }
}

/// Drive a [`Probe`] of `path` as far as the provider's answers are
/// decided. The file is closed whenever it answers anything but
/// `Pending`.
unsafe fn poll_probe(p: &mut Probe, sys: &super::SyscallTable, path: &[u8]) -> ProbePoll {
    loop {
        match p.phase {
            PR_OPEN => {
                let fd = (sys.provider_call)(-1, FS_OPEN, path.as_ptr() as *mut u8, path.len());
                if pending(fd) {
                    return ProbePoll::Pending;
                }
                if fd < 0 {
                    return ProbePoll::Absent;
                }
                p.fd = fd;
                p.phase = PR_STAT;
            }
            PR_STAT => {
                let rc = (sys.provider_call)(p.fd, FS_STAT, p.stat.as_mut_ptr(), p.stat.len());
                if pending(rc) {
                    return ProbePoll::Pending;
                }
                if rc < 0 {
                    close_fd(sys, p.fd);
                    p.phase = PR_OPEN;
                    return ProbePoll::Absent;
                }
                p.got = 0;
                p.phase = PR_MAGIC;
            }
            _ => {
                // Keyed-ness sniff: keyed blobs (EC shards) open with a
                // known magic, so a few bytes tell them apart from
                // content-addressed bodies without a body read. A short
                // read keeps going while bytes move; end of file or an
                // error ends the sniff with what arrived.
                while (p.got as usize) < p.magic.len() {
                    let at = p.got as usize;
                    let want = p.magic.len() - at;
                    let n = (sys.provider_call)(p.fd, FS_READ, p.magic.as_mut_ptr().add(at), want);
                    if pending(n) {
                        return ProbePoll::Pending;
                    }
                    if n <= 0 {
                        break;
                    }
                    p.got = (at + (n as usize).min(want)) as u8;
                }
                close_fd(sys, p.fd);
                p.phase = PR_OPEN;
                let size = u32::from_le_bytes([p.stat[0], p.stat[1], p.stat[2], p.stat[3]]);
                let keyed = if p.got as usize >= p.magic.len()
                    && super::ec_wire::blob_is_shard_magic(&p.magic)
                {
                    1
                } else {
                    0
                };
                return ProbePoll::Found { size, keyed };
            }
        }
    }
}

// ── PUT ───────────────────────────────────────────────────────────

/// PUT. Answers once the body is published or the publication has
/// failed; `false` while it is parked.
unsafe fn handle_put(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> bool {
    if s.root_dir_len == 0 {
        nak(s, super::wire::ERR_NO_ROOT);
        return true;
    }
    // Decoded on every poll: the record is held unchanged, so this
    // yields the same body each time, and only the first poll can
    // refuse it.
    let body = match super::wire::decode_put_req(bytes) {
        Ok(b) => b,
        Err(super::wire::WireError::BodyTooLarge { .. }) => {
            nak(s, super::wire::ERR_TOO_LARGE);
            return true;
        }
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return true;
        }
    };

    if s.job.phase == 0 {
        let mut hasher = super::sha256::Sha256::new();
        hasher.update(body);
        let digest = hasher.finalize();

        // If a slot already holds this digest, idempotent ack.
        if find_slot(s, &digest).is_some() {
            respond_put(s, &digest);
            s.puts = s.puts.wrapping_add(1);
            return true;
        }
        if !begin_blob(s, &digest, 0) {
            nak(s, super::wire::ERR_IO);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return true;
        }
    }

    match poll_blob(s, sys, body) {
        Poll::Pending => false,
        Poll::Done => {
            let digest = s.job.digest;
            respond_put(s, &digest);
            s.puts = s.puts.wrapping_add(1);
            true
        }
        Poll::Failed => {
            nak(s, super::wire::ERR_IO);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            true
        }
    }
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

/// Which publication recipe this provider supports, or `None` while
/// that is not known.
///
/// Queried until it is answered, not once: a probe that lands before the
/// provider's volume has attached is refused, and recording that refusal
/// would pin the store to its weakest recipe for good. An unanswered
/// probe is not an answer either — the caller parks and asks again,
/// rather than refusing a publication over a question nobody has
/// answered.
pub unsafe fn publish_tier(s: &mut ModuleState) -> Option<PublishTier> {
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
            None => return None,
        }
    }
    Some(if s.caps & super::fs_names::CAP_RENAME != 0 {
        PublishTier::Rename
    } else if s.caps & super::fs_names::CAP_FSYNC_NAME != 0 {
        PublishTier::NameFence
    } else {
        PublishTier::Unavailable
    })
}

/// Longest line [`take_tier_report`] writes.
pub const TIER_REPORT_LEN: usize = 40;

/// The negotiated publication tier as a line to log, written into `out`
/// once and then never again; answers its length, 0 when there is
/// nothing to report.
///
/// Which recipe a store runs is a property of the provider in front of
/// it, so it is not derivable from the store's own configuration — a
/// composite that can log should say it, or an operator is left
/// inferring the fence from the artefacts it leaves behind. Nothing
/// before the first capability query, and nothing after the line has
/// been taken.
///
/// The line is copied byte by byte out of ONE literal that holds every
/// tier's word, and the tier selects only an offset and a length into
/// it. Selecting between `&'static [u8]` literals instead can lower to
/// a `.rodata` table of absolute pointers that the PIC loader never
/// relocates, and the module wedges silently on the first report.
pub unsafe fn take_tier_report(state_ptr: *mut u8, out: &mut [u8; TIER_REPORT_LEN]) -> usize {
    let s = &mut *(state_ptr as *mut ModuleState);
    if s.caps_known == 0 || s.tier_reported != 0 {
        return 0;
    }
    s.tier_reported = 1;
    let line = b"[body_store] publish tier=renamename_fenceunavailable";
    // `[body_store] publish tier=`, then the words in order:
    // `rename` (6), `name_fence` (10), `unavailable` (11).
    const HEAD: usize = 26;
    let (at, len) = if s.caps & super::fs_names::CAP_RENAME != 0 {
        (HEAD, 6)
    } else if s.caps & super::fs_names::CAP_FSYNC_NAME != 0 {
        (HEAD + 6, 10)
    } else {
        (HEAD + 16, 11)
    };
    let mut n = 0usize;
    let words = line.iter().take(HEAD).chain(line.iter().skip(at).take(len));
    for (o, b) in out.iter_mut().zip(words) {
        *o = *b;
        n += 1;
    }
    n
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

// The phases of a whole-body publication (`poll_blob`).
const BLOB_TIER: u8 = 1;
/// Remove what the write would otherwise build on: a staging file left
/// by a crashed attempt, or (in place) the keyed blob being replaced.
const BLOB_CLEAR: u8 = 2;
const BLOB_WRITE: u8 = 3;
const BLOB_PUBLISH: u8 = 4;
/// The publication failed after staging: remove the staging file, then
/// answer the failure.
const BLOB_DISCARD: u8 = 5;

/// Arm a publication of `digest`'s blob. False when its path cannot be
/// built.
unsafe fn begin_blob(
    s: &mut ModuleState,
    digest: &[u8; super::wire::DIGEST_LEN],
    keyed: u8,
) -> bool {
    let mut path = [0u8; PATH_BUF];
    let plen = build_body_path(s, digest, &mut path);
    if plen == 0 {
        return false;
    }
    s.job.path = path;
    s.job.plen = plen as u16;
    s.job.digest = *digest;
    s.job.keyed = keyed;
    s.job.wf.phase = WF_CREATE;
    s.job.phase = BLOB_TIER;
    true
}

/// Publish `bytes` under the armed digest and record a slot. `Failed`
/// on any disk failure. The slot table is a lookup index, not the
/// inventory: a body written past a full table is stored all the same,
/// and a GET reads it from disk and verifies it, as after a restart.
///
/// A file already at the content path is NOT proof that its bytes
/// hash to that path. A crash during an in-place publication can
/// leave a full-length file whose interior was never fenced, and a
/// length comparison accepts it forever without reading it. The
/// supplied bytes are known-good and in hand, so they are republished
/// rather than acknowledging bytes nothing has verified. The cost is
/// one rewrite per retried PUT; the alternative is a durability claim
/// over unverified content.
///
/// Keyed blobs are overwritten in place on a re-put, so they take the
/// same recipe as content-addressed ones rather than a weaker one. On
/// `Rename` that makes an overwrite atomic: the crash-visible outcomes
/// are the old blob or the new one, never an absent or half-replaced
/// one.
unsafe fn poll_blob(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> Poll {
    loop {
        match s.job.phase {
            BLOB_TIER => match publish_tier(s) {
                None => return Poll::Pending,
                Some(PublishTier::Rename) => {
                    let digest = s.job.digest;
                    let mut tmp = [0u8; PATH_BUF];
                    let tlen = build_pub_path(s, &digest, &mut tmp);
                    if tlen == 0 {
                        return Poll::Failed;
                    }
                    s.job.tmp = tmp;
                    s.job.tlen = tlen as u16;
                    s.job.tier = TIER_RENAME;
                    // Staging is transient, and a crashed attempt can
                    // leave one behind. `FS_OPEN_CREATE` does not
                    // truncate, so a shorter payload would inherit the
                    // old tail and rename it into place. Remove it
                    // first.
                    s.job.phase = BLOB_CLEAR;
                }
                Some(PublishTier::NameFence) => {
                    s.job.tier = TIER_NAME_FENCE;
                    // No atomic replace on this tier. A keyed blob may
                    // shrink, and `FS_OPEN_CREATE` does not truncate, so
                    // the old entry has to go first — which leaves a
                    // window where the blob is absent. That window is
                    // the cost of the tier, not of the operation.
                    s.job.phase = if s.job.keyed != 0 {
                        BLOB_CLEAR
                    } else {
                        BLOB_WRITE
                    };
                }
                // No durable name publication exists on this backend,
                // and the PUT response is a durability claim. Refuse it
                // rather than acknowledge bytes reachable by no durable
                // name.
                Some(PublishTier::Unavailable) => return Poll::Failed,
            },
            BLOB_CLEAR => {
                let target = if s.job.tier == TIER_RENAME {
                    held(&s.job.tmp, s.job.tlen)
                } else {
                    held(&s.job.path, s.job.plen)
                };
                // Absent already is as good as removed; only an
                // undecided removal holds the write back.
                if pending(unlink(sys, target)) {
                    return Poll::Pending;
                }
                s.job.wf.phase = WF_CREATE;
                s.job.phase = BLOB_WRITE;
            }
            BLOB_WRITE => {
                let target = if s.job.tier == TIER_RENAME {
                    held(&s.job.tmp, s.job.tlen)
                } else {
                    held(&s.job.path, s.job.plen)
                };
                match poll_write_fence(&mut s.job.wf, sys, target, bytes) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Done => s.job.phase = BLOB_PUBLISH,
                    Poll::Failed => {
                        if s.job.tier == TIER_RENAME {
                            s.job.phase = BLOB_DISCARD;
                        } else {
                            return Poll::Failed;
                        }
                    }
                }
            }
            BLOB_PUBLISH => {
                // `Rename` publishes the fenced staging file onto the
                // content path; `NameFence` fences the entry the write
                // minted. Either is re-asked, identically, until it
                // decides.
                let rc = if s.job.tier == TIER_RENAME {
                    super::fs_names::rename(
                        sys.provider_call,
                        held(&s.job.tmp, s.job.tlen),
                        held(&s.job.path, s.job.plen),
                    )
                } else {
                    super::fs_names::fsync_name(sys.provider_call, held(&s.job.path, s.job.plen))
                };
                if pending(rc) {
                    return Poll::Pending;
                }
                if rc < 0 {
                    if s.job.tier == TIER_RENAME {
                        s.job.phase = BLOB_DISCARD;
                        continue;
                    }
                    return Poll::Failed;
                }
                let digest = s.job.digest;
                let keyed = s.job.keyed;
                let _ = record_slot(s, &digest, bytes.len(), keyed);
                return Poll::Done;
            }
            BLOB_DISCARD => {
                if pending(unlink(sys, held(&s.job.tmp, s.job.tlen))) {
                    return Poll::Pending;
                }
                return Poll::Failed;
            }
            _ => return Poll::Failed,
        }
    }
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
/// Used for EC shard blobs, whose key derives from (body_digest, shard
/// index); they are self-describing, so disk-fallback reads verify them
/// against the key instead of a content hash. A re-put of an existing
/// key overwrites it, which for a shard is a no-op by value: a shard's
/// content is a deterministic function of its key.
unsafe fn handle_put_keyed(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> bool {
    if s.root_dir_len == 0 {
        nak(s, super::wire::ERR_NO_ROOT);
        return true;
    }
    let (key_bytes, blob) = match super::wire::decode_put_keyed_req(bytes) {
        Ok(v) => v,
        Err(super::wire::WireError::BodyTooLarge { .. }) => {
            nak(s, super::wire::ERR_TOO_LARGE);
            return true;
        }
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return true;
        }
    };
    if s.job.phase == 0 {
        let key = digest_from(key_bytes);
        if !begin_blob(s, &key, 1) {
            nak(s, super::wire::ERR_IO);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return true;
        }
    }
    match poll_blob(s, sys, blob) {
        Poll::Pending => return false,
        Poll::Done => {}
        Poll::Failed => {
            nak(s, super::wire::ERR_IO);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return true;
        }
    }
    let key = s.job.digest;
    let n = match super::wire::encode_put_keyed_resp(&mut s.scratch, &key) {
        Ok(n) => n,
        Err(_) => {
            nak(s, super::wire::ERR_IO);
            return true;
        }
    };
    write_resp(s, n);
    s.puts = s.puts.wrapping_add(1);
    true
}

// ── GET ───────────────────────────────────────────────────────────

const GET_OPEN: u8 = 1;
const GET_SEEK: u8 = 2;
const GET_READ: u8 = 3;
/// `Job::flags` bit for GET: the slot table supplied the exact size.
const GET_SIZED: u8 = 1;

unsafe fn handle_get(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> bool {
    // Read into the scratch buffer past the 5-byte response header, so
    // the answer is encoded in place.
    const READ_DST_OFF: usize = 5;
    if s.job.phase == 0 {
        if s.root_dir_len == 0 {
            nak(s, super::wire::ERR_NO_ROOT);
            return true;
        }
        let digest = match super::wire::decode_get_req(bytes) {
            Ok(d) => digest_from(d),
            Err(_) => {
                nak(s, super::wire::ERR_BAD_REQ);
                return true;
            }
        };

        // Slot hit → exact size. Slot miss → DISK FALLBACK: the table is
        // in-arena and empty after a restart, but the content-addressed
        // file may still exist, so it is read to EOF and verified.
        let size: Option<usize> = match find_slot(s, &digest) {
            Some(slot) => Some(slot.size as usize),
            None => None,
        };
        if let Some(sz) = size {
            if sz > super::wire::MAX_BODY {
                nak(s, super::wire::ERR_TOO_LARGE);
                return true;
            }
        }
        let mut path = [0u8; PATH_BUF];
        let plen = build_body_path(s, &digest, &mut path);
        if plen == 0 {
            nak(s, super::wire::ERR_IO);
            return true;
        }
        let cap = match size {
            Some(sz) => sz,
            None => super::wire::MAX_BODY, // fallback: bounded read-to-EOF
        };
        if READ_DST_OFF + cap > s.scratch.len() {
            nak(s, super::wire::ERR_IO);
            return true;
        }
        s.job.path = path;
        s.job.plen = plen as u16;
        s.job.digest = digest;
        s.job.size = cap as u32;
        s.job.flags = if size.is_some() { GET_SIZED } else { 0 };
        s.job.filled = 0;
        s.job.phase = GET_OPEN;
    }

    loop {
        match s.job.phase {
            GET_OPEN => {
                let path = held(&s.job.path, s.job.plen);
                let fd = (sys.provider_call)(-1, FS_OPEN, path.as_ptr() as *mut u8, path.len());
                if pending(fd) {
                    return false;
                }
                if fd < 0 {
                    nak(s, super::wire::ERR_NOT_FOUND);
                    return true;
                }
                s.job.fd = fd;
                s.job.phase = GET_SEEK;
            }
            GET_SEEK => {
                // Seek to 0 in case the FD was reused (slot table may
                // have been recreated; provider seeks to 0 on open, but
                // be safe).
                let zero: [u8; 4] = 0u32.to_le_bytes();
                if pending((sys.provider_call)(
                    s.job.fd,
                    FS_SEEK,
                    zero.as_ptr() as *mut u8,
                    4,
                )) {
                    return false;
                }
                s.job.phase = GET_READ;
            }
            _ => break,
        }
    }

    // Read toward the cap for as long as bytes keep arriving. A pending
    // read parks with the bytes so far kept in `scratch`; zero is end
    // of file, and an error ends the read with what arrived (a sized
    // read then fails its length check, a fallback its verification).
    let cap = (s.job.size as usize).min(s.scratch.len().saturating_sub(READ_DST_OFF));
    while (s.job.filled as usize) < cap {
        let at = READ_DST_OFF + s.job.filled as usize;
        let want = cap - s.job.filled as usize;
        let n = (sys.provider_call)(s.job.fd, FS_READ, s.scratch.as_mut_ptr().add(at), want);
        if pending(n) {
            return false;
        }
        if n <= 0 {
            break;
        }
        s.job.filled = s.job.filled.wrapping_add((n as usize).min(want) as u32);
    }
    close_fd(sys, s.job.fd);
    let filled = s.job.filled as usize;
    let digest = s.job.digest;
    let size = if s.job.flags & GET_SIZED != 0 {
        if filled != cap {
            nak(s, super::wire::ERR_IO);
            return true;
        }
        cap
    } else {
        // Fallback read: verify the bytes really belong to this key
        // before serving. A body blob's key IS its content hash; an EC
        // shard blob's key derives from the header it carries — both
        // checks are exact.
        let (verified, is_keyed) = match s.scratch.get(READ_DST_OFF..READ_DST_OFF + filled) {
            Some(bytes) => {
                let mut hasher = super::sha256::Sha256::new();
                hasher.update(bytes);
                if hasher.finalize() == digest {
                    (true, 0u8)
                } else if super::ec_wire::shard_blob_matches_key(bytes, &digest) {
                    (true, 1u8)
                } else {
                    (false, 0u8)
                }
            }
            None => (false, 0u8),
        };
        if !verified {
            nak(s, super::wire::ERR_NOT_FOUND);
            return true;
        }
        if let Some(slot) = find_empty_slot(s) {
            slot.digest = digest;
            slot.size = filled as u32;
            slot.in_use = 1;
            slot.keyed = is_keyed;
        } // full table: fine — next GET re-reads from disk
        filled
    };

    // Write the 5-byte response header in front of the body bytes.
    let hdr = (size as u32).to_le_bytes();
    s.scratch[0] = super::wire::OP_GET;
    for (o, b) in s.scratch.iter_mut().skip(1).zip(hdr.iter()) {
        *o = *b;
    }
    write_resp(s, READ_DST_OFF + size);
    s.gets = s.gets.wrapping_add(1);
    true
}

// ── HEAD ──────────────────────────────────────────────────────────

const HEAD_PROBE: u8 = 1;

unsafe fn handle_head(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> bool {
    // Slot miss → DISK FALLBACK, same as GET: the slot table is
    // in-arena and empty after a restart, but the file may exist.
    // Size via FS_STAT, keyed-ness via a 4-byte magic sniff; the
    // slot is rehydrated so later ops are table hits. (Unlike the
    // GET fallback this serves without a full-content verify — a
    // HEAD answers existence + size, and the GET that follows any
    // consequential read still verifies.)
    if s.job.phase == 0 {
        let digest = match super::wire::decode_head_req(bytes) {
            Ok(d) => digest_from(d),
            Err(_) => {
                nak(s, super::wire::ERR_BAD_REQ);
                return true;
            }
        };
        if let Some(slot) = find_slot(s, &digest) {
            let size = slot.size as u64;
            respond_head(s, size);
            return true;
        }
        let mut path = [0u8; PATH_BUF];
        let plen = build_body_path(s, &digest, &mut path);
        if plen == 0 {
            nak(s, super::wire::ERR_IO);
            return true;
        }
        s.job.path = path;
        s.job.plen = plen as u16;
        s.job.digest = digest;
        s.job.probe.phase = PR_OPEN;
        s.job.phase = HEAD_PROBE;
    }
    let (size, keyed) = match poll_probe(&mut s.job.probe, sys, held(&s.job.path, s.job.plen)) {
        ProbePoll::Pending => return false,
        ProbePoll::Absent => {
            nak(s, super::wire::ERR_NOT_FOUND);
            return true;
        }
        ProbePoll::Found { size, keyed } => (size, keyed),
    };
    if size as usize > super::wire::MAX_BODY {
        nak(s, super::wire::ERR_TOO_LARGE);
        return true;
    }
    let digest = s.job.digest;
    if let Some(slot) = find_empty_slot(s) {
        slot.digest = digest;
        slot.size = size;
        slot.in_use = 1;
        slot.keyed = keyed;
    }
    respond_head(s, size as u64);
    true
}

unsafe fn respond_head(s: &mut ModuleState, size: u64) {
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

const DEL_CAPS: u8 = 1;
const DEL_UNLINK: u8 = 2;
const DEL_FENCE: u8 = 3;
const DEL_PROBE: u8 = 4;
/// `Job::flags` bits for DELETE.
const DEL_SLOT_PRESENT: u8 = 1;
const DEL_FILE_EXISTED: u8 = 2;

unsafe fn handle_delete(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> bool {
    // Retirement is fail-closed: the slot is the store's record that
    // the blob is reachable, so it is cleared only once the file is
    // provably gone. Clearing first would report a delete that did not
    // happen — the file survives, the next disk sweep rehydrates it,
    // and the caller has already been told it was retired.
    if s.job.phase == 0 {
        let digest = match super::wire::decode_delete_req(bytes) {
            Ok(d) => digest_from(d),
            Err(_) => {
                nak(s, super::wire::ERR_BAD_REQ);
                return true;
            }
        };
        s.job.digest = digest;
        s.job.flags = if find_slot(s, &digest).is_some() {
            DEL_SLOT_PRESENT
        } else {
            0
        };
        if s.root_dir_len == 0 {
            // Nothing on disk to retire: the slot is the whole record.
            return finish_delete(s, true);
        }
        let mut path = [0u8; PATH_BUF];
        let plen = build_body_path(s, &digest, &mut path);
        if plen == 0 {
            nak(s, super::wire::ERR_IO);
            return true;
        }
        s.job.path = path;
        s.job.plen = plen as u16;
        s.job.phase = DEL_CAPS;
    }
    loop {
        match s.job.phase {
            DEL_CAPS => {
                // Whether a removal can be fenced is a capability; an
                // unanswered query is asked again, never read as "no".
                if publish_tier(s).is_none() {
                    return false;
                }
                s.job.phase = DEL_UNLINK;
            }
            DEL_UNLINK => {
                let rc = unlink(sys, held(&s.job.path, s.job.plen));
                if pending(rc) {
                    return false;
                }
                if rc == 0 {
                    s.job.flags |= DEL_FILE_EXISTED;
                    s.job.phase = DEL_FENCE;
                } else {
                    s.job.phase = DEL_PROBE;
                }
            }
            DEL_FENCE => {
                // An unlink whose directory entry is still volatile can
                // reappear after a power cut, so the removal is not
                // retired until its name is fenced. Without that fence
                // the store cannot prove retirement and must not claim
                // it.
                if s.caps & super::fs_names::CAP_FSYNC_NAME == 0 {
                    return finish_delete(s, false);
                }
                let rc =
                    super::fs_names::fsync_name(sys.provider_call, held(&s.job.path, s.job.plen));
                if pending(rc) {
                    return false;
                }
                return finish_delete(s, rc >= 0);
            }
            DEL_PROBE => {
                // Unlink failed. Deleting a blob that was never there
                // is a retirement that has already happened, so probe
                // the name rather than trust an errno mapping: absent
                // is success, present is failure, unknown is asked
                // again.
                return match super::fs_names::name_present(
                    sys.provider_call,
                    held(&s.job.path, s.job.plen),
                ) {
                    None => false,
                    Some(present) => finish_delete(s, !present),
                };
            }
            _ => return finish_delete(s, false),
        }
    }
}

unsafe fn finish_delete(s: &mut ModuleState, retired: bool) -> bool {
    if !retired {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        nak(s, super::wire::ERR_IO);
        return true;
    }
    let digest = s.job.digest;
    if let Some(slot) = find_slot(s, &digest) {
        slot.in_use = 0;
        slot.size = 0;
        slot.digest = [0u8; super::wire::DIGEST_LEN];
    }
    let existed = s.job.flags & (DEL_SLOT_PRESENT | DEL_FILE_EXISTED) != 0;
    let n = match super::wire::encode_delete_resp(&mut s.scratch, existed) {
        Ok(n) => n,
        Err(_) => {
            nak(s, super::wire::ERR_IO);
            return true;
        }
    };
    write_resp(s, n);
    s.deletes = s.deletes.wrapping_add(1);
    true
}

// ── SCAN ──────────────────────────────────────────────────────────

const SCAN_OPENDIR: u8 = 1;
const SCAN_READDIR: u8 = 2;
const SCAN_ENTRY: u8 = 3;
const SCAN_UNLINK: u8 = 4;
const SCAN_PROBE: u8 = 5;
const SCAN_PAGE: u8 = 6;

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
///
/// The sweep keeps a resumable cursor in the job — the open directory,
/// the READDIR answer being worked through and the position in it — so
/// a pending answer anywhere in it parks the SCAN and the next step
/// carries on from the same entry. A READDIR that answers `EAGAIN` is
/// re-asked as it was; nothing has been consumed.
unsafe fn handle_scan(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> bool {
    if s.job.phase == 0 {
        let (cursor, max) = match super::wire::decode_scan_req(bytes) {
            Ok(v) => v,
            Err(_) => {
                nak(s, super::wire::ERR_BAD_REQ);
                return true;
            }
        };
        s.job.off = cursor as u64;
        s.job.size = max as u32;
        s.job.phase = if cursor == 0 && s.root_dir_len != 0 {
            SCAN_OPENDIR
        } else {
            SCAN_PAGE
        };
    }
    let mut budget = SWEEP_ENTRIES_PER_STEP;
    loop {
        match s.job.phase {
            SCAN_OPENDIR => {
                let rl = (s.root_dir_len as usize).min(ROOT_DIR_BUF);
                let dir = match s.root_dir.get(..rl) {
                    Some(d) => d,
                    None => &[],
                };
                let fd = (sys.provider_call)(-1, FS_OPENDIR, dir.as_ptr() as *mut u8, dir.len());
                if pending(fd) {
                    return false;
                }
                if fd < 0 {
                    s.job.phase = SCAN_PAGE;
                    continue;
                }
                s.job.dir_fd = fd;
                s.job.phase = SCAN_READDIR;
            }
            SCAN_READDIR => {
                // READDIR output: [count: u16 LE][ [len: u8][is_dir: u8][name] ]*
                // repeated until the provider returns 0 ("drained").
                let n =
                    (sys.provider_call)(s.job.dir_fd, FS_READDIR, s.job.dir.as_mut_ptr(), DIR_BUF);
                if pending(n) {
                    return false;
                }
                let count = u16::from_le_bytes([s.job.dir[0], s.job.dir[1]]);
                if n < 2 || count == 0 {
                    close_fd(sys, s.job.dir_fd);
                    s.job.phase = SCAN_PAGE;
                    continue;
                }
                s.job.dir_n = (n as usize).min(DIR_BUF) as u16;
                s.job.dir_pos = 2;
                s.job.dir_count = count;
                s.job.dir_seen = 0;
                s.job.phase = SCAN_ENTRY;
            }
            SCAN_ENTRY => {
                if budget == 0 {
                    // Yield the step; the cursor resumes at this entry.
                    return false;
                }
                budget -= 1;
                s.job.phase = match next_sweep_entry(s) {
                    SWEEP_BATCH => SCAN_READDIR,
                    SWEEP_UNLINK => SCAN_UNLINK,
                    SWEEP_PROBE => {
                        s.job.probe.phase = PR_OPEN;
                        SCAN_PROBE
                    }
                    _ => SCAN_ENTRY,
                };
            }
            SCAN_UNLINK => {
                // A removal answers nobody: only an undecided one holds
                // the sweep.
                if pending(unlink(sys, held(&s.job.tmp, s.job.tlen))) {
                    return false;
                }
                s.job.phase = SCAN_ENTRY;
            }
            SCAN_PROBE => {
                match poll_probe(&mut s.job.probe, sys, held(&s.job.path, s.job.plen)) {
                    ProbePoll::Pending => return false,
                    ProbePoll::Absent => s.job.phase = SCAN_ENTRY,
                    ProbePoll::Found { size, keyed } => {
                        s.job.phase = SCAN_ENTRY;
                        if size as usize <= super::wire::MAX_BODY {
                            let digest = s.job.digest;
                            match find_empty_slot(s) {
                                Some(slot) => {
                                    slot.digest = digest;
                                    slot.size = size;
                                    slot.in_use = 1;
                                    slot.keyed = keyed;
                                    s.rehydrated = s.rehydrated.wrapping_add(1);
                                }
                                // The table is full: the sweep stops.
                                None => {
                                    close_fd(sys, s.job.dir_fd);
                                    s.job.phase = SCAN_PAGE;
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                let cursor = s.job.off as u32;
                let max = s.job.size as u8;
                scan_page(s, cursor, max);
                return true;
            }
        }
    }
}

/// Answer one SCAN page from the slot table.
unsafe fn scan_page(s: &mut ModuleState, cursor: u32, max: u8) {
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

// What `next_sweep_entry` found.
/// The held READDIR answer is used up: read the next batch.
const SWEEP_BATCH: u8 = 0;
/// Not ours, or already indexed: move on.
const SWEEP_SKIP: u8 = 1;
/// A dead temporary or staging file, its path in `job.tmp`: remove it.
const SWEEP_UNLINK: u8 = 2;
/// An unindexed body, its path in `job.path`: probe it for a slot.
const SWEEP_PROBE: u8 = 3;

/// Consume the next entry of the held READDIR answer and say what the
/// sweep owes it. The cursor advances before the work is done, which is
/// safe because the work's arguments are copied into the job first.
unsafe fn next_sweep_entry(s: &mut ModuleState) -> u8 {
    let n = (s.job.dir_n as usize).min(DIR_BUF);
    let pos = s.job.dir_pos as usize;
    if s.job.dir_seen >= s.job.dir_count {
        return SWEEP_BATCH;
    }
    let (name_len, is_dir) = match (s.job.dir.get(pos), s.job.dir.get(pos + 1)) {
        (Some(l), Some(d)) if pos + 2 <= n => (*l as usize, *d),
        _ => return SWEEP_BATCH,
    };
    let start = pos + 2;
    let end = start + name_len;
    if end > n {
        return SWEEP_BATCH;
    }
    s.job.dir_pos = end as u16;
    s.job.dir_seen = s.job.dir_seen.wrapping_add(1);
    if is_dir != 0 {
        return SWEEP_SKIP;
    }
    let mut name_buf = [0u8; 256];
    if let Some(src) = s.job.dir.get(start..end) {
        for (o, b) in name_buf.iter_mut().zip(src.iter()) {
            *o = *b;
        }
    }
    let raw = match name_buf.get(..name_len) {
        Some(r) => r,
        None => return SWEEP_SKIP,
    };
    // A `.wip_N` file is a streamed write's temporary. One whose
    // session is gone belongs to a stream that died before its commit:
    // no live state names it and no future one will, because the next
    // WOPEN for that id unlinks it first. Remove it so the boot
    // treatment of an interrupted stream is the same every time. (A
    // session whose own removal is still owed is left to that removal.)
    //
    // Any `.wip_<digits>` name is a temporary, whatever id it carries:
    // one written under a larger `WRITE_SESSIONS`, or in a form this
    // build does not mint, belongs to no session here and is removed by
    // the name the directory gave, not one rebuilt from a parsed id.
    if is_wip_name(raw) {
        let live = match wip_id_from_name(raw).and_then(|wid| s.wsessions.get(wid)) {
            Some(sess) => sess.in_use != 0 || sess.unlink_owed != 0,
            None => false,
        };
        if live {
            return SWEEP_SKIP;
        }
        return sweep_unlink_entry(s, raw);
    }
    // A `.pub_*` file is a publication that was interrupted before its
    // rename. Its bytes are unreachable by any content path, so a
    // re-PUT stages afresh; leaving it would accumulate one per
    // interrupted write.
    if is_pub_staging_name(raw) {
        return sweep_unlink_entry(s, raw);
    }
    let digest = match hex_digest_from_name(raw) {
        Some(d) => d,
        None => return SWEEP_SKIP,
    };
    if find_slot(s, &digest).is_some() {
        return SWEEP_SKIP;
    }
    let mut path = [0u8; PATH_BUF];
    let plen = build_body_path(s, &digest, &mut path);
    if plen == 0 {
        return SWEEP_SKIP;
    }
    s.job.path = path;
    s.job.plen = plen as u16;
    s.job.digest = digest;
    SWEEP_PROBE
}

pub use super::hash::hex_val;

/// Stage the removal of directory entry `raw` (a name in the root) as
/// the sweep's next unlink, its path in `job.tmp`. `SWEEP_SKIP` when the
/// path does not fit.
fn sweep_unlink_entry(s: &mut ModuleState, raw: &[u8]) -> u8 {
    let rl = (s.root_dir_len as usize).min(ROOT_DIR_BUF);
    let mut path = [0u8; PATH_BUF];
    if rl + 1 + raw.len() > path.len() {
        return SWEEP_SKIP;
    }
    for (o, b) in path.iter_mut().zip(s.root_dir.iter().take(rl)) {
        *o = *b;
    }
    if let Some(slash) = path.get_mut(rl) {
        *slash = b'/';
    }
    for (o, b) in path.iter_mut().skip(rl + 1).zip(raw.iter()) {
        *o = *b;
    }
    s.job.tmp = path;
    s.job.tlen = (rl + 1 + raw.len()) as u16;
    SWEEP_UNLINK
}

/// The `.wip_` prefix every streamed write's temporary carries.
fn wip_prefix(name: &[u8]) -> Option<&[u8]> {
    let (head, digits) = (name.get(..5)?, name.get(5..)?);
    if head == [b'.', b'w', b'i', b'p', b'_'] {
        Some(digits)
    } else {
        None
    }
}

/// True for any `.wip_<digits>` temporary name, whichever id it
/// carries.
fn is_wip_name(name: &[u8]) -> bool {
    match wip_prefix(name) {
        Some(digits) => !digits.is_empty() && digits.iter().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

/// Parse a `.wip_<wid>` temporary name back into the session id that
/// would write it: the canonical decimal form `build_wip_path` mints (no
/// leading zero, at most three digits), naming an id below
/// `WRITE_SESSIONS`. Any other temporary name belongs to no session.
fn wip_id_from_name(name: &[u8]) -> Option<usize> {
    let digits = wip_prefix(name)?;
    if digits.is_empty() || digits.len() > WIP_ID_DIGITS {
        return None;
    }
    if digits.len() > 1 && digits.first() == Some(&b'0') {
        return None;
    }
    let mut wid = 0usize;
    for c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        wid = wid * 10 + (c - b'0') as usize;
    }
    if wid < WRITE_SESSIONS {
        Some(wid)
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

// ── Chunked writes (WOPEN / WAPPEND / WCOMMIT / WABORT) ───────────

/// `<root>/.wip_<wid>` into `out`, `<wid>` the session's full id in
/// decimal; returns length or 0. An id outside the session table names
/// no temporary and builds nothing.
unsafe fn build_wip_path(s: &ModuleState, wid: usize, out: &mut [u8]) -> usize {
    let rl = (s.root_dir_len as usize).min(ROOT_DIR_BUF);
    if rl == 0 || wid >= WRITE_SESSIONS {
        return 0;
    }
    // The id's digits, least significant first.
    let mut digits = [0u8; WIP_ID_DIGITS];
    let mut nd = 0usize;
    let mut v = wid;
    while nd < WIP_ID_DIGITS {
        if let Some(d) = digits.get_mut(nd) {
            *d = b'0' + (v % 10) as u8;
        }
        nd += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let prefix = [b'/', b'.', b'w', b'i', b'p', b'_'];
    let needed = rl + prefix.len() + nd;
    if out.len() < needed {
        return 0;
    }
    for (o, b) in out.iter_mut().zip(s.root_dir.iter().take(rl)) {
        *o = *b;
    }
    for (o, b) in out.iter_mut().skip(rl).zip(prefix.iter()) {
        *o = *b;
    }
    for (o, b) in out
        .iter_mut()
        .skip(rl + prefix.len())
        .take(nd)
        .zip(digits.iter().take(nd).rev())
    {
        *o = *b;
    }
    needed
}

/// End session `wid`: release its descriptor and owe the removal of its
/// temporary. The removal is asked once here; if the provider has not
/// decided it, `retire_sessions` re-asks it on later steps, and the id
/// stays out of use until it has.
unsafe fn session_cleanup(s: &mut ModuleState, wid: usize) {
    let sys = s.syscalls.as_ref();
    let sess = match s.wsessions.get_mut(wid) {
        Some(sess) => sess,
        None => return,
    };
    if sess.fd >= 0 {
        if let Some(sys) = sys {
            close_fd(sys, sess.fd);
        }
    }
    sess.in_use = 0;
    sess.fd = -1;
    sess.unlink_owed = 1;
    if let Some(sys) = sys {
        retire_one(s, sys, wid);
    }
}

/// Re-ask the owed removal of `wid`'s temporary. Any decided answer
/// ends the debt — absent already is removed — and frees the id.
unsafe fn retire_one(s: &mut ModuleState, sys: &super::SyscallTable, wid: usize) {
    let mut path = [0u8; PATH_BUF];
    let plen = build_wip_path(s, wid, &mut path);
    let path = match path.get(..plen) {
        Some(p) => p,
        None => &[],
    };
    if plen != 0 && pending(unlink(sys, path)) {
        return;
    }
    if let Some(sess) = s.wsessions.get_mut(wid) {
        sess.unlink_owed = 0;
    }
}

/// Progress every owed temporary removal by one ask.
unsafe fn retire_sessions(s: &mut ModuleState, sys: &super::SyscallTable) {
    for wid in 0..WRITE_SESSIONS {
        if s.wsessions[wid].unlink_owed != 0 {
            retire_one(s, sys, wid);
        }
    }
}

/// The session a parked request is working on, which the reaper must
/// leave alone: its descriptor is part of a sequence still in flight.
fn session_in_job(s: &ModuleState, wid: usize) -> bool {
    s.job.phase != 0 && s.job.wid as usize == wid
}

unsafe fn reap_stale_sessions(s: &mut ModuleState) {
    for wid in 0..WRITE_SESSIONS {
        if s.wsessions[wid].in_use != 0
            && !session_in_job(s, wid)
            && s.ticks.wrapping_sub(s.wsessions[wid].last_tick) > SESSION_REAP_TICKS
        {
            session_cleanup(s, wid);
            s.stream_aborts = s.stream_aborts.wrapping_add(1);
        }
    }
}

const WOPEN_CLEAR: u8 = 1;
const WOPEN_CREATE: u8 = 2;

unsafe fn handle_wopen(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> bool {
    if s.job.phase == 0 {
        if s.root_dir_len == 0 {
            nak(s, super::wire::ERR_NO_ROOT);
            return true;
        }
        let (digest_bytes, total_len) = match super::wire::decode_wopen_req(bytes) {
            Ok(v) => v,
            Err(_) => {
                nak(s, super::wire::ERR_BAD_REQ);
                return true;
            }
        };
        if total_len == 0 || total_len > super::wire::MAX_STREAM_TOTAL {
            nak(s, super::wire::ERR_TOO_LARGE);
            return true;
        }
        // A free id is one with no session and no removal still owed
        // for its temporary.
        let mut wid = WRITE_SESSIONS;
        for i in 0..WRITE_SESSIONS {
            if s.wsessions[i].in_use == 0 && s.wsessions[i].unlink_owed == 0 {
                wid = i;
                break;
            }
        }
        if wid >= WRITE_SESSIONS {
            nak(s, super::wire::ERR_IO);
            return true;
        }
        let mut path = [0u8; PATH_BUF];
        let plen = build_wip_path(s, wid, &mut path);
        if plen == 0 {
            nak(s, super::wire::ERR_IO);
            return true;
        }
        s.job.tmp = path;
        s.job.tlen = plen as u16;
        s.job.wid = wid as u8;
        s.job.digest = digest_from(digest_bytes);
        s.job.off = total_len;
        s.job.phase = WOPEN_CLEAR;
    }
    if s.job.phase == WOPEN_CLEAR {
        // A leftover temp from a crashed stream must not contribute
        // stale prefix bytes — unlink before create.
        if pending(unlink(sys, held(&s.job.tmp, s.job.tlen))) {
            return false;
        }
        s.job.phase = WOPEN_CREATE;
    }
    let path = held(&s.job.tmp, s.job.tlen);
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_ptr() as *mut u8, path.len());
    if pending(fd) {
        return false;
    }
    if fd < 0 {
        nak(s, super::wire::ERR_IO);
        return true;
    }
    let wid = s.job.wid as usize;
    let ticks = s.ticks;
    let expect = s.job.digest;
    let total_len = s.job.off;
    let sess = match s.wsessions.get_mut(wid) {
        Some(sess) => sess,
        None => {
            close_fd(sys, fd);
            nak(s, super::wire::ERR_IO);
            return true;
        }
    };
    sess.in_use = 1;
    sess.fd = fd;
    sess.expect = expect;
    sess.total_len = total_len;
    sess.written = 0;
    sess.last_tick = ticks;
    sess.hasher = super::sha256::Sha256::new();
    s.stream_opens = s.stream_opens.wrapping_add(1);
    let n = match super::wire::encode_wopen_resp(&mut s.scratch, wid as u8) {
        Ok(n) => n,
        Err(_) => return true,
    };
    write_resp(s, n);
    true
}

const WAPPEND_WRITE: u8 = 1;

unsafe fn handle_wappend(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> bool {
    let (wid, chunk) = match super::wire::decode_wappend_req(bytes) {
        Ok(v) => v,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return true;
        }
    };
    let wid = wid as usize;
    if s.job.phase == 0 {
        if wid >= WRITE_SESSIONS || s.wsessions[wid].in_use == 0 {
            nak(s, super::wire::ERR_BAD_REQ);
            return true;
        }
        if s.wsessions[wid].written + chunk.len() as u64 > s.wsessions[wid].total_len {
            session_cleanup(s, wid);
            nak(s, super::wire::ERR_TOO_LARGE);
            return true;
        }
        s.job.wid = wid as u8;
        s.job.filled = 0;
        s.job.phase = WAPPEND_WRITE;
    }
    let fd = match s.wsessions.get(wid) {
        Some(sess) => sess.fd,
        None => {
            nak(s, super::wire::ERR_BAD_REQ);
            return true;
        }
    };
    // Offer what the temporary has not taken yet, for as long as it
    // keeps taking it. A short count is progress; the chunk stays held
    // in the inbox, so the rest is offered from there on a later step.
    // An empty chunk moves nothing and is acknowledged as such.
    loop {
        let rest = match chunk.get(s.job.filled as usize..) {
            Some(r) => r,
            None => &[],
        };
        if rest.is_empty() {
            break;
        }
        let n = (sys.provider_call)(fd, FS_WRITE, rest.as_ptr() as *mut u8, rest.len());
        if pending(n) {
            // Parked mid-chunk is not idle: keep the reaper off it.
            s.wsessions[wid].last_tick = s.ticks;
            return false;
        }
        if n <= 0 || n as usize > rest.len() {
            session_cleanup(s, wid);
            nak(s, super::wire::ERR_IO);
            return true;
        }
        s.job.filled = s.job.filled.wrapping_add(n as u32);
    }
    s.wsessions[wid].hasher.update(chunk);
    s.wsessions[wid].written += chunk.len() as u64;
    s.wsessions[wid].last_tick = s.ticks;
    let n = match super::wire::encode_wappend_resp(&mut s.scratch, wid as u8) {
        Ok(n) => n,
        Err(_) => return true,
    };
    write_resp(s, n);
    true
}

const WC_TIER: u8 = 1;
const WC_FENCE_TMP: u8 = 2;
const WC_RENAME: u8 = 3;
const WC_CREATE: u8 = 4;
const WC_SEEK: u8 = 5;
const WC_COPY: u8 = 6;
const WC_FENCE_OUT: u8 = 7;
const WC_FENCE_NAME: u8 = 8;

unsafe fn handle_wcommit(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> bool {
    if s.job.phase == 0 {
        let wid = match super::wire::decode_wid_req(bytes, super::wire::OP_WCOMMIT) {
            Ok(w) => w as usize,
            Err(_) => {
                nak(s, super::wire::ERR_BAD_REQ);
                return true;
            }
        };
        if wid >= WRITE_SESSIONS || s.wsessions[wid].in_use == 0 {
            nak(s, super::wire::ERR_BAD_REQ);
            return true;
        }
        // Verify: every declared byte arrived AND hashes to the
        // declared digest. Either failure aborts — nothing publishes.
        // The hash is consumed here, once; the job keeps the digest.
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
            return true;
        }
        let mut final_path = [0u8; PATH_BUF];
        let plen = build_body_path(s, &digest, &mut final_path);
        let mut tmp_path = [0u8; PATH_BUF];
        let tlen = build_wip_path(s, wid, &mut tmp_path);
        if plen == 0 || tlen == 0 {
            session_cleanup(s, wid);
            nak(s, super::wire::ERR_IO);
            return true;
        }
        s.job.path = final_path;
        s.job.plen = plen as u16;
        s.job.tmp = tmp_path;
        s.job.tlen = tlen as u16;
        s.job.digest = digest;
        s.job.wid = wid as u8;
        s.job.fd = -1;
        s.job.phase = WC_TIER;
    }
    let wid = s.job.wid as usize;
    if wid >= WRITE_SESSIONS {
        nak(s, super::wire::ERR_IO);
        return true;
    }
    // A parked commit is not an idle session.
    s.wsessions[wid].last_tick = s.ticks;
    let written = s.wsessions[wid].written;
    let mut rounds = COPY_ROUNDS_PER_STEP;
    loop {
        match s.job.phase {
            WC_TIER => match publish_tier(s) {
                None => return false,
                // No short-circuit on an existing same-length file:
                // length is not a digest, and this session holds bytes
                // whose digest is verified. Publishing them is the only
                // path that makes the acknowledgement true. Without a
                // name fence the commit cannot claim publication and
                // refuses.
                Some(PublishTier::Unavailable) => {
                    session_cleanup(s, wid);
                    nak(s, super::wire::ERR_IO);
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    return true;
                }
                Some(PublishTier::Rename) => {
                    s.job.tier = TIER_RENAME;
                    s.job.phase = WC_FENCE_TMP;
                }
                Some(PublishTier::NameFence) => {
                    s.job.tier = TIER_NAME_FENCE;
                    s.job.phase = WC_FENCE_TMP;
                }
            },
            WC_FENCE_TMP => {
                // The stream has written every byte to the temporary and
                // verified the digest; this fences those bytes, and only
                // the name is left.
                let rc =
                    (sys.provider_call)(s.wsessions[wid].fd, FS_FSYNC, core::ptr::null_mut(), 0);
                if pending(rc) {
                    return false;
                }
                if rc < 0 {
                    session_cleanup(s, wid);
                    nak(s, super::wire::ERR_IO);
                    return true;
                }
                if s.job.tier == TIER_RENAME {
                    // The temporary already holds the verified, fenced
                    // bytes: the publication is the rename of that file
                    // onto its content path, one provider call, and no
                    // partial final artefact is ever observable. Its
                    // descriptor is done with.
                    close_fd(sys, s.wsessions[wid].fd);
                    s.wsessions[wid].fd = -1;
                    s.job.phase = WC_RENAME;
                } else {
                    // `NameFence` has no atomic replace, so the bytes
                    // are copied to the content path and the name fenced
                    // after; content addressing is what makes an
                    // interrupted copy detectable.
                    s.job.phase = WC_CREATE;
                }
            }
            WC_RENAME => {
                let rc = super::fs_names::rename(
                    sys.provider_call,
                    held(&s.job.tmp, s.job.tlen),
                    held(&s.job.path, s.job.plen),
                );
                if pending(rc) {
                    return false;
                }
                if rc < 0 {
                    session_cleanup(s, wid); // owes the temp's removal
                    nak(s, super::wire::ERR_IO);
                    return true;
                }
                // The temporary became the artefact: nothing to remove.
                s.wsessions[wid].in_use = 0;
                return finish_wcommit(s, written);
            }
            WC_CREATE => {
                let path = held(&s.job.path, s.job.plen);
                let fd =
                    (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_ptr() as *mut u8, path.len());
                if pending(fd) {
                    return false;
                }
                if fd < 0 {
                    session_cleanup(s, wid);
                    nak(s, super::wire::ERR_IO);
                    return true;
                }
                s.job.fd = fd;
                s.job.phase = WC_SEEK;
            }
            WC_SEEK => {
                let zero: [u8; 4] = 0u32.to_le_bytes();
                let rc =
                    (sys.provider_call)(s.wsessions[wid].fd, FS_SEEK, zero.as_ptr() as *mut u8, 4);
                if pending(rc) {
                    return false;
                }
                s.job.copied = 0;
                s.job.copy_len = 0;
                s.job.copy_at = 0;
                s.job.phase = WC_COPY;
            }
            WC_COPY => {
                // `scratch` stages one read at a time. Its bytes are
                // offered to the target until all are taken, and only
                // then is the next read made, so a short write never
                // loses the tail it did not take.
                if s.job.copy_at < s.job.copy_len {
                    let at = s.job.copy_at as usize;
                    let len = (s.job.copy_len - s.job.copy_at) as usize;
                    if at + len > s.scratch.len() {
                        return fail_wcommit_copy(s, sys, wid);
                    }
                    let w = (sys.provider_call)(
                        s.job.fd,
                        FS_WRITE,
                        s.scratch.as_mut_ptr().add(at),
                        len,
                    );
                    if pending(w) {
                        return false;
                    }
                    if w <= 0 || w as usize > len {
                        return fail_wcommit_copy(s, sys, wid);
                    }
                    s.job.copy_at = s.job.copy_at.wrapping_add(w as u32);
                    continue;
                }
                if s.job.copied >= written {
                    s.job.phase = WC_FENCE_OUT;
                    continue;
                }
                if rounds == 0 {
                    // Yield the step; the copy resumes from here.
                    return false;
                }
                rounds -= 1;
                let want = super::wire::MAX_BODY
                    .min((written - s.job.copied) as usize)
                    .min(s.scratch.len());
                let n =
                    (sys.provider_call)(s.wsessions[wid].fd, FS_READ, s.scratch.as_mut_ptr(), want);
                if pending(n) {
                    return false;
                }
                if n <= 0 || n as usize > want {
                    return fail_wcommit_copy(s, sys, wid);
                }
                s.job.copy_len = n as u32;
                s.job.copy_at = 0;
                s.job.copied += n as u64;
            }
            WC_FENCE_OUT => {
                let rc = (sys.provider_call)(s.job.fd, FS_FSYNC, core::ptr::null_mut(), 0);
                if pending(rc) {
                    return false;
                }
                close_fd(sys, s.job.fd);
                s.job.fd = -1;
                if rc < 0 {
                    session_cleanup(s, wid);
                    nak(s, super::wire::ERR_IO);
                    return true;
                }
                s.job.phase = WC_FENCE_NAME;
            }
            WC_FENCE_NAME => {
                // The name is what a later mount finds the bytes by, so
                // it is fenced before the commit is acknowledged.
                let rc =
                    super::fs_names::fsync_name(sys.provider_call, held(&s.job.path, s.job.plen));
                if pending(rc) {
                    return false;
                }
                session_cleanup(s, wid); // closes + unlinks the temp
                if rc < 0 {
                    nak(s, super::wire::ERR_IO);
                    return true;
                }
                return finish_wcommit(s, written);
            }
            _ => {
                session_cleanup(s, wid);
                nak(s, super::wire::ERR_IO);
                return true;
            }
        }
    }
}

/// A streamed commit's copy failed: release the half-written target and
/// the session, and refuse the commit.
unsafe fn fail_wcommit_copy(s: &mut ModuleState, sys: &super::SyscallTable, wid: usize) -> bool {
    close_fd(sys, s.job.fd);
    s.job.fd = -1;
    session_cleanup(s, wid);
    nak(s, super::wire::ERR_IO);
    true
}

unsafe fn finish_wcommit(s: &mut ModuleState, written: u64) -> bool {
    let digest = s.job.digest;
    record_slot(s, &digest, written.min(u32::MAX as u64) as usize, 0);
    s.stream_commits = s.stream_commits.wrapping_add(1);
    let n = match super::wire::encode_wcommit_resp(&mut s.scratch, &digest) {
        Ok(n) => n,
        Err(_) => return true,
    };
    write_resp(s, n);
    true
}

unsafe fn handle_wabort(s: &mut ModuleState, bytes: &[u8]) -> bool {
    let wid = match super::wire::decode_wid_req(bytes, super::wire::OP_WABORT) {
        Ok(w) => w as usize,
        Err(_) => {
            nak(s, super::wire::ERR_BAD_REQ);
            return true;
        }
    };
    // The temporary's removal is owed, not awaited: the abort answers
    // now, and the id stays out of use until the removal is decided.
    if wid < WRITE_SESSIONS && s.wsessions[wid].in_use != 0 {
        session_cleanup(s, wid);
        s.stream_aborts = s.stream_aborts.wrapping_add(1);
    }
    let n = match super::wire::encode_wabort_resp(&mut s.scratch) {
        Ok(n) => n,
        Err(_) => return true,
    };
    write_resp(s, n);
    true
}

// ── Ranged reads ──────────────────────────────────────────────────

const RANGE_OPEN: u8 = 1;
const RANGE_STAT: u8 = 2;
const RANGE_SEEK: u8 = 3;
const RANGE_READ: u8 = 4;

unsafe fn handle_range(s: &mut ModuleState, sys: &super::SyscallTable, bytes: &[u8]) -> bool {
    if s.job.phase == 0 {
        if s.root_dir_len == 0 {
            nak(s, super::wire::ERR_NO_ROOT);
            return true;
        }
        let (digest_bytes, off, want) = match super::wire::decode_range_req(bytes) {
            Ok(v) => v,
            Err(_) => {
                nak(s, super::wire::ERR_BAD_REQ);
                return true;
            }
        };
        let digest = digest_from(digest_bytes);
        let mut path = [0u8; PATH_BUF];
        let plen = build_body_path(s, &digest, &mut path);
        if plen == 0 {
            nak(s, super::wire::ERR_IO);
            return true;
        }
        s.job.path = path;
        s.job.plen = plen as u16;
        s.job.off = off;
        s.job.size = want;
        s.job.filled = 0;
        s.job.phase = RANGE_OPEN;
    }
    loop {
        match s.job.phase {
            RANGE_OPEN => {
                let path = held(&s.job.path, s.job.plen);
                let fd = (sys.provider_call)(-1, FS_OPEN, path.as_ptr() as *mut u8, path.len());
                if pending(fd) {
                    return false;
                }
                if fd < 0 {
                    nak(s, super::wire::ERR_NOT_FOUND);
                    return true;
                }
                s.job.fd = fd;
                s.job.phase = RANGE_STAT;
            }
            RANGE_STAT => {
                // File size via STAT so a past-EOF range answers empty
                // rather than a short read being ambiguous.
                let rc = (sys.provider_call)(
                    s.job.fd,
                    FS_STAT,
                    s.job.stat.as_mut_ptr(),
                    s.job.stat.len(),
                );
                if pending(rc) {
                    return false;
                }
                if rc < 0 {
                    close_fd(sys, s.job.fd);
                    nak(s, super::wire::ERR_IO);
                    return true;
                }
                let st = s.job.stat;
                let size = u32::from_le_bytes([st[0], st[1], st[2], st[3]]) as u64;
                let off = s.job.off;
                if off >= size {
                    close_fd(sys, s.job.fd);
                    let n = match super::wire::encode_range_resp(&mut s.scratch, &[]) {
                        Ok(n) => n,
                        Err(_) => return true,
                    };
                    write_resp(s, n);
                    s.ranges = s.ranges.wrapping_add(1);
                    return true;
                }
                s.job.size = (s.job.size as u64)
                    .min(super::wire::MAX_BODY as u64)
                    .min(size - off) as u32;
                s.job.phase = RANGE_SEEK;
            }
            RANGE_SEEK => {
                let off32: [u8; 4] = (s.job.off as u32).to_le_bytes();
                if pending((sys.provider_call)(
                    s.job.fd,
                    FS_SEEK,
                    off32.as_ptr() as *mut u8,
                    4,
                )) {
                    return false;
                }
                s.job.phase = RANGE_READ;
            }
            _ => break,
        }
    }
    // Read into scratch past the 5-byte header, encode in place. A
    // pending read parks with the bytes so far kept in `scratch`; end
    // of file or an error serves what arrived.
    let take = (s.job.size as usize).min(s.scratch.len().saturating_sub(5));
    while (s.job.filled as usize) < take {
        let at = 5 + s.job.filled as usize;
        let want = take - s.job.filled as usize;
        let n = (sys.provider_call)(s.job.fd, FS_READ, s.scratch.as_mut_ptr().add(at), want);
        if pending(n) {
            return false;
        }
        if n <= 0 {
            break;
        }
        s.job.filled = s.job.filled.wrapping_add((n as usize).min(want) as u32);
    }
    close_fd(sys, s.job.fd);
    let filled = s.job.filled as usize;
    let hdr = (filled as u32).to_le_bytes();
    s.scratch[0] = super::wire::OP_RANGE;
    for (o, b) in s.scratch.iter_mut().skip(1).zip(hdr.iter()) {
        *o = *b;
    }
    write_resp(s, 5 + filled);
    s.ranges = s.ranges.wrapping_add(1);
    true
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
    s.out.stage(s.cid, n);
    let _ = flush_resp(s);
}

/// Offer the owed response. True once every byte has been accepted,
/// and when nothing is owed, so a caller can gate on it directly.
unsafe fn flush_resp(s: &mut ModuleState) -> bool {
    let sys = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return false,
    };
    let chan = s.out_chan;
    s.out.flush(sys, chan, &s.scratch)
}

#[allow(
    clippy::manual_find,
    reason = "an explicit scan keeps the PIC build panic-free: iterator adapters pull core::panicking paths the bare-metal SDK does not carry"
)]
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

#[allow(
    clippy::manual_find,
    reason = "an explicit scan keeps the PIC build panic-free: iterator adapters pull core::panicking paths the bare-metal SDK does not carry"
)]
fn find_empty_slot(s: &mut ModuleState) -> Option<&mut DiskSlot> {
    for slot in s.slots.iter_mut() {
        if slot.in_use == 0 {
            return Some(slot);
        }
    }
    None
}
