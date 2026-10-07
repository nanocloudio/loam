// Step body for the `object_provider` PIC: loam's `storage.object`.
//
// A consumer — an S3 server, a backup agent — calls the canonical object
// surface (`contracts/storage/object.rs`); this module answers it from
// loam's admin plane, reached over one in-graph link to `admin_gate`.
// Every operation runs under a grant: `PRESENT` carries a scope and a
// capability chain, and the provider opens a session of its own on the
// gate's link for each, presents the chain there, and answers the grant
// handle once the gate has verified it. A scope's authority therefore
// never mixes with another's, and the gate decides every request against
// the grant its session holds — the provider's own checks (scope,
// permission, window) only refuse early what the gate would refuse.
//
// Names: an object key is `root/path` — the root is the key up to its
// first `/`, the path the rest. An S3 server's `B/o/K` is root `B`,
// path `o/K`.
//
// Operations, and what each becomes on the admin wire:
//
//   PUT                one PUT_FILE, or OPEN / CHUNK… / COMMIT past one
//                      body (the digest computed over the caller's buffer)
//   PUT_STREAMED_*     the bytes spooled to a file under `spool_dir` and
//                      hashed as they arrive; COMMIT uploads the spool as
//                      PUT does
//   GET / RANGE_GET    a LOOKUP, then READ_FILE_RANGE pinned to the object
//                      the lookup found, a window of one body at a time
//   HEAD               a LOOKUP
//   DELETE             DELETE_FILE
//   LIST               LIST_FILES
//
// A write's condition (`precondition`) is the admin wire's `WriteCond`,
// decided by the router at the namespace's single point of order. An
// etag is the content digest, so `ETAG` is "bound to `sha256:<etag>`".
//
// A dispatch returns now and answers when the gate has: writes answer
// `EINPROGRESS` and reads `EAGAIN` until then, and the caller asks
// again. An ask is recognised by who asked and what it names, so asking
// again is a second look at the same request, never a second request.
// `PUT_STREAMED_OPEN` and `PUT_STREAMED_WRITE` decide inside the call.
//
// A write reports the fence the namespace achieved for its bind, which
// the admin plane's answer carries: `ReplicatedDurable` with the commit's
// proof, `LocalDurable` behind a WAL. This module claims nothing of its
// own; a read reports `Volatile`.
//
// The includer's scope provides `SyscallTable`, `abi`, `admin`
// (loam_admin_wire), `body_wire`, `hash`, `limits`, `Sha256` and
// `sha256` (the SDK's SHA-256).

#![allow(
    dead_code,
    reason = "shared #[path]-included body; each includer drives a subset"
)]

use super::abi::contracts::mesh::capability as cap;
use super::abi::contracts::storage::object as obj;
use super::admin as aw;

pub const CONTRACT_STORAGE_OBJECT: u32 = 0x0014;

const GRANTS: usize = super::limits::OBJECT_GRANTS;
const PENDING: usize = super::limits::OBJECT_PENDING;
const READS: usize = super::limits::OBJECT_READS;
const STREAMS: usize = super::limits::OBJECT_STREAMS;
const LISTS: usize = super::limits::OBJECT_LISTS;
const MAX_BODY: usize = super::body_wire::MAX_BODY;
const KEY_MAX: usize = super::abi::contracts::storage::handle::STORAGE_KEY_MAX;
/// What a write binds: a file (`loam_wire::KIND_FILE`).
const KIND_FILE: u8 = 0;
const SCOPE_MAX: usize = obj::grant::SCOPE_MAX;
const CTYPE_MAX: usize = super::limits::CONTENT_TYPE_MAX;
/// `sha256:` and 64 hex digits: an etag as the object id it names.
const OID_LEN: usize = 7 + 64;
const ETAG_LEN: usize = 32;
/// Longest spool directory. A spool file's name adds at most 24 bytes
/// to it: `/loam-`, a tag, the slot and generation in hex, `.spool`.
pub const SPOOL_DIR_MAX: usize = 192;
const SPOOL_NAME_MAX: usize = SPOOL_DIR_MAX + 24;
/// Entries one listing page holds: the admin wire's page.
const PAGE_KEYS: usize = aw::LIST_PAGE_MAX;
/// A listing page as this module holds it: the contract's layout,
/// sixteen entries of the longest key, and the trailer.
const LIST_BYTES: usize = obj::list::PAGE_HEADER_LEN
    + PAGE_KEYS * obj::list::entry_len(KEY_MAX, ETAG_LEN)
    + obj::list::TRAILER_HEADER_LEN
    + KEY_MAX;
const OUT_MAX: usize = 4 + aw::REQUEST_MAX;
const RX_MAX: usize = 4 + aw::RESPONSE_MAX;
const FENCE_LEN: usize = super::abi::fence::WIRE_MAX_LEN;

// errno
const E_IO: i32 = -5;
const E_NXIO: i32 = -6;
const E_AGAIN: i32 = -11;
const E_NOMEM: i32 = -12;
const E_ACCES: i32 = -13;
const E_BUSY: i32 = -16;
const E_EXIST: i32 = -17;
const E_INVAL: i32 = -22;
const E_NOSPC: i32 = -28;
const E_INPROGRESS: i32 = -36;
const E_NOSYS: i32 = -38;
const E_OVERFLOW: i32 = -75;

// fs
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_CLOSE: u32 = 0x0903;
const FS_WRITE: u32 = 0x0906;
const FS_OPEN_CREATE: u32 = 0x0909;
const FS_UNLINK: u32 = 0x090A;

const TIMER_MILLIS: u32 = 0x0602;
const CALLER_OWNER: u32 = super::abi::kernel_abi::query_key::CALLER_OWNER;

// Handles: `[gen:14][kind:4][index:8]` under the contract's tag.
const KIND_GRANT: i32 = 1;
const KIND_READ: i32 = 2;
const KIND_STREAM: i32 = 3;

fn handle_of(kind: i32, gen: u16, index: usize) -> i32 {
    let slot = (((gen as i32) & 0x3FFF) << 12) | (kind << 8) | (index as i32 & 0xFF);
    super::abi::kernel_abi::fd::tag_fd(super::abi::kernel_abi::fd::FD_TAG_STORAGE_OBJECT, slot)
}

/// `(kind, gen, index)` of a handle, tagged or not.
fn handle_parts(handle: i32) -> (i32, u16, usize) {
    let slot = handle & super::abi::kernel_abi::fd::SLOT_MASK;
    (
        (slot >> 8) & 0xF,
        ((slot >> 12) & 0x3FFF) as u16,
        (slot & 0xFF) as usize,
    )
}

// ── State ──────────────────────────────────────────────────────────────────

/// Who asked: the kernel's owner of the calling module.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Owner {
    pub slot: u16,
    pub gen: u32,
}

const G_FREE: u8 = 0;
/// The presentation is owed to the gate.
const G_PRESENT: u8 = 1;
/// Presented; the gate has not answered.
const G_WAIT: u8 = 2;
const G_GRANTED: u8 = 3;
const G_REFUSED: u8 = 4;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Grant {
    pub state: u8,
    /// The answer has been collected: the handle is the caller's.
    pub collected: u8,
    /// The session's end is owed to the gate.
    pub close_owed: u8,
    pub refusal: u8,
    pub result: i32,
    pub gen: u16,
    pub owner: Owner,
    pub ask: [u8; 32],
    pub session: u32,
    pub scope: [u8; SCOPE_MAX],
    pub scope_len: u16,
    pub chain: [u8; cap::MAX_CHAIN_BYTES],
    pub chain_len: u16,
    pub permissions: u16,
    pub not_after: u32,
    pub decided_ms: u64,
}

const O_FREE: u8 = 0;
/// The next request is owed to the gate.
const O_SEND: u8 = 1;
/// A request is with the gate.
const O_SENT: u8 = 2;
const O_DECIDED: u8 = 3;

const K_PUT: u8 = 1;
const K_DELETE: u8 = 2;
const K_HEAD: u8 = 3;
const K_GET: u8 = 4;
const K_LIST: u8 = 5;
/// A streamed write's upload.
const K_COMMIT: u8 = 6;
/// A presentation, keyed in the ops table like a request.
const K_PRESENT: u8 = 7;

/// Where an upload's bytes come from.
const SRC_MEM: u8 = 1;
const SRC_SPOOL: u8 = 2;

/// Which request of an upload is next.
const U_SINGLE: u8 = 0;
const U_OPEN: u8 = 1;
const U_CHUNK: u8 = 2;
const U_COMMIT: u8 = 3;

/// No condition this store can satisfy: an etag that is not a content
/// digest names no object here.
const MODE_NEVER: u8 = 0xFF;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Op {
    /// The fence a decided write achieved, as the admin plane reported
    /// it (fluxor's fence wire form); empty for anything else.
    pub fence: [u8; FENCE_LEN],
    pub fence_len: u8,
    pub state: u8,
    pub kind: u8,
    pub grant: u8,
    pub src: u8,
    pub stage: u8,
    pub pfid: u8,
    /// The stream this upload commits, or 0xFF once nobody waits on it.
    pub stream: u8,
    pub list: u8,
    pub owner: Owner,
    pub ask: [u8; 32],
    pub cid: u32,
    pub result: i32,
    pub started_ms: u64,
    pub decided_ms: u64,
    pub key: [u8; KEY_MAX],
    pub key_len: u16,
    /// LIST: the cursor; the page's size limit in `max_keys`.
    pub after: [u8; KEY_MAX],
    pub after_len: u16,
    pub max_keys: u16,
    pub ctype: [u8; CTYPE_MAX],
    pub ctype_len: u8,
    pub mode: u8,
    pub expect: [u8; OID_LEN],
    pub expect_len: u8,
    // An upload.
    pub mem: u64,
    pub total: u64,
    pub sent: u64,
    pub digest: [u8; 32],
    pub fd: i32,
    pub spool: [u8; SPOOL_NAME_MAX],
    pub spool_len: u16,
    // What a lookup answered.
    pub size: u64,
    pub stamp_ms: u64,
    pub etag_len: u8,
    pub etag: [u8; ETAG_LEN],
}

/// A read handle: the object a `GET` resolved, pinned, and one window of
/// its bytes.
#[repr(C)]
pub struct Read {
    pub in_use: u8,
    /// 0 idle, 1 a fetch is owed to the gate, 2 a fetch is with it.
    pub fetch: u8,
    pub grant: u8,
    pub gen: u16,
    pub owner: Owner,
    pub key: [u8; KEY_MAX],
    pub key_len: u16,
    pub oid: [u8; OID_LEN],
    pub size: u64,
    pub fetch_off: u64,
    pub fetch_len: u32,
    pub cid: u32,
    pub failed: i32,
    pub started_ms: u64,
    pub win_off: u64,
    pub win_len: u32,
    pub win: [u8; MAX_BODY],
}

#[repr(C)]
pub struct Stream {
    /// The fence its COMMIT achieved, kept with the decided answer.
    pub fence: [u8; FENCE_LEN],
    pub fence_len: u8,
    pub in_use: u8,
    pub grant: u8,
    /// The upload carrying the commit, 0xFF before COMMIT.
    pub op: u8,
    /// COMMIT decided; `result` is its answer.
    pub decided: u8,
    pub gen: u16,
    pub owner: Owner,
    pub result: i32,
    pub key: [u8; KEY_MAX],
    pub key_len: u16,
    pub ctype: [u8; CTYPE_MAX],
    pub ctype_len: u8,
    pub mode: u8,
    pub expect: [u8; OID_LEN],
    pub expect_len: u8,
    pub fd: i32,
    pub spool: [u8; SPOOL_NAME_MAX],
    pub spool_len: u16,
    pub written: u64,
    pub hash: super::Sha256,
}

#[repr(C)]
pub struct ListPage {
    pub in_use: u8,
    pub len: u32,
    pub page: [u8; LIST_BYTES],
}

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    pub link_in: i32,
    pub link_out: i32,
    pub spool_dir: [u8; SPOOL_DIR_MAX],
    pub spool_dir_len: u16,
    pub now_ms: u64,
    pub next_gen: u16,
    pub cid_next: u32,
    pub grants: [Grant; GRANTS],
    pub ops: [Op; PENDING],
    pub reads: [Read; READS],
    pub streams: [Stream; STREAMS],
    pub lists: [ListPage; LISTS],
    /// The link record owed to the gate.
    pub out: [u8; OUT_MAX],
    pub out_len: u32,
    pub rx: [u8; RX_MAX],
    /// A body read from a spool, on its way into `out`.
    pub chunk: [u8; MAX_BODY],
    pub sent_records: u32,
    pub answers: u32,
    pub stray_answers: u32,
    pub protocol_errors: u32,
    pub expired: u32,
    /// The provider selector (`provider_selector::hash` of `volume`), or 0:
    /// the graph's default `storage.object` provider.
    pub selector: u32,
}

unsafe fn sys(s: &ModuleState) -> &super::SyscallTable {
    &*s.syscalls
}

/// Copy `src` to the front of `dst` by index: a slice copy of a runtime
/// length pulls panic paths the PIC link does not carry.
fn put(dst: &mut [u8], src: &[u8]) {
    let mut i = 0;
    while i < src.len() && i < dst.len() {
        dst[i] = src[i];
        i += 1;
    }
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    let lo = u32_at(b, at)? as u64;
    let hi = u32_at(b, at + 4)? as u64;
    Some(lo | (hi << 32))
}

/// The SHA-256 a scope's object is computed with.
struct ScopeHash;

impl cap::CapCrypto for ScopeHash {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        super::sha256(data)
    }
    fn ed25519_verify(&self, _key: &[u8; cap::KEY_LEN], _msg: &[u8], _sig: &[u8; 64]) -> bool {
        // The gate verifies chains; this module only names scopes.
        false
    }
}

// ── Construction ───────────────────────────────────────────────────────────

/// # Safety
/// `state_ptr` is this module's state of `state_size` bytes; `syscalls`
/// outlives the module.
pub unsafe fn module_new_impl(
    link_in: i32,
    link_out: i32,
    spool_dir: &[u8],
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
    if spool_dir.is_empty() || spool_dir.len() > SPOOL_DIR_MAX {
        return E_INVAL;
    }
    core::ptr::write_bytes(state_ptr, 0, state_size);
    let s = &mut *(state_ptr as *mut ModuleState);
    s.syscalls = syscalls;
    s.link_in = link_in;
    s.link_out = link_out;
    put(&mut s.spool_dir, spool_dir);
    s.spool_dir_len = spool_dir.len() as u16;
    let mut i = 0;
    while i < STREAMS {
        s.streams[i].fd = -1;
        i += 1;
    }
    let mut i = 0;
    while i < PENDING {
        s.ops[i].fd = -1;
        i += 1;
    }
    0
}

unsafe fn now_ms(s: &ModuleState) -> u64 {
    let mut b = [0u8; 8];
    (sys(s).provider_call)(-1, TIMER_MILLIS, b.as_mut_ptr(), 8);
    u64::from_le_bytes(b)
}

unsafe fn trusted_clock(s: &ModuleState) -> Option<cap::Clock> {
    let mut rec = [0u8; super::abi::kernel_abi::trusted_time::LEN];
    let rc = (sys(s).provider_call)(
        -1,
        super::abi::kernel_abi::timer::TRUSTED_UNIX,
        rec.as_mut_ptr(),
        rec.len(),
    );
    if rc < 0 {
        return None;
    }
    cap::Clock::from_trusted(&rec)
}

/// The owner of the module calling in; `None` outside a dispatch.
unsafe fn caller(s: &ModuleState) -> Option<Owner> {
    let mut b = [0u8; 8];
    let rc = (sys(s).provider_query)(-1, CALLER_OWNER, b.as_mut_ptr(), b.len());
    if rc < 8 {
        return None;
    }
    Some(Owner {
        slot: u16::from_le_bytes([b[0], b[1]]),
        gen: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    })
}

fn next_gen(s: &mut ModuleState) -> u16 {
    s.next_gen = s.next_gen.wrapping_add(1) & 0x3FFF;
    if s.next_gen == 0 {
        s.next_gen = 1;
    }
    s.next_gen
}

fn next_cid(s: &mut ModuleState) -> u32 {
    s.cid_next = s.cid_next.wrapping_add(1);
    if s.cid_next == 0 {
        s.cid_next = 1;
    }
    s.cid_next
}

/// What an ask is recognised by: who asked, the kind of request
/// (`K_*`), and the bytes it names.
fn ask_of(owner: Owner, kind: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = super::Sha256::new();
    h.update(&[kind]);
    h.update(&owner.slot.to_le_bytes());
    h.update(&owner.gen.to_le_bytes());
    for p in parts {
        h.update(&(p.len() as u32).to_le_bytes());
        h.update(p);
    }
    h.finalize()
}

// ── Keys, scopes and conditions ────────────────────────────────────────────

/// `(root, path)` of a key, or `None` when it is not one this store
/// holds: no `/`, an empty root or path, either past its ceiling, or not
/// UTF-8.
fn split_key(key: &[u8]) -> Option<(&[u8], &[u8])> {
    if key.is_empty() || key.len() > KEY_MAX || !super::hash::utf8_valid(key) {
        return None;
    }
    let mut i = 0;
    while i < key.len() && key[i] != b'/' {
        i += 1;
    }
    if i == 0 || i >= key.len() - 1 || i > super::limits::MAX_ROOT {
        return None;
    }
    let path = &key[i + 1..];
    if path.len() > super::limits::MAX_PATH {
        return None;
    }
    Some((&key[..i], path))
}

/// The admin condition a contract precondition and etag become.
fn condition(pre: u8, etag: &[u8], expect: &mut [u8; OID_LEN]) -> Option<(u8, usize)> {
    match pre {
        p if p == obj::precondition::ANY && etag.is_empty() => Some((aw::WRITE_ANY, 0)),
        p if p == obj::precondition::ABSENT && etag.is_empty() => Some((aw::WRITE_ABSENT, 0)),
        p if p == obj::precondition::ETAG => {
            if etag.len() != ETAG_LEN {
                return Some((MODE_NEVER, 0));
            }
            put(&mut expect[..7], b"sha256:");
            let mut d = [0u8; 32];
            put(&mut d, etag);
            super::body_wire::hex_lower_into(&d, &mut expect[7..]);
            Some((aw::WRITE_IF, OID_LEN))
        }
        _ => None,
    }
}

/// The etag a bound object id carries: its content digest, or nothing
/// when the id is not content-addressed.
fn etag_of(oid: &[u8], out: &mut [u8; ETAG_LEN]) -> usize {
    if oid.len() != OID_LEN || !eq(&oid[..7], b"sha256:") {
        return 0;
    }
    let mut i = 0;
    while i < ETAG_LEN {
        let (h, l) = (nibble(oid[7 + 2 * i]), nibble(oid[8 + 2 * i]));
        match (h, l) {
            (Some(h), Some(l)) => out[i] = (h << 4) | l,
            _ => return 0,
        }
        i += 1;
    }
    ETAG_LEN
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// The admin status a write answered, as the contract's errno.
fn write_errno(status: u8) -> i32 {
    match status {
        aw::STATUS_OK => 0,
        aw::STATUS_EXISTS => E_EXIST,
        aw::STATUS_CONFLICT => E_AGAIN,
        aw::STATUS_NOT_FOUND => E_NXIO,
        aw::STATUS_BUSY => E_BUSY,
        aw::STATUS_QUOTA => E_NOSPC,
        aw::STATUS_FORBIDDEN => E_ACCES,
        _ => E_IO,
    }
}

/// The admin status a read answered, as the contract's errno.
fn read_errno(status: u8) -> i32 {
    match status {
        aw::STATUS_OK => 0,
        aw::STATUS_NOT_FOUND => E_NXIO,
        aw::STATUS_BUSY => E_BUSY,
        aw::STATUS_FORBIDDEN => E_ACCES,
        // A pinned read whose key was rebound mid-read.
        aw::STATUS_CONFLICT => E_IO,
        _ => E_IO,
    }
}

/// Answer the caller's fence: `fence` as the admin plane reported it,
/// or `Volatile` when there is none to report — a read, or a write the
/// plane answered without one.
unsafe fn write_fence(ptr: u64, cap: u16, fence: &[u8]) {
    if ptr == 0 || (cap as usize) < FENCE_LEN {
        return;
    }
    let out = core::slice::from_raw_parts_mut(ptr as usize as *mut u8, cap as usize);
    if fence.is_empty() || fence.len() > out.len() {
        let _ = super::abi::fence::Fence::Volatile.encode(out);
    } else {
        put(out, fence);
    }
}

fn fence_ok(ptr: u64, cap: u16) -> bool {
    ptr != 0 && cap as usize >= FENCE_LEN
}

// ── Grants ─────────────────────────────────────────────────────────────────

/// The grant `handle` names for `owner`, admitted for `need` on `key`
/// (a key, or a listing prefix): its index, or the errno refusing it.
unsafe fn admit(
    s: &ModuleState,
    handle: i32,
    owner: Owner,
    write: bool,
    key: &[u8],
) -> Result<usize, i32> {
    let (kind, gen, i) = handle_parts(handle);
    if handle < 0 || kind != KIND_GRANT || i >= GRANTS {
        return Err(E_ACCES);
    }
    let g = &s.grants[i];
    if g.state != G_GRANTED || g.collected == 0 || g.gen != gen || g.owner != owner {
        return Err(E_ACCES);
    }
    if !grant_live(s, i) {
        return Err(E_ACCES);
    }
    let need = if write {
        cap::perm::SEND_COMMAND
    } else {
        cap::perm::READ_STATE
    };
    if g.permissions & need != need {
        return Err(E_ACCES);
    }
    if !obj::grant::in_scope(&g.scope[..g.scope_len as usize], key) {
        return Err(E_ACCES);
    }
    Ok(i)
}

/// The grant's window is open by the trusted clock.
unsafe fn grant_live(s: &ModuleState, i: usize) -> bool {
    match trusted_clock(s) {
        Some(c) => c.now.saturating_add(c.uncertainty) <= s.grants[i].not_after as u64,
        None => false,
    }
}

unsafe fn present(s: &mut ModuleState, owner: Owner, arg: &mut [u8]) -> i32 {
    let Some(p) = obj::grant::parse_present(arg) else {
        return E_INVAL;
    };
    if !obj::grant::valid_scope(p.scope) || p.chain.len() > cap::MAX_CHAIN_BYTES {
        return E_INVAL;
    }
    let ask = ask_of(owner, K_PRESENT, &[p.scope, p.chain]);
    let mut i = 0;
    while i < GRANTS {
        let g = &mut s.grants[i];
        if g.state != G_FREE && g.collected == 0 && g.owner == owner && eq(&g.ask, &ask) {
            return match g.state {
                G_GRANTED => {
                    g.collected = 1;
                    handle_of(KIND_GRANT, g.gen, i)
                }
                G_REFUSED => {
                    arg[obj::grant::REFUSAL_AT] = g.refusal;
                    let rc = g.result;
                    free_grant(s, i);
                    rc
                }
                _ => E_AGAIN,
            };
        }
        i += 1;
    }
    // A slot whose session's end is still owed to the gate is not free:
    // its next session would reach the gate before the old one ended.
    let mut i = 0;
    while i < GRANTS && (s.grants[i].state != G_FREE || s.grants[i].close_owed != 0) {
        i += 1;
    }
    if i == GRANTS {
        return E_NOMEM;
    }
    let gen = next_gen(s);
    let now = s.now_ms;
    let g = &mut s.grants[i];
    g.state = G_PRESENT;
    g.collected = 0;
    g.refusal = 0;
    g.result = 0;
    g.gen = gen;
    g.owner = owner;
    g.ask = ask;
    g.session = ((gen as u32) << 8) | i as u32;
    put(&mut g.scope, p.scope);
    g.scope_len = p.scope.len() as u16;
    put(&mut g.chain, p.chain);
    g.chain_len = p.chain.len() as u16;
    g.permissions = 0;
    g.not_after = 0;
    g.decided_ms = now;
    E_AGAIN
}

/// Release grant `i`; the gate's session ends when the outbox can say so.
fn free_grant(s: &mut ModuleState, i: usize) {
    let g = &mut s.grants[i];
    if g.state != G_PRESENT {
        g.close_owed = 1;
    }
    g.state = G_FREE;
    g.collected = 0;
}

/// The gate answered grant `i`'s presentation.
fn grant_answered(s: &mut ModuleState, i: usize, payload: &[u8]) {
    let g = &mut s.grants[i];
    if g.state != G_WAIT || payload.len() < cap::ANSWER_FIXED {
        s.protocol_errors = s.protocol_errors.wrapping_add(1);
        return;
    }
    g.decided_ms = s.now_ms;
    let status = payload[4];
    if status == cap::status::GRANTED && payload.len() >= cap::ANSWER_GRANTED {
        let mut object = [0u8; 16];
        put(&mut object, &payload[6..22]);
        // The leaf must name this scope, or the grant would be for a
        // scope the caller did not ask for.
        match obj::grant::scope_object(&ScopeHash, &g.scope[..g.scope_len as usize]) {
            Some(o) if o == object => {
                g.permissions = u16::from_be_bytes([payload[22], payload[23]]);
                g.not_after =
                    u32::from_be_bytes([payload[24], payload[25], payload[26], payload[27]]);
                g.state = G_GRANTED;
            }
            _ => {
                g.state = G_REFUSED;
                g.result = E_ACCES;
                g.refusal = cap::Refusal::ObjectMismatch as u8;
            }
        }
        return;
    }
    g.state = G_REFUSED;
    g.refusal = payload[5];
    g.result = if status == cap::status::GRANTS_FULL {
        E_NOMEM
    } else {
        E_ACCES
    };
}

// ── Pending requests ───────────────────────────────────────────────────────

/// The pending request `ask` names, if one is held.
fn find_op(s: &ModuleState, owner: Owner, ask: &[u8; 32]) -> Option<usize> {
    let mut i = 0;
    while i < PENDING {
        let o = &s.ops[i];
        if o.state != O_FREE && o.kind != K_COMMIT && o.owner == owner && eq(&o.ask, ask) {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn alloc_op(
    s: &mut ModuleState,
    kind: u8,
    grant: usize,
    owner: Owner,
    ask: [u8; 32],
) -> Option<usize> {
    let mut i = 0;
    while i < PENDING && s.ops[i].state != O_FREE {
        i += 1;
    }
    if i == PENDING {
        return None;
    }
    let now = s.now_ms;
    let o = &mut s.ops[i];
    o.state = O_SEND;
    o.kind = kind;
    o.grant = grant as u8;
    o.src = 0;
    o.stage = U_SINGLE;
    o.pfid = 0;
    o.stream = 0xFF;
    o.list = 0xFF;
    o.owner = owner;
    o.ask = ask;
    o.cid = 0;
    o.result = 0;
    o.started_ms = now;
    o.decided_ms = 0;
    o.key_len = 0;
    o.after_len = 0;
    o.max_keys = 0;
    o.ctype_len = 0;
    o.mode = aw::WRITE_ANY;
    o.expect_len = 0;
    o.mem = 0;
    o.total = 0;
    o.sent = 0;
    o.fd = -1;
    o.spool_len = 0;
    o.size = 0;
    o.stamp_ms = 0;
    o.etag_len = 0;
    Some(i)
}

unsafe fn free_op(s: &mut ModuleState, i: usize) {
    if s.ops[i].fd >= 0 {
        let fd = s.ops[i].fd;
        let _ = (sys(s).provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.ops[i].fd = -1;
    }
    if s.ops[i].spool_len != 0 {
        let n = s.ops[i].spool_len as usize;
        let mut name = [0u8; SPOOL_NAME_MAX];
        put(&mut name, &s.ops[i].spool[..n]);
        let _ = (sys(s).provider_call)(-1, FS_UNLINK, name.as_mut_ptr(), n);
        s.ops[i].spool_len = 0;
    }
    if s.ops[i].list != 0xFF {
        let l = s.ops[i].list as usize;
        s.lists[l].in_use = 0;
        s.ops[i].list = 0xFF;
    }
    s.ops[i].state = O_FREE;
}

fn decide(s: &mut ModuleState, i: usize, result: i32) {
    s.ops[i].state = O_DECIDED;
    s.ops[i].result = result;
    s.ops[i].decided_ms = s.now_ms;
    s.ops[i].fence_len = 0;
}

/// Decide write `i`, keeping the fence the admin plane reported for it.
/// A fence too long to be one is not kept; the write then reports none.
fn decide_write(s: &mut ModuleState, i: usize, result: i32, fence: &[u8]) {
    decide(s, i, result);
    if result == 0 && fence.len() <= FENCE_LEN {
        put(&mut s.ops[i].fence, fence);
        s.ops[i].fence_len = fence.len() as u8;
    }
}

/// Store the key, content type and condition a write names on op `i`.
fn set_write(o: &mut Op, key: &[u8], ctype: &[u8], mode: u8, expect: &[u8]) {
    put(&mut o.key, key);
    o.key_len = key.len() as u16;
    put(&mut o.ctype, ctype);
    o.ctype_len = ctype.len() as u8;
    o.mode = mode;
    put(&mut o.expect, expect);
    o.expect_len = expect.len() as u8;
}

// ── Dispatch ───────────────────────────────────────────────────────────────

/// # Safety
/// The loader passes this module's own state and a caller buffer valid
/// for `arg_len` bytes; pointers inside the argument are the caller's.
pub unsafe fn provider_dispatch_impl(
    state_ptr: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state_ptr.is_null() {
        return E_INVAL;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    if s.syscalls.is_null() {
        return E_INVAL;
    }
    s.now_ms = now_ms(s);
    let Some(owner) = caller(s) else {
        return E_ACCES;
    };
    let a: &mut [u8] = if arg.is_null() || arg_len == 0 {
        &mut []
    } else {
        core::slice::from_raw_parts_mut(arg, arg_len)
    };
    match opcode {
        obj::PRESENT => present(s, owner, a),
        obj::PUT => op_put(s, handle, owner, a),
        obj::GET => op_get(s, handle, owner, a),
        obj::HEAD => op_head(s, handle, owner, a),
        obj::RANGE_GET => op_range(s, handle, owner, a),
        obj::DELETE => op_delete(s, handle, owner, a),
        obj::CLOSE => op_close(s, handle, owner),
        obj::LIST => op_list(s, handle, owner, a),
        obj::PUT_STREAMED_OPEN => stream_open(s, handle, owner, a),
        obj::PUT_STREAMED_WRITE => stream_write(s, handle, owner, a),
        obj::PUT_STREAMED_COMMIT => stream_commit(s, handle, owner, a),
        obj::PUT_STREAMED_ABORT => stream_abort(s, handle, owner),
        _ => E_NOSYS,
    }
}

/// `[key_len:u16][key][ct_len:u8][ct][body_ptr:u64][body_len:u64][pre:u8]
/// [etag_len:u8][etag][fence_ptr:u64][fence_cap:u16]`
unsafe fn op_put(s: &mut ModuleState, handle: i32, owner: Owner, a: &[u8]) -> i32 {
    let Some(kl) = u16_at(a, 0) else {
        return E_INVAL;
    };
    let kl = kl as usize;
    let Some(key) = a.get(2..2 + kl) else {
        return E_INVAL;
    };
    let mut p = 2 + kl;
    let Some(&cl) = a.get(p) else { return E_INVAL };
    let Some(ctype) = a.get(p + 1..p + 1 + cl as usize) else {
        return E_INVAL;
    };
    p += 1 + cl as usize;
    let (Some(body_ptr), Some(body_len), Some(&pre), Some(&el)) =
        (u64_at(a, p), u64_at(a, p + 8), a.get(p + 16), a.get(p + 17))
    else {
        return E_INVAL;
    };
    p += 18;
    let Some(etag) = a.get(p..p + el as usize) else {
        return E_INVAL;
    };
    p += el as usize;
    let (Some(fence_ptr), Some(fence_cap)) = (u64_at(a, p), u16_at(a, p + 8)) else {
        return E_INVAL;
    };
    if a.len() != p + 10 || !fence_ok(fence_ptr, fence_cap) {
        return E_INVAL;
    }
    if split_key(key).is_none() || ctype.len() > CTYPE_MAX || (body_len != 0 && body_ptr == 0) {
        return E_INVAL;
    }
    if body_len > super::body_wire::MAX_STREAM_TOTAL {
        return E_INVAL;
    }
    let g = match admit(s, handle, owner, true, key) {
        Ok(g) => g,
        Err(e) => return e,
    };
    let ask = ask_of(owner, K_PUT, &[a.get(..p).unwrap_or(&[])]);
    if let Some(i) = find_op(s, owner, &ask) {
        if s.ops[i].state != O_DECIDED {
            return E_INPROGRESS;
        }
        let rc = s.ops[i].result;
        if rc == 0 {
            let f = s.ops[i].fence;
            write_fence(fence_ptr, fence_cap, &f[..s.ops[i].fence_len as usize]);
        }
        free_op(s, i);
        return rc;
    }
    let mut expect = [0u8; OID_LEN];
    let Some((mode, elen)) = condition(pre, etag, &mut expect) else {
        return E_INVAL;
    };
    if mode == MODE_NEVER {
        return E_AGAIN;
    }
    let Some(i) = alloc_op(s, K_PUT, g, owner, ask) else {
        return E_BUSY;
    };
    let body: &[u8] = if body_len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(body_ptr as usize as *const u8, body_len as usize)
    };
    let o = &mut s.ops[i];
    set_write(o, key, ctype, mode, &expect[..elen]);
    o.src = SRC_MEM;
    o.mem = body_ptr;
    o.total = body_len;
    o.digest = super::sha256(body);
    o.stage = if body_len as usize <= MAX_BODY {
        U_SINGLE
    } else {
        U_OPEN
    };
    E_INPROGRESS
}

/// `[key_len:u16][key][pre:u8][etag_len:u8][etag][fence_ptr:u64][fence_cap:u16]`
unsafe fn op_delete(s: &mut ModuleState, handle: i32, owner: Owner, a: &[u8]) -> i32 {
    let Some(kl) = u16_at(a, 0) else {
        return E_INVAL;
    };
    let kl = kl as usize;
    let Some(key) = a.get(2..2 + kl) else {
        return E_INVAL;
    };
    let p = 2 + kl;
    let (Some(&pre), Some(&el)) = (a.get(p), a.get(p + 1)) else {
        return E_INVAL;
    };
    let Some(etag) = a.get(p + 2..p + 2 + el as usize) else {
        return E_INVAL;
    };
    let p = p + 2 + el as usize;
    let (Some(fence_ptr), Some(fence_cap)) = (u64_at(a, p), u16_at(a, p + 8)) else {
        return E_INVAL;
    };
    if a.len() != p + 10 || !fence_ok(fence_ptr, fence_cap) || split_key(key).is_none() {
        return E_INVAL;
    }
    let g = match admit(s, handle, owner, true, key) {
        Ok(g) => g,
        Err(e) => return e,
    };
    let ask = ask_of(owner, K_DELETE, &[&a[..p]]);
    if let Some(i) = find_op(s, owner, &ask) {
        if s.ops[i].state != O_DECIDED {
            return E_INPROGRESS;
        }
        let rc = s.ops[i].result;
        if rc == 0 {
            let f = s.ops[i].fence;
            write_fence(fence_ptr, fence_cap, &f[..s.ops[i].fence_len as usize]);
        }
        free_op(s, i);
        return rc;
    }
    let mut expect = [0u8; OID_LEN];
    let Some((mode, elen)) = condition(pre, etag, &mut expect) else {
        return E_INVAL;
    };
    if mode == MODE_NEVER {
        return E_AGAIN;
    }
    // Deleting on condition of absence deletes nothing.
    if mode == aw::WRITE_ABSENT {
        return E_INVAL;
    }
    let Some(i) = alloc_op(s, K_DELETE, g, owner, ask) else {
        return E_BUSY;
    };
    set_write(&mut s.ops[i], key, &[], mode, &expect[..elen]);
    E_INPROGRESS
}

/// A lookup's answer for `key`, held for whoever asks it next: the op's
/// index once decided, or the errno to answer now.
unsafe fn lookup(
    s: &mut ModuleState,
    kind: u8,
    handle: i32,
    owner: Owner,
    key: &[u8],
) -> Result<usize, i32> {
    if split_key(key).is_none() {
        return Err(E_INVAL);
    }
    let g = admit(s, handle, owner, false, key)?;
    let ask = ask_of(owner, kind, &[key]);
    if let Some(i) = find_op(s, owner, &ask) {
        return if s.ops[i].state == O_DECIDED {
            Ok(i)
        } else {
            Err(E_AGAIN)
        };
    }
    let Some(i) = alloc_op(s, kind, g, owner, ask) else {
        return Err(E_BUSY);
    };
    set_write(&mut s.ops[i], key, &[], aw::WRITE_ANY, &[]);
    Err(E_AGAIN)
}

/// `GET`: the argument is the key.
unsafe fn op_get(s: &mut ModuleState, handle: i32, owner: Owner, a: &[u8]) -> i32 {
    let i = match lookup(s, K_GET, handle, owner, a) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let rc = s.ops[i].result;
    if rc != 0 {
        free_op(s, i);
        return rc;
    }
    if s.ops[i].expect_len as usize != OID_LEN {
        // Bound, but not to content: there are no bytes to read.
        free_op(s, i);
        return E_INVAL;
    }
    let mut r = 0;
    while r < READS && s.reads[r].in_use != 0 {
        r += 1;
    }
    if r == READS {
        // Keep the answer: the caller asks again once a handle closes.
        return E_BUSY;
    }
    let gen = next_gen(s);
    let o = s.ops[i];
    let rd = &mut s.reads[r];
    rd.in_use = 1;
    rd.fetch = 0;
    rd.grant = o.grant;
    rd.gen = gen;
    rd.owner = owner;
    put(&mut rd.key, &o.key[..o.key_len as usize]);
    rd.key_len = o.key_len;
    put(&mut rd.oid, &o.expect);
    rd.size = o.size;
    rd.failed = 0;
    rd.win_off = 0;
    rd.win_len = 0;
    free_op(s, i);
    handle_of(KIND_READ, gen, r)
}

/// `[key_len:u16][key][out_ptr:u64][out_cap:u32][fence_ptr:u64][fence_cap:u16]`
unsafe fn op_head(s: &mut ModuleState, handle: i32, owner: Owner, a: &[u8]) -> i32 {
    let Some(kl) = u16_at(a, 0) else {
        return E_INVAL;
    };
    let kl = kl as usize;
    let Some(key) = a.get(2..2 + kl) else {
        return E_INVAL;
    };
    let p = 2 + kl;
    let (Some(out_ptr), Some(out_cap), Some(fence_ptr), Some(fence_cap)) = (
        u64_at(a, p),
        u32_at(a, p + 8),
        u64_at(a, p + 12),
        u16_at(a, p + 20),
    ) else {
        return E_INVAL;
    };
    if a.len() != p + 22 || out_ptr == 0 || !fence_ok(fence_ptr, fence_cap) {
        return E_INVAL;
    }
    let i = match lookup(s, K_HEAD, handle, owner, key) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let o = s.ops[i];
    if o.result != 0 {
        free_op(s, i);
        return o.result;
    }
    let out = core::slice::from_raw_parts_mut(out_ptr as usize as *mut u8, out_cap as usize);
    let n = obj::range::encode_head(
        out,
        o.size,
        o.stamp_ms.saturating_mul(1_000_000),
        &o.ctype[..o.ctype_len as usize],
        &o.etag[..o.etag_len as usize],
    );
    free_op(s, i);
    match n {
        Some(n) => {
            write_fence(fence_ptr, fence_cap, &[]);
            n as i32
        }
        None => E_NOMEM,
    }
}

/// `[offset:u64][length:u32][out_ptr:u64]` on a `GET` handle.
unsafe fn op_range(s: &mut ModuleState, handle: i32, owner: Owner, a: &[u8]) -> i32 {
    let (kind, gen, r) = handle_parts(handle);
    if kind != KIND_READ || r >= READS || s.reads[r].in_use == 0 || s.reads[r].gen != gen {
        return E_INVAL;
    }
    if s.reads[r].owner != owner {
        return E_ACCES;
    }
    let (Some(off), Some(len), Some(out_ptr)) = (u64_at(a, 0), u32_at(a, 8), u64_at(a, 12)) else {
        return E_INVAL;
    };
    if a.len() != 20 || (len != 0 && out_ptr == 0) {
        return E_INVAL;
    }
    let g = s.reads[r].grant as usize;
    if s.grants[g].state != G_GRANTED || !grant_live(s, g) {
        return E_ACCES;
    }
    let rd = &mut s.reads[r];
    if rd.failed != 0 {
        let rc = rd.failed;
        rd.failed = 0;
        return rc;
    }
    if len == 0 || off >= rd.size {
        return 0;
    }
    let win_end = rd.win_off + rd.win_len as u64;
    if rd.win_len != 0 && off >= rd.win_off && off < win_end {
        let avail = (win_end - off) as usize;
        let n = if (len as usize) < avail {
            len as usize
        } else {
            avail
        };
        let from = (off - rd.win_off) as usize;
        let out = core::slice::from_raw_parts_mut(out_ptr as usize as *mut u8, n);
        put(out, &rd.win[from..from + n]);
        return n as i32;
    }
    if rd.fetch == 0 {
        let left = rd.size - off;
        rd.fetch_off = off;
        rd.fetch_len = if left < MAX_BODY as u64 {
            left as u32
        } else {
            MAX_BODY as u32
        };
        rd.fetch = 1;
        rd.started_ms = s.now_ms;
    }
    E_AGAIN
}

/// `LIST` under a grant: one page from the admin plane's listing.
unsafe fn op_list(s: &mut ModuleState, handle: i32, owner: Owner, a: &[u8]) -> i32 {
    let Some(req) = obj::list::parse_request(a) else {
        return E_INVAL;
    };
    // The prefix names a root: up to its first `/`.
    let mut cut = 0;
    while cut < req.prefix.len() && req.prefix[cut] != b'/' {
        cut += 1;
    }
    if cut == 0
        || cut == req.prefix.len()
        || cut > super::limits::MAX_ROOT
        || !super::hash::utf8_valid(req.prefix)
    {
        return E_INVAL;
    }
    if !req.cursor.is_empty()
        && (!req.cursor.starts_with(req.prefix) || !super::hash::utf8_valid(req.cursor))
    {
        return E_INVAL;
    }
    let g = match admit(s, handle, owner, false, req.prefix) {
        Ok(g) => g,
        Err(e) => return e,
    };
    let ask = ask_of(
        owner,
        K_LIST,
        &[req.prefix, req.cursor, &req.max_keys.to_le_bytes()],
    );
    if let Some(i) = find_op(s, owner, &ask) {
        if s.ops[i].state != O_DECIDED {
            return E_AGAIN;
        }
        let rc = s.ops[i].result;
        if rc != 0 {
            free_op(s, i);
            return rc;
        }
        let l = s.ops[i].list as usize;
        let out =
            core::slice::from_raw_parts_mut(req.out_ptr as usize as *mut u8, req.out_cap as usize);
        let rc = deliver_page(
            &s.lists[l].page[..s.lists[l].len as usize],
            out,
            req.max_keys,
        );
        free_op(s, i);
        if rc >= 0 {
            write_fence(req.fence_out_ptr, req.fence_out_cap, &[]);
        }
        return rc;
    }
    let mut l = 0;
    while l < LISTS && s.lists[l].in_use != 0 {
        l += 1;
    }
    if l == LISTS {
        return E_BUSY;
    }
    let Some(i) = alloc_op(s, K_LIST, g, owner, ask) else {
        return E_BUSY;
    };
    s.lists[l].in_use = 1;
    s.lists[l].len = 0;
    let o = &mut s.ops[i];
    o.list = l as u8;
    put(&mut o.key, req.prefix);
    o.key_len = req.prefix.len() as u16;
    put(&mut o.after, req.cursor);
    o.after_len = req.cursor.len() as u16;
    o.max_keys = if (req.max_keys as usize) < PAGE_KEYS {
        req.max_keys
    } else {
        PAGE_KEYS as u16
    };
    E_AGAIN
}

/// Copy a held page into the caller's buffer: as many entries as fit it
/// and its `max_keys`, the trailer resuming after the last one copied.
fn deliver_page(held: &[u8], out: &mut [u8], max_keys: u16) -> i32 {
    let Some(page) = obj::list::decode_page(held) else {
        return E_IO;
    };
    let mut w = obj::list::PageWriter::new(out, max_keys);
    let mut last: &[u8] = &[];
    let mut all = true;
    for e in page.entries() {
        if !w.push(e.key, e.size, e.mtime, e.etag) {
            all = false;
            break;
        }
        last = e.key;
    }
    if w.count() == 0 && page.count() != 0 {
        return E_NOMEM;
    }
    let cursor = if all { page.cursor() } else { last };
    match w.finish(cursor) {
        Some(n) => n as i32,
        None => E_NOMEM,
    }
}

unsafe fn op_close(s: &mut ModuleState, handle: i32, owner: Owner) -> i32 {
    let (kind, gen, i) = handle_parts(handle);
    match kind {
        KIND_GRANT if i < GRANTS && s.grants[i].gen == gen && s.grants[i].state == G_GRANTED => {
            if s.grants[i].owner != owner {
                return E_ACCES;
            }
            free_grant(s, i);
            // Handles minted under it die with it.
            let mut r = 0;
            while r < READS {
                if s.reads[r].in_use != 0 && s.reads[r].grant as usize == i {
                    s.reads[r].in_use = 0;
                }
                r += 1;
            }
            let mut w = 0;
            while w < STREAMS {
                if s.streams[w].in_use != 0 && s.streams[w].grant as usize == i {
                    free_stream(s, w);
                }
                w += 1;
            }
            0
        }
        KIND_READ if i < READS && s.reads[i].in_use != 0 && s.reads[i].gen == gen => {
            if s.reads[i].owner != owner {
                return E_ACCES;
            }
            s.reads[i].in_use = 0;
            0
        }
        KIND_STREAM if i < STREAMS && s.streams[i].in_use != 0 && s.streams[i].gen == gen => {
            if s.streams[i].owner != owner {
                return E_ACCES;
            }
            free_stream(s, i);
            0
        }
        _ => E_INVAL,
    }
}

// ── Streamed writes ────────────────────────────────────────────────────────

/// `[key_len:u16][key][ct_len:u8][ct][expected:u64][pre:u8][etag_len:u8][etag]`
unsafe fn stream_open(s: &mut ModuleState, handle: i32, owner: Owner, a: &[u8]) -> i32 {
    let Some(kl) = u16_at(a, 0) else {
        return E_INVAL;
    };
    let kl = kl as usize;
    let Some(key) = a.get(2..2 + kl) else {
        return E_INVAL;
    };
    let mut p = 2 + kl;
    let Some(&cl) = a.get(p) else { return E_INVAL };
    let Some(ctype) = a.get(p + 1..p + 1 + cl as usize) else {
        return E_INVAL;
    };
    p += 1 + cl as usize;
    let (Some(expected), Some(&pre), Some(&el)) = (u64_at(a, p), a.get(p + 8), a.get(p + 9)) else {
        return E_INVAL;
    };
    p += 10;
    let Some(etag) = a.get(p..p + el as usize) else {
        return E_INVAL;
    };
    if a.len() != p + el as usize || split_key(key).is_none() || ctype.len() > CTYPE_MAX {
        return E_INVAL;
    }
    if expected > super::body_wire::MAX_STREAM_TOTAL {
        return E_INVAL;
    }
    let g = match admit(s, handle, owner, true, key) {
        Ok(g) => g,
        Err(e) => return e,
    };
    let mut expect = [0u8; OID_LEN];
    let Some((mode, elen)) = condition(pre, etag, &mut expect) else {
        return E_INVAL;
    };
    let mut i = 0;
    while i < STREAMS && s.streams[i].in_use != 0 {
        i += 1;
    }
    if i == STREAMS {
        return E_NOMEM;
    }
    let gen = next_gen(s);
    let mut name = [0u8; SPOOL_NAME_MAX];
    let n = spool_name(s, b's', i, gen, &mut name);
    let _ = (sys(s).provider_call)(-1, FS_UNLINK, name.as_mut_ptr(), n);
    let fd = (sys(s).provider_call)(-1, FS_OPEN_CREATE, name.as_mut_ptr(), n);
    if fd < 0 {
        return E_IO;
    }
    let st = &mut s.streams[i];
    st.in_use = 1;
    st.grant = g as u8;
    st.op = 0xFF;
    st.decided = 0;
    st.gen = gen;
    st.owner = owner;
    st.result = 0;
    put(&mut st.key, key);
    st.key_len = kl as u16;
    put(&mut st.ctype, ctype);
    st.ctype_len = ctype.len() as u8;
    st.mode = mode;
    put(&mut st.expect, &expect[..elen]);
    st.expect_len = elen as u8;
    st.fd = fd;
    put(&mut st.spool, &name[..n]);
    st.spool_len = n as u16;
    st.written = 0;
    st.hash = super::Sha256::new();
    handle_of(KIND_STREAM, gen, i)
}

/// `<spool_dir>/loam-<tag><index>-<gen>.spool`, in hex; its length.
fn spool_name(
    s: &ModuleState,
    tag: u8,
    index: usize,
    gen: u16,
    out: &mut [u8; SPOOL_NAME_MAX],
) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let d = s.spool_dir_len as usize;
    put(out, &s.spool_dir[..d]);
    let mut n = d;
    for b in b"/loam-" {
        out[n] = *b;
        n += 1;
    }
    out[n] = tag;
    out[n + 1] = HEX[(index >> 4) & 0xF];
    out[n + 2] = HEX[index & 0xF];
    out[n + 3] = b'-';
    n += 4;
    let mut sh = 12;
    loop {
        out[n] = HEX[((gen >> sh) & 0xF) as usize];
        n += 1;
        if sh == 0 {
            break;
        }
        sh -= 4;
    }
    for b in b".spool" {
        out[n] = *b;
        n += 1;
    }
    n
}

unsafe fn stream_of(s: &ModuleState, handle: i32, owner: Owner) -> Result<usize, i32> {
    let (kind, gen, i) = handle_parts(handle);
    if kind != KIND_STREAM || i >= STREAMS || s.streams[i].in_use == 0 || s.streams[i].gen != gen {
        return Err(E_INVAL);
    }
    if s.streams[i].owner != owner {
        return Err(E_ACCES);
    }
    let g = s.streams[i].grant as usize;
    if s.grants[g].state != G_GRANTED || !grant_live(s, g) {
        return Err(E_ACCES);
    }
    Ok(i)
}

unsafe fn stream_write(s: &mut ModuleState, handle: i32, owner: Owner, a: &[u8]) -> i32 {
    let i = match stream_of(s, handle, owner) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let st = &mut s.streams[i];
    if st.op != 0xFF || st.decided != 0 || st.fd < 0 {
        return E_INVAL;
    }
    if a.is_empty() {
        return 0;
    }
    if st.written + a.len() as u64 > super::body_wire::MAX_STREAM_TOTAL {
        return E_INVAL;
    }
    let fd = st.fd;
    let wrote = (sys(s).provider_call)(fd, FS_WRITE, a.as_ptr() as *mut u8, a.len());
    if wrote < 0 || wrote as usize != a.len() {
        return E_IO;
    }
    let st = &mut s.streams[i];
    st.hash.update(a);
    st.written += a.len() as u64;
    0
}

/// `[fence_ptr:u64][fence_cap:u16]`
unsafe fn stream_commit(s: &mut ModuleState, handle: i32, owner: Owner, a: &[u8]) -> i32 {
    let i = match stream_of(s, handle, owner) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let (Some(fence_ptr), Some(fence_cap)) = (u64_at(a, 0), u16_at(a, 8)) else {
        return E_INVAL;
    };
    if a.len() != 10 || !fence_ok(fence_ptr, fence_cap) {
        return E_INVAL;
    }
    if s.streams[i].decided != 0 {
        let rc = s.streams[i].result;
        if rc == 0 {
            let f = s.streams[i].fence;
            write_fence(fence_ptr, fence_cap, &f[..s.streams[i].fence_len as usize]);
        }
        return rc;
    }
    if s.streams[i].op != 0xFF {
        let o = s.streams[i].op as usize;
        if s.ops[o].state != O_DECIDED {
            return E_INPROGRESS;
        }
        let rc = s.ops[o].result;
        let (f, fl) = (s.ops[o].fence, s.ops[o].fence_len);
        free_op(s, o);
        let st = &mut s.streams[i];
        st.op = 0xFF;
        st.decided = 1;
        st.result = rc;
        st.fence = f;
        st.fence_len = fl;
        if rc == 0 {
            write_fence(fence_ptr, fence_cap, &f[..fl as usize]);
        }
        return rc;
    }
    if s.streams[i].mode == MODE_NEVER {
        s.streams[i].decided = 1;
        s.streams[i].result = E_AGAIN;
        return E_AGAIN;
    }
    // Seal the spool and hand it to an upload, which reads it back.
    let fd = s.streams[i].fd;
    let _ = (sys(s).provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    s.streams[i].fd = -1;
    let n = s.streams[i].spool_len as usize;
    let mut name = [0u8; SPOOL_NAME_MAX];
    put(&mut name, &s.streams[i].spool[..n]);
    let rfd = (sys(s).provider_call)(-1, FS_OPEN, name.as_mut_ptr(), n);
    if rfd < 0 {
        s.streams[i].decided = 1;
        s.streams[i].result = E_IO;
        return E_IO;
    }
    let ask = [0u8; 32];
    let g = s.streams[i].grant as usize;
    let Some(o) = alloc_op(s, K_COMMIT, g, owner, ask) else {
        // Sealed and not taken: the write is refused, and the caller
        // backs off and writes it again.
        let _ = (sys(s).provider_call)(rfd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.streams[i].decided = 1;
        s.streams[i].result = E_BUSY;
        return E_BUSY;
    };
    let st = &mut s.streams[i];
    let digest = core::mem::take(&mut st.hash).finalize();
    let (key, kl) = (st.key, st.key_len as usize);
    let (ctype, cl) = (st.ctype, st.ctype_len as usize);
    let (mode, expect, el) = (st.mode, st.expect, st.expect_len as usize);
    let total = st.written;
    st.op = o as u8;
    // The spool now belongs to the upload, which removes it when done.
    st.spool_len = 0;
    let op = &mut s.ops[o];
    set_write(op, &key[..kl], &ctype[..cl], mode, &expect[..el]);
    op.stream = i as u8;
    op.src = SRC_SPOOL;
    op.fd = rfd;
    put(&mut op.spool, &name[..n]);
    op.spool_len = n as u16;
    op.total = total;
    op.digest = digest;
    op.stage = if total as usize <= MAX_BODY {
        U_SINGLE
    } else {
        U_OPEN
    };
    E_INPROGRESS
}

unsafe fn stream_abort(s: &mut ModuleState, handle: i32, owner: Owner) -> i32 {
    let (kind, gen, i) = handle_parts(handle);
    if kind != KIND_STREAM || i >= STREAMS || s.streams[i].in_use == 0 || s.streams[i].gen != gen {
        return E_INVAL;
    }
    if s.streams[i].owner != owner {
        return E_ACCES;
    }
    free_stream(s, i);
    0
}

/// Release stream `i`. An upload already carrying its commit runs to its
/// decision — it was taken — and only its answer goes uncollected.
unsafe fn free_stream(s: &mut ModuleState, i: usize) {
    if s.streams[i].op != 0xFF {
        let o = s.streams[i].op as usize;
        s.ops[o].stream = 0xFF;
        if s.ops[o].state == O_DECIDED {
            free_op(s, o);
        }
    }
    if s.streams[i].fd >= 0 {
        let fd = s.streams[i].fd;
        let _ = (sys(s).provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.streams[i].fd = -1;
    }
    if s.streams[i].spool_len != 0 {
        let n = s.streams[i].spool_len as usize;
        let mut name = [0u8; SPOOL_NAME_MAX];
        put(&mut name, &s.streams[i].spool[..n]);
        let _ = (sys(s).provider_call)(-1, FS_UNLINK, name.as_mut_ptr(), n);
        s.streams[i].spool_len = 0;
    }
    s.streams[i].in_use = 0;
    s.streams[i].op = 0xFF;
}

// ── The step ───────────────────────────────────────────────────────────────

/// # Safety
/// `state_ptr` is this module's state, built by `module_new_impl`.
pub unsafe fn module_step_impl(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    if s.syscalls.is_null() {
        return -1;
    }
    s.now_ms = now_ms(s);
    read_answers(s);
    expire(s);
    let mut sent = 0;
    while sent < super::limits::OPS_PER_STEP {
        if s.out_len == 0 && !stage_next(s) {
            break;
        }
        if !flush(s) {
            break;
        }
        sent += 1;
    }
    0
}

/// Offer the owed record; true once the link has taken it.
unsafe fn flush(s: &mut ModuleState) -> bool {
    if s.out_len == 0 {
        return true;
    }
    if s.link_out < 0 {
        return false;
    }
    let n = s.out_len as usize;
    let rc = (sys(s).channel_write)(s.link_out, s.out.as_ptr(), n);
    if rc < 0 || rc as usize != n {
        return false;
    }
    s.out_len = 0;
    s.sent_records = s.sent_records.wrapping_add(1);
    true
}

/// Build the next owed record into `out`. False when nothing is owed.
unsafe fn stage_next(s: &mut ModuleState) -> bool {
    // Sessions first: a grant's presentation or its end.
    let mut i = 0;
    while i < GRANTS {
        if s.grants[i].close_owed != 0 && s.grants[i].state == G_FREE {
            let session = s.grants[i].session;
            put(&mut s.out[..4], &session.to_le_bytes());
            s.out_len = 4;
            s.grants[i].close_owed = 0;
            return true;
        }
        if s.grants[i].state == G_PRESENT {
            let g = &s.grants[i];
            let cl = g.chain_len as usize;
            let session = g.session;
            let presentation = g.gen as u32;
            put(&mut s.out[..4], &session.to_le_bytes());
            s.out[4] = cap::MSG_CAP_PRESENT;
            put(&mut s.out[5..7], &((4 + cl) as u16).to_le_bytes());
            put(&mut s.out[7..11], &presentation.to_le_bytes());
            let chain = s.grants[i].chain;
            put(&mut s.out[11..11 + cl], &chain[..cl]);
            s.out_len = (11 + cl) as u32;
            s.grants[i].state = G_WAIT;
            return true;
        }
        i += 1;
    }
    // Read windows.
    let mut r = 0;
    while r < READS {
        if s.reads[r].in_use != 0 && s.reads[r].fetch == 1 {
            let cid = next_cid(s);
            let g = s.reads[r].grant as usize;
            let session = s.grants[g].session;
            let rd = &s.reads[r];
            let key = &rd.key[..rd.key_len as usize];
            let Some((root, path)) = split_key(key) else {
                s.reads[r].fetch = 0;
                s.reads[r].failed = E_INVAL;
                r += 1;
                continue;
            };
            put(&mut s.out[..4], &session.to_le_bytes());
            let out: &mut [u8] = &mut *(&mut s.out[4..] as *mut [u8]);
            match aw::encode_read_file_range(
                out,
                cid,
                rd.fetch_off,
                rd.fetch_len,
                root,
                path,
                &rd.oid,
            ) {
                Ok(n) => {
                    s.out_len = (4 + n) as u32;
                    s.reads[r].cid = cid;
                    s.reads[r].fetch = 2;
                    s.reads[r].started_ms = s.now_ms;
                    return true;
                }
                Err(_) => {
                    s.reads[r].fetch = 0;
                    s.reads[r].failed = E_IO;
                }
            }
        }
        r += 1;
    }
    // Requests.
    let mut i = 0;
    while i < PENDING {
        if s.ops[i].state == O_SEND && stage_op(s, i) {
            return true;
        }
        i += 1;
    }
    false
}

/// Build op `i`'s next request into `out`. False when it has none to
/// send (it was decided instead).
unsafe fn stage_op(s: &mut ModuleState, i: usize) -> bool {
    let g = s.ops[i].grant as usize;
    if s.grants[g].state != G_GRANTED {
        // The grant went; nothing it admitted may be sent.
        decide(s, i, E_ACCES);
        return false;
    }
    let session = s.grants[g].session;
    let cid = next_cid(s);
    let o: &Op = &*(&s.ops[i] as *const Op);
    let key = &o.key[..o.key_len as usize];
    let ctype = &o.ctype[..o.ctype_len as usize];
    let cond = aw::WriteCond {
        mode: o.mode,
        expect: &o.expect[..o.expect_len as usize],
    };
    put(&mut s.out[..4], &session.to_le_bytes());
    let out: &mut [u8] = &mut *(&mut s.out[4..] as *mut [u8]);
    let encoded = match o.kind {
        K_PUT | K_COMMIT => {
            let Some((root, path)) = split_key(key) else {
                decide(s, i, E_INVAL);
                return false;
            };
            match o.stage {
                U_SINGLE => match upload_bytes(s, i, o.total as usize) {
                    Some(body) => aw::encode_admin_put_file(
                        out, cid, root, path, KIND_FILE, &cond, ctype, body,
                    ),
                    None => {
                        decide(s, i, E_IO);
                        return false;
                    }
                },
                U_OPEN => aw::encode_put_file_open(
                    out, cid, root, path, KIND_FILE, &cond, ctype, &o.digest, o.total,
                ),
                U_CHUNK => {
                    let left = o.total - o.sent;
                    let n = if left < MAX_BODY as u64 {
                        left as usize
                    } else {
                        MAX_BODY
                    };
                    match upload_bytes(s, i, n) {
                        Some(bytes) => aw::encode_put_file_chunk(out, cid, o.pfid, bytes),
                        None => {
                            decide(s, i, E_IO);
                            return false;
                        }
                    }
                }
                _ => aw::encode_put_file_commit(out, cid, o.pfid),
            }
        }
        K_DELETE => match split_key(key) {
            Some((root, path)) => aw::encode_admin_delete_file(out, cid, root, path, &cond),
            None => {
                decide(s, i, E_INVAL);
                return false;
            }
        },
        K_HEAD | K_GET => match split_key(key) {
            Some((root, path)) => aw::encode_admin_lookup(out, cid, root, path),
            None => {
                decide(s, i, E_INVAL);
                return false;
            }
        },
        K_LIST => {
            // `root/prefix…` and a cursor `root/after…`.
            let mut cut = 0;
            while cut < key.len() && key[cut] != b'/' {
                cut += 1;
            }
            let after = &o.after[..o.after_len as usize];
            let after_path: &[u8] = if after.is_empty() {
                &[]
            } else {
                &after[cut + 1..]
            };
            aw::encode_admin_list_files(
                out,
                cid,
                &key[..cut],
                &key[cut + 1..],
                after_path,
                o.max_keys as u8,
            )
        }
        _ => {
            decide(s, i, E_IO);
            return false;
        }
    };
    match encoded {
        Ok(n) => {
            s.out_len = (4 + n) as u32;
            s.ops[i].cid = cid;
            s.ops[i].state = O_SENT;
            // The gate's deadline runs per request: an upload is many.
            s.ops[i].started_ms = s.now_ms;
            true
        }
        Err(_) => {
            decide(s, i, E_INVAL);
            false
        }
    }
}

/// The next `n` bytes of op `i`'s upload: from the caller's buffer, or
/// read from the spool into `chunk`.
unsafe fn upload_bytes(s: &mut ModuleState, i: usize, n: usize) -> Option<&'static [u8]> {
    let o = &s.ops[i];
    if n == 0 {
        return Some(&[]);
    }
    if o.src == SRC_MEM {
        let p = (o.mem as usize).wrapping_add(o.sent as usize) as *const u8;
        return Some(core::slice::from_raw_parts(p, n));
    }
    let fd = o.fd;
    let mut got = 0usize;
    while got < n {
        let rc = (sys(s).provider_call)(fd, FS_READ, s.chunk.as_mut_ptr().add(got), n - got);
        if rc <= 0 {
            return None;
        }
        got += rc as usize;
    }
    Some(&*(&s.chunk[..n] as *const [u8]))
}

// ── Answers ────────────────────────────────────────────────────────────────

unsafe fn read_answers(s: &mut ModuleState) {
    if s.link_in < 0 {
        return;
    }
    let mut taken = 0;
    while taken < 2 * super::limits::OPS_PER_STEP {
        let n = (sys(s).channel_read)(s.link_in, s.rx.as_mut_ptr(), RX_MAX);
        if n <= 0 {
            return;
        }
        taken += 1;
        let n = n as usize;
        if n < 5 {
            s.protocol_errors = s.protocol_errors.wrapping_add(1);
            continue;
        }
        s.answers = s.answers.wrapping_add(1);
        let session = u32::from_le_bytes([s.rx[0], s.rx[1], s.rx[2], s.rx[3]]);
        let frame: &[u8] = &*(&s.rx[4..n] as *const [u8]);
        if frame[0] == cap::MSG_CAP_ANSWER {
            let mut g = 0;
            while g < GRANTS && !(s.grants[g].state == G_WAIT && s.grants[g].session == session) {
                g += 1;
            }
            if g == GRANTS || frame.len() < cap::FRAME_HDR {
                s.stray_answers = s.stray_answers.wrapping_add(1);
                continue;
            }
            grant_answered(s, g, &frame[cap::FRAME_HDR..]);
            continue;
        }
        let Some(cid) = u32_at(frame, 1) else {
            s.protocol_errors = s.protocol_errors.wrapping_add(1);
            continue;
        };
        answer(s, cid, frame);
    }
}

/// Route an admin answer to what asked it.
unsafe fn answer(s: &mut ModuleState, cid: u32, frame: &[u8]) {
    let mut r = 0;
    while r < READS {
        if s.reads[r].in_use != 0 && s.reads[r].fetch == 2 && s.reads[r].cid == cid {
            let rd = &mut s.reads[r];
            rd.fetch = 0;
            match aw::decode_read_file_range_ack(frame) {
                Ok((_, aw::STATUS_OK, Some(bytes))) if bytes.len() <= MAX_BODY => {
                    put(&mut rd.win, bytes);
                    rd.win_off = rd.fetch_off;
                    rd.win_len = bytes.len() as u32;
                    if bytes.is_empty() {
                        // Shorter than the binding said: the bytes ended.
                        rd.failed = E_IO;
                    }
                }
                Ok((_, status, _)) => {
                    rd.failed = if status == aw::STATUS_OK {
                        E_IO
                    } else {
                        read_errno(status)
                    }
                }
                Err(_) => rd.failed = E_IO,
            }
            return;
        }
        r += 1;
    }
    let mut i = 0;
    while i < PENDING {
        if s.ops[i].state == O_SENT && s.ops[i].cid == cid {
            op_answered(s, i, frame);
            return;
        }
        i += 1;
    }
    s.stray_answers = s.stray_answers.wrapping_add(1);
}

unsafe fn op_answered(s: &mut ModuleState, i: usize, frame: &[u8]) {
    match s.ops[i].kind {
        K_PUT | K_COMMIT => upload_answered(s, i, frame),
        K_DELETE => match aw::decode_admin_delete_file_ack(frame) {
            Ok((_, status, fence)) => decide_write(s, i, write_errno(status), fence),
            Err(_) => decide(s, i, E_IO),
        },
        K_HEAD | K_GET => match aw::decode_admin_lookup_ack(frame) {
            Ok((_, aw::STATUS_OK, Some(b))) => {
                let o = &mut s.ops[i];
                o.size = b.size;
                o.stamp_ms = b.stamp_ms;
                put(&mut o.ctype, b.content_type);
                o.ctype_len = if b.content_type.len() <= CTYPE_MAX {
                    b.content_type.len() as u8
                } else {
                    0
                };
                let mut etag = [0u8; ETAG_LEN];
                o.etag_len = etag_of(b.object_id, &mut etag) as u8;
                o.etag = etag;
                // GET pins what it reads to the object it found.
                if o.etag_len as usize == ETAG_LEN {
                    put(&mut o.expect, b.object_id);
                    o.expect_len = OID_LEN as u8;
                } else {
                    o.expect_len = 0;
                }
                decide(s, i, 0);
            }
            Ok((_, status, _)) => decide(
                s,
                i,
                read_errno(if status == aw::STATUS_OK {
                    0xFF
                } else {
                    status
                }),
            ),
            Err(_) => decide(s, i, E_IO),
        },
        K_LIST => list_answered(s, i, frame),
        _ => decide(s, i, E_IO),
    }
}

/// An upload's request answered: advance to its next request, or decide.
unsafe fn upload_answered(s: &mut ModuleState, i: usize, frame: &[u8]) {
    let stage = s.ops[i].stage;
    match stage {
        U_OPEN => match aw::decode_put_file_open_ack(frame) {
            Ok((_, aw::STATUS_OK, pfid)) => {
                let o = &mut s.ops[i];
                o.pfid = pfid;
                o.stage = if o.total == 0 { U_COMMIT } else { U_CHUNK };
                o.state = O_SEND;
            }
            Ok((_, status, _)) => decide(s, i, write_errno(status)),
            Err(_) => decide(s, i, E_IO),
        },
        U_CHUNK => match aw::decode_put_file_chunk_ack(frame) {
            Ok((_, aw::STATUS_OK)) => {
                let o = &mut s.ops[i];
                let left = o.total - o.sent;
                o.sent += if left < MAX_BODY as u64 {
                    left
                } else {
                    MAX_BODY as u64
                };
                o.stage = if o.sent >= o.total { U_COMMIT } else { U_CHUNK };
                o.state = O_SEND;
            }
            Ok((_, status)) => decide(s, i, write_errno(status)),
            Err(_) => decide(s, i, E_IO),
        },
        _ => match aw::decode_admin_put_file_ack(frame) {
            Ok((_, aw::STATUS_OK, Some(d), fence)) if eq(d, &s.ops[i].digest) => {
                decide_write(s, i, 0, fence)
            }
            // Stored under another digest than the bytes hashed to.
            Ok((_, aw::STATUS_OK, _, _)) => decide(s, i, E_IO),
            Ok((_, status, _, _)) => decide(s, i, write_errno(status)),
            Err(_) => decide(s, i, E_IO),
        },
    }
}

/// A listing page answered: hold it in the contract's layout.
unsafe fn list_answered(s: &mut ModuleState, i: usize, frame: &[u8]) {
    let l = s.ops[i].list as usize;
    let root_len = {
        let o = &s.ops[i];
        let mut cut = 0;
        while cut < o.key_len as usize && o.key[cut] != b'/' {
            cut += 1;
        }
        cut
    };
    let mut root = [0u8; KEY_MAX];
    put(&mut root, &s.ops[i].key[..root_len]);
    let page: &mut [u8] = &mut *(&mut s.lists[l].page[..] as *mut [u8]);
    let mut w = obj::list::PageWriter::new(page, PAGE_KEYS as u16);
    let mut last = [0u8; KEY_MAX];
    let mut last_len = 0usize;
    let mut fault = 0i32;
    let decoded = aw::decode_admin_list_files_ack(frame, |path, b| {
        if fault != 0 {
            return;
        }
        let klen = root_len + 1 + path.len();
        if klen > KEY_MAX {
            fault = E_OVERFLOW;
            return;
        }
        let mut key = [0u8; KEY_MAX];
        put(&mut key, &root[..root_len]);
        key[root_len] = b'/';
        put(&mut key[root_len + 1..], path);
        let mut etag = [0u8; ETAG_LEN];
        let el = etag_of(b.object_id, &mut etag);
        if !w.push(
            &key[..klen],
            b.size,
            b.stamp_ms.saturating_mul(1_000_000),
            &etag[..el],
        ) {
            fault = E_IO;
            return;
        }
        put(&mut last, &key[..klen]);
        last_len = klen;
    });
    let result = match decoded {
        _ if fault != 0 => fault,
        Ok((_, aw::STATUS_OK, more)) => {
            let cursor: &[u8] = if more { &last[..last_len] } else { &[] };
            match w.finish(cursor) {
                Some(n) => {
                    s.lists[l].len = n as u32;
                    0
                }
                None => E_IO,
            }
        }
        Ok((_, status, _)) => read_errno(status),
        Err(_) => E_IO,
    };
    decide(s, i, result);
}

/// Drop what nobody collects, and answer what the gate never did.
unsafe fn expire(s: &mut ModuleState) {
    let now = s.now_ms;
    let mut i = 0;
    while i < PENDING {
        let o = &s.ops[i];
        let stale = match o.state {
            O_DECIDED => {
                // An upload a stream still waits on is the stream's to
                // collect; the stream's own life bounds it.
                o.stream == 0xFF && now.saturating_sub(o.decided_ms) > super::limits::OBJECT_HOLD_MS
            }
            // A request owed but not yet sent waits on this module's own
            // outbox, which drains; one with the gate waits on its answer.
            O_SENT => now.saturating_sub(o.started_ms) > super::limits::OBJECT_HOLD_MS,
            _ => false,
        };
        if stale {
            s.expired = s.expired.wrapping_add(1);
            if s.ops[i].state == O_DECIDED {
                free_op(s, i);
            } else {
                decide(s, i, E_IO);
            }
        }
        i += 1;
    }
    let mut g = 0;
    while g < GRANTS {
        let gr = &s.grants[g];
        let waiting = gr.state == G_WAIT || gr.state == G_PRESENT;
        let uncollected = (gr.state == G_GRANTED && gr.collected == 0) || gr.state == G_REFUSED;
        if (waiting || uncollected)
            && now.saturating_sub(gr.decided_ms) > super::limits::OBJECT_HOLD_MS
        {
            s.expired = s.expired.wrapping_add(1);
            free_grant(s, g);
        }
        g += 1;
    }
    let mut r = 0;
    while r < READS {
        let rd = &mut s.reads[r];
        if rd.in_use != 0
            && rd.fetch == 2
            && now.saturating_sub(rd.started_ms) > super::limits::OBJECT_HOLD_MS
        {
            rd.fetch = 0;
            rd.failed = E_IO;
        }
        r += 1;
    }
}
