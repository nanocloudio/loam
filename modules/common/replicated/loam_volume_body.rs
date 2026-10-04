// Step body for the `loam_volume` PIC: a `storage.block` source over
// one Loam volume.
//
// The volume is a copy-on-write map of content-addressed extent bodies,
// committed by a fenced, revisioned bind. This module is its one writer:
// it takes the volume's writer lease, reads through the committed map,
// stages written extents in memory, and makes them durable by the
// volume commit — BEGIN, the extent bodies,
// the leaf pages on changed paths, the root page, COMMIT at the next
// revision under the lease's fence. Every exchange is one admin-wire
// request and its ack through the admin client (`admin_client.rs`): over
// an in-graph link to `admin_gate`, or over the network through a
// client-mode `tls`, after presenting the capabilities in the module's
// capability file — one covering the volume's key, one the body plane.
//
// Block requests:
//
// - `EXEC` completes inside the call when it can: a read of resident
//   extents, a write that stages without a fetch, a flush with nothing
//   left to commit. Anything that needs the store answers `EAGAIN` and
//   arranges what it needs — the fetch, or the commit — so a retry
//   after the module has stepped completes. A retried write of the same
//   bytes changes nothing and so owes no new commit, which is what lets
//   a flush retried around a write converge.
// - `SUBMIT` queues the request; the module steps it to completion and
//   `REAP` hands the completion back. The write buffer is lent until the
//   completion is reaped: a queued write reads it when it stages.
//
// Fences: a write that is only staged completes `Volatile`. A flush, a
// FUA write, and a PREFLUSH complete only after the commit that covers
// them, with `RevisionMonotone { source, revision }` — the volume's
// commit point. That is the strongest fence the admin wire proves: its
// VOLUME ack carries the revision the bind landed at, not the replica
// group's commit proof, so a `ReplicatedDurable` claim here would be
// unsubstantiated.
//
// Failure is closed. A commit refused `CONFLICT` or `LEASE_LOST`, a
// lease that cannot be renewed before its deadline, a store that loses a
// committed body, or a peer that stops answering ends the device: every
// request after it fails `EIO`, staged writes are dropped, and nothing is
// merged. A new instance reopens the volume at its committed revision.
//
// The includer's scope provides `SyscallTable`, `abi` (block contract
// and fence), `admin` (loam_admin_wire), `admin_client`, `map_wire`
// (loam_volume_map_wire), `limits` and `sha256::Sha256`.
//
// PIC discipline: no division by a runtime value (the geometry is powers
// of two and moves by shifts), no slice index taken from the wire
// without a bound check, and per-step work bounded by the tables below.

use core::convert::TryInto;
use core::ffi::c_void;

use super::abi::contracts::storage::block::{self as blk, Caps, Cpl, Req};
use super::abi::fence::Fence;
use super::admin as aw;
use super::map_wire as map;

/// Largest extent this module holds: the largest power of two one body
/// carries (`MAX_EXTENT_SIZE` is 60 KiB). The module moves through a
/// volume by shifts, so a volume whose extents are larger, or not a
/// power of two, is refused at open.
pub const EXTENT_CAP: usize = 32768;
/// Extents resident at once, staged or clean (profiled).
pub const EXTENT_SLOTS: usize = super::limits::VOLUME_EXTENT_SLOTS;
/// Extents staged before a write forces a commit. Below `EXTENT_SLOTS`
/// so a read can always find a clean slot to fetch into.
pub const STAGED_MAX: usize = EXTENT_SLOTS - 2;
/// Leaf pages of a depth-2 map held at once.
pub const LEAF_SLOTS: usize = 2;
/// Extents a stalled request can ask to be fetched at once.
pub const WANT_SLOTS: usize = 4;
/// Requests queued or completed and not yet reaped.
pub const QUEUE_DEPTH: usize = 8;
/// One admin frame in either direction: the largest is a PUT or GET of a
/// full map page.
pub const IO_CAP: usize = map::MAX_PAGE_LEN + 64;

/// An ack that has not arrived by then ends the device: a commit whose
/// outcome is unknown cannot be retried as if it had not happened.
const ACK_TIMEOUT_MS: u64 = 10_000;
/// How long a flush waits for a GC sweep's reservation to lift.
const BEGIN_PATIENCE_MS: u64 = 10_000;
const RETRY_MS: u64 = 5;
const ACQUIRE_RETRY_MS: u64 = 50;
const TTL_MIN_MS: u32 = 100;
/// The namespace kind a volume binding carries.
const KIND_VOLUME: u8 = 3;
const DIGEST: usize = 32;
const SOURCE_DOMAIN: &[u8] = b"loam-volume-block\x01";

const EIO: i32 = -5;
const ENOENT: i32 = -2;
const EAGAIN: i32 = -11;
const EACCES: i32 = -13;
const EBUSY: i32 = -16;
const EINVAL: i32 = -22;
const ENOSYS: i32 = -38;

const P_LEASE: u8 = 0;
const P_LOOKUP: u8 = 1;
const P_ROOT: u8 = 2;
const P_READY: u8 = 3;
const P_FAILED: u8 = 4;

const J_NONE: u8 = 0;
const J_ACQUIRE: u8 = 1;
const J_RENEW: u8 = 2;
const J_LOOKUP: u8 = 3;
const J_ROOT: u8 = 4;
const J_LEAF: u8 = 5;
const J_EXTENT: u8 = 6;
const J_BEGIN: u8 = 7;
const J_PUT_LEAF: u8 = 9;
const J_PUT_ROOT: u8 = 10;
const J_COMMIT: u8 = 11;
const J_ABORT: u8 = 12;
/// A commit's extent bodies, sent back to back with their acks collected
/// as they come (`bodies_pump`).
const J_PUT_BODIES: u8 = 13;
/// The lease's release, the last request of a drain.
const J_RELEASE: u8 = 14;

const C_IDLE: u8 = 0;
const C_BEGIN: u8 = 1;
const C_BODIES: u8 = 2;
const C_LEAVES: u8 = 3;
const C_ROOT: u8 = 4;
const C_COMMIT: u8 = 5;
const C_ABORT: u8 = 6;

const S_FREE: u8 = 0;
const S_CLEAN: u8 = 1;
const S_STAGED: u8 = 2;
const S_FETCHING: u8 = 3;

/// One resident extent.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Extent {
    pub state: u8,
    /// Part of the commit in flight: its bytes are being uploaded.
    pub committing: u8,
    pub _pad: [u8; 2],
    /// Recency stamp; the lowest clean one is evicted first.
    pub used: u32,
    pub idx: u64,
    /// FETCHING: the digest the bytes must hash to. Committing: the
    /// digest the store named the staged bytes by.
    pub digest: [u8; DIGEST],
}

/// One resident leaf page of a depth-2 map.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Leaf {
    pub valid: u8,
    pub _pad: [u8; 3],
    pub used: u32,
    pub child: u64,
    pub digest: [u8; DIGEST],
}

/// A leaf the commit in flight replaces, and the digest of its new page.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct LeafNew {
    pub child: u64,
    pub digest: [u8; DIGEST],
}

/// A queued request and how far it has got.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Pending {
    pub used: u8,
    /// 0: waiting on its PREFLUSH; 1: to execute; 2: executed, waiting
    /// for the commit that makes it durable.
    pub stage: u8,
    pub _pad: [u8; 6],
    /// The write generation that must be durable before it completes.
    pub target: u64,
    pub req: Req,
}

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    /// The admin plane: requests out, answers in.
    pub client: super::admin_client::Client,
    /// Where the capability file is, and whether it has been loaded.
    pub cap_path: [u8; CAP_PATH_MAX],
    pub cap_path_len: u16,
    pub cap_loaded: u8,
    /// The gate's authority; empty, the module is a link session.
    pub admin: [u8; super::admin_client::AUTHORITY_MAX],
    pub admin_len: u8,
    /// The link session id.
    pub link_session: u32,
    /// The `storage.block` channel this source answers on.
    pub blocks_chan: i32,
    pub phase: u8,
    /// The admin exchange in flight, `J_*`.
    pub job: u8,
    /// The commit's progress, `C_*`.
    pub commit: u8,
    /// Something waits for everything written so far to be durable.
    pub flush_wanted: u8,
    /// Draining: no new request is admitted; what is staged commits, the
    /// lease is released, and the module reports itself done.
    pub draining: u8,
    pub drained: u8,
    /// Negative errno once the device has failed; every request gets it.
    pub fail: i32,
    pub ready_reported: u8,
    pub fail_reported: u8,
    pub depth: u8,
    pub _pad: u8,
    // ── Parameters ──
    pub block_size: u32,
    pub ttl_ms: u32,
    pub root_len: u16,
    pub path_len: u16,
    pub root: [u8; super::limits::MAX_ROOT],
    pub path: [u8; super::limits::MAX_PATH],
    // ── Lease ──
    pub holder: [u8; aw::LEASE_HOLDER_LEN],
    /// The fence the attach flow bound into its key release, or 0 for none.
    /// A lease acquired under any other fence is not the one the key was
    /// released for.
    pub expect_fence: u64,
    /// A `holder` or `fence` parameter did not parse.
    pub bad_param: u8,
    pub lease_fence: u64,
    /// When the request behind the live grant was sent (local clock). The
    /// server's expiry is at least `ttl_ms` after it.
    pub lease_at: u64,
    // ── Admin exchange ──
    pub next_cid: u32,
    pub job_cid: u32,
    pub job_at: u64,
    pub job_slot: u32,
    pub _pad2: u32,
    pub job_child: u64,
    pub retry_at: u64,
    pub begin_since: u64,
    /// The request built in `io`, and whether the client has taken it.
    pub io_len: u32,
    pub io_sent: u32,
    pub io: [u8; IO_CAP],
    // ── Committed view ──
    pub revision: u64,
    pub root_digest: [u8; DIGEST],
    pub new_root: [u8; DIGEST],
    pub volume_id: [u8; map::VOLUME_ID_LEN],
    /// The identity durable fences name: the volume, at its path.
    pub source: [u8; 16],
    pub device_id: u64,
    pub size_bytes: u64,
    pub extent_size: u32,
    pub extent_shift: u32,
    pub block_shift: u32,
    pub children_count: u32,
    pub block_count: u64,
    pub extent_count: u64,
    pub children: [[u8; DIGEST]; map::PAGE_ENTRIES],
    // ── Extents ──
    pub clock: u32,
    pub staged: u32,
    pub slots: [Extent; EXTENT_SLOTS],
    pub ext: [[u8; EXTENT_CAP]; EXTENT_SLOTS],
    pub leaves: [Leaf; LEAF_SLOTS],
    pub leaf_data: [[[u8; DIGEST]; map::PAGE_ENTRIES]; LEAF_SLOTS],
    pub wants: [u64; WANT_SLOTS],
    pub wants_len: u32,
    // ── Commit ──
    pub commit_cursor: u32,
    pub leaf_new: [LeafNew; STAGED_MAX],
    pub leaf_new_len: u32,
    pub _pad4: u32,
    /// Bumped by every write that changes staged bytes.
    pub write_gen: u64,
    /// The write generation the last commit covered.
    pub durable_gen: u64,
    pub commit_gen: u64,
    // ── Requests ──
    pub pending: [Pending; QUEUE_DEPTH],
    pub done: [Cpl; QUEUE_DEPTH],
    pub done_head: u32,
    pub done_count: u32,
    // ── Counters, readable by a host harness ──
    pub commits: u32,
    pub fetches: u32,
    /// Commits abandoned before their bind, and the admin status that
    /// ended the last one.
    pub abandoned: u32,
    pub abandon_status: u8,
    /// A commit was abandoned and no waiter has been told yet.
    pub refused: u8,
    pub _pad5: [u8; 2],
    // ── Pipelined bodies ──
    /// The PUTs of the commit's extents sent and not yet acknowledged:
    /// their correlation ids and slots, in the order they went out.
    pub pipe_cids: [u32; EXTENT_SLOTS],
    pub pipe_slots: [u8; EXTENT_SLOTS],
    pub pipe_len: u8,
    /// A PUT was refused: send no more, collect what is owed, then abort.
    pub pipe_refused: u8,
    pub _pad6: [u8; 2],
}

/// Longest capability-file path: a string parameter's ceiling.
pub const CAP_PATH_MAX: usize = 255;

// ── Construction ────────────────────────────────────────────────────

/// Zero the state and bind the block channel. The admin transport
/// (`connect_link` / `connect_net`) and the parameters are set after
/// this, and checked on the first step.
pub unsafe fn module_new_impl(
    blocks_chan: i32,
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
    core::ptr::write_bytes(state_ptr, 0u8, core::mem::size_of::<ModuleState>());
    let s = &mut *(state_ptr as *mut ModuleState);
    s.syscalls = syscalls;
    s.blocks_chan = blocks_chan;
    s.block_size = 4096;
    s.ttl_ms = 30_000;
    // A fresh holder per instance: nothing about it is secret, it only
    // has to differ from every other attachment's. Correlation ids start
    // at random too, so instances sharing one admin connection do not
    // collide.
    let mut seed = [0u8; aw::LEASE_HOLDER_LEN + 4];
    let rc = (sys(s).provider_call)(-1, 0x0C3C, seed.as_mut_ptr(), seed.len());
    if rc < 0 {
        s.phase = P_FAILED;
        s.fail = EIO;
    }
    s.holder.copy_from_slice(&seed[..aw::LEASE_HOLDER_LEN]);
    s.next_cid = u32::from_le_bytes([seed[16], seed[17], seed[18], seed[19]]).max(1);
    0
}

/// Set the parameters directly, as the TLV parser does.
pub unsafe fn configure(
    state_ptr: *mut u8,
    root: &[u8],
    path: &[u8],
    ttl_ms: u32,
    block_size: u32,
) {
    let s = &mut *(state_ptr as *mut ModuleState);
    set_root(s, root);
    set_path(s, path);
    s.ttl_ms = ttl_ms;
    s.block_size = block_size;
}

/// Bring up the admin transport the parameters chose: the network
/// through a client-mode `tls` when an `admin` authority is set, else an
/// in-graph link as `link_session`.
pub unsafe fn connect(state_ptr: *mut u8, admin_in: i32, admin_out: i32, tag: u8) {
    let s = &mut *(state_ptr as *mut ModuleState);
    let t = now_ms(s);
    if s.admin_len > 0 {
        let authority: &[u8] = &*(&s.admin[..s.admin_len as usize] as *const [u8]);
        super::admin_client::init_net(&mut s.client, admin_in, admin_out, tag, authority, t);
    } else {
        super::admin_client::init_link(&mut s.client, admin_in, admin_out, s.link_session, t);
    }
}

/// The gate's authority. Longer than the client holds is refused at the
/// first step.
#[allow(
    clippy::manual_memcpy,
    reason = "a slice copy of a runtime length pulls panic paths the PIC link does not carry"
)]
pub fn set_admin(s: &mut ModuleState, v: &[u8]) {
    if v.len() > s.admin.len() {
        s.bad_param = 1;
        return;
    }
    for i in 0..v.len() {
        s.admin[i] = v[i];
    }
    s.admin_len = v.len() as u8;
}

/// The capability file's path. Longer than a parameter can carry is
/// refused at the first step.
#[allow(
    clippy::manual_memcpy,
    reason = "a slice copy of a runtime length pulls panic paths the PIC link does not carry"
)]
pub fn set_capability(s: &mut ModuleState, v: &[u8]) {
    if v.len() > CAP_PATH_MAX {
        s.bad_param = 1;
        return;
    }
    for i in 0..v.len() {
        s.cap_path[i] = v[i];
    }
    s.cap_path_len = v.len() as u16;
}

pub fn set_root(s: &mut ModuleState, v: &[u8]) {
    let n = v.len().min(s.root.len());
    s.root[..n].copy_from_slice(&v[..n]);
    s.root_len = if v.len() > s.root.len() { 0 } else { n as u16 };
}

pub fn set_path(s: &mut ModuleState, v: &[u8]) {
    let n = v.len().min(s.path.len());
    s.path[..n].copy_from_slice(&v[..n]);
    s.path_len = if v.len() > s.path.len() { 0 } else { n as u16 };
}

unsafe fn sys(s: &ModuleState) -> &super::SyscallTable {
    &*s.syscalls
}

unsafe fn now_ms(s: &ModuleState) -> u64 {
    let mut b = [0u8; 8];
    (sys(s).provider_call)(-1, 0x0602, b.as_mut_ptr(), 8);
    u64::from_le_bytes(b)
}

unsafe fn log(s: &ModuleState, level: u8, msg: &[u8]) {
    (sys(s).provider_call)(level as i32, 0x0C40, msg.as_ptr() as *mut u8, msg.len());
}

// ── Geometry ────────────────────────────────────────────────────────

fn extent_len(s: &ModuleState, idx: u64) -> usize {
    let start = idx << s.extent_shift;
    let rest = s.size_bytes.saturating_sub(start);
    rest.min(s.extent_size as u64) as usize
}

fn leaf_len(s: &ModuleState, child: u64) -> usize {
    let first = child << 10;
    let rest = s.extent_count.saturating_sub(first);
    rest.min(map::PAGE_ENTRIES as u64) as usize
}

fn is_zero(b: &[u8]) -> bool {
    let mut acc = 0u8;
    for x in b {
        acc |= *x;
    }
    acc == 0
}

fn caps_of(s: &ModuleState) -> Caps {
    let per = (s.extent_size >> s.block_shift).max(1);
    Caps {
        logical_block_size: s.block_size,
        block_count: s.block_count,
        max_blocks: per,
        // A request is staged whole before any commit can take it, and a
        // commit lands whole or not at all.
        atomic_blocks: per,
        queue_depth: QUEUE_DEPTH as u16,
        flags: blk::caps::F_WRITE | blk::caps::F_FLUSH | blk::caps::F_ASYNC,
        device_id: s.device_id,
    }
}

fn durable_fence(s: &ModuleState) -> Fence {
    Fence::RevisionMonotone {
        source: s.source,
        revision: s.revision,
    }
}

fn with_fence(tag: u64, f: Fence) -> Cpl {
    let mut c = Cpl::bare(tag, 0);
    if let Some(n) = f.encode(&mut c.fence) {
        c.fence_len = n as u16;
    }
    c
}

// ── The admin exchange ─────────────────────────────────────────────

fn take_cid(s: &mut ModuleState) -> u32 {
    let c = s.next_cid;
    s.next_cid = c.wrapping_add(1).max(1);
    s.job_cid = c;
    c
}

/// Start the exchange whose request is `io[..n]`.
unsafe fn issue(s: &mut ModuleState, job: u8, n: usize) {
    s.job = job;
    s.io_len = n as u32;
    s.io_sent = 0;
    s.job_at = now_ms(s);
    hand(s);
}

/// Hand the built request to the client once it can take one.
unsafe fn hand(s: &mut ModuleState) {
    if s.io_sent >= s.io_len {
        return;
    }
    let sys = &*s.syscalls;
    let n = s.io_len as usize;
    let frame: &[u8] = &*(&s.io[..n] as *const [u8]);
    if super::admin_client::send(&mut s.client, sys, frame) {
        s.io_sent = s.io_len;
    }
}

/// Hand over the request, then collect its ack.
unsafe fn pump(s: &mut ModuleState, t: u64) {
    if s.job == J_NONE {
        return;
    }
    if s.job == J_PUT_BODIES {
        bodies_pump(s, t);
        return;
    }
    if s.io_sent < s.io_len {
        hand(s);
        if s.io_sent < s.io_len {
            timeout_check(s, t);
            return;
        }
    }
    match super::admin_client::recv(&mut s.client) {
        Some(ack) => {
            // The ack stays in the client until `take`; nothing below
            // receives another before it has finished reading this one.
            let frame: &[u8] = &*(ack as *const [u8]);
            on_ack(s, t, frame);
            super::admin_client::take(&mut s.client);
        }
        None => timeout_check(s, t),
    }
}

unsafe fn timeout_check(s: &mut ModuleState, t: u64) {
    if t.saturating_sub(s.job_at) > ACK_TIMEOUT_MS {
        // One call per arm: a match yielding the message would lower to a
        // table of absolute pointers, which a PIC module cannot hold.
        match s.job {
            J_ACQUIRE | J_RENEW => fail(s, EIO, b"[loam_volume] the node stopped answering: lease"),
            J_LOOKUP | J_ROOT | J_LEAF | J_EXTENT => {
                fail(s, EIO, b"[loam_volume] the node stopped answering: fetch")
            }
            J_PUT_BODIES | J_PUT_LEAF | J_PUT_ROOT => {
                fail(s, EIO, b"[loam_volume] the node stopped answering: put")
            }
            _ => fail(s, EIO, b"[loam_volume] the node stopped answering: commit"),
        }
    }
}

/// The commit's extent bodies: each committing extent's PUT is sent as
/// soon as the one before it has gone out, and the acks are matched by
/// correlation id as they arrive, so the round trips overlap instead of
/// adding up. Once every PUT is sent and acknowledged the commit moves on
/// to its map pages. A refusal stops the sending, and the commit aborts
/// once nothing it sent is still owed an answer: an ack left in flight
/// would otherwise arrive in the middle of the next exchange.
unsafe fn bodies_pump(s: &mut ModuleState, t: u64) {
    // Send: finish the PUT in hand, then start the next.
    while s.pipe_refused == 0 {
        if s.io_sent < s.io_len {
            hand(s);
            if s.io_sent < s.io_len {
                break;
            }
        }
        let Some(i) = next_body(s) else {
            break;
        };
        let len = extent_len(s, s.slots[i].idx).min(EXTENT_CAP);
        let cid = take_cid(s);
        let Ok(h) = aw::encode_admin_put_body_header(&mut s.io, cid, len) else {
            s.pipe_refused = 1;
            break;
        };
        s.io[h..h + len].copy_from_slice(&s.ext[i][..len]);
        let k = s.pipe_len as usize;
        s.pipe_cids[k] = cid;
        s.pipe_slots[k] = i as u8;
        s.pipe_len += 1;
        s.commit_cursor += 1;
        s.io_len = (h + len) as u32;
        s.io_sent = 0;
        hand(s);
    }
    // Receive: every whole ack in hand.
    while let Some(ack) = super::admin_client::recv(&mut s.client) {
        let frame: &[u8] = &*(ack as *const [u8]);
        let cid = cid_of(frame);
        let mut found = None;
        for k in 0..s.pipe_len as usize {
            if s.pipe_cids[k] == cid {
                found = Some(k);
                break;
            }
        }
        let Some(k) = found else {
            fail(s, EIO, b"[loam_volume] ack for another request");
            return;
        };
        let slot = s.pipe_slots[k] as usize;
        match aw::decode_admin_put_body_ack(frame) {
            Ok(a) if a.status == aw::STATUS_OK && a.digest.is_some_and(|d| d.len() == DIGEST) => {
                if let Some(d) = a.digest {
                    s.slots[slot].digest.copy_from_slice(d);
                }
            }
            Ok(a) => {
                if s.pipe_refused == 0 {
                    s.abandon_status = a.status;
                }
                s.pipe_refused = 1;
            }
            Err(_) => s.pipe_refused = 1,
        }
        super::admin_client::take(&mut s.client);
        // Drop the answered entry.
        let len = s.pipe_len as usize;
        for j in k..len - 1 {
            s.pipe_cids[j] = s.pipe_cids[j + 1];
            s.pipe_slots[j] = s.pipe_slots[j + 1];
        }
        s.pipe_len -= 1;
        s.job_at = t;
    }
    let sent_all = s.pipe_refused != 0 || (s.io_sent >= s.io_len && next_body_ahead(s).is_none());
    if sent_all && s.pipe_len == 0 {
        s.job = J_NONE;
        s.io_len = 0;
        s.io_sent = 0;
        if s.pipe_refused != 0 {
            begin_abort(s);
            return;
        }
        s.commit_cursor = 0;
        s.leaf_new_len = 0;
        s.commit = if s.depth == 2 { C_LEAVES } else { C_ROOT };
        return;
    }
    timeout_check(s, t);
}

/// The next committing extent to PUT, from `commit_cursor` on. An all-zero
/// extent is never stored (it reads as the zero digest) and is passed over.
/// `None` once every one has been sent.
fn next_body(s: &mut ModuleState) -> Option<usize> {
    while (s.commit_cursor as usize) < EXTENT_SLOTS {
        let i = s.commit_cursor as usize;
        if s.slots[i].committing == 0 {
            s.commit_cursor += 1;
            continue;
        }
        let len = extent_len(s, s.slots[i].idx).min(EXTENT_CAP);
        if is_zero(&s.ext[i][..len]) {
            s.slots[i].digest = map::ZERO_DIGEST;
            s.commit_cursor += 1;
            continue;
        }
        return Some(i);
    }
    None
}

/// Whether a committing extent is still to be sent, without moving on.
fn next_body_ahead(s: &ModuleState) -> Option<usize> {
    (s.commit_cursor as usize..EXTENT_SLOTS).find(|&i| s.slots[i].committing != 0)
}

fn cid_of(frame: &[u8]) -> u32 {
    if frame.len() < 5 {
        return 0;
    }
    u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]])
}

/// Handle the complete ack `frame`.
unsafe fn on_ack(s: &mut ModuleState, t: u64, frame: &[u8]) {
    let job = s.job;
    s.job = J_NONE;
    s.io_len = 0;
    s.io_sent = 0;
    if cid_of(frame) != s.job_cid {
        fail(s, EIO, b"[loam_volume] ack for another request");
        return;
    }
    match job {
        J_ACQUIRE | J_RENEW => on_lease(s, t, job, frame),
        J_LOOKUP => on_lookup(s, frame),
        J_ROOT => on_root(s, frame),
        J_LEAF => on_leaf(s, frame),
        J_EXTENT => on_extent(s, frame),
        J_BEGIN | J_COMMIT | J_ABORT => on_volume(s, t, job, frame),
        J_PUT_LEAF | J_PUT_ROOT => on_put(s, job, frame),
        // Released or not, the writer is done with the volume: a lease it
        // could not release lapses at its TTL.
        J_RELEASE => s.drained = 1,
        _ => fail(s, EIO, b"[loam_volume] ack with nothing in flight"),
    }
}

// ── Open ───────────────────────────────────────────────────────────

fn open_error(s: &ModuleState) -> i32 {
    let bs = s.block_size;
    if s.root_len == 0 || s.path_len == 0 || s.bad_param != 0 {
        return EINVAL;
    }
    if bs < 512 || !bs.is_power_of_two() || bs as usize > EXTENT_CAP {
        return EINVAL;
    }
    if s.ttl_ms < TTL_MIN_MS || s.ttl_ms > super::limits::LEASE_TTL_MAX_MS {
        return EINVAL;
    }
    0
}

unsafe fn on_lease(s: &mut ModuleState, t: u64, job: u8, frame: &[u8]) {
    let Ok((_, status, fence, _)) = aw::decode_admin_lease_ack(frame) else {
        fail(s, EIO, b"[loam_volume] lease ack does not decode");
        return;
    };
    match (job, status) {
        (J_ACQUIRE, aw::STATUS_OK) if s.expect_fence != 0 && fence != s.expect_fence => fail(
            s,
            EACCES,
            b"[loam_volume] the lease is not under the fence the key was released for",
        ),
        (J_ACQUIRE, aw::STATUS_OK) => {
            s.lease_fence = fence;
            s.lease_at = s.job_at;
            s.phase = P_LOOKUP;
        }
        (J_RENEW, aw::STATUS_OK) if fence == s.lease_fence => s.lease_at = s.job_at,
        (J_ACQUIRE, aw::STATUS_LEASE_HELD) => {
            fail(s, EBUSY, b"[loam_volume] the volume has another writer")
        }
        (J_ACQUIRE, aw::STATUS_BUSY) => s.retry_at = t + ACQUIRE_RETRY_MS,
        // A renew refused busy is asked again next step; the deadline
        // decides whether it came in time.
        (J_RENEW, aw::STATUS_BUSY) => {}
        (_, aw::STATUS_FORBIDDEN) => fail(s, EACCES, b"[loam_volume] no grant for the volume"),
        _ => fail(s, EIO, b"[loam_volume] writer lease lost"),
    }
}

unsafe fn on_lookup(s: &mut ModuleState, frame: &[u8]) {
    let Ok((_, status, binding)) = aw::decode_admin_lookup_ack(frame) else {
        fail(s, EIO, b"[loam_volume] lookup ack does not decode");
        return;
    };
    match (status, binding) {
        (aw::STATUS_OK, Some(b)) if b.kind == KIND_VOLUME => match digest_of_oid(b.object_id) {
            Some(d) => {
                s.root_digest = d;
                s.revision = b.revision;
                s.phase = P_ROOT;
            }
            None => fail(s, EIO, b"[loam_volume] volume binding names no digest"),
        },
        (aw::STATUS_OK, _) => fail(s, EINVAL, b"[loam_volume] the path is not a volume"),
        (aw::STATUS_NOT_FOUND, _) => fail(s, ENOENT, b"[loam_volume] no volume at the path"),
        (aw::STATUS_FORBIDDEN, _) => fail(s, EACCES, b"[loam_volume] no grant for the volume"),
        _ => fail(s, EIO, b"[loam_volume] lookup refused"),
    }
}

/// The body digest of a volume's object id, `sha256:<64 lowercase hex>`.
fn digest_of_oid(oid: &[u8]) -> Option<[u8; DIGEST]> {
    if oid.len() != 7 + 2 * DIGEST || &oid[..7] != b"sha256:" {
        return None;
    }
    let mut out = [0u8; DIGEST];
    for i in 0..DIGEST {
        let hi = nibble(oid[7 + 2 * i])?;
        let lo = nibble(oid[8 + 2 * i])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + n - 10
    }
}

fn sha(bytes: &[u8]) -> [u8; DIGEST] {
    let mut h = super::sha256::Sha256::new();
    h.update(bytes);
    h.finalize()
}

/// The body of an OK GET_BODY ack, `None` otherwise; `Err` when it names
/// a missing body.
fn got_body(frame: &[u8]) -> Result<Option<&[u8]>, ()> {
    match aw::decode_admin_get_body_ack(frame) {
        Ok((_, aw::STATUS_OK, Some(b))) => Ok(Some(b)),
        Ok((_, aw::STATUS_NOT_FOUND, _)) => Err(()),
        _ => Ok(None),
    }
}

unsafe fn on_root(s: &mut ModuleState, frame: &[u8]) {
    let page = match got_body(frame) {
        Ok(Some(p)) => p,
        _ => {
            fail(
                s,
                EIO,
                b"[loam_volume] the committed map root is unreadable",
            );
            return;
        }
    };
    if sha(page) != s.root_digest {
        fail(s, EIO, b"[loam_volume] map root does not match its digest");
        return;
    }
    let Ok(root) = map::decode_root(page) else {
        fail(s, EIO, b"[loam_volume] map root does not decode");
        return;
    };
    let es = root.extent_size;
    if !es.is_power_of_two() || es as usize > EXTENT_CAP || es < s.block_size {
        fail(s, EINVAL, b"[loam_volume] extent size unsupported here");
        return;
    }
    let count = root.count();
    if count > map::PAGE_ENTRIES {
        fail(s, EIO, b"[loam_volume] map root too wide");
        return;
    }
    for i in 0..count {
        s.children[i] = root.child(i).unwrap_or(map::ZERO_DIGEST);
    }
    s.children_count = count as u32;
    s.volume_id = root.volume_id;
    s.size_bytes = root.size_bytes;
    s.extent_size = es;
    s.extent_shift = es.trailing_zeros();
    s.block_shift = s.block_size.trailing_zeros();
    s.depth = root.depth;
    s.block_count = root.size_bytes >> s.block_shift;
    s.extent_count = (root.size_bytes + (es as u64 - 1)) >> s.extent_shift;
    if s.block_count == 0 {
        fail(s, EINVAL, b"[loam_volume] volume smaller than one block");
        return;
    }
    let mut h = super::sha256::Sha256::new();
    h.update(SOURCE_DOMAIN);
    h.update(&s.volume_id);
    h.update(&s.root_len.to_le_bytes());
    h.update(&s.root[..s.root_len as usize]);
    h.update(&s.path[..s.path_len as usize]);
    let d = h.finalize();
    s.source.copy_from_slice(&d[..16]);
    s.device_id = u64::from_le_bytes(d[..8].try_into().unwrap_or([0; 8]));
    s.phase = P_READY;
}

// ── Reads through the map ──────────────────────────────────────────

fn find_extent(s: &ModuleState, idx: u64) -> Option<usize> {
    for i in 0..EXTENT_SLOTS {
        let e = &s.slots[i];
        if (e.state == S_CLEAN || e.state == S_STAGED) && e.idx == idx {
            return Some(i);
        }
    }
    None
}

fn fetching(s: &ModuleState, idx: u64) -> bool {
    for i in 0..EXTENT_SLOTS {
        if s.slots[i].state == S_FETCHING && s.slots[i].idx == idx {
            return true;
        }
    }
    false
}

/// A free slot, or the least recently used clean one not in `keep`.
fn alloc_slot(s: &ModuleState, keep: &[usize]) -> Option<usize> {
    let mut best: Option<usize> = None;
    for i in 0..EXTENT_SLOTS {
        if keep.contains(&i) {
            continue;
        }
        match s.slots[i].state {
            S_FREE => return Some(i),
            S_CLEAN => {
                let older = match best {
                    Some(b) => s.slots[i].used < s.slots[b].used,
                    None => true,
                };
                if older {
                    best = Some(i);
                }
            }
            _ => {}
        }
    }
    best
}

fn touch(s: &mut ModuleState, i: usize) {
    s.clock = s.clock.wrapping_add(1);
    s.slots[i].used = s.clock;
}

fn want(s: &mut ModuleState, idx: u64) {
    let n = s.wants_len as usize;
    for i in 0..n.min(WANT_SLOTS) {
        if s.wants[i] == idx {
            return;
        }
    }
    if n < WANT_SLOTS {
        s.wants[n] = idx;
        s.wants_len += 1;
    }
}

fn drop_want(s: &mut ModuleState, at: usize) {
    let n = (s.wants_len as usize).min(WANT_SLOTS);
    if at >= n {
        return;
    }
    for i in at..n - 1 {
        s.wants[i] = s.wants[i + 1];
    }
    s.wants_len = (n - 1) as u32;
}

fn leaf_find(s: &ModuleState, child: u64) -> Option<usize> {
    let digest = s.children.get(child as usize)?;
    for k in 0..LEAF_SLOTS {
        let l = &s.leaves[k];
        if l.valid != 0 && l.child == child && &l.digest == digest {
            return Some(k);
        }
    }
    None
}

fn leaf_claim(s: &mut ModuleState) -> usize {
    let mut best = 0usize;
    for k in 0..LEAF_SLOTS {
        if s.leaves[k].valid == 0 {
            return k;
        }
        if s.leaves[k].used < s.leaves[best].used {
            best = k;
        }
    }
    best
}

/// Make leaf `child` resident, or ask for it. `Some(slot)` when it is.
unsafe fn leaf_ready(s: &mut ModuleState, child: u64) -> Option<usize> {
    if let Some(k) = leaf_find(s, child) {
        s.clock = s.clock.wrapping_add(1);
        s.leaves[k].used = s.clock;
        return Some(k);
    }
    let digest = *s.children.get(child as usize)?;
    let k = leaf_claim(s);
    if digest == map::ZERO_DIGEST {
        // A never-written leaf is all zero digests, and is no body.
        s.leaf_data[k] = [map::ZERO_DIGEST; map::PAGE_ENTRIES];
        s.leaves[k] = Leaf {
            valid: 1,
            _pad: [0; 3],
            used: s.clock,
            child,
            digest,
        };
        return Some(k);
    }
    s.leaves[k].valid = 0;
    s.job_slot = k as u32;
    s.job_child = child;
    let cid = take_cid(s);
    match aw::encode_admin_get_body(&mut s.io, cid, &digest) {
        Ok(n) => issue(s, J_LEAF, n),
        Err(_) => fail(s, EIO, b"[loam_volume] leaf request does not encode"),
    }
    None
}

unsafe fn on_leaf(s: &mut ModuleState, frame: &[u8]) {
    let page = match got_body(frame) {
        Ok(Some(p)) => p,
        _ => {
            fail(s, EIO, b"[loam_volume] a committed leaf page is unreadable");
            return;
        }
    };
    let child = s.job_child;
    let k = s.job_slot as usize;
    let Some(want_digest) = s.children.get(child as usize).copied() else {
        fail(s, EIO, b"[loam_volume] leaf past the map");
        return;
    };
    if k >= LEAF_SLOTS || sha(page) != want_digest {
        fail(s, EIO, b"[loam_volume] leaf page does not match its digest");
        return;
    }
    let Ok(leaf) = map::decode_leaf(page) else {
        fail(s, EIO, b"[loam_volume] leaf page does not decode");
        return;
    };
    if !map::leaf_fits(&leaf, child, s.size_bytes, s.extent_size) {
        fail(s, EIO, b"[loam_volume] leaf page does not fit the map");
        return;
    }
    let count = leaf.count().min(map::PAGE_ENTRIES);
    for i in 0..map::PAGE_ENTRIES {
        s.leaf_data[k][i] = if i < count {
            leaf.digest(i).unwrap_or(map::ZERO_DIGEST)
        } else {
            map::ZERO_DIGEST
        };
    }
    s.clock = s.clock.wrapping_add(1);
    s.leaves[k] = Leaf {
        valid: 1,
        _pad: [0; 3],
        used: s.clock,
        child,
        digest: want_digest,
    };
}

/// Fetch the first wanted extent, one exchange at a time.
unsafe fn fetch_next(s: &mut ModuleState) {
    let mut rounds = 0;
    while s.wants_len > 0 && rounds < WANT_SLOTS {
        rounds += 1;
        let idx = s.wants[0];
        if idx >= s.extent_count || find_extent(s, idx).is_some() || fetching(s, idx) {
            drop_want(s, 0);
            continue;
        }
        let digest = if s.depth == 1 {
            match s.children.get(idx as usize) {
                Some(d) => *d,
                None => {
                    drop_want(s, 0);
                    continue;
                }
            }
        } else {
            let Some(k) = leaf_ready(s, idx >> 10) else {
                return;
            };
            s.leaf_data[k][(idx & 1023) as usize]
        };
        let Some(i) = alloc_slot(s, &[]) else {
            // Every slot is staged: a commit frees them.
            s.flush_wanted = 1;
            return;
        };
        s.slots[i].idx = idx;
        s.slots[i].committing = 0;
        s.slots[i].digest = digest;
        if digest == map::ZERO_DIGEST {
            s.ext[i].fill(0);
            s.slots[i].state = S_CLEAN;
            touch(s, i);
            drop_want(s, 0);
            continue;
        }
        s.slots[i].state = S_FETCHING;
        s.job_slot = i as u32;
        let cid = take_cid(s);
        match aw::encode_admin_get_body(&mut s.io, cid, &digest) {
            Ok(n) => issue(s, J_EXTENT, n),
            Err(_) => fail(s, EIO, b"[loam_volume] extent request does not encode"),
        }
        return;
    }
}

unsafe fn on_extent(s: &mut ModuleState, frame: &[u8]) {
    let i = s.job_slot as usize;
    if i >= EXTENT_SLOTS || s.slots[i].state != S_FETCHING {
        fail(s, EIO, b"[loam_volume] extent ack for no slot");
        return;
    }
    let body = match got_body(frame) {
        Ok(Some(b)) => b,
        _ => {
            fail(s, EIO, b"[loam_volume] a committed extent is unreadable");
            return;
        }
    };
    let len = extent_len(s, s.slots[i].idx);
    if body.len() > len || sha(body) != s.slots[i].digest {
        fail(s, EIO, b"[loam_volume] extent does not match its digest");
        return;
    }
    s.ext[i][..body.len()].copy_from_slice(body);
    s.ext[i][body.len()..].fill(0);
    s.slots[i].state = S_CLEAN;
    s.fetches = s.fetches.wrapping_add(1);
    touch(s, i);
    let idx = s.slots[i].idx;
    for w in 0..(s.wants_len as usize).min(WANT_SLOTS) {
        if s.wants[w] == idx {
            drop_want(s, w);
            break;
        }
    }
}

// ── Request execution ──────────────────────────────────────────────

/// One extent a request touches: which, where in it, and how much.
#[derive(Clone, Copy)]
struct Span {
    idx: u64,
    in_ext: usize,
    take: usize,
    off: usize,
}

/// Split `r`'s byte range at extent boundaries. A request is at most one
/// extent long, so it touches at most two.
fn spans(s: &ModuleState, r: &Req, out: &mut [Span; 2]) -> usize {
    let start = r.lba << s.block_shift;
    let len = r.buf_len as u64;
    let es = s.extent_size as u64;
    let mut n = 0usize;
    let mut done = 0u64;
    while done < len && n < 2 {
        let pos = start + done;
        let idx = pos >> s.extent_shift;
        let in_ext = (pos & (es - 1)) as usize;
        let take = (es - in_ext as u64).min(len - done) as usize;
        out[n] = Span {
            idx,
            in_ext,
            take,
            off: done as usize,
        };
        n += 1;
        done += take as u64;
    }
    n
}

/// Copy a read out of resident extents, or ask for the missing ones.
unsafe fn read_now(s: &mut ModuleState, r: &Req) -> bool {
    let mut sp = [Span {
        idx: 0,
        in_ext: 0,
        take: 0,
        off: 0,
    }; 2];
    let n = spans(s, r, &mut sp);
    let mut missing = false;
    for p in sp.iter().take(n) {
        if find_extent(s, p.idx).is_none() {
            want(s, p.idx);
            missing = true;
        }
    }
    if missing {
        return false;
    }
    for p in sp.iter().take(n) {
        if let Some(i) = find_extent(s, p.idx) {
            core::ptr::copy_nonoverlapping(
                s.ext[i].as_ptr().add(p.in_ext),
                (r.buf_ptr as *mut u8).add(p.off),
                p.take,
            );
            touch(s, i);
        }
    }
    true
}

/// Staged.
const W_DONE: u8 = 0;
/// Waiting for an extent to be fetched, or for the commit in flight.
const W_WAIT: u8 = 1;
/// Waiting for a commit to make room.
const W_ROOM: u8 = 2;

/// Stage a write, or say why it must wait. Whole or not at all: every
/// extent it touches is checked before any byte moves.
unsafe fn write_now(s: &mut ModuleState, r: &Req) -> u8 {
    if s.commit != C_IDLE {
        return W_WAIT;
    }
    let mut sp = [Span {
        idx: 0,
        in_ext: 0,
        take: 0,
        off: 0,
    }; 2];
    let n = spans(s, r, &mut sp);
    let src = r.buf_ptr as *const u8;
    let mut resident = [usize::MAX; 2];
    let mut new_staged = 0usize;
    let mut new_slots = 0usize;
    let mut missing = false;
    for k in 0..n {
        let p = sp[k];
        match find_extent(s, p.idx) {
            Some(i) => {
                resident[k] = i;
                let cur = &s.ext[i][p.in_ext..p.in_ext + p.take];
                let data = core::slice::from_raw_parts(src.add(p.off), p.take);
                if cur != data && s.slots[i].state == S_CLEAN {
                    new_staged += 1;
                }
            }
            None => {
                if p.in_ext == 0 && p.take == extent_len(s, p.idx) {
                    new_staged += 1;
                    new_slots += 1;
                } else {
                    want(s, p.idx);
                    missing = true;
                }
            }
        }
    }
    if missing {
        return W_WAIT;
    }
    if s.staged as usize + new_staged > STAGED_MAX {
        s.flush_wanted = 1;
        return W_ROOM;
    }
    let keep = [resident[0], resident[1]];
    let mut free = 0usize;
    for i in 0..EXTENT_SLOTS {
        if !keep.contains(&i) && (s.slots[i].state == S_FREE || s.slots[i].state == S_CLEAN) {
            free += 1;
        }
    }
    if free < new_slots {
        s.flush_wanted = 1;
        return W_ROOM;
    }
    let mut changed = false;
    for k in 0..n {
        let p = sp[k];
        let i = resident[k];
        if i == usize::MAX {
            continue;
        }
        let data = core::slice::from_raw_parts(src.add(p.off), p.take);
        if &s.ext[i][p.in_ext..p.in_ext + p.take] != data {
            s.ext[i][p.in_ext..p.in_ext + p.take].copy_from_slice(data);
            if s.slots[i].state == S_CLEAN {
                s.slots[i].state = S_STAGED;
                s.staged += 1;
            }
            changed = true;
        }
        touch(s, i);
    }
    for k in 0..n {
        if resident[k] != usize::MAX {
            continue;
        }
        let p = sp[k];
        let Some(i) = alloc_slot(s, &keep) else {
            // Counted free above; unreachable, but never write blind.
            s.flush_wanted = 1;
            return W_ROOM;
        };
        let data = core::slice::from_raw_parts(src.add(p.off), p.take);
        s.ext[i][..p.take].copy_from_slice(data);
        s.ext[i][p.take..].fill(0);
        s.slots[i].state = S_STAGED;
        s.slots[i].committing = 0;
        s.slots[i].idx = p.idx;
        s.staged += 1;
        touch(s, i);
        changed = true;
    }
    if changed {
        s.write_gen += 1;
    }
    W_DONE
}

/// Advance `r` as far as it can go now. `Some` is its completion.
unsafe fn run(s: &mut ModuleState, r: &Req, stage: &mut u8, target: &mut u64) -> Option<Cpl> {
    if s.phase == P_FAILED {
        return Some(Cpl::bare(r.tag, s.fail));
    }
    if *stage == 0 {
        if r.flags & blk::F_PREFLUSH != 0 && s.durable_gen < *target {
            return commit_wait(s, r.tag);
        }
        *stage = 1;
    }
    if *stage == 1 {
        match r.op {
            blk::op::READ => {
                return if read_now(s, r) {
                    Some(Cpl::bare(r.tag, 0))
                } else {
                    None
                };
            }
            blk::op::WRITE => {
                match write_now(s, r) {
                    W_DONE => {}
                    W_ROOM => return commit_wait(s, r.tag),
                    _ => return None,
                }
                if r.flags & blk::F_FUA == 0 {
                    return Some(with_fence(r.tag, Fence::Volatile));
                }
                *target = s.write_gen;
            }
            blk::op::FLUSH => {}
            _ => return Some(Cpl::bare(r.tag, EINVAL)),
        }
        *stage = 2;
    }
    if s.durable_gen >= *target {
        Some(with_fence(r.tag, durable_fence(s)))
    } else {
        commit_wait(s, r.tag)
    }
}

/// Wait for a commit — unless the last one was abandoned and nobody has
/// been told. The first request to ask gets `EIO`, so a consumer that
/// retries in `EXEC` hears the store's refusal instead of `EAGAIN`
/// forever; its retry then starts a fresh commit.
fn commit_wait(s: &mut ModuleState, tag: u64) -> Option<Cpl> {
    if s.refused != 0 {
        s.refused = 0;
        return Some(Cpl::bare(tag, EIO));
    }
    s.flush_wanted = 1;
    None
}

fn push_done(s: &mut ModuleState, c: Cpl) {
    if s.done_count as usize >= QUEUE_DEPTH {
        return;
    }
    let tail = (s.done_head as usize + s.done_count as usize) & (QUEUE_DEPTH - 1);
    s.done[tail] = c;
    s.done_count += 1;
}

fn queued(s: &ModuleState) -> usize {
    let mut n = s.done_count as usize;
    for p in s.pending.iter() {
        if p.used != 0 {
            n += 1;
        }
    }
    n
}

/// Step every queued request as far as it goes.
unsafe fn service(s: &mut ModuleState) {
    for i in 0..QUEUE_DEPTH {
        if s.pending[i].used == 0 {
            continue;
        }
        let mut p = s.pending[i];
        match run(s, &p.req, &mut p.stage, &mut p.target) {
            Some(c) => {
                s.pending[i].used = 0;
                push_done(s, c);
            }
            None => s.pending[i] = p,
        }
    }
}

/// Fail every flush-bound request the commit that just gave up was to
/// cover. Their writes stay staged for the next commit.
fn fail_waiters(s: &mut ModuleState) {
    for i in 0..QUEUE_DEPTH {
        let p = s.pending[i];
        if p.used == 0 || s.durable_gen >= p.target {
            continue;
        }
        let bound = p.stage == 2 || (p.stage == 0 && p.req.flags & blk::F_PREFLUSH != 0);
        if bound {
            s.pending[i].used = 0;
            push_done(s, Cpl::bare(p.req.tag, EIO));
            s.refused = 0;
        }
    }
}

// ── The commit ─────────────────────────────────────────────────────

unsafe fn commit_next(s: &mut ModuleState, t: u64) {
    match s.commit {
        C_BEGIN => {
            if t < s.retry_at {
                return;
            }
            issue_volume(s, J_BEGIN, aw::VOLUME_BEGIN, 0, false);
        }
        C_BODIES => {
            s.job = J_PUT_BODIES;
            s.job_at = t;
            s.io_len = 0;
            s.io_sent = 0;
            s.pipe_len = 0;
            s.pipe_refused = 0;
            bodies_pump(s, t);
        }
        C_LEAVES => {
            while (s.commit_cursor as usize) < EXTENT_SLOTS {
                let i = s.commit_cursor as usize;
                if s.slots[i].committing == 0 || leaf_done(s, s.slots[i].idx >> 10) {
                    s.commit_cursor += 1;
                    continue;
                }
                let child = s.slots[i].idx >> 10;
                let Some(k) = leaf_ready(s, child) else {
                    // Fetching the base page; resumed on its ack.
                    return;
                };
                let count = leaf_len(s, child);
                let cid = take_cid(s);
                let body = map::LEAF_HDR + count * DIGEST;
                let Ok(h) = aw::encode_admin_put_body_header(&mut s.io, cid, body) else {
                    begin_abort(s);
                    return;
                };
                if map::encode_leaf(&mut s.io[h..], child << 10, &s.leaf_data[k][..count]).is_err()
                {
                    begin_abort(s);
                    return;
                }
                // The staged extents of this leaf, over its committed page.
                for j in 0..EXTENT_SLOTS {
                    let e = s.slots[j];
                    if e.committing != 0 && e.idx >> 10 == child {
                        let at = h + map::LEAF_HDR + ((e.idx & 1023) as usize) * DIGEST;
                        s.io[at..at + DIGEST].copy_from_slice(&e.digest);
                    }
                }
                if is_zero(&s.io[h + map::LEAF_HDR..h + body]) {
                    leaf_new(s, child, map::ZERO_DIGEST);
                    s.commit_cursor += 1;
                    continue;
                }
                s.job_child = child;
                issue(s, J_PUT_LEAF, h + body);
                return;
            }
            s.commit = C_ROOT;
        }
        C_ROOT => {
            let count = (s.children_count as usize).min(map::PAGE_ENTRIES);
            let body = map::ROOT_HDR + count * DIGEST;
            let cid = take_cid(s);
            let Ok(h) = aw::encode_admin_put_body_header(&mut s.io, cid, body) else {
                begin_abort(s);
                return;
            };
            if map::encode_root(
                &mut s.io[h..],
                &s.volume_id,
                s.size_bytes,
                s.extent_size,
                &s.children[..count],
            )
            .is_err()
            {
                begin_abort(s);
                return;
            }
            if s.depth == 1 {
                for j in 0..EXTENT_SLOTS {
                    let e = s.slots[j];
                    if e.committing != 0 && (e.idx as usize) < count {
                        let at = h + map::ROOT_HDR + e.idx as usize * DIGEST;
                        s.io[at..at + DIGEST].copy_from_slice(&e.digest);
                    }
                }
            } else {
                for j in 0..(s.leaf_new_len as usize).min(STAGED_MAX) {
                    let l = s.leaf_new[j];
                    if (l.child as usize) < count {
                        let at = h + map::ROOT_HDR + l.child as usize * DIGEST;
                        s.io[at..at + DIGEST].copy_from_slice(&l.digest);
                    }
                }
            }
            issue(s, J_PUT_ROOT, h + body);
        }
        C_COMMIT => {
            let expected = s.revision;
            issue_volume(s, J_COMMIT, aw::VOLUME_COMMIT, expected, true);
        }
        C_ABORT => issue_volume(s, J_ABORT, aw::VOLUME_ABORT, 0, false),
        _ => {}
    }
}

fn leaf_done(s: &ModuleState, child: u64) -> bool {
    for j in 0..(s.leaf_new_len as usize).min(STAGED_MAX) {
        if s.leaf_new[j].child == child {
            return true;
        }
    }
    false
}

fn leaf_new(s: &mut ModuleState, child: u64, digest: [u8; DIGEST]) {
    let n = s.leaf_new_len as usize;
    if n < STAGED_MAX {
        s.leaf_new[n] = LeafNew { child, digest };
        s.leaf_new_len += 1;
    }
}

unsafe fn issue_volume(s: &mut ModuleState, job: u8, mode: u8, expected: u64, with_root: bool) {
    let mut oid = [0u8; 7 + 2 * DIGEST];
    oid[..7].copy_from_slice(b"sha256:");
    for i in 0..DIGEST {
        oid[7 + 2 * i] = hex_digit(s.new_root[i] >> 4);
        oid[8 + 2 * i] = hex_digit(s.new_root[i] & 0x0f);
    }
    let cid = take_cid(s);
    let rl = s.root_len as usize;
    let pl = s.path_len as usize;
    let req = aw::DecodedAdminVolume {
        correlation_id: cid,
        mode,
        namespace_root: &s.root[..rl],
        path: &s.path[..pl],
        object_id: if with_root { &oid[..] } else { &[] },
        holder: s.holder,
        fence: s.lease_fence,
        expected,
    };
    match aw::encode_admin_volume(&mut s.io, &req) {
        Ok(n) => issue(s, job, n),
        Err(_) => fail(s, EIO, b"[loam_volume] volume request does not encode"),
    }
}

unsafe fn on_put(s: &mut ModuleState, job: u8, frame: &[u8]) {
    let digest = match aw::decode_admin_put_body_ack(frame) {
        Ok(a) if a.status != aw::STATUS_OK => {
            s.abandon_status = a.status;
            begin_abort(s);
            return;
        }
        Ok(a) => match a.digest {
            Some(d) if d.len() == DIGEST => {
                let mut out = [0u8; DIGEST];
                out.copy_from_slice(d);
                out
            }
            _ => {
                begin_abort(s);
                return;
            }
        },
        _ => {
            begin_abort(s);
            return;
        }
    };
    match job {
        J_PUT_LEAF => {
            let child = s.job_child;
            leaf_new(s, child, digest);
            s.commit_cursor += 1;
        }
        _ => {
            s.new_root = digest;
            s.commit = C_COMMIT;
        }
    }
}

unsafe fn on_volume(s: &mut ModuleState, t: u64, job: u8, frame: &[u8]) {
    let Ok((_, status, revision)) = aw::decode_admin_volume_ack(frame) else {
        fail(s, EIO, b"[loam_volume] volume ack does not decode");
        return;
    };
    match (job, status) {
        (J_BEGIN, aw::STATUS_OK) => {
            for i in 0..EXTENT_SLOTS {
                if s.slots[i].state == S_STAGED {
                    s.slots[i].committing = 1;
                }
            }
            s.commit_gen = s.write_gen;
            s.commit_cursor = 0;
            s.commit = C_BODIES;
        }
        (J_BEGIN, aw::STATUS_BUSY) => {
            if t.saturating_sub(s.begin_since) > BEGIN_PATIENCE_MS {
                s.abandon_status = aw::STATUS_BUSY;
                give_up(s);
            } else {
                s.retry_at = t + RETRY_MS;
            }
        }
        (J_BEGIN, aw::STATUS_LEASE_LOST) => fail(s, EIO, b"[loam_volume] writer lease lost"),
        (J_BEGIN, st) => {
            s.abandon_status = st;
            give_up(s)
        }
        (J_COMMIT, aw::STATUS_OK) => apply(s, revision),
        // Another commit landed, or the lease passed on: this writer's
        // view is no longer the volume, and writing over what it has not
        // read is the corruption the commit exists to refuse.
        (J_COMMIT, _) => fail(s, EIO, b"[loam_volume] commit refused; device closed"),
        _ => give_up(s),
    }
}

/// A commit that cannot finish after BEGIN: close the open flush first,
/// so the GC is not held off until the next one.
fn begin_abort(s: &mut ModuleState) {
    s.commit = C_ABORT;
}

/// The commit is abandoned; its writes stay staged. The waiter that asks
/// next hears EIO; the log says what the node answered, at the 1st, 2nd,
/// 4th, … abandon, so a store that keeps refusing cannot flood it.
unsafe fn give_up(s: &mut ModuleState) {
    s.abandoned = s.abandoned.wrapping_add(1);
    // One call per arm: a value-yielding branch over the messages could
    // lower to a table of absolute pointers, which a PIC module cannot hold.
    if s.abandoned.is_power_of_two() && s.abandon_status == 0 {
        log(
            s,
            2,
            b"[loam_volume] commit abandoned before the node answered: a request did not encode; the writes stay staged",
        );
    } else if s.abandoned.is_power_of_two() {
        let mut m = *b"[loam_volume] commit abandoned: the node answered status 000; the writes stay staged";
        let at = m.iter().position(|&b| b == b'0').unwrap_or(0);
        let st = s.abandon_status;
        m[at] = b'0' + st / 100;
        m[at + 1] = b'0' + st / 10 % 10;
        m[at + 2] = b'0' + st % 10;
        log(s, 2, &m);
    }
    s.refused = 1;
    for i in 0..EXTENT_SLOTS {
        s.slots[i].committing = 0;
    }
    s.commit = C_IDLE;
    s.flush_wanted = 0;
    fail_waiters(s);
}

/// The bind landed at `revision`: the committed view is the new root.
unsafe fn apply(s: &mut ModuleState, revision: u64) {
    s.revision = revision;
    s.root_digest = s.new_root;
    for i in 0..EXTENT_SLOTS {
        let e = s.slots[i];
        if e.committing == 0 {
            continue;
        }
        if s.depth == 1 {
            if let Some(c) = s.children.get_mut(e.idx as usize) {
                *c = e.digest;
            }
        } else {
            let child = e.idx >> 10;
            for k in 0..LEAF_SLOTS {
                if s.leaves[k].valid != 0 && s.leaves[k].child == child {
                    s.leaf_data[k][(e.idx & 1023) as usize] = e.digest;
                }
            }
        }
        s.slots[i].state = S_CLEAN;
        s.slots[i].committing = 0;
    }
    if s.depth == 2 {
        for j in 0..(s.leaf_new_len as usize).min(STAGED_MAX) {
            let l = s.leaf_new[j];
            if let Some(c) = s.children.get_mut(l.child as usize) {
                *c = l.digest;
            }
            for k in 0..LEAF_SLOTS {
                if s.leaves[k].valid != 0 && s.leaves[k].child == l.child {
                    s.leaves[k].digest = l.digest;
                }
            }
        }
    }
    s.staged = 0;
    s.durable_gen = s.commit_gen;
    s.commit = C_IDLE;
    s.flush_wanted = 0;
    s.commits = s.commits.wrapping_add(1);
}

// ── Failure ────────────────────────────────────────────────────────

unsafe fn fail(s: &mut ModuleState, err: i32, why: &[u8]) {
    if s.phase == P_FAILED {
        return;
    }
    log(s, 1, why);
    s.phase = P_FAILED;
    s.fail = err;
    s.job = J_NONE;
    s.commit = C_IDLE;
    s.staged = 0;
    for i in 0..EXTENT_SLOTS {
        s.slots[i].state = S_FREE;
        s.slots[i].committing = 0;
    }
}

// ── Scheduling ─────────────────────────────────────────────────────

unsafe fn issue_lease(s: &mut ModuleState, job: u8, mode: u8) {
    let cid = take_cid(s);
    let rl = s.root_len as usize;
    let pl = s.path_len as usize;
    match aw::encode_admin_lease(
        &mut s.io,
        cid,
        mode,
        &s.root[..rl],
        &s.path[..pl],
        &s.holder,
        s.ttl_ms,
    ) {
        Ok(n) => issue(s, job, n),
        Err(_) => fail(s, EINVAL, b"[loam_volume] lease request does not encode"),
    }
}

unsafe fn schedule(s: &mut ModuleState, t: u64) {
    match s.phase {
        P_LEASE => {
            if t < s.retry_at {
                return;
            }
            issue_lease(s, J_ACQUIRE, aw::LEASE_ACQUIRE);
        }
        P_LOOKUP => {
            let cid = take_cid(s);
            let rl = s.root_len as usize;
            let pl = s.path_len as usize;
            match aw::encode_admin_lookup(&mut s.io, cid, &s.root[..rl], &s.path[..pl]) {
                Ok(n) => issue(s, J_LOOKUP, n),
                Err(_) => fail(s, EINVAL, b"[loam_volume] lookup does not encode"),
            }
        }
        P_ROOT => {
            let cid = take_cid(s);
            let digest = s.root_digest;
            match aw::encode_admin_get_body(&mut s.io, cid, &digest) {
                Ok(n) => issue(s, J_ROOT, n),
                Err(_) => fail(s, EIO, b"[loam_volume] root request does not encode"),
            }
        }
        P_READY => {
            if t.saturating_sub(s.lease_at) >= (s.ttl_ms >> 1) as u64 {
                issue_lease(s, J_RENEW, aw::LEASE_RENEW);
                return;
            }
            if s.commit != C_IDLE {
                commit_next(s, t);
                return;
            }
            if s.draining != 0 && s.flush_wanted == 0 && queued(s) == 0 {
                // The drain's flush is decided — committed, or abandoned
                // with its waiters answered — and nothing waits: the lease
                // goes back, so the next writer need not wait it out.
                issue_lease(s, J_RELEASE, aw::LEASE_RELEASE);
                return;
            }
            if s.flush_wanted != 0 {
                if s.staged > 0 {
                    s.commit = C_BEGIN;
                    s.abandon_status = 0;
                    s.begin_since = t;
                    s.retry_at = 0;
                    commit_next(s, t);
                    return;
                }
                s.flush_wanted = 0;
            }
            fetch_next(s);
        }
        _ => {}
    }
}

/// Stop before the lease can lapse: past three quarters of its TTL with
/// no renewal granted, another writer may be about to take the volume.
unsafe fn lease_guard(s: &mut ModuleState, t: u64) {
    let ttl = s.ttl_ms as u64;
    if t >= s.lease_at + ttl - (ttl >> 2) {
        fail(
            s,
            EIO,
            b"[loam_volume] lease not renewed in time; device closed",
        );
    }
}

/// Bring the admin client up: load the capability file, then drive the
/// client. True once it is ready; a client that fails ends the device.
unsafe fn admin_up(s: &mut ModuleState, t: u64) -> bool {
    let sys = &*s.syscalls;
    if s.cap_loaded == 0 {
        if s.cap_path_len == 0 {
            fail(
                s,
                EINVAL,
                b"[loam_volume] the capability parameter is required",
            );
            return false;
        }
        let mut file = [0u8; super::admin_client::CAP_FILE_MAX];
        let path: &[u8] = &*(&s.cap_path[..s.cap_path_len as usize] as *const [u8]);
        if let Err(why) = super::admin_client::load_chain_file(&mut s.client, sys, path, &mut file)
        {
            fail(s, EINVAL, why);
            return false;
        }
        s.cap_loaded = 1;
    }
    super::admin_client::poll(&mut s.client, sys, t);
    if super::admin_client::has_failed(&s.client) {
        // One call per arm: a match yielding the message would lower to
        // a table of absolute pointers, which a PIC module cannot hold.
        match s.client.why {
            super::admin_client::WHY_REFUSED => {
                fail(s, EACCES, b"[loam_volume] the gate refused a capability")
            }
            super::admin_client::WHY_UNAUTHENTICATED => fail(
                s,
                EACCES,
                b"[loam_volume] the gate saw no authenticated peer",
            ),
            super::admin_client::WHY_TIMEOUT => {
                fail(s, EIO, b"[loam_volume] the admin plane did not answer")
            }
            _ => fail(s, EIO, b"[loam_volume] the admin plane connection failed"),
        }
        return false;
    }
    super::admin_client::is_ready(&s.client)
}

pub unsafe fn module_step_impl(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    if s.syscalls.is_null() {
        return -1;
    }
    if s.phase == P_LEASE && s.job == J_NONE && s.fail == 0 {
        let e = open_error(s);
        if e != 0 {
            fail(s, e, b"[loam_volume] bad parameters");
        }
    }
    let t = now_ms(s);
    if s.drained != 0 || (s.draining != 0 && s.phase != P_READY && s.job == J_NONE) {
        // Drained, or draining with no lease to give back.
        return 1;
    }
    if s.phase != P_FAILED && !admin_up(s, t) {
        return if s.phase == P_FAILED && s.fail_reported == 0 {
            s.fail_reported = 1;
            s.fail
        } else {
            0
        };
    }
    if s.phase != P_FAILED {
        pump(s, t);
    }
    if s.phase == P_READY {
        lease_guard(s, t);
    }
    if s.phase == P_READY || s.phase == P_FAILED {
        service(s);
    }
    // More than one exchange per step would let a busy volume starve the
    // lane; one keeps the step bounded.
    if s.phase != P_FAILED && s.job == J_NONE {
        schedule(s, t);
    }
    if s.phase == P_READY && s.ready_reported == 0 {
        s.ready_reported = 1;
        log(s, 3, b"[loam_volume] ready");
        return 3;
    }
    // An attach that failed is reported once, as the module's own
    // failure. A device that closed after it was ready keeps stepping,
    // so what is still queued is answered with the error.
    if s.phase == P_FAILED && s.fail_reported == 0 {
        s.fail_reported = 1;
        if s.ready_reported == 0 {
            return s.fail;
        }
    }
    0
}

/// Begin a drain: admit nothing new, commit what is staged, release the
/// writer lease, then report done. A stop that drains loses no
/// acknowledged-but-unflushed write and leaves the volume free at once.
pub fn drain(s: &mut ModuleState) {
    s.draining = 1;
    s.flush_wanted = 1;
}

// ── The block channel ──────────────────────────────────────────────

unsafe fn admitted(s: &ModuleState, body: &[u8]) -> Result<Req, i32> {
    if s.draining != 0 {
        return Err(EBUSY);
    }
    match s.phase {
        P_READY => {}
        P_FAILED => return Err(s.fail),
        _ => return Err(EAGAIN),
    }
    match Req::decode(body) {
        Some(r) if caps_of(s).admits(&r) => Ok(r),
        _ => Err(EINVAL),
    }
}

/// The `storage.block` channel ioctl handler.
pub unsafe extern "C" fn block_ioctl(state: *mut c_void, cmd: u32, arg: *mut u8) -> i32 {
    if state.is_null() || arg.is_null() {
        return EINVAL;
    }
    let s = &mut *(state as *mut ModuleState);
    match cmd {
        blk::ioctl::CAPS => match s.phase {
            P_READY => {
                caps_of(s).encode(core::slice::from_raw_parts_mut(arg, blk::caps::LEN));
                blk::caps::LEN as i32
            }
            P_FAILED => s.fail,
            _ => EAGAIN,
        },
        blk::ioctl::EXEC => {
            let r = match admitted(s, core::slice::from_raw_parts(arg, blk::req::LEN)) {
                Ok(r) => r,
                Err(rc) => return rc,
            };
            let mut stage = 0u8;
            let mut target = s.write_gen;
            match run(s, &r, &mut stage, &mut target) {
                Some(c) => {
                    c.encode(core::slice::from_raw_parts_mut(
                        arg.add(blk::req::LEN),
                        blk::cpl::LEN,
                    ));
                    c.status
                }
                None => EAGAIN,
            }
        }
        blk::ioctl::SUBMIT => {
            let r = match admitted(s, core::slice::from_raw_parts(arg, blk::req::LEN)) {
                Ok(r) => r,
                Err(rc) => return rc,
            };
            if queued(s) >= QUEUE_DEPTH {
                return EAGAIN;
            }
            let mut p = Pending {
                used: 1,
                stage: 0,
                _pad: [0; 6],
                target: s.write_gen,
                req: r,
            };
            match run(s, &r, &mut p.stage, &mut p.target) {
                Some(c) => push_done(s, c),
                None => {
                    for i in 0..QUEUE_DEPTH {
                        if s.pending[i].used == 0 {
                            s.pending[i] = p;
                            break;
                        }
                    }
                }
            }
            0
        }
        blk::ioctl::REAP => {
            if s.done_count == 0 {
                return 0;
            }
            let c = s.done[s.done_head as usize & (QUEUE_DEPTH - 1)];
            s.done_head = ((s.done_head as usize + 1) & (QUEUE_DEPTH - 1)) as u32;
            s.done_count -= 1;
            c.encode(core::slice::from_raw_parts_mut(arg, blk::cpl::LEN));
            1
        }
        _ => ENOSYS,
    }
}

const _: () = assert!(QUEUE_DEPTH.is_power_of_two());
const _: () = assert!(STAGED_MAX < EXTENT_SLOTS);
const _: () = assert!(EXTENT_CAP <= map::MAX_EXTENT_SIZE as usize);
const _: () = assert!(IO_CAP >= 10 + map::MAX_PAGE_LEN);

/// Take the lease holder from 32 hex digits: the attach flow's own holder,
/// so acquiring here re-acquires the lease it already holds and keeps its
/// fence. Empty is the parameter's absence; anything else marks the
/// parameters bad.
pub fn set_holder(s: &mut ModuleState, hex: &[u8]) {
    if hex.is_empty() {
        return;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    if hex.len() != 2 * aw::LEASE_HOLDER_LEN {
        s.bad_param = 1;
        return;
    }
    let mut out = [0u8; aw::LEASE_HOLDER_LEN];
    for (i, b) in out.iter_mut().enumerate() {
        match (nib(hex[2 * i]), nib(hex[2 * i + 1])) {
            (Some(h), Some(l)) => *b = (h << 4) | l,
            _ => {
                s.bad_param = 1;
                return;
            }
        }
    }
    s.holder = out;
}

/// Take the expected lease fence from its decimal digits. Empty is the
/// parameter's absence.
pub fn set_fence(s: &mut ModuleState, digits: &[u8]) {
    let mut v: u64 = 0;
    if digits.is_empty() {
        return;
    }
    for &c in digits {
        let d = match c {
            b'0'..=b'9' => u64::from(c - b'0'),
            _ => {
                s.bad_param = 1;
                return;
            }
        };
        v = match v.checked_mul(10).and_then(|x| x.checked_add(d)) {
            Some(x) => x,
            None => {
                s.bad_param = 1;
                return;
            }
        };
    }
    s.expect_fence = v;
}
