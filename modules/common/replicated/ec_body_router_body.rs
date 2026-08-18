// Shared step-body for `ec_body_router`. The erasure-coding
// sibling of `body_fanout_router`: sits between `admin_router`
// (or any body_wire consumer) and a fleet of `body_store`
// instances, but stores k data + m parity SHARD blobs instead of
// full replicas — any k of the k+m shards reconstruct the body,
// at a storage overhead of (k+m)/k instead of the fanout
// router's replica_count.
//
// Addressing is stateless end to end. For a body with digest D:
//
//   shard i  lives on   ranked target i = pick_targets(D, k+m)[i]
//   under key           K_i = derive_shard_key(D, i)
//
// Both are pure functions of (D, fleet snapshot), so the router
// keeps no durable state — same as the fanout router. The shard
// blob (loam_ec_wire framing) carries (k, m, index, body_len, D),
// which is what makes K_i verifiable by body_store and the
// reconstruction verifiable here: a rebuilt body must sha256 back
// to D before it is served.
//
// Semantics:
//   - PUT: sha256 the body, encode k+m shard blobs, PUT_KEYED one
//          to each of the k+m ranked targets. All-must-succeed:
//          any target NAK fails the upstream PUT (a body that
//          starts life under-replicated is a scrub burden, not a
//          success).
//   - GET: GET(K_i) fanned to all ranked targets; the body is
//          reconstructed and served as soon as any k shards
//          arrive. More than m failures → upstream NAK. One GET
//          reassembly is in flight at a time (the shard buffer is
//          the arena's big allocation); a second concurrent GET
//          NAKs ERR_IO and the client retries.
//   - HEAD: walk the ranked targets serially, GET one shard, and
//          answer from its header's body_len.
//   - DELETE: fan DELETE(K_i) to every ranked target; existed is
//          the OR of the replies, NAK only if every target failed.
//
// Bounded step contract: at most MAX_OPS_PER_STEP upstream
// requests + MAX_OPS_PER_STEP responses-per-target per step; the
// reconstruction solve is one ≤16×16 GF(256) inversion.

const MAX_OPS_PER_STEP: u32 = 4;
const READ_BUF: usize = super::body_wire::MAX_BODY + 64;
const SCRATCH: usize = super::body_wire::MAX_BODY + 64;
const PENDING_CAP: usize = 64;
const JOIN_CAP: usize = 32;

/// Per-shard stride in the reassembly buffer. k ≥ 2 bounds a
/// shard at ceil(MAX_BODY / 2); blobs add SHARD_HDR on the wire
/// but only the payload lands here.
const SHARD_SLOT: usize = super::body_wire::MAX_BODY.div_ceil(2);
const BLOB_BUF: usize = super::ec_wire::SHARD_HDR + SHARD_SLOT;

const KIND_PUT: u8 = 0;
const KIND_GET: u8 = 1;
const KIND_HEAD: u8 = 2;
const KIND_DELETE: u8 = 3;
const KIND_SCRUB_SCAN: u8 = 4;
const KIND_SCRUB_IDENT: u8 = 5;
const KIND_SCRUB_PROBE: u8 = 6;
const KIND_SCRUB_FETCH: u8 = 7;
const KIND_SCRUB_REPAIR: u8 = 8;
const KIND_SCRUB_CLEANUP: u8 = 9;

use super::ec::MAX_SHARDS;
use super::placement::Fleet;
use super::placement_wire::MAX_FLEET;

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct PendingTarget {
    pub in_use: u8,
    pub join_idx: u16,
    pub join_gen: u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct JoinSlot {
    pub in_use: u8,
    pub kind: u8,
    pub need: u8,
    pub ack: u8,
    pub fail: u8,
    pub existed: u8, // DELETE OR-accumulator
    pub attempt: u8, // HEAD serial walk cursor
    pub target_count: u8,
    pub last_errno: u8,
    pub saw_not_found: u8,
    pub gen: u16,
    pub targets: [u8; MAX_FLEET],
    pub digest: [u8; super::body_wire::DIGEST_LEN],
}

/// The single in-flight reassembly. Owns the big shard buffer;
/// `join_idx` ties it to the join collecting responses. A client
/// GET and a scrub fetch share it (`internal` = scrub): whichever
/// holds it first wins, the other retries.
#[repr(C)]
pub struct Assembly {
    pub busy: u8,
    pub internal: u8, // 1 = scrub fetch, no upstream traffic
    pub join_idx: u16,
    pub present_mask: u32,
    pub shard_len: u32, // 0 until the first shard arrives
    pub body_len: u32,
    pub digest: [u8; super::body_wire::DIGEST_LEN],
    pub shards: [u8; MAX_SHARDS * SHARD_SLOT],
}

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    pub admin_in_chan: i32,
    pub admin_out_chan: i32,
    pub fleet_in_chan: i32,
    pub body_req_chans: [i32; MAX_FLEET],
    pub body_resp_chans: [i32; MAX_FLEET],
    pub body_fleet_count: u8,
    /// EC geometry. k ≥ 2 data shards, m parity shards,
    /// k + m ≤ MAX_SHARDS (= MAX_FLEET).
    pub ec_k: u8,
    pub ec_m: u8,
    pub fleet_epoch: u64,
    pub fleet_members: [u8; MAX_FLEET],
    pub fleet_count: u8,
    pub per_target_head: [u32; MAX_FLEET],
    pub per_target_tail: [u32; MAX_FLEET],
    pub per_target_pending: [[PendingTarget; PENDING_CAP]; MAX_FLEET],
    pub joins: [JoinSlot; JOIN_CAP],
    pub join_gen: u16,
    pub assembly: Assembly,
    pub blob_buf: [u8; BLOB_BUF],
    pub scratch: [u8; SCRATCH],
    /// EC scrub (active when `scrub_interval` != 0): SCAN one page
    /// of one member's key inventory per interval, identify each
    /// shard blob (IDENT: the blob's header carries body digest,
    /// geometry, and index), HEAD-probe every ranked home, then
    /// heal — direct-copy when only the discovered shard's own
    /// home is missing (the re-placement case: rendezvous ranking
    /// moved after a fleet change), reconstruct-and-re-encode when
    /// other shards are lost, and delete the stray from the
    /// scanned member once every ranked home is verified present.
    /// One body is processed at a time; a stray is only deleted in
    /// a round where nothing needed repairing, so cleanup can
    /// never race the copy it depends on.
    pub scrub_interval: u32,
    pub scrub_target: u8,
    pub scrub_cursor: u32,
    pub scrub_scan_inflight: u8,
    pub scrub_busy: u8,
    pub scrub_keys: [[u8; super::body_wire::DIGEST_LEN]; super::body_wire::MAX_SCAN_DIGESTS],
    pub scrub_q_len: u8,
    pub scrub_q_pos: u8,
    pub scrub_scanned_member: u8,
    pub scrub_ident_index: u8,
    pub scrub_shard_len: u32,
    pub scrub_body_len: u32,
    pub scrub_digest: [u8; super::body_wire::DIGEST_LEN],
    pub scrub_ranked: [u8; MAX_FLEET],
    pub scrub_ranked_count: u8,
    pub scrub_present: u16,
    pub scrub_probe_resp: u8,
    pub scrub_repair_mask: u16,
    /// The IDENT shard's payload — the known-good copy that seeds
    /// a fetch or is copied directly to its ranked home.
    pub scrub_shard_buf: [u8; SHARD_SLOT],
    pub scrub_scans: u32,
    pub scrub_probes: u32,
    pub scrub_replaced: u32,
    pub scrub_repairs: u32,
    pub scrub_repairs_ok: u32,
    pub scrub_repairs_failed: u32,
    pub scrub_cleanups: u32,
    pub scrub_lost: u32,
    pub scrub_skipped: u32,
    pub ticks: u32,
    pub fanned_out: u32,
    pub upstream_acked: u32,
    pub upstream_naked: u32,
    pub reconstructions: u32,
    pub apply_errors: u32,
}

pub unsafe fn module_new_with_targets_impl(
    admin_in_chan: i32,
    admin_out_chan: i32,
    fleet_in_chan: i32,
    req_chans: &[i32],
    resp_chans: &[i32],
    k: u8,
    m: u8,
    scrub_interval: u32,
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
    if req_chans.len() != resp_chans.len() || req_chans.len() > MAX_FLEET {
        return -3;
    }
    // k = 1 is replication — that's body_fanout_router's job.
    if k < 2 || (k as usize + m as usize) > MAX_SHARDS {
        return -4;
    }
    core::ptr::write_bytes(state_ptr, 0u8, state_size);
    let s = &mut *(state_ptr as *mut ModuleState);
    s.syscalls = syscalls;
    s.admin_in_chan = admin_in_chan;
    s.admin_out_chan = admin_out_chan;
    s.fleet_in_chan = fleet_in_chan;
    s.body_fleet_count = req_chans.len() as u8;
    for i in 0..req_chans.len() {
        s.body_req_chans[i] = req_chans[i];
        s.body_resp_chans[i] = resp_chans[i];
    }
    for i in req_chans.len()..MAX_FLEET {
        s.body_req_chans[i] = -1;
        s.body_resp_chans[i] = -1;
    }
    s.ec_k = k;
    s.ec_m = m;
    s.scrub_interval = scrub_interval;
    0
}

/// Host-test helper: enable/adjust scrub after setup traffic, so
/// tests control exactly which tick the first SCAN fires on.
pub unsafe fn set_scrub_for_test(state_ptr: *mut u8, interval: u32) {
    let s = &mut *(state_ptr as *mut ModuleState);
    s.scrub_interval = interval;
}

/// Host-test helper: seed the cached fleet snapshot directly.
pub unsafe fn set_fleet_for_test(state_ptr: *mut u8, epoch: u64, members: &[u8]) {
    let s = &mut *(state_ptr as *mut ModuleState);
    let take = members.len().min(MAX_FLEET);
    s.fleet_members[..take].copy_from_slice(&members[..take]);
    s.fleet_count = take as u8;
    s.fleet_epoch = epoch;
}

// ── Join + pending-FIFO plumbing (fanout-router discipline) ────────

unsafe fn alloc_join(s: &mut ModuleState) -> Option<u16> {
    for i in 0..s.joins.len() {
        if s.joins[i].in_use == 0 {
            s.join_gen = s.join_gen.wrapping_add(1);
            let gen = s.join_gen;
            s.joins[i] = JoinSlot {
                in_use: 1,
                kind: KIND_PUT,
                need: 0,
                ack: 0,
                fail: 0,
                existed: 0,
                attempt: 0,
                target_count: 0,
                last_errno: 0,
                saw_not_found: 0,
                gen,
                targets: [0u8; MAX_FLEET],
                digest: [0u8; super::body_wire::DIGEST_LEN],
            };
            return Some(i as u16);
        }
    }
    None
}

unsafe fn free_join(s: &mut ModuleState, idx: u16) {
    if (idx as usize) < s.joins.len() {
        s.joins[idx as usize].in_use = 0;
    }
}

unsafe fn enqueue_target(
    s: &mut ModuleState,
    target_slot: u8,
    join_idx: u16,
    join_gen: u16,
) -> bool {
    let t = target_slot as usize;
    let next = (s.per_target_tail[t].wrapping_add(1)) % PENDING_CAP as u32;
    if next == s.per_target_head[t] {
        return false;
    }
    s.per_target_pending[t][s.per_target_tail[t] as usize] = PendingTarget {
        in_use: 1,
        join_idx,
        join_gen,
    };
    s.per_target_tail[t] = next;
    true
}

unsafe fn unenqueue_tail(s: &mut ModuleState, target_slot: u8) {
    let t = target_slot as usize;
    if s.per_target_head[t] == s.per_target_tail[t] {
        return;
    }
    let prev = (s.per_target_tail[t].wrapping_add(PENDING_CAP as u32 - 1)) % PENDING_CAP as u32;
    s.per_target_pending[t][prev as usize].in_use = 0;
    s.per_target_tail[t] = prev;
}

unsafe fn dequeue_target(s: &mut ModuleState, target_slot: u8) -> Option<PendingTarget> {
    let t = target_slot as usize;
    if s.per_target_head[t] == s.per_target_tail[t] {
        return None;
    }
    let entry = s.per_target_pending[t][s.per_target_head[t] as usize];
    s.per_target_pending[t][s.per_target_head[t] as usize].in_use = 0;
    s.per_target_head[t] = (s.per_target_head[t].wrapping_add(1)) % PENDING_CAP as u32;
    Some(entry)
}

/// Write `req_n` bytes of `s.scratch` to `member_id` with a
/// pending entry; false = unwound, no response will come.
unsafe fn dispatch_to_target(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    member_id: u8,
    join_idx: u16,
    join_gen: u16,
    req_n: usize,
) -> bool {
    if (member_id as usize) >= s.body_fleet_count as usize {
        return false;
    }
    let req_chan = s.body_req_chans[member_id as usize];
    if req_chan < 0 {
        return false;
    }
    if !enqueue_target(s, member_id, join_idx, join_gen) {
        return false;
    }
    let wrote = (syscalls.channel_write)(req_chan, s.scratch.as_ptr(), req_n);
    if wrote < 0 || (wrote as usize) != req_n {
        unenqueue_tail(s, member_id);
        return false;
    }
    s.fanned_out = s.fanned_out.wrapping_add(1);
    true
}

/// Ranked target list for `digest`: exactly k+m members, or 0 if
/// the fleet can't cover the geometry.
unsafe fn rank_targets(
    s: &ModuleState,
    digest: &[u8; super::body_wire::DIGEST_LEN],
    out: &mut [u8; MAX_FLEET],
) -> usize {
    let want = s.ec_k as usize + s.ec_m as usize;
    if (s.fleet_count as usize) < want {
        return 0;
    }
    let fleet = Fleet::from_slice(s.fleet_epoch, &s.fleet_members[..s.fleet_count as usize]);
    let chosen = super::placement::pick_targets(digest, want as u8, &fleet, out);
    if chosen == want {
        chosen
    } else {
        0
    }
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

    // ── 1. FleetEpoch updates. ──────────────────────────────────
    if s.fleet_in_chan >= 0 {
        let mut handled: u32 = 0;
        while handled < MAX_OPS_PER_STEP {
            let mut buf = [0u8; 64];
            let n = (syscalls.channel_read)(s.fleet_in_chan, buf.as_mut_ptr(), buf.len());
            if n <= 0 {
                break;
            }
            match super::placement_wire::decode_fleet_epoch(&buf[..n as usize]) {
                Ok(decoded) => {
                    let take = decoded.members.len().min(MAX_FLEET);
                    s.fleet_members[..take].copy_from_slice(&decoded.members[..take]);
                    s.fleet_count = take as u8;
                    s.fleet_epoch = decoded.epoch;
                }
                Err(_) => s.apply_errors = s.apply_errors.wrapping_add(1),
            }
            handled = handled.wrapping_add(1);
        }
    }

    // ── 2. Scrub: kick one SCAN when due and idle. ──────────────
    if s.scrub_interval != 0
        && s.body_fleet_count != 0
        && s.scrub_scan_inflight == 0
        && s.scrub_busy == 0
        && s.scrub_q_len == 0
        && s.ticks % s.scrub_interval == 0
    {
        scrub_kick(s, syscalls);
    }

    // ── 3. Upstream body requests. ──────────────────────────────
    let mut handled: u32 = 0;
    while handled < MAX_OPS_PER_STEP {
        let mut buf = [0u8; READ_BUF];
        let n = (syscalls.channel_read)(s.admin_in_chan, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        let bytes = &buf[..n as usize];
        match super::body_wire::peek_opcode(bytes).unwrap_or(0xFF) {
            super::body_wire::OP_PUT => handle_put(s, syscalls, bytes),
            super::body_wire::OP_GET => handle_get(s, syscalls, bytes),
            super::body_wire::OP_HEAD => handle_head(s, syscalls, bytes),
            super::body_wire::OP_DELETE => handle_delete(s, syscalls, bytes),
            _ => emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ),
        }
        handled = handled.wrapping_add(1);
    }

    // ── 4. Per-target responses. ────────────────────────────────
    for t in 0..s.body_fleet_count as usize {
        let resp_chan = s.body_resp_chans[t];
        if resp_chan < 0 {
            continue;
        }
        let mut drained: u32 = 0;
        while drained < MAX_OPS_PER_STEP {
            let mut buf = [0u8; READ_BUF];
            let n = (syscalls.channel_read)(resp_chan, buf.as_mut_ptr(), buf.len());
            if n <= 0 {
                break;
            }
            let resp = &buf[..n as usize];
            match dequeue_target(s, t as u8) {
                Some(pending) => {
                    let ji = pending.join_idx as usize;
                    if ji >= JOIN_CAP
                        || s.joins[ji].in_use == 0
                        || s.joins[ji].gen != pending.join_gen
                    {
                        s.apply_errors = s.apply_errors.wrapping_add(1);
                    } else {
                        apply_join_response(s, syscalls, pending.join_idx, t as u8, resp);
                    }
                }
                None => s.apply_errors = s.apply_errors.wrapping_add(1),
            }
            drained = drained.wrapping_add(1);
        }
    }
    0
}

// ── PUT ────────────────────────────────────────────────────────────

unsafe fn handle_put(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let body = match super::body_wire::decode_put_req(bytes) {
        Ok(b) => b,
        Err(_) => {
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    // The shard buffer doubles as PUT encode space; an in-flight
    // GET reassembly owns it.
    if s.assembly.busy != 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
        return;
    }
    let mut hasher = super::sha256::Sha256::new();
    hasher.update(body);
    let digest = hasher.finalize();

    let mut targets_buf = [0u8; MAX_FLEET];
    let total = rank_targets(s, &digest, &mut targets_buf);
    if total == 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let (k, m) = (s.ec_k, s.ec_m);
    let shard_len = super::ec::shard_len_for(body.len(), k);
    if shard_len > SHARD_SLOT {
        emit_nak(s, syscalls, super::body_wire::ERR_TOO_LARGE);
        return;
    }
    // Encode k+m shards contiguously into the assembly buffer.
    if super::ec::encode(body, k, m, &mut s.assembly.shards[..total * shard_len]).is_err() {
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            return;
        }
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_PUT;
        j.need = total as u8;
        j.digest = digest;
        j.gen
    };
    for i in 0..total {
        // Frame shard i and wrap it in a PUT_KEYED for target i.
        let hdr = super::ec_wire::ShardHeader {
            k,
            m,
            index: i as u8,
            body_len: body.len() as u32,
            body_digest: digest,
            shard_len: shard_len as u32,
        };
        let blob_n = match super::ec_wire::encode_shard_blob(
            &mut s.blob_buf,
            &hdr,
            &s.assembly.shards[i * shard_len..(i + 1) * shard_len],
        ) {
            Ok(n) => n,
            Err(_) => {
                s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
                continue;
            }
        };
        let key = super::ec_wire::derive_shard_key(&digest, i as u8);
        let req_n = match super::body_wire::encode_put_keyed_req(
            &mut s.scratch,
            &key,
            &s.blob_buf[..blob_n],
        ) {
            Ok(n) => n,
            Err(_) => {
                s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
                continue;
            }
        };
        if !dispatch_to_target(s, syscalls, targets_buf[i], join_idx, gen, req_n) {
            s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
        }
    }
    let j = s.joins[join_idx as usize];
    if j.fail > 0 && j.fail == j.need {
        free_join(s, join_idx);
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
    }
}

// ── GET ────────────────────────────────────────────────────────────

unsafe fn handle_get(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    if bytes.len() < 1 + super::body_wire::DIGEST_LEN {
        emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
        return;
    }
    if s.assembly.busy != 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
        return;
    }
    let mut digest = [0u8; super::body_wire::DIGEST_LEN];
    digest.copy_from_slice(&bytes[1..1 + super::body_wire::DIGEST_LEN]);
    let mut targets_buf = [0u8; MAX_FLEET];
    let total = rank_targets(s, &digest, &mut targets_buf);
    if total == 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_NOT_FOUND);
        return;
    }
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            return;
        }
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_GET;
        j.need = total as u8;
        j.target_count = total as u8;
        j.targets[..total].copy_from_slice(&targets_buf[..total]);
        j.digest = digest;
        j.gen
    };
    s.assembly.busy = 1;
    s.assembly.join_idx = join_idx;
    s.assembly.present_mask = 0;
    s.assembly.shard_len = 0;
    s.assembly.body_len = 0;
    s.assembly.digest = digest;

    for (i, &member) in targets_buf[..total].iter().enumerate() {
        let key = super::ec_wire::derive_shard_key(&digest, i as u8);
        s.scratch[0] = super::body_wire::OP_GET;
        s.scratch[1..1 + super::body_wire::DIGEST_LEN].copy_from_slice(&key);
        if !dispatch_to_target(
            s,
            syscalls,
            member,
            join_idx,
            gen,
            1 + super::body_wire::DIGEST_LEN,
        ) {
            s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
        }
    }
    let j = s.joins[join_idx as usize];
    if j.fail > s.ec_m {
        resolve_get_failure(s, syscalls, join_idx);
    }
}

/// A GET join can no longer reach k shards — NAK upstream and
/// release the assembly.
unsafe fn resolve_get_failure(s: &mut ModuleState, syscalls: &super::SyscallTable, join_idx: u16) {
    let j = s.joins[join_idx as usize];
    let errno = if j.saw_not_found != 0 {
        super::body_wire::ERR_NOT_FOUND
    } else if j.last_errno != 0 {
        j.last_errno
    } else {
        super::body_wire::ERR_IO
    };
    emit_nak(s, syscalls, errno);
    free_join(s, join_idx);
    s.assembly.busy = 0;
    s.upstream_naked = s.upstream_naked.wrapping_add(1);
}

/// A shard blob arrived for the live assembly. Returns true when
/// the body was served (assembly released).
unsafe fn assembly_take_shard(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    join_idx: u16,
    from_target: u8,
    resp: &[u8],
) -> bool {
    let (k, m) = (s.ec_k, s.ec_m);
    let total = k as usize + m as usize;
    // Which shard index is this target responsible for?
    let j = &s.joins[join_idx as usize];
    let mut idx: Option<usize> = None;
    for (i, &t) in j.targets[..j.target_count as usize].iter().enumerate() {
        if t == from_target {
            idx = Some(i);
            break;
        }
    }
    let idx = match idx {
        Some(i) => i,
        None => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return false;
        }
    };
    let blob = match super::body_wire::decode_get_resp(resp) {
        Ok(b) => b,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return false;
        }
    };
    let hdr = match super::ec_wire::decode_shard_header(blob) {
        Ok(h) => h,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return false;
        }
    };
    // The blob must be shard `idx` of THIS body with THIS geometry.
    if hdr.body_digest != s.assembly.digest
        || hdr.index as usize != idx
        || hdr.k != k
        || hdr.m != m
        || hdr.shard_len as usize > SHARD_SLOT
        || hdr.shard_len == 0
    {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return false;
    }
    if s.assembly.shard_len == 0 {
        if (hdr.body_len as usize) > super::body_wire::MAX_BODY
            || (hdr.body_len as usize) > k as usize * hdr.shard_len as usize
        {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return false;
        }
        s.assembly.shard_len = hdr.shard_len;
        s.assembly.body_len = hdr.body_len;
    } else if hdr.shard_len != s.assembly.shard_len || hdr.body_len != s.assembly.body_len {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return false;
    }
    let payload = match super::ec_wire::shard_payload(blob) {
        Ok(p) => p,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return false;
        }
    };
    // Land the payload at the fixed stride; compaction to the
    // tight stride happens once at reconstruct time.
    let dst = idx * SHARD_SLOT;
    s.assembly.shards[dst..dst + payload.len()].copy_from_slice(payload);
    s.assembly.present_mask |= 1u32 << idx;

    if (s.assembly.present_mask.count_ones() as usize) < k as usize {
        return false;
    }

    // Enough shards: compact SHARD_SLOT stride → shard_len stride.
    // Byte loop rather than copy_within: dst < src throughout (the
    // tight stride only ever moves shards left), and copy_within's
    // internal asserts would drag core's panic formatting into the
    // bare-metal link.
    let shard_len = s.assembly.shard_len as usize;
    for i in 1..total {
        if s.assembly.present_mask & (1u32 << i) == 0 {
            continue;
        }
        let (dst_off, src_off) = (i * shard_len, i * SHARD_SLOT);
        for b in 0..shard_len {
            s.assembly.shards[dst_off + b] = s.assembly.shards[src_off + b];
        }
    }
    let needed_reconstruct = s.assembly.present_mask & ((1u32 << k) - 1) != (1u32 << k) - 1;
    let internal = s.assembly.internal != 0;
    if super::ec::reconstruct(
        &mut s.assembly.shards[..total * shard_len],
        shard_len,
        k,
        m,
        s.assembly.present_mask,
    )
    .is_err()
    {
        if internal {
            scrub_fetch_failed(s, syscalls, join_idx);
        } else {
            resolve_get_failure(s, syscalls, join_idx);
        }
        return true;
    }
    if needed_reconstruct {
        s.reconstructions = s.reconstructions.wrapping_add(1);
    }
    // Verify end to end: the reconstruction must hash back to the
    // digest before anything is served or re-written.
    let body_len = s.assembly.body_len as usize;
    let mut hasher = super::sha256::Sha256::new();
    hasher.update(&s.assembly.shards[..body_len]);
    if hasher.finalize() != s.assembly.digest {
        if internal {
            scrub_fetch_failed(s, syscalls, join_idx);
        } else {
            resolve_get_failure(s, syscalls, join_idx);
        }
        return true;
    }
    if internal {
        // Scrub fetch complete: re-encode every missing shard and
        // PUT_KEYED it to its ranked home.
        free_join(s, join_idx);
        scrub_dispatch_repairs_from_assembly(s, syscalls);
        s.assembly.busy = 0;
        s.assembly.internal = 0;
        scrub_next_key(s, syscalls);
        return true;
    }
    s.scratch[0] = super::body_wire::OP_GET;
    s.scratch[1..5].copy_from_slice(&(body_len as u32).to_le_bytes());
    s.scratch[5..5 + body_len].copy_from_slice(&s.assembly.shards[..body_len]);
    let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), 5 + body_len);
    free_join(s, join_idx);
    s.assembly.busy = 0;
    s.upstream_acked = s.upstream_acked.wrapping_add(1);
    true
}

// ── HEAD ───────────────────────────────────────────────────────────

unsafe fn handle_head(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    if bytes.len() < 1 + super::body_wire::DIGEST_LEN {
        emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
        return;
    }
    let mut digest = [0u8; super::body_wire::DIGEST_LEN];
    digest.copy_from_slice(&bytes[1..1 + super::body_wire::DIGEST_LEN]);
    let mut targets_buf = [0u8; MAX_FLEET];
    let total = rank_targets(s, &digest, &mut targets_buf);
    if total == 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_NOT_FOUND);
        return;
    }
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            return;
        }
    };
    {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_HEAD;
        j.need = 1;
        j.target_count = total as u8;
        j.targets[..total].copy_from_slice(&targets_buf[..total]);
        j.digest = digest;
    }
    advance_head(s, syscalls, join_idx);
}

/// Serially walk the ranked targets asking each for its shard;
/// the first blob that arrives answers the HEAD from its header.
unsafe fn advance_head(s: &mut ModuleState, syscalls: &super::SyscallTable, join_idx: u16) {
    loop {
        let (digest, attempt, target_count, gen, last_errno, saw_nf) = {
            let j = &s.joins[join_idx as usize];
            (
                j.digest,
                j.attempt,
                j.target_count,
                j.gen,
                j.last_errno,
                j.saw_not_found,
            )
        };
        if attempt >= target_count {
            let errno = if saw_nf != 0 {
                super::body_wire::ERR_NOT_FOUND
            } else if last_errno != 0 {
                last_errno
            } else {
                super::body_wire::ERR_IO
            };
            emit_nak(s, syscalls, errno);
            free_join(s, join_idx);
            s.upstream_naked = s.upstream_naked.wrapping_add(1);
            return;
        }
        let member = s.joins[join_idx as usize].targets[attempt as usize];
        let key = super::ec_wire::derive_shard_key(&digest, attempt);
        s.scratch[0] = super::body_wire::OP_GET;
        s.scratch[1..1 + super::body_wire::DIGEST_LEN].copy_from_slice(&key);
        if dispatch_to_target(
            s,
            syscalls,
            member,
            join_idx,
            gen,
            1 + super::body_wire::DIGEST_LEN,
        ) {
            return;
        }
        let j = &mut s.joins[join_idx as usize];
        j.last_errno = super::body_wire::ERR_IO;
        j.attempt = j.attempt.wrapping_add(1);
    }
}

// ── DELETE ─────────────────────────────────────────────────────────

unsafe fn handle_delete(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    if bytes.len() < 1 + super::body_wire::DIGEST_LEN {
        emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
        return;
    }
    let mut digest = [0u8; super::body_wire::DIGEST_LEN];
    digest.copy_from_slice(&bytes[1..1 + super::body_wire::DIGEST_LEN]);
    let mut targets_buf = [0u8; MAX_FLEET];
    let total = rank_targets(s, &digest, &mut targets_buf);
    if total == 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_NOT_FOUND);
        return;
    }
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            return;
        }
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_DELETE;
        j.need = total as u8;
        j.digest = digest;
        j.gen
    };
    for (i, &member) in targets_buf[..total].iter().enumerate() {
        let key = super::ec_wire::derive_shard_key(&digest, i as u8);
        s.scratch[0] = super::body_wire::OP_DELETE;
        s.scratch[1..1 + super::body_wire::DIGEST_LEN].copy_from_slice(&key);
        if !dispatch_to_target(
            s,
            syscalls,
            member,
            join_idx,
            gen,
            1 + super::body_wire::DIGEST_LEN,
        ) {
            s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
        }
    }
    let j = s.joins[join_idx as usize];
    if j.fail == j.need {
        free_join(s, join_idx);
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
    }
}

// ── Response demux ─────────────────────────────────────────────────

unsafe fn apply_join_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    join_idx: u16,
    from_target: u8,
    resp: &[u8],
) {
    let kind = s.joins[join_idx as usize].kind;
    let resp_op = super::body_wire::peek_opcode(resp).unwrap_or(0xFF);
    let nak_errno = if resp_op == super::body_wire::OP_NAK && resp.len() >= 2 {
        resp[1]
    } else {
        0
    };

    match kind {
        KIND_PUT => {
            let succeeded = resp_op == super::body_wire::OP_PUT_KEYED;
            let j = &mut s.joins[join_idx as usize];
            if succeeded {
                j.ack = j.ack.wrapping_add(1);
            } else {
                j.fail = j.fail.wrapping_add(1);
            }
            let j = s.joins[join_idx as usize];
            if j.fail > 0 {
                let errno = if nak_errno != 0 {
                    nak_errno
                } else {
                    super::body_wire::ERR_IO
                };
                emit_nak(s, syscalls, errno);
                free_join(s, join_idx);
                s.upstream_naked = s.upstream_naked.wrapping_add(1);
            } else if j.ack == j.need {
                let mut out = [0u8; 1 + super::body_wire::DIGEST_LEN];
                if super::body_wire::encode_put_resp(&mut out, &j.digest).is_ok() {
                    let _ = (syscalls.channel_write)(s.admin_out_chan, out.as_ptr(), out.len());
                }
                free_join(s, join_idx);
                s.upstream_acked = s.upstream_acked.wrapping_add(1);
            }
        }
        KIND_GET => {
            if resp_op == super::body_wire::OP_GET {
                let _ = assembly_take_shard(s, syscalls, join_idx, from_target, resp);
            } else {
                {
                    let j = &mut s.joins[join_idx as usize];
                    j.fail = j.fail.wrapping_add(1);
                    if nak_errno == super::body_wire::ERR_NOT_FOUND {
                        j.saw_not_found = 1;
                    } else if nak_errno != 0 {
                        j.last_errno = nak_errno;
                    }
                }
                if s.joins[join_idx as usize].fail > s.ec_m {
                    resolve_get_failure(s, syscalls, join_idx);
                }
            }
        }
        KIND_HEAD => {
            if resp_op == super::body_wire::OP_GET {
                let served = super::body_wire::decode_get_resp(resp)
                    .ok()
                    .and_then(|blob| super::ec_wire::decode_shard_header(blob).ok())
                    .map(|hdr| {
                        let mut out = [0u8; 16];
                        if let Ok(n) =
                            super::body_wire::encode_head_resp(&mut out, hdr.body_len as u64)
                        {
                            let _ = (syscalls.channel_write)(s.admin_out_chan, out.as_ptr(), n);
                        }
                    })
                    .is_some();
                if served {
                    free_join(s, join_idx);
                    s.upstream_acked = s.upstream_acked.wrapping_add(1);
                } else {
                    let j = &mut s.joins[join_idx as usize];
                    j.last_errno = super::body_wire::ERR_IO;
                    j.attempt = j.attempt.wrapping_add(1);
                    advance_head(s, syscalls, join_idx);
                }
            } else {
                {
                    let j = &mut s.joins[join_idx as usize];
                    if nak_errno == super::body_wire::ERR_NOT_FOUND {
                        j.saw_not_found = 1;
                    } else if nak_errno != 0 {
                        j.last_errno = nak_errno;
                    }
                    j.attempt = j.attempt.wrapping_add(1);
                }
                advance_head(s, syscalls, join_idx);
            }
        }
        KIND_DELETE => {
            {
                let j = &mut s.joins[join_idx as usize];
                if resp_op == super::body_wire::OP_DELETE {
                    j.ack = j.ack.wrapping_add(1);
                    if resp.len() >= 2 && resp[1] != 0 {
                        j.existed = 1;
                    }
                } else {
                    j.fail = j.fail.wrapping_add(1);
                    if nak_errno != 0 {
                        j.last_errno = nak_errno;
                    }
                }
            }
            let j = s.joins[join_idx as usize];
            if j.ack.wrapping_add(j.fail) == j.need {
                if j.ack > 0 {
                    let mut out = [0u8; 2];
                    if super::body_wire::encode_delete_resp(&mut out, j.existed != 0).is_ok() {
                        let _ = (syscalls.channel_write)(s.admin_out_chan, out.as_ptr(), out.len());
                    }
                    s.upstream_acked = s.upstream_acked.wrapping_add(1);
                } else {
                    let errno = if j.last_errno != 0 {
                        j.last_errno
                    } else {
                        super::body_wire::ERR_IO
                    };
                    emit_nak(s, syscalls, errno);
                    s.upstream_naked = s.upstream_naked.wrapping_add(1);
                }
                free_join(s, join_idx);
            }
        }
        KIND_SCRUB_SCAN => {
            free_join(s, join_idx);
            s.scrub_scan_inflight = 0;
            if resp_op != super::body_wire::OP_SCAN {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                scrub_next_member(s);
                return;
            }
            let mut keys =
                [[0u8; super::body_wire::DIGEST_LEN]; super::body_wire::MAX_SCAN_DIGESTS];
            let mut scan_keyed = [0u8; super::body_wire::MAX_SCAN_DIGESTS];
            match super::body_wire::decode_scan_resp(resp, &mut keys, &mut scan_keyed) {
                Ok((next, count)) => {
                    s.scrub_cursor = next;
                    if next == 0 {
                        scrub_next_member(s);
                    }
                    if count > 0 {
                        s.scrub_keys[..count].copy_from_slice(&keys[..count]);
                        s.scrub_q_len = count as u8;
                        s.scrub_q_pos = 0;
                        s.scrub_busy = 1;
                        scrub_start_ident(s, syscalls);
                    }
                }
                Err(_) => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    scrub_next_member(s);
                }
            }
        }
        KIND_SCRUB_IDENT => {
            let key = s.joins[join_idx as usize].digest;
            free_join(s, join_idx);
            scrub_apply_ident(s, syscalls, key, resp_op, resp);
        }
        KIND_SCRUB_PROBE => {
            let j = s.joins[join_idx as usize];
            if resp_op == super::body_wire::OP_HEAD {
                for r in 0..j.target_count {
                    if j.targets[r as usize] == from_target {
                        s.scrub_present |= 1u16 << r;
                        break;
                    }
                }
            }
            s.scrub_probe_resp = s.scrub_probe_resp.wrapping_add(1);
            if s.scrub_probe_resp >= j.need {
                free_join(s, join_idx);
                scrub_probe_resolve(s, syscalls);
            }
        }
        KIND_SCRUB_FETCH => {
            if resp_op == super::body_wire::OP_GET {
                let done = assembly_take_shard(s, syscalls, join_idx, from_target, resp);
                if !done {
                    s.joins[join_idx as usize].ack = s.joins[join_idx as usize].ack.wrapping_add(1);
                    scrub_fetch_check(s, syscalls, join_idx);
                }
            } else {
                s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
                scrub_fetch_check(s, syscalls, join_idx);
            }
        }
        KIND_SCRUB_REPAIR => {
            if resp_op == super::body_wire::OP_PUT_KEYED {
                s.scrub_repairs_ok = s.scrub_repairs_ok.wrapping_add(1);
            } else {
                s.scrub_repairs_failed = s.scrub_repairs_failed.wrapping_add(1);
            }
            free_join(s, join_idx);
        }
        KIND_SCRUB_CLEANUP => {
            free_join(s, join_idx);
        }
        _ => {
            free_join(s, join_idx);
            s.apply_errors = s.apply_errors.wrapping_add(1);
        }
    }
}

/// After each scrub-fetch response: can the assembly still reach
/// k shards? If not, give the body up now instead of waiting.
unsafe fn scrub_fetch_check(s: &mut ModuleState, syscalls: &super::SyscallTable, join_idx: u16) {
    let j = s.joins[join_idx as usize];
    if j.in_use == 0 {
        return;
    }
    let responded = j.ack.wrapping_add(j.fail);
    let outstanding = j.need.saturating_sub(responded) as usize;
    let present = s.assembly.present_mask.count_ones() as usize;
    if present + outstanding < s.ec_k as usize {
        scrub_fetch_failed(s, syscalls, join_idx);
    }
}

// ── EC scrub ───────────────────────────────────────────────────────

/// Send one SCAN page request to the current scrub member.
unsafe fn scrub_kick(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    // Local nonzero check so the % below can't be a div-by-zero
    // panic path (which would drag core's panic machinery into the
    // bare-metal link).
    let count = s.body_fleet_count;
    if count == 0 {
        return;
    }
    let target = s.scrub_target % count;
    s.scrub_target = target;
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => return,
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_SCRUB_SCAN;
        j.need = 1;
        j.gen
    };
    let req_n = match super::body_wire::encode_scan_req(
        &mut s.scratch,
        s.scrub_cursor,
        super::body_wire::MAX_SCAN_DIGESTS as u8,
    ) {
        Ok(n) => n,
        Err(_) => {
            free_join(s, join_idx);
            return;
        }
    };
    if dispatch_to_target(s, syscalls, target, join_idx, gen, req_n) {
        s.scrub_scan_inflight = 1;
        s.scrub_scanned_member = target;
        s.scrub_scans = s.scrub_scans.wrapping_add(1);
    } else {
        free_join(s, join_idx);
        scrub_next_member(s);
    }
}

unsafe fn scrub_next_member(s: &mut ModuleState) {
    s.scrub_cursor = 0;
    if s.body_fleet_count != 0 {
        s.scrub_target = (s.scrub_target + 1) % s.body_fleet_count;
    }
}

/// Advance to the next queued key, or go idle.
unsafe fn scrub_next_key(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    s.scrub_q_pos = s.scrub_q_pos.wrapping_add(1);
    if s.scrub_q_pos < s.scrub_q_len {
        scrub_start_ident(s, syscalls);
    } else {
        s.scrub_q_len = 0;
        s.scrub_q_pos = 0;
        s.scrub_busy = 0;
    }
}

/// IDENT: fetch the blob behind the queued key from the scanned
/// member — its header tells us what shard of what body it is.
unsafe fn scrub_start_ident(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    let key = s.scrub_keys[s.scrub_q_pos as usize];
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            s.scrub_skipped = s.scrub_skipped.wrapping_add(1);
            scrub_next_key(s, syscalls);
            return;
        }
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_SCRUB_IDENT;
        j.need = 1;
        j.digest = key;
        j.gen
    };
    s.scratch[0] = super::body_wire::OP_GET;
    s.scratch[1..1 + super::body_wire::DIGEST_LEN].copy_from_slice(&key);
    if !dispatch_to_target(
        s,
        syscalls,
        s.scrub_scanned_member,
        join_idx,
        gen,
        1 + super::body_wire::DIGEST_LEN,
    ) {
        free_join(s, join_idx);
        s.scrub_skipped = s.scrub_skipped.wrapping_add(1);
        scrub_next_key(s, syscalls);
    }
}

/// The IDENT blob arrived (or didn't). Validate it, stash the
/// payload, and launch the ranked-home probe.
unsafe fn scrub_skip(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    s.scrub_skipped = s.scrub_skipped.wrapping_add(1);
    scrub_next_key(s, syscalls);
}

unsafe fn scrub_apply_ident(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    key: [u8; super::body_wire::DIGEST_LEN],
    resp_op: u8,
    resp: &[u8],
) {
    if resp_op != super::body_wire::OP_GET {
        scrub_skip(s, syscalls);
        return;
    }
    let blob = match super::body_wire::decode_get_resp(resp) {
        Ok(b) => b,
        Err(_) => {
            scrub_skip(s, syscalls);
            return;
        }
    };
    let hdr = match super::ec_wire::decode_shard_header(blob) {
        Ok(h) => h,
        Err(_) => {
            // Not a shard blob (e.g. a whole-body blob) — not ours
            // to scrub.
            scrub_skip(s, syscalls);
            return;
        }
    };
    let (k, m) = (s.ec_k, s.ec_m);
    let total = k as usize + m as usize;
    if hdr.k != k
        || hdr.m != m
        || (hdr.index as usize) >= total
        || hdr.shard_len == 0
        || hdr.shard_len as usize > SHARD_SLOT
        || (hdr.body_len as usize) > super::body_wire::MAX_BODY
        || (hdr.body_len as usize) > k as usize * hdr.shard_len as usize
        || super::ec_wire::derive_shard_key(&hdr.body_digest, hdr.index) != key
    {
        scrub_skip(s, syscalls);
        return;
    }
    let payload = match super::ec_wire::shard_payload(blob) {
        Ok(p) => p,
        Err(_) => {
            scrub_skip(s, syscalls);
            return;
        }
    };
    let mut ranked = [0u8; MAX_FLEET];
    let chosen = rank_targets(s, &hdr.body_digest, &mut ranked);
    if chosen == 0 {
        scrub_skip(s, syscalls);
        return;
    }
    s.scrub_digest = hdr.body_digest;
    s.scrub_ident_index = hdr.index;
    s.scrub_shard_len = hdr.shard_len;
    s.scrub_body_len = hdr.body_len;
    s.scrub_shard_buf[..payload.len()].copy_from_slice(payload);
    s.scrub_ranked = ranked;
    s.scrub_ranked_count = chosen as u8;
    s.scrub_present = 0;
    s.scrub_probe_resp = 0;

    // PROBE: HEAD every shard at its ranked home.
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            scrub_skip(s, syscalls);
            return;
        }
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_SCRUB_PROBE;
        j.need = chosen as u8;
        j.target_count = chosen as u8;
        j.targets[..chosen].copy_from_slice(&ranked[..chosen]);
        j.digest = hdr.body_digest;
        j.gen
    };
    for (jdx, &member) in ranked[..chosen].iter().enumerate() {
        let shard_key = super::ec_wire::derive_shard_key(&hdr.body_digest, jdx as u8);
        s.scratch[0] = super::body_wire::OP_HEAD;
        s.scratch[1..1 + super::body_wire::DIGEST_LEN].copy_from_slice(&shard_key);
        if !dispatch_to_target(
            s,
            syscalls,
            member,
            join_idx,
            gen,
            1 + super::body_wire::DIGEST_LEN,
        ) {
            // Unreachable home: counts as a response with the
            // present bit left clear.
            s.scrub_probe_resp = s.scrub_probe_resp.wrapping_add(1);
        }
    }
    s.scrub_probes = s.scrub_probes.wrapping_add(1);
    if s.scrub_probe_resp >= chosen as u8 {
        free_join(s, join_idx);
        scrub_probe_resolve(s, syscalls);
    }
}

/// All ranked homes answered the probe — decide how to heal.
unsafe fn scrub_probe_resolve(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    let total = s.scrub_ranked_count as usize;
    let full: u16 = if total >= 16 {
        u16::MAX
    } else {
        (1u16 << total) - 1
    };
    let missing = full & !s.scrub_present;
    let i = s.scrub_ident_index as usize;
    let t = s.scrub_scanned_member;

    if missing == 0 {
        // Fully placed. If the scanned member is not this shard's
        // ranked home, the copy we identified is a stray — its home
        // is verified present, so delete it.
        if s.scrub_ranked[i] != t {
            scrub_dispatch_cleanup(s, syscalls, t);
        }
        scrub_next_key(s, syscalls);
        return;
    }
    if missing == (1u16 << i) {
        // Only the discovered shard's own home is missing — the
        // re-placement case. Copy the blob we already hold.
        scrub_dispatch_repair_from_buf(s, syscalls);
        s.scrub_replaced = s.scrub_replaced.wrapping_add(1);
        scrub_next_key(s, syscalls);
        return;
    }
    // Other shards are missing: reconstruct. Sources are the
    // ranked-home holders plus the shard in hand.
    let effective = s.scrub_present | (1u16 << i);
    if (effective.count_ones() as usize) < s.ec_k as usize {
        s.scrub_lost = s.scrub_lost.wrapping_add(1);
        scrub_next_key(s, syscalls);
        return;
    }
    if s.assembly.busy != 0 {
        // A client GET owns the buffer — retry this body on a
        // later round rather than stalling the pipeline.
        s.scrub_skipped = s.scrub_skipped.wrapping_add(1);
        scrub_next_key(s, syscalls);
        return;
    }
    s.scrub_repair_mask = missing;
    s.assembly.busy = 1;
    s.assembly.internal = 1;
    s.assembly.present_mask = 1u32 << i;
    s.assembly.shard_len = s.scrub_shard_len;
    s.assembly.body_len = s.scrub_body_len;
    s.assembly.digest = s.scrub_digest;
    let shard_len = s.scrub_shard_len as usize;
    let dst = i * SHARD_SLOT;
    for b in 0..shard_len {
        s.assembly.shards[dst + b] = s.scrub_shard_buf[b];
    }
    let join_idx = match alloc_join(s) {
        Some(idx) => idx,
        None => {
            s.assembly.busy = 0;
            s.assembly.internal = 0;
            s.scrub_skipped = s.scrub_skipped.wrapping_add(1);
            scrub_next_key(s, syscalls);
            return;
        }
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_SCRUB_FETCH;
        j.target_count = total as u8;
        j.targets[..total].copy_from_slice(&s.scrub_ranked[..total]);
        j.digest = s.scrub_digest;
        j.gen
    };
    let mut dispatched: u8 = 0;
    for jdx in 0..total {
        if jdx == i || s.scrub_present & (1u16 << jdx) == 0 {
            continue;
        }
        let shard_key = super::ec_wire::derive_shard_key(&s.scrub_digest, jdx as u8);
        s.scratch[0] = super::body_wire::OP_GET;
        s.scratch[1..1 + super::body_wire::DIGEST_LEN].copy_from_slice(&shard_key);
        if dispatch_to_target(
            s,
            syscalls,
            s.scrub_ranked[jdx],
            join_idx,
            gen,
            1 + super::body_wire::DIGEST_LEN,
        ) {
            dispatched = dispatched.wrapping_add(1);
        }
    }
    s.joins[join_idx as usize].need = dispatched;
    if 1 + (dispatched as usize) < s.ec_k as usize {
        scrub_fetch_failed(s, syscalls, join_idx);
    }
}

/// The scrub fetch can't reach k shards — give this body up for
/// now; a later round retries.
unsafe fn scrub_fetch_failed(s: &mut ModuleState, syscalls: &super::SyscallTable, join_idx: u16) {
    free_join(s, join_idx);
    s.assembly.busy = 0;
    s.assembly.internal = 0;
    s.scrub_lost = s.scrub_lost.wrapping_add(1);
    scrub_next_key(s, syscalls);
}

/// Re-encode every shard in `scrub_repair_mask` from the (fully
/// reconstructed, digest-verified) assembly and PUT_KEYED each to
/// its ranked home.
unsafe fn scrub_dispatch_repairs_from_assembly(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
) {
    let total = s.scrub_ranked_count as usize;
    let shard_len = s.assembly.shard_len as usize;
    for jdx in 0..total {
        if s.scrub_repair_mask & (1u16 << jdx) == 0 {
            continue;
        }
        let hdr = super::ec_wire::ShardHeader {
            k: s.ec_k,
            m: s.ec_m,
            index: jdx as u8,
            body_len: s.assembly.body_len,
            body_digest: s.assembly.digest,
            shard_len: s.assembly.shard_len,
        };
        let blob_n = match super::ec_wire::encode_shard_blob(
            &mut s.blob_buf,
            &hdr,
            &s.assembly.shards[jdx * shard_len..(jdx + 1) * shard_len],
        ) {
            Ok(n) => n,
            Err(_) => continue,
        };
        scrub_dispatch_one_repair(s, syscalls, jdx, blob_n);
    }
}

/// Direct copy: the IDENT shard's own home is the only gap.
unsafe fn scrub_dispatch_repair_from_buf(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    let i = s.scrub_ident_index as usize;
    let hdr = super::ec_wire::ShardHeader {
        k: s.ec_k,
        m: s.ec_m,
        index: i as u8,
        body_len: s.scrub_body_len,
        body_digest: s.scrub_digest,
        shard_len: s.scrub_shard_len,
    };
    let blob_n = match super::ec_wire::encode_shard_blob(
        &mut s.blob_buf,
        &hdr,
        &s.scrub_shard_buf[..s.scrub_shard_len as usize],
    ) {
        Ok(n) => n,
        Err(_) => return,
    };
    scrub_dispatch_one_repair(s, syscalls, i, blob_n);
}

/// PUT_KEYED `blob_buf[..blob_n]` (shard `jdx`) to its ranked home
/// as a fire-and-forget repair join.
unsafe fn scrub_dispatch_one_repair(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    jdx: usize,
    blob_n: usize,
) {
    let key = super::ec_wire::derive_shard_key(&s.scrub_digest, jdx as u8);
    let req_n =
        match super::body_wire::encode_put_keyed_req(&mut s.scratch, &key, &s.blob_buf[..blob_n]) {
            Ok(n) => n,
            Err(_) => {
                s.scrub_repairs_failed = s.scrub_repairs_failed.wrapping_add(1);
                return;
            }
        };
    let join_idx = match alloc_join(s) {
        Some(idx) => idx,
        None => {
            s.scrub_repairs_failed = s.scrub_repairs_failed.wrapping_add(1);
            return;
        }
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_SCRUB_REPAIR;
        j.need = 1;
        j.gen
    };
    if dispatch_to_target(s, syscalls, s.scrub_ranked[jdx], join_idx, gen, req_n) {
        s.scrub_repairs = s.scrub_repairs.wrapping_add(1);
    } else {
        free_join(s, join_idx);
        s.scrub_repairs_failed = s.scrub_repairs_failed.wrapping_add(1);
    }
}

/// DELETE the stray copy from the scanned member (only reached
/// when every ranked home is verified present).
unsafe fn scrub_dispatch_cleanup(s: &mut ModuleState, syscalls: &super::SyscallTable, member: u8) {
    let key = super::ec_wire::derive_shard_key(&s.scrub_digest, s.scrub_ident_index);
    let join_idx = match alloc_join(s) {
        Some(idx) => idx,
        None => return,
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_SCRUB_CLEANUP;
        j.need = 1;
        j.gen
    };
    s.scratch[0] = super::body_wire::OP_DELETE;
    s.scratch[1..1 + super::body_wire::DIGEST_LEN].copy_from_slice(&key);
    if dispatch_to_target(
        s,
        syscalls,
        member,
        join_idx,
        gen,
        1 + super::body_wire::DIGEST_LEN,
    ) {
        s.scrub_cleanups = s.scrub_cleanups.wrapping_add(1);
    } else {
        free_join(s, join_idx);
    }
}

unsafe fn emit_nak(s: &ModuleState, syscalls: &super::SyscallTable, errno: u8) {
    let mut buf = [0u8; 2];
    if super::body_wire::encode_nak(&mut buf, errno).is_ok() {
        let _ = (syscalls.channel_write)(s.admin_out_chan, buf.as_ptr(), buf.len());
    }
}
