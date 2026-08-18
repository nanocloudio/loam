// Shared step-body for `body_fanout_router`. Sits between
// `admin_router` (or any single-channel body consumer) and a fleet
// of `body_store` instances. Subscribes to `placement_router`'s
// FleetEpoch broadcast, caches the current fleet snapshot, and on
// each upstream PUT computes per-body target indices via
// `loam_placement::pick_targets`, fans the PUT to each chosen
// member, and only acks upstream once every chosen replica has
// reported success.
//
// Why a router PIC rather than a body_store-internal multi-root?
// Channels-as-state-surfaces: the placement decision is published
// state on a channel (FleetEpoch), and per-replica health is a
// per-target channel concern. Keeping the body_store PIC single-
// rooted preserves the simple disk-backed invariant; the
// replication concern lives here.
//
// Semantics:
//   - PUT: fans out to `min(replica_count, fleet.count)` targets,
//          ranked by rendezvous order over the body's first 32
//          bytes (zero-padded). All-must-succeed semantics: any
//          target NAK causes an upstream NAK.
//   - GET/HEAD: serial fallback through the ranked replica set.
//          The primary is tried first; a NAK (or a dead channel)
//          advances to the next-ranked replica. Only when every
//          ranked replica has failed is a NAK forwarded upstream.
//   - READ REPAIR: when a GET succeeds on a fallback replica and
//          one or more earlier-ranked replicas NAKed NOT_FOUND,
//          the returned body is re-PUT to those replicas
//          (best-effort, one-shot, never surfaced upstream).
//   - DELETE: fans out to the full ranked replica set (a primary-
//          only delete would strand the blob on secondaries).
//          Upstream response is DeleteResp(existed = OR of replica
//          flags) if any replica responded OK; NAK only when every
//          replica failed.
//   - SCRUB: when `scrub_interval` is nonzero, the router
//          periodically SCANs each target's digest inventory,
//          HEAD-probes every digest's ranked replica set, and
//          re-replicates bodies missing from ranked replicas —
//          under-replication is found and healed without waiting
//          for a client read.
//
// Bounded step contract: at most MAX_OPS_PER_STEP upstream
// requests + MAX_OPS_PER_STEP responses-per-target are handled
// per `module_step` call. Per-request join state lives in a fixed-
// size JOIN_CAP table; join slots carry a generation stamp so a
// late response for a freed-and-reused slot is dropped instead of
// misattributed.

const MAX_OPS_PER_STEP: u32 = 4;
// Buffers derive from the wire cap so a max-size body can't be
// truncated on the way through the router (body_store idiom).
const READ_BUF: usize = super::body_wire::MAX_BODY + 64;
const SCRATCH: usize = super::body_wire::MAX_BODY + 64;
const PENDING_CAP: usize = 64;
const JOIN_CAP: usize = 32;
const DEFAULT_REPLICA_COUNT: u8 = 1;

const KIND_CLIENT: u8 = 0;
const KIND_REPAIR: u8 = 1;
const KIND_SCRUB_SCAN: u8 = 2;
const KIND_SCRUB_PROBE: u8 = 3;
const KIND_SCRUB_FETCH: u8 = 4;
const KIND_STREAM_OPEN: u8 = 5;
const KIND_STREAM_APPEND: u8 = 6;
const KIND_STREAM_COMMIT: u8 = 7;
const KIND_STREAM_ABORT: u8 = 8;

/// Concurrent upstream streams the router can fan out.
const ROUTER_STREAMS: usize = 4;

use super::placement::Fleet;
use super::placement_wire::MAX_FLEET;

/// Per-target FIFO entry: which join slot (and which incarnation of
/// it) this downstream response is expected to satisfy. Channels
/// are FIFO so the per-target dequeue head matches response order.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct PendingTarget {
    pub in_use: u8,
    pub join_idx: u16,
    pub join_gen: u16,
}

/// Aggregated per-upstream-request state.
///
/// PUT: `need` replicas fanned, `ack`/`fail` counted, first OK
/// digest captured for the upstream PutResp.
/// GET/HEAD: `targets[..target_count]` is the ranked replica set,
/// `attempt` the cursor of the in-flight try, `not_found_mask` the
/// ranked indices that NAKed NOT_FOUND (repair candidates).
/// DELETE: `need` replicas fanned, `existed` ORs the per-replica
/// existed flags.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct JoinSlot {
    pub in_use: u8,
    pub kind: u8, // KIND_CLIENT | KIND_REPAIR
    pub op: u8,
    pub need: u8, // replicas to wait for (PUT / DELETE)
    pub ack: u8,
    pub fail: u8,
    pub existed: u8, // DELETE: OR of replica existed flags
    pub digest_set: u8,
    pub attempt: u8, // GET/HEAD: ranked-target cursor
    pub target_count: u8,
    pub last_errno: u8, // most recent downstream NAK errno
    pub gen: u16,       // incarnation stamp (stale-response guard)
    pub not_found_mask: u16,
    pub present_mask: u16, // SCRUB_PROBE: ranked indices that HeadResp'd
    pub repair_count: u8,  // SCRUB_FETCH: members to re-PUT on success
    pub stream_idx: u8,    // KIND_STREAM_*: which RouterStream
    pub range_off: u64,    // OP_RANGE walk: request offset
    pub range_len: u32,    // OP_RANGE walk: request length
    pub repair_targets: [u8; MAX_FLEET],
    pub targets: [u8; MAX_FLEET],
    /// PUT: digest from the first replica OK. GET/HEAD: the
    /// requested digest (needed to re-encode fallback requests).
    pub digest: [u8; super::body_wire::DIGEST_LEN],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct RouterStream {
    pub in_use: u8,
    pub targets: [u8; MAX_FLEET],
    pub count: u8,
    pub member_wid: [u8; MAX_FLEET],
}

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    /// Upstream-facing input (admin_router speaks body_wire here).
    pub admin_in_chan: i32,
    /// Upstream-facing output (PutResp / NAK back to admin_router).
    pub admin_out_chan: i32,
    /// FleetEpoch subscription. -1 disables placement updates;
    /// the cached fleet stays whatever it was last initialized to.
    pub fleet_in_chan: i32,
    /// Per-target downstream request channels. Slot i corresponds
    /// to fleet member index i (not member ID); `body_fleet_count`
    /// determines which slots are wired.
    pub body_req_chans: [i32; MAX_FLEET],
    pub body_resp_chans: [i32; MAX_FLEET],
    pub body_fleet_count: u8,
    /// Replica count config. PUT/DELETE fan out to (and GET/HEAD
    /// fall back through) min(this, fleet.count) targets.
    pub replica_count: u8,
    /// Cached fleet snapshot, populated from FleetEpoch reads.
    pub fleet_epoch: u64,
    pub fleet_members: [u8; MAX_FLEET],
    pub fleet_count: u8,
    /// Per-target FIFO ring (channels are FIFO; entry order = response
    /// order). `head/tail/pending` are parallel arrays indexed by
    /// target slot.
    pub per_target_head: [u32; MAX_FLEET],
    pub per_target_tail: [u32; MAX_FLEET],
    pub per_target_pending: [[PendingTarget; PENDING_CAP]; MAX_FLEET],
    pub joins: [JoinSlot; JOIN_CAP],
    pub join_gen: u16,
    /// Upstream chunked streams fanned to the replica set:
    /// stream sid ↔ per-member store wids. All-must-succeed at
    /// every stage (open/append/commit), like single-shot PUT.
    pub streams: [RouterStream; ROUTER_STREAMS],
    pub scratch: [u8; SCRATCH],
    pub ticks: u32,
    pub fanned_out: u32,
    pub upstream_acked: u32,
    pub upstream_naked: u32,
    pub read_fallbacks: u32,
    pub repairs_started: u32,
    pub repairs_ok: u32,
    pub repairs_failed: u32,
    /// Background scrub: every `scrub_interval` ticks (0 = scrub
    /// off) the router SCANs one page of one target's digest
    /// inventory, HEAD-probes each digest's ranked replica set,
    /// and re-replicates bodies that are present somewhere but
    /// missing from a ranked replica. Targets are walked
    /// round-robin over ALL wired channel slots — so bodies
    /// stranded on a member that left the fleet still get probed
    /// (and repaired onto the current fleet).
    pub scrub_interval: u32,
    pub scrub_target: u8,
    pub scrub_cursor: u32,
    pub scrub_scan_inflight: u8,
    pub scrub_scans: u32,
    pub scrub_probes: u32,
    pub scrub_fetches: u32,
    pub scrub_fetch_failed: u32,
    pub apply_errors: u32,
}

/// Init with no downstream targets wired and an empty fleet.
/// Mainly useful for incremental host-test setup; production
/// callers should use `module_new_with_targets_impl`.
pub unsafe fn module_new_impl(
    admin_in_chan: i32,
    admin_out_chan: i32,
    fleet_in_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(
        admin_in_chan,
        admin_out_chan,
        fleet_in_chan,
        &[],
        &[],
        DEFAULT_REPLICA_COUNT,
        0,
        state_ptr,
        state_size,
        syscalls,
    )
}

/// Init with the downstream body channel arrays + replica count.
/// `req_chans` and `resp_chans` must be the same length (the
/// number of body_store fleet members this router fronts). The
/// cached fleet is empty until the first FleetEpoch arrives; in
/// the absence of a placement_router subscription, callers can
/// drive `set_fleet_for_test` to seed the snapshot directly.
pub unsafe fn module_new_with_targets_impl(
    admin_in_chan: i32,
    admin_out_chan: i32,
    fleet_in_chan: i32,
    req_chans: &[i32],
    resp_chans: &[i32],
    replica_count: u8,
    scrub_interval: u32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(
        admin_in_chan,
        admin_out_chan,
        fleet_in_chan,
        req_chans,
        resp_chans,
        replica_count,
        scrub_interval,
        state_ptr,
        state_size,
        syscalls,
    )
}

/// Host-test helper: directly seed the cached fleet snapshot so a
/// PUT can be exercised without a live placement_router on the
/// fleet_in_chan side. Members must reference slot indices in
/// `body_req_chans[0..body_fleet_count]`.
pub unsafe fn set_fleet_for_test(state_ptr: *mut u8, epoch: u64, members: &[u8]) {
    let s = &mut *(state_ptr as *mut ModuleState);
    let take = members.len().min(MAX_FLEET);
    s.fleet_members[..take].copy_from_slice(&members[..take]);
    s.fleet_count = take as u8;
    s.fleet_epoch = epoch;
}

unsafe fn init_state(
    admin_in_chan: i32,
    admin_out_chan: i32,
    fleet_in_chan: i32,
    req_chans: &[i32],
    resp_chans: &[i32],
    replica_count: u8,
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
    s.replica_count = if replica_count == 0 {
        DEFAULT_REPLICA_COUNT
    } else {
        replica_count
    };
    s.scrub_interval = scrub_interval;
    0
}

fn body_key_from_bytes(body: &[u8]) -> [u8; super::placement::DIGEST_LEN] {
    let mut k = [0u8; super::placement::DIGEST_LEN];
    let take = body.len().min(super::placement::DIGEST_LEN);
    k[..take].copy_from_slice(&body[..take]);
    k
}

unsafe fn alloc_join(s: &mut ModuleState) -> Option<u16> {
    for i in 0..s.joins.len() {
        if s.joins[i].in_use == 0 {
            s.join_gen = s.join_gen.wrapping_add(1);
            let gen = s.join_gen;
            let slot = &mut s.joins[i];
            *slot = JoinSlot {
                in_use: 1,
                kind: KIND_CLIENT,
                op: 0,
                need: 0,
                ack: 0,
                fail: 0,
                existed: 0,
                digest_set: 0,
                attempt: 0,
                target_count: 0,
                last_errno: 0,
                gen,
                not_found_mask: 0,
                present_mask: 0,
                repair_count: 0,
                stream_idx: 0,
                range_off: 0,
                range_len: 0,
                repair_targets: [0u8; MAX_FLEET],
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

/// Undo the most recent `enqueue_target` for this target (the
/// downstream write failed, so no response will ever arrive).
/// Steps the TAIL back — popping the head would evict someone
/// else's in-flight entry and desync the whole FIFO.
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

    // ── 1. Drain FleetEpoch updates. ────────────────────────────
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
                Err(_) => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                }
            }
            handled = handled.wrapping_add(1);
        }
    }

    // ── 2. Background scrub: kick one SCAN when due. ────────────
    if s.scrub_interval != 0
        && s.body_fleet_count != 0
        && s.scrub_scan_inflight == 0
        && s.ticks % s.scrub_interval == 0
    {
        scrub_kick(s, syscalls);
    }

    // ── 3. Drain upstream body requests, fan out / route. ───────
    let mut handled: u32 = 0;
    while handled < MAX_OPS_PER_STEP {
        let mut buf = [0u8; READ_BUF];
        let n = (syscalls.channel_read)(s.admin_in_chan, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        let bytes = &buf[..n as usize];
        let op = super::body_wire::peek_opcode(bytes).unwrap_or(0xFF);
        match op {
            super::body_wire::OP_PUT => handle_put(s, syscalls, bytes),
            super::body_wire::OP_PUT_KEYED => handle_put_keyed(s, syscalls, bytes),
            super::body_wire::OP_GET | super::body_wire::OP_HEAD => {
                handle_read(s, syscalls, bytes);
            }
            super::body_wire::OP_DELETE => handle_delete(s, syscalls, bytes),
            super::body_wire::OP_WOPEN => handle_stream_open(s, syscalls, bytes),
            super::body_wire::OP_WAPPEND => handle_stream_append(s, syscalls, bytes),
            super::body_wire::OP_WCOMMIT => {
                handle_stream_ctl(s, syscalls, bytes, super::body_wire::OP_WCOMMIT);
            }
            super::body_wire::OP_WABORT => {
                handle_stream_ctl(s, syscalls, bytes, super::body_wire::OP_WABORT);
            }
            super::body_wire::OP_RANGE => handle_range_read(s, syscalls, bytes),
            _ => {
                emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            }
        }
        handled = handled.wrapping_add(1);
    }

    // ── 4. Drain per-target responses, aggregate into joins. ───
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
                        // Stale response — join was resolved/freed
                        // (and possibly reallocated). Drop.
                        s.apply_errors = s.apply_errors.wrapping_add(1);
                    } else {
                        apply_join_response(s, syscalls, pending.join_idx, t as u8, resp);
                    }
                }
                None => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                }
            }
            drained = drained.wrapping_add(1);
        }
    }

    0
}

/// Rank the replica set for `key` from the cached fleet snapshot.
/// Returns the number of targets written into `out`.
unsafe fn rank_targets(
    s: &ModuleState,
    key: &[u8; super::placement::DIGEST_LEN],
    out: &mut [u8; MAX_FLEET],
) -> usize {
    let effective = (s.replica_count as usize).min(s.fleet_count as usize);
    if effective == 0 {
        return 0;
    }
    let fleet = Fleet::from_slice(s.fleet_epoch, &s.fleet_members[..s.fleet_count as usize]);
    super::placement::pick_targets(key, effective as u8, &fleet, out)
}

unsafe fn handle_put(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let body = match super::body_wire::decode_put_req(bytes) {
        Ok(b) => b,
        Err(_) => {
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    // Compute placement: rendezvous over the body's first 32 bytes.
    let key = body_key_from_bytes(body);
    let mut targets_buf = [0u8; MAX_FLEET];
    let chosen = rank_targets(s, &key, &mut targets_buf);
    if chosen == 0 {
        // No fleet — nothing to write to.
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    // Reserve a join slot.
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    {
        let j = &mut s.joins[join_idx as usize];
        j.op = super::body_wire::OP_PUT;
        j.need = chosen as u8;
    }

    // Encode the body once into scratch and forward to each chosen
    // target's request channel. The fleet member IDs ARE the
    // target-slot indices in `body_req_chans[..body_fleet_count]`.
    let req_n = match super::body_wire::encode_put_req(&mut s.scratch, body) {
        Ok(n) => n,
        Err(_) => {
            free_join(s, join_idx);
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let gen = s.joins[join_idx as usize].gen;
    for i in 0..chosen {
        let member_id = targets_buf[i];
        if !dispatch_to_target(s, syscalls, member_id, join_idx, gen, req_n) {
            s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
        }
    }

    // If every fan-out attempt failed during dispatch, resolve the
    // join immediately as an upstream NAK.
    let j = s.joins[join_idx as usize];
    if j.fail == j.need {
        free_join(s, join_idx);
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
    }
}

/// Keyed put: same strict all-must-succeed fan-out as PUT, but the
/// placement key IS the request's explicit key (so extents and EC
/// shards land on the replica set a later GET-by-key will rank),
/// and the ack echoes the key instead of a computed digest.
unsafe fn handle_put_keyed(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let (key_bytes, blob) = match super::body_wire::decode_put_keyed_req(bytes) {
        Ok(v) => v,
        Err(_) => {
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let mut key = [0u8; super::body_wire::DIGEST_LEN];
    key.copy_from_slice(key_bytes);
    let mut targets_buf = [0u8; MAX_FLEET];
    let chosen = rank_targets(s, &key, &mut targets_buf);
    if chosen == 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    {
        let j = &mut s.joins[join_idx as usize];
        j.op = super::body_wire::OP_PUT_KEYED;
        j.need = chosen as u8;
        j.digest = key;
        j.digest_set = 1;
    }
    let req_n = match super::body_wire::encode_put_keyed_req(&mut s.scratch, &key, blob) {
        Ok(n) => n,
        Err(_) => {
            free_join(s, join_idx);
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let gen = s.joins[join_idx as usize].gen;
    for i in 0..chosen {
        let member_id = targets_buf[i];
        if !dispatch_to_target(s, syscalls, member_id, join_idx, gen, req_n) {
            s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
        }
    }
    let j = s.joins[join_idx as usize];
    if j.fail == j.need {
        free_join(s, join_idx);
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
    }
}

/// Write `req_n` bytes of `s.scratch` to `member_id`'s request
/// channel with a pending-FIFO entry for the join. Returns false
/// (with the enqueue unwound) if the target is unwired or the
/// write fails — no response will arrive for a false return.
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

/// GET / HEAD: serial fallback through the ranked replica set.
unsafe fn handle_read(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    if bytes.len() < 1 + super::body_wire::DIGEST_LEN {
        emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let mut key = [0u8; super::placement::DIGEST_LEN];
    key.copy_from_slice(&bytes[1..1 + super::body_wire::DIGEST_LEN]);
    let mut targets_buf = [0u8; MAX_FLEET];
    let chosen = rank_targets(s, &key, &mut targets_buf);
    if chosen == 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_NOT_FOUND);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    {
        let j = &mut s.joins[join_idx as usize];
        j.op = bytes[0]; // OP_GET / OP_HEAD
        j.need = 1;
        j.target_count = chosen as u8;
        j.targets[..chosen].copy_from_slice(&targets_buf[..chosen]);
        j.digest.copy_from_slice(&key);
    }
    advance_read(s, syscalls, join_idx);
}

/// Dispatch a digest-walk join's current attempt ([op][digest] to
/// `targets[attempt]`), skipping past targets that can't even be
/// dispatched to. Used by client GET/HEAD fallback (exhaustion =
/// upstream NAK carrying the last downstream errno) and by scrub
/// fetches (exhaustion = counted, nothing upstream).
unsafe fn advance_read(s: &mut ModuleState, syscalls: &super::SyscallTable, join_idx: u16) {
    loop {
        let (op, kind, digest, attempt, target_count, gen, last_errno) = {
            let j = &s.joins[join_idx as usize];
            (
                j.op,
                j.kind,
                j.digest,
                j.attempt,
                j.target_count,
                j.gen,
                j.last_errno,
            )
        };
        if attempt >= target_count {
            free_join(s, join_idx);
            if kind == KIND_SCRUB_FETCH {
                s.scrub_fetch_failed = s.scrub_fetch_failed.wrapping_add(1);
            } else {
                let errno = if last_errno == 0 {
                    super::body_wire::ERR_IO
                } else {
                    last_errno
                };
                emit_nak(s, syscalls, errno);
                s.upstream_naked = s.upstream_naked.wrapping_add(1);
            }
            return;
        }
        let member_id = s.joins[join_idx as usize].targets[attempt as usize];
        // Re-encode the request into scratch.
        let req_n = if op == super::body_wire::OP_RANGE {
            let (off, len) = {
                let j = &s.joins[join_idx as usize];
                (j.range_off, j.range_len)
            };
            match super::body_wire::encode_range_req(&mut s.scratch, &digest, off, len) {
                Ok(n) => n,
                Err(_) => {
                    free_join(s, join_idx);
                    emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
                    return;
                }
            }
        } else {
            s.scratch[0] = op;
            s.scratch[1..1 + super::body_wire::DIGEST_LEN].copy_from_slice(&digest);
            1 + super::body_wire::DIGEST_LEN
        };
        if dispatch_to_target(s, syscalls, member_id, join_idx, gen, req_n) {
            return;
        }
        // Dead target: not a repair candidate (nothing tells us the
        // blob is missing there), just skip past it.
        let j = &mut s.joins[join_idx as usize];
        j.last_errno = super::body_wire::ERR_IO;
        j.attempt = j.attempt.wrapping_add(1);
        if kind == KIND_CLIENT {
            s.read_fallbacks = s.read_fallbacks.wrapping_add(1);
        }
    }
}

/// DELETE: fan out to the full ranked replica set. A primary-only
/// delete would leave the blob live on the secondaries forever.
unsafe fn handle_delete(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    if bytes.len() < 1 + super::body_wire::DIGEST_LEN {
        emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let mut key = [0u8; super::placement::DIGEST_LEN];
    key.copy_from_slice(&bytes[1..1 + super::body_wire::DIGEST_LEN]);
    let mut targets_buf = [0u8; MAX_FLEET];
    let chosen = rank_targets(s, &key, &mut targets_buf);
    if chosen == 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_NOT_FOUND);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    {
        let j = &mut s.joins[join_idx as usize];
        j.op = super::body_wire::OP_DELETE;
        j.need = chosen as u8;
    }
    // Forward the request bytes verbatim to every ranked replica.
    s.scratch[..bytes.len()].copy_from_slice(bytes);
    let gen = s.joins[join_idx as usize].gen;
    for i in 0..chosen {
        let member_id = targets_buf[i];
        if !dispatch_to_target(s, syscalls, member_id, join_idx, gen, bytes.len()) {
            s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
        }
    }
    let j = s.joins[join_idx as usize];
    if j.fail == j.need {
        free_join(s, join_idx);
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
    }
}

// ── Chunked streams: fan the write to the replica set ─────────────

/// RANGE reads walk the ranked replica set exactly like GET —
/// same join machinery, the request just carries (off, len).
unsafe fn handle_range_read(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let (digest_bytes, off, len) = match super::body_wire::decode_range_req(bytes) {
        Ok(v) => v,
        Err(_) => {
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            return;
        }
    };
    let mut digest = [0u8; super::body_wire::DIGEST_LEN];
    digest.copy_from_slice(digest_bytes);
    let mut targets_buf = [0u8; MAX_FLEET];
    let chosen = rank_targets(s, &digest, &mut targets_buf);
    if chosen == 0 {
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
        j.op = super::body_wire::OP_RANGE;
        j.need = 1;
        j.target_count = chosen as u8;
        j.targets[..chosen].copy_from_slice(&targets_buf[..chosen]);
        j.digest = digest;
        j.range_off = off;
        j.range_len = len;
    }
    advance_read(s, syscalls, join_idx);
}

unsafe fn free_stream(s: &mut ModuleState, sid: usize) {
    if sid < ROUTER_STREAMS {
        s.streams[sid].in_use = 0;
    }
}

/// Best-effort WABORT to every member of a failing stream, then
/// free it. The caller owns the upstream NAK.
unsafe fn abort_stream_members(s: &mut ModuleState, syscalls: &super::SyscallTable, sid: usize) {
    let stream = s.streams[sid];
    for i in 0..stream.count as usize {
        let member = stream.targets[i];
        let join_idx = match alloc_join(s) {
            Some(idx) => idx,
            None => continue,
        };
        let gen = {
            let j = &mut s.joins[join_idx as usize];
            j.kind = KIND_STREAM_ABORT;
            j.op = super::body_wire::OP_WABORT;
            j.need = 1;
            j.stream_idx = 0xFF; // fire-and-forget: no upstream reply
            j.gen
        };
        let req_n = match super::body_wire::encode_wabort_req(&mut s.scratch, stream.member_wid[i])
        {
            Ok(n) => n,
            Err(_) => {
                free_join(s, join_idx);
                continue;
            }
        };
        if !dispatch_to_target(s, syscalls, member, join_idx, gen, req_n) {
            free_join(s, join_idx);
        }
    }
    free_stream(s, sid);
}

/// WOPEN: rank the replica set for the DECLARED digest (that is
/// what makes streamed placement identical to single-shot) and
/// open a session on every member.
unsafe fn handle_stream_open(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let (digest_bytes, total_len) = match super::body_wire::decode_wopen_req(bytes) {
        Ok(v) => v,
        Err(_) => {
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            return;
        }
    };
    let mut digest = [0u8; super::body_wire::DIGEST_LEN];
    digest.copy_from_slice(digest_bytes);
    let mut targets_buf = [0u8; MAX_FLEET];
    let chosen = rank_targets(s, &digest, &mut targets_buf);
    if chosen == 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
        return;
    }
    let sid = match (0..ROUTER_STREAMS).find(|&i| s.streams[i].in_use == 0) {
        Some(i) => i,
        None => {
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            return;
        }
    };
    {
        let st = &mut s.streams[sid];
        st.in_use = 1;
        st.count = chosen as u8;
        st.targets[..chosen].copy_from_slice(&targets_buf[..chosen]);
        st.member_wid = [0u8; MAX_FLEET];
    }
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            free_stream(s, sid);
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            return;
        }
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_STREAM_OPEN;
        j.op = super::body_wire::OP_WOPEN;
        j.need = chosen as u8;
        j.target_count = chosen as u8;
        j.targets[..chosen].copy_from_slice(&targets_buf[..chosen]);
        j.stream_idx = sid as u8;
        j.gen
    };
    let req_n = match super::body_wire::encode_wopen_req(&mut s.scratch, &digest, total_len) {
        Ok(n) => n,
        Err(_) => {
            free_join(s, join_idx);
            free_stream(s, sid);
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            return;
        }
    };
    for i in 0..chosen {
        if !dispatch_to_target(s, syscalls, targets_buf[i], join_idx, gen, req_n) {
            s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
        }
    }
    let j = s.joins[join_idx as usize];
    if j.fail > 0 {
        free_join(s, join_idx);
        abort_stream_members(s, syscalls, sid);
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
    }
}

/// WAPPEND: forward the chunk to every member under its wid.
unsafe fn handle_stream_append(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let (sid, chunk_len) = match super::body_wire::decode_wappend_req(bytes) {
        Ok((sid, chunk)) => (sid as usize, chunk.len()),
        Err(_) => {
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            return;
        }
    };
    if sid >= ROUTER_STREAMS || s.streams[sid].in_use == 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
        return;
    }
    let stream = s.streams[sid];
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            abort_stream_members(s, syscalls, sid);
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            return;
        }
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_STREAM_APPEND;
        j.op = super::body_wire::OP_WAPPEND;
        j.need = stream.count;
        j.stream_idx = sid as u8;
        j.gen
    };
    // Re-frame per member: same chunk, that member's wid. The
    // chunk sits at bytes[6..6+len] in the upstream frame.
    for i in 0..stream.count as usize {
        s.scratch[0] = super::body_wire::OP_WAPPEND;
        s.scratch[1] = stream.member_wid[i];
        s.scratch[2..6].copy_from_slice(&(chunk_len as u32).to_le_bytes());
        s.scratch[6..6 + chunk_len].copy_from_slice(&bytes[6..6 + chunk_len]);
        if !dispatch_to_target(s, syscalls, stream.targets[i], join_idx, gen, 6 + chunk_len) {
            s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
        }
    }
    let j = s.joins[join_idx as usize];
    if j.fail > 0 {
        free_join(s, join_idx);
        abort_stream_members(s, syscalls, sid);
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
    }
}

/// WCOMMIT / WABORT: forward to every member.
unsafe fn handle_stream_ctl(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    bytes: &[u8],
    op: u8,
) {
    let sid = match super::body_wire::decode_wid_req(bytes, op) {
        Ok(w) => w as usize,
        Err(_) => {
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            return;
        }
    };
    if sid >= ROUTER_STREAMS || s.streams[sid].in_use == 0 {
        emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
        return;
    }
    let stream = s.streams[sid];
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            abort_stream_members(s, syscalls, sid);
            emit_nak(s, syscalls, super::body_wire::ERR_IO);
            return;
        }
    };
    let kind = if op == super::body_wire::OP_WCOMMIT {
        KIND_STREAM_COMMIT
    } else {
        KIND_STREAM_ABORT
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = kind;
        j.op = op;
        j.need = stream.count;
        j.stream_idx = sid as u8;
        j.gen
    };
    for i in 0..stream.count as usize {
        s.scratch[0] = op;
        s.scratch[1] = stream.member_wid[i];
        if !dispatch_to_target(s, syscalls, stream.targets[i], join_idx, gen, 2) {
            s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
        }
    }
    let j = s.joins[join_idx as usize];
    if j.fail > 0 && kind == KIND_STREAM_COMMIT {
        free_join(s, join_idx);
        abort_stream_members(s, syscalls, sid);
        emit_nak(s, syscalls, super::body_wire::ERR_IO);
    } else if j.fail == j.need {
        // Abort with every dispatch failed: nothing to wait for.
        free_join(s, join_idx);
        free_stream(s, sid);
        let mut out = [0u8; 1];
        if super::body_wire::encode_wabort_resp(&mut out).is_ok() {
            let _ = (syscalls.channel_write)(s.admin_out_chan, out.as_ptr(), 1);
        }
    }
}

unsafe fn apply_join_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    join_idx: u16,
    from_target: u8,
    resp: &[u8],
) {
    let (j_op, j_kind) = {
        let j = &s.joins[join_idx as usize];
        (j.op, j.kind)
    };
    let resp_op = super::body_wire::peek_opcode(resp).unwrap_or(0xFF);
    let succeeded = resp_op == j_op;
    let nak_errno = if resp_op == super::body_wire::OP_NAK && resp.len() >= 2 {
        resp[1]
    } else {
        super::body_wire::ERR_IO
    };

    // ── Repair joins: count, free, never touch upstream. ────────
    if j_kind == KIND_REPAIR {
        if succeeded {
            s.repairs_ok = s.repairs_ok.wrapping_add(1);
        } else {
            s.repairs_failed = s.repairs_failed.wrapping_add(1);
        }
        free_join(s, join_idx);
        return;
    }

    // ── Scrub joins: never touch upstream. ──────────────────────
    if j_kind == KIND_SCRUB_SCAN {
        free_join(s, join_idx);
        scrub_apply_scan(s, syscalls, succeeded, resp);
        return;
    }
    if j_kind == KIND_SCRUB_PROBE {
        scrub_apply_probe(s, syscalls, join_idx, from_target, succeeded, nak_errno);
        return;
    }
    if j_kind == KIND_SCRUB_FETCH {
        if succeeded {
            let j = s.joins[join_idx as usize];
            free_join(s, join_idx);
            let members = j.repair_targets;
            spawn_repair_puts(s, syscalls, &members[..j.repair_count as usize], resp);
        } else {
            s.joins[join_idx as usize].attempt = s.joins[join_idx as usize].attempt.wrapping_add(1);
            advance_read(s, syscalls, join_idx);
        }
        return;
    }

    // ── Chunked-stream joins ────────────────────────────────────
    if j_kind == KIND_STREAM_OPEN {
        let sid = s.joins[join_idx as usize].stream_idx as usize;
        if succeeded {
            // Record which wid THIS member assigned.
            let wid = super::body_wire::decode_wopen_resp(resp).unwrap_or(0);
            let j = s.joins[join_idx as usize];
            for r in 0..j.target_count as usize {
                if j.targets[r] == from_target && sid < ROUTER_STREAMS {
                    s.streams[sid].member_wid[r] = wid;
                    break;
                }
            }
            s.joins[join_idx as usize].ack = s.joins[join_idx as usize].ack.wrapping_add(1);
            let j = s.joins[join_idx as usize];
            if j.ack == j.need {
                free_join(s, join_idx);
                let mut out = [0u8; 2];
                if super::body_wire::encode_wopen_resp(&mut out, sid as u8).is_ok() {
                    let _ = (syscalls.channel_write)(s.admin_out_chan, out.as_ptr(), 2);
                }
                s.upstream_acked = s.upstream_acked.wrapping_add(1);
            }
        } else {
            free_join(s, join_idx);
            abort_stream_members(s, syscalls, sid);
            emit_nak(s, syscalls, nak_errno);
            s.upstream_naked = s.upstream_naked.wrapping_add(1);
        }
        return;
    }
    if j_kind == KIND_STREAM_APPEND {
        let sid = s.joins[join_idx as usize].stream_idx as usize;
        if succeeded {
            s.joins[join_idx as usize].ack = s.joins[join_idx as usize].ack.wrapping_add(1);
            let j = s.joins[join_idx as usize];
            if j.ack == j.need {
                free_join(s, join_idx);
                let mut out = [0u8; 2];
                if super::body_wire::encode_wappend_resp(&mut out, sid as u8).is_ok() {
                    let _ = (syscalls.channel_write)(s.admin_out_chan, out.as_ptr(), 2);
                }
                s.upstream_acked = s.upstream_acked.wrapping_add(1);
            }
        } else {
            free_join(s, join_idx);
            abort_stream_members(s, syscalls, sid);
            emit_nak(s, syscalls, nak_errno);
            s.upstream_naked = s.upstream_naked.wrapping_add(1);
        }
        return;
    }
    if j_kind == KIND_STREAM_COMMIT {
        let sid = s.joins[join_idx as usize].stream_idx as usize;
        if succeeded {
            if s.joins[join_idx as usize].digest_set == 0 {
                if let Ok(d) = super::body_wire::decode_wcommit_resp(resp) {
                    s.joins[join_idx as usize].digest.copy_from_slice(d);
                    s.joins[join_idx as usize].digest_set = 1;
                }
            }
            s.joins[join_idx as usize].ack = s.joins[join_idx as usize].ack.wrapping_add(1);
            let j = s.joins[join_idx as usize];
            if j.ack == j.need {
                free_join(s, join_idx);
                free_stream(s, sid);
                let mut out = [0u8; 1 + super::body_wire::DIGEST_LEN];
                if super::body_wire::encode_wcommit_resp(&mut out, &j.digest).is_ok() {
                    let _ = (syscalls.channel_write)(s.admin_out_chan, out.as_ptr(), out.len());
                }
                s.upstream_acked = s.upstream_acked.wrapping_add(1);
            }
        } else {
            // Some members may have already committed — their blobs
            // are unreferenced (writer hears a NAK) and scrub/GC
            // reconciles. Nothing partial is ever *served*: reads
            // resolve by digest, and the digest was never returned.
            free_join(s, join_idx);
            abort_stream_members(s, syscalls, sid);
            emit_nak(s, syscalls, nak_errno);
            s.upstream_naked = s.upstream_naked.wrapping_add(1);
        }
        return;
    }
    if j_kind == KIND_STREAM_ABORT {
        let j = &mut s.joins[join_idx as usize];
        j.ack = j.ack.wrapping_add(1);
        let done = j.ack.wrapping_add(j.fail) >= j.need;
        let sid = j.stream_idx;
        if done {
            free_join(s, join_idx);
            if sid != 0xFF {
                free_stream(s, sid as usize);
                let mut out = [0u8; 1];
                if super::body_wire::encode_wabort_resp(&mut out).is_ok() {
                    let _ = (syscalls.channel_write)(s.admin_out_chan, out.as_ptr(), 1);
                }
            }
        }
        return;
    }

    match j_op {
        // ── PUT / PUT_KEYED: strict all-must-succeed. ───────────
        super::body_wire::OP_PUT | super::body_wire::OP_PUT_KEYED => {
            if succeeded {
                s.joins[join_idx as usize].ack = s.joins[join_idx as usize].ack.wrapping_add(1);
                if s.joins[join_idx as usize].digest_set == 0 {
                    if let Ok(d) = super::body_wire::decode_put_resp(resp) {
                        s.joins[join_idx as usize].digest.copy_from_slice(d);
                        s.joins[join_idx as usize].digest_set = 1;
                    }
                }
            } else {
                s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
            }
            let j = s.joins[join_idx as usize];
            if j.fail > 0 {
                // Late responses from the other replicas dequeue
                // against a freed (or reused) slot; the gen check
                // in the drain loop drops them as stale.
                emit_nak(s, syscalls, nak_errno);
                free_join(s, join_idx);
                s.upstream_naked = s.upstream_naked.wrapping_add(1);
            } else if j.ack == j.need {
                if j.digest_set == 0 {
                    emit_nak(s, syscalls, super::body_wire::ERR_IO);
                    s.upstream_naked = s.upstream_naked.wrapping_add(1);
                } else {
                    let mut out = [0u8; 1 + super::body_wire::DIGEST_LEN];
                    let enc = if j_op == super::body_wire::OP_PUT_KEYED {
                        super::body_wire::encode_put_keyed_resp(&mut out, &j.digest).is_ok()
                    } else {
                        super::body_wire::encode_put_resp(&mut out, &j.digest).is_ok()
                    };
                    if enc {
                        let _ = (syscalls.channel_write)(s.admin_out_chan, out.as_ptr(), out.len());
                    }
                    s.upstream_acked = s.upstream_acked.wrapping_add(1);
                }
                free_join(s, join_idx);
            }
        }

        // ── GET / HEAD / RANGE: forward on success, else fall
        // back through the ranked replicas. ─────────────────────
        super::body_wire::OP_GET | super::body_wire::OP_HEAD | super::body_wire::OP_RANGE => {
            if succeeded {
                let _ = (syscalls.channel_write)(s.admin_out_chan, resp.as_ptr(), resp.len());
                s.upstream_acked = s.upstream_acked.wrapping_add(1);
                let j = s.joins[join_idx as usize];
                free_join(s, join_idx);
                if j_op == super::body_wire::OP_GET && j.not_found_mask != 0 {
                    // Read repair: re-PUT to the earlier-ranked
                    // replicas that NAKed NOT_FOUND.
                    let mut members = [0u8; MAX_FLEET];
                    let mut cnt = 0usize;
                    for idx in 0..j.target_count {
                        if j.not_found_mask & (1u16 << idx) != 0 {
                            members[cnt] = j.targets[idx as usize];
                            cnt += 1;
                        }
                    }
                    spawn_repair_puts(s, syscalls, &members[..cnt], resp);
                }
            } else {
                {
                    let j = &mut s.joins[join_idx as usize];
                    j.last_errno = nak_errno;
                    if nak_errno == super::body_wire::ERR_NOT_FOUND {
                        j.not_found_mask |= 1u16 << j.attempt;
                    }
                    j.attempt = j.attempt.wrapping_add(1);
                }
                s.read_fallbacks = s.read_fallbacks.wrapping_add(1);
                advance_read(s, syscalls, join_idx);
            }
        }

        // ── DELETE: aggregate; OK if any replica responded OK. ──
        super::body_wire::OP_DELETE => {
            if succeeded {
                s.joins[join_idx as usize].ack = s.joins[join_idx as usize].ack.wrapping_add(1);
                if resp.len() >= 2 && resp[1] != 0 {
                    s.joins[join_idx as usize].existed = 1;
                }
            } else {
                s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
                s.joins[join_idx as usize].last_errno = nak_errno;
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
                    let errno = if j.last_errno == 0 {
                        super::body_wire::ERR_IO
                    } else {
                        j.last_errno
                    };
                    emit_nak(s, syscalls, errno);
                    s.upstream_naked = s.upstream_naked.wrapping_add(1);
                }
                free_join(s, join_idx);
            }
        }

        _ => {
            emit_nak(s, syscalls, super::body_wire::ERR_BAD_REQ);
            free_join(s, join_idx);
        }
    }
}

/// Repair: re-PUT the body carried by `get_resp` to each member in
/// `members`. Best-effort and one-shot: each repair is a
/// KIND_REPAIR join whose eventual response is counted but never
/// surfaced upstream; a failed repair is retried naturally by the
/// next fallback read or scrub pass over the same digest. Callers
/// are read repair (fallback GET success → NOT_FOUND replicas) and
/// scrub fetch (probe found holders + missers).
unsafe fn spawn_repair_puts(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    members: &[u8],
    get_resp: &[u8],
) {
    let body = match super::body_wire::decode_get_resp(get_resp) {
        Ok(b) => b,
        Err(_) => return,
    };
    let req_n = match super::body_wire::encode_put_req(&mut s.scratch, body) {
        Ok(n) => n,
        Err(_) => return,
    };
    for &member_id in members {
        let join_idx = match alloc_join(s) {
            Some(i) => i,
            None => {
                s.repairs_failed = s.repairs_failed.wrapping_add(1);
                continue;
            }
        };
        let gen = {
            let j = &mut s.joins[join_idx as usize];
            j.kind = KIND_REPAIR;
            j.op = super::body_wire::OP_PUT;
            j.need = 1;
            j.gen
        };
        if dispatch_to_target(s, syscalls, member_id, join_idx, gen, req_n) {
            s.repairs_started = s.repairs_started.wrapping_add(1);
        } else {
            free_join(s, join_idx);
            s.repairs_failed = s.repairs_failed.wrapping_add(1);
        }
    }
}

// ── Background scrub ───────────────────────────────────────────────
//
// One SCAN page per interval; each returned digest becomes a HEAD
// probe of its ranked replica set; a digest present on some ranked
// replicas but NOT_FOUND on others becomes a fetch-from-holder +
// re-PUT-to-missers. All scrub joins are internal — nothing is
// ever written upstream. Targets are walked round-robin over all
// wired channel slots (not the fleet snapshot) so bodies stranded
// on a member that left the fleet still get probed and repaired
// onto the current fleet.
//
// Coverage note: body_store's slot table is rehydrated lazily
// after a restart, so a freshly-rebooted member reports only what
// this boot has touched. Scrub still converges because every
// member is scanned — a digest is probed as long as ANY member
// remembers it. A disk-inventory (READDIR-backed) scan is the
// remaining gap for an all-members-rebooted-at-once fleet.

/// Send one SCAN page request to the current scrub target.
unsafe fn scrub_kick(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    let target = s.scrub_target % s.body_fleet_count;
    s.scrub_target = target;
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => return, // join table busy — try next interval
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_SCRUB_SCAN;
        j.op = super::body_wire::OP_SCAN;
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
        s.scrub_scans = s.scrub_scans.wrapping_add(1);
    } else {
        // Dead channel — skip this member so scrub doesn't wedge.
        free_join(s, join_idx);
        scrub_next_target(s);
    }
}

unsafe fn scrub_next_target(s: &mut ModuleState) {
    s.scrub_cursor = 0;
    if s.body_fleet_count != 0 {
        s.scrub_target = (s.scrub_target + 1) % s.body_fleet_count;
    }
}

unsafe fn scrub_apply_scan(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    succeeded: bool,
    resp: &[u8],
) {
    s.scrub_scan_inflight = 0;
    if !succeeded {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        scrub_next_target(s);
        return;
    }
    let mut digests = [[0u8; super::body_wire::DIGEST_LEN]; super::body_wire::MAX_SCAN_DIGESTS];
    let mut keyed = [0u8; super::body_wire::MAX_SCAN_DIGESTS];
    let (next_cursor, count) =
        match super::body_wire::decode_scan_resp(resp, &mut digests, &mut keyed) {
            Ok(v) => v,
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                scrub_next_target(s);
                return;
            }
        };
    s.scrub_cursor = next_cursor;
    if next_cursor == 0 {
        scrub_next_target(s);
    }
    for (i, d) in digests.iter().take(count).enumerate() {
        // Keyed blobs (extents, EC shards) are not this scrub's to
        // heal: the repair re-put would store them under a CONTENT
        // hash, not their key. Extent replica heal is the tracked
        // follow-up; EC shard heal is the EC router's scrub.
        if keyed[i] != 0 {
            continue;
        }
        scrub_spawn_probe(s, syscalls, d);
    }
}

/// HEAD-probe every ranked replica of `digest`.
unsafe fn scrub_spawn_probe(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    digest: &[u8; super::body_wire::DIGEST_LEN],
) {
    let mut targets_buf = [0u8; MAX_FLEET];
    let chosen = rank_targets(s, digest, &mut targets_buf);
    if chosen < 2 {
        // Single-replica (or empty) placement — nothing to compare.
        return;
    }
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => return, // best-effort: next pass re-covers
    };
    let gen = {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_SCRUB_PROBE;
        j.op = super::body_wire::OP_HEAD;
        j.need = chosen as u8;
        j.target_count = chosen as u8;
        j.targets[..chosen].copy_from_slice(&targets_buf[..chosen]);
        j.digest = *digest;
        j.gen
    };
    s.scratch[0] = super::body_wire::OP_HEAD;
    s.scratch[1..1 + super::body_wire::DIGEST_LEN].copy_from_slice(digest);
    let req_n = 1 + super::body_wire::DIGEST_LEN;
    for i in 0..chosen {
        let member_id = targets_buf[i];
        if !dispatch_to_target(s, syscalls, member_id, join_idx, gen, req_n) {
            s.joins[join_idx as usize].fail = s.joins[join_idx as usize].fail.wrapping_add(1);
        }
    }
    let j = s.joins[join_idx as usize];
    if j.fail == j.need {
        free_join(s, join_idx);
        return;
    }
    s.scrub_probes = s.scrub_probes.wrapping_add(1);
}

unsafe fn scrub_apply_probe(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    join_idx: u16,
    from_target: u8,
    succeeded: bool,
    nak_errno: u8,
) {
    {
        let j = &mut s.joins[join_idx as usize];
        let mut rank: Option<u8> = None;
        for i in 0..j.target_count {
            if j.targets[i as usize] == from_target {
                rank = Some(i);
                break;
            }
        }
        if succeeded {
            j.ack = j.ack.wrapping_add(1);
            if let Some(r) = rank {
                j.present_mask |= 1u16 << r;
            }
        } else {
            j.fail = j.fail.wrapping_add(1);
            if nak_errno == super::body_wire::ERR_NOT_FOUND {
                if let Some(r) = rank {
                    j.not_found_mask |= 1u16 << r;
                }
            }
        }
    }
    let j = s.joins[join_idx as usize];
    if j.ack.wrapping_add(j.fail) != j.need {
        return; // more probe responses outstanding
    }
    free_join(s, join_idx);
    if j.not_found_mask == 0 || j.present_mask == 0 {
        // Fully replicated, or nobody has it (lost body — nothing
        // to copy from), or failures were transient (non-NOT_FOUND).
        return;
    }
    scrub_spawn_fetch(s, syscalls, &j);
}

/// GET the body from a holder (walking the present replicas), then
/// re-PUT it to the NOT_FOUND replicas.
unsafe fn scrub_spawn_fetch(s: &mut ModuleState, syscalls: &super::SyscallTable, probe: &JoinSlot) {
    let join_idx = match alloc_join(s) {
        Some(i) => i,
        None => {
            s.scrub_fetch_failed = s.scrub_fetch_failed.wrapping_add(1);
            return;
        }
    };
    {
        let j = &mut s.joins[join_idx as usize];
        j.kind = KIND_SCRUB_FETCH;
        j.op = super::body_wire::OP_GET;
        j.need = 1;
        j.digest = probe.digest;
        let mut cnt = 0usize;
        for i in 0..probe.target_count {
            if probe.present_mask & (1u16 << i) != 0 {
                j.targets[cnt] = probe.targets[i as usize];
                cnt += 1;
            }
        }
        j.target_count = cnt as u8;
        let mut rc = 0usize;
        for i in 0..probe.target_count {
            if probe.not_found_mask & (1u16 << i) != 0 {
                j.repair_targets[rc] = probe.targets[i as usize];
                rc += 1;
            }
        }
        j.repair_count = rc as u8;
    }
    s.scrub_fetches = s.scrub_fetches.wrapping_add(1);
    advance_read(s, syscalls, join_idx);
}

unsafe fn emit_nak(s: &ModuleState, syscalls: &super::SyscallTable, errno: u8) {
    let mut buf = [0u8; 2];
    if super::body_wire::encode_nak(&mut buf, errno).is_ok() {
        let _ = (syscalls.channel_write)(s.admin_out_chan, buf.as_ptr(), buf.len());
    }
}
