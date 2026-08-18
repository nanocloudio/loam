// Shared step-body for the `placement_router` PIC. The router owns
// the fleet membership table and broadcasts the current FleetEpoch
// snapshot on its output channel whenever membership changes.
// Consumers (admin_router, future EC body router, future read-path
// router) cache the latest snapshot and compute per-object targets
// locally via `loam_placement::pick_targets` — there is no per-PUT
// RPC into this PIC.
//
// Two init paths, mirroring the other public-surface PICs:
//
//   `module_new_impl`           — empty fleet at boot; rely on a
//                                 control-channel FleetUpdate to
//                                 populate.
//   `module_new_with_seed_impl` — seed the fleet from raw bytes,
//                                 used by the TLV path for the
//                                 launch-time member list.
//
// State changes are atomic: a FleetUpdate replaces the entire
// member list, bumps the epoch, and re-broadcasts. Empty fleet is
// a legal state (epoch advances; consumers cache count=0 and
// answer "no targets" to upstream PUT attempts).

const MAX_OPS_PER_STEP: u32 = 4;
const READ_BUF: usize = 64;
const EMIT_BUF: usize = 64;

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    /// `placement_requests` per manifest — control-channel for
    /// FleetUpdate messages. Producers may be the operator-CLI
    /// path, the raft_metadata_client (when membership is itself
    /// replicated), or a healthcheck PIC trimming dead members.
    pub in_chan: i32,
    /// `placement_decisions` per manifest — broadcasts the current
    /// FleetEpoch snapshot. Consumers cache.
    pub out_chan: i32,
    /// Member-count for the current snapshot; mirrors `fleet[..count]`.
    pub member_count: u8,
    /// Monotonic epoch — bumps on every membership change.
    pub epoch: u64,
    pub fleet: [u8; super::placement_wire::MAX_FLEET],
    /// Sticky flag: set after the first FleetEpoch emission so we
    /// don't re-emit unchanged state every step. Cleared whenever
    /// the fleet changes.
    pub emitted_current: u8,
    pub ticks: u32,
    pub updates_applied: u32,
    pub apply_errors: u32,
    pub broadcasts: u32,
    pub scratch: [u8; EMIT_BUF],
}

pub unsafe fn module_new_impl(
    in_chan: i32,
    out_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(in_chan, out_chan, state_ptr, state_size, syscalls)
}

/// Seed-with-initial-members entry. The router immediately bumps
/// the epoch to 1 (since the empty→seeded transition IS a fleet
/// change) and the first step broadcasts the snapshot.
pub unsafe fn module_new_with_seed_impl(
    in_chan: i32,
    out_chan: i32,
    seed_members: &[u8],
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    let rc = init_state(in_chan, out_chan, state_ptr, state_size, syscalls);
    if rc != 0 {
        return rc;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    apply_fleet_update(s, seed_members);
    0
}

unsafe fn init_state(
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
    // Empty fleet is the legal initial state — consumers will see
    // count=0 in the first broadcast and report "no placement
    // available" upstream. emitted_current=0 forces the first step
    // to publish even the empty snapshot so subscribers know what
    // epoch they're at.
    s.emitted_current = 0;
    0
}

/// Parse the launch-time params blob for an initial member list.
/// Supports both the TLV format (`tag=1` carries the byte slice)
/// and a raw-bytes fallback (entire blob is the member list).
///
/// SAFETY: `state_ptr` must reference an initialized
/// `ModuleState`; `params` must be a valid byte slice for the
/// duration of the call.
pub unsafe fn decode_seed_params(state_ptr: *mut u8, params: *const u8, params_len: usize) {
    if state_ptr.is_null() || params.is_null() || params_len == 0 {
        return;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    let is_tlv = params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
    if is_tlv {
        let mut off = 4usize;
        while off + 2 <= params_len {
            let tag = *params.add(off);
            let elen = *params.add(off + 1) as usize;
            off += 2;
            if tag == 0xFF {
                break;
            }
            if tag == 1 && off + elen <= params_len {
                let copy = elen.min(super::placement_wire::MAX_FLEET);
                let src = params.add(off);
                let slice = core::slice::from_raw_parts(src, copy);
                apply_fleet_update(s, slice);
                return;
            }
            off += elen;
        }
        return;
    }
    let copy = params_len.min(super::placement_wire::MAX_FLEET);
    let slice = core::slice::from_raw_parts(params, copy);
    apply_fleet_update(s, slice);
}

/// Public wrapper around `apply_fleet_update` for the PIC shim's
/// TLV closure — the macro expansion runs in `mod.rs`, so the
/// atomic-update fn must be reachable via `super::body::*`.
///
/// SAFETY: same as `apply_fleet_update`; caller must hold a valid
/// `&mut ModuleState`.
pub unsafe fn apply_fleet_update_pub(s: &mut ModuleState, members: &[u8]) {
    apply_fleet_update(s, members);
}

/// Replace the fleet membership atomically and bump the epoch.
/// Deduplicates and clamps to `MAX_FLEET`; preserves caller order
/// after dedup (first occurrence wins).
unsafe fn apply_fleet_update(s: &mut ModuleState, members: &[u8]) {
    let mut next = [0u8; super::placement_wire::MAX_FLEET];
    let mut next_count: usize = 0;
    for &m in members.iter() {
        if next_count >= super::placement_wire::MAX_FLEET {
            break;
        }
        let mut seen = false;
        let mut i = 0;
        while i < next_count {
            if next[i] == m {
                seen = true;
                break;
            }
            i += 1;
        }
        if !seen {
            next[next_count] = m;
            next_count += 1;
        }
    }
    let unchanged =
        (next_count as u8 == s.member_count) && next[..next_count] == s.fleet[..next_count];
    if unchanged {
        // No-op update — don't bump epoch, don't re-broadcast.
        return;
    }
    s.fleet = next;
    s.member_count = next_count as u8;
    s.epoch = s.epoch.wrapping_add(1);
    s.emitted_current = 0;
    s.updates_applied = s.updates_applied.wrapping_add(1);
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

    // ── 1. Drain incoming FleetUpdate messages. ────────────────
    let mut handled: u32 = 0;
    while handled < MAX_OPS_PER_STEP {
        let mut buf = [0u8; READ_BUF];
        let n = (syscalls.channel_read)(s.in_chan, buf.as_mut_ptr(), READ_BUF);
        if n <= 0 {
            break;
        }
        let bytes = &buf[..n as usize];
        match super::placement_wire::peek_opcode(bytes) {
            Some(super::placement_wire::OP_FLEET_UPDATE) => {
                match super::placement_wire::decode_fleet_update(bytes) {
                    Ok(decoded) => {
                        apply_fleet_update(s, decoded.members);
                    }
                    Err(_) => {
                        s.apply_errors = s.apply_errors.wrapping_add(1);
                    }
                }
            }
            _ => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
            }
        }
        handled = handled.wrapping_add(1);
    }

    // ── 2. Broadcast current snapshot if not yet emitted at this
    //      epoch. Bounded by EMIT_BUF + a single channel_write. ─
    if s.emitted_current == 0 {
        let members_len = s.member_count as usize;
        let n = match super::placement_wire::encode_fleet_epoch(
            &mut s.scratch,
            s.epoch,
            &s.fleet[..members_len],
        ) {
            Ok(n) => n,
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                return 0;
            }
        };
        let wrote = (syscalls.channel_write)(s.out_chan, s.scratch.as_ptr(), n);
        if wrote >= 0 && (wrote as usize) == n {
            s.emitted_current = 1;
            s.broadcasts = s.broadcasts.wrapping_add(1);
        }
        // If the write was rejected (backpressure), leave
        // emitted_current=0 and retry next step.
    }

    0
}
