// Pure placement compute. Consumed by `placement_router` (which
// publishes fleet snapshots) AND by any module that needs to
// compute per-object targets from a cached snapshot — today that's
// `admin_router`, tomorrow it will be the EC body router and the
// read-path router.
//
// Placement strategy: rendezvous hashing (HRW). For each fleet
// member, compute a hash of (object_key || member_id), sort members
// by hash descending, take the top N. This gives:
//
//   - Determinism: same (key, fleet) → same ordered targets.
//   - Minimal disruption on membership change: when one member
//     leaves, only ~1/|fleet| of objects are reassigned.
//   - Uniform load: SHA-quality mix would be ideal, but a 64-bit
//     FNV-1a mix is good enough for the small fleet sizes we run
//     and stays no_std + no-syscall.
//
// All compute is bounded: O(fleet_size * log(fleet_size)) per
// pick_targets call. With MAX_FLEET=16 that's ~64 comparisons.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use super::placement_wire::MAX_FLEET;

pub const DIGEST_LEN: usize = 32;

/// A snapshot of the fleet at a specific epoch. Consumers cache
/// the latest snapshot from `placement_router`'s broadcast and
/// pass it into `pick_targets` per request.
#[derive(Debug, Clone, Copy)]
pub struct Fleet {
    pub epoch: u64,
    pub members: [u8; MAX_FLEET],
    /// Failure domain per member, positionally aligned with
    /// `members` — a rack, a chassis, a power feed, an availability
    /// zone. Whatever the operator says fails together.
    ///
    /// All-zero means one domain, which is the honest default for a
    /// fleet nobody has described: it says "assume these can all
    /// fail together" rather than pretending otherwise. It also
    /// degenerates `pick_targets` to plain rendezvous ranking, so an
    /// undescribed fleet behaves exactly as it did before domains
    /// existed.
    pub domains: [u8; MAX_FLEET],
    /// Per-member state, positionally aligned with `members`.
    /// A bitfield of `MEMBER_DRAINING` / `MEMBER_COLD`; 0 is an
    /// ordinary hot member taking writes.
    pub states: [u8; MAX_FLEET],
    pub count: u8,
}

/// No flags: a hot member, taking new writes and serving reads.
/// The default, so a fleet nobody has described is fully active.
pub const MEMBER_ACTIVE: u8 = 0;

/// Takes NO new writes, still serves reads.
///
/// Draining is the difference between "remove the node and hope the
/// scrub catches up before something else fails" and "move the data
/// off, then remove it". A drained member must stay READABLE while
/// it drains, or every object that still lives only there is
/// unavailable for the whole drain — which is the outage the drain
/// existed to avoid.
///
/// So draining changes only where new writes are PLACED. Reads rank
/// the full fleet, and the existing scrub does the moving: it
/// already probes every digest's ranked home and re-replicates what
/// is missing, so a draining member's objects heal onto active ones
/// with no new machinery.
pub const MEMBER_DRAINING: u8 = 1 << 0;

/// A COLD-tier member: cheaper, slower, or further away. Takes no
/// new writes and serves reads, exactly like a draining member —
/// but for the opposite reason, and that difference matters.
///
/// Draining means "this member is leaving, move everything off".
/// Cold means "this member is staying, and things move ONTO it as
/// they age". They are flags rather than states because a cold
/// member can also be drained, and a scheme that made them
/// exclusive would have no way to say that.
///
/// Tiering is deliberately NOT a third router. This docket first
/// proposed one and called it "nearly free once A-2 lands" — but
/// A-2's remaining extraction is only worth doing for a real third
/// consumer, so a third router justified by a trait justified by a
/// third router is circular. A member CLASS breaks that: placement
/// already ranks by key and already filters by state, so the whole
/// feature is one flag and one function.
///
/// What makes a body cold is a POLICY question and is not answered
/// here. It belongs with lifecycle (`expired_page` is the same
/// shape): something decides, and then calls `pick_cold_targets`.
pub const MEMBER_COLD: u8 = 1 << 1;

impl Fleet {
    pub const fn empty() -> Self {
        Self {
            epoch: 0,
            members: [0; MAX_FLEET],
            domains: [0; MAX_FLEET],
            states: [MEMBER_ACTIVE; MAX_FLEET],
            count: 0,
        }
    }

    /// A fleet with no topology described: every member in domain 0.
    pub fn from_slice(epoch: u64, members: &[u8]) -> Self {
        Self::from_slice_with_domains(epoch, members, &[])
    }

    /// A fleet with a failure domain per member. `domains` shorter
    /// than `members` leaves the remainder in domain 0 — partial
    /// topology is better than none, and pretending an undescribed
    /// member is isolated would be the dangerous direction.
    pub fn from_slice_with_domains(epoch: u64, members: &[u8], domains: &[u8]) -> Self {
        Self::from_parts(epoch, members, domains, &[])
    }

    /// A fleet with domains and per-member states. A short `states`
    /// leaves the remainder ACTIVE — the safe default, since
    /// wrongly believing a member is draining would stop placing on
    /// a perfectly good node.
    pub fn from_parts(epoch: u64, members: &[u8], domains: &[u8], states: &[u8]) -> Self {
        let mut buf = [0u8; MAX_FLEET];
        let mut dom = [0u8; MAX_FLEET];
        let mut st = [MEMBER_ACTIVE; MAX_FLEET];
        let n = members.len().min(MAX_FLEET);
        buf[..n].copy_from_slice(&members[..n]);
        let d = domains.len().min(n);
        dom[..d].copy_from_slice(&domains[..d]);
        let c = states.len().min(n);
        st[..c].copy_from_slice(&states[..c]);
        Self {
            epoch,
            members: buf,
            domains: dom,
            states: st,
            count: n as u8,
        }
    }

    pub fn states_slice(&self) -> &[u8] {
        &self.states[..self.count as usize]
    }

    /// Is `member` accepting NEW writes? False when it is draining
    /// or cold — both take data only by deliberate movement.
    pub fn accepts_writes(&self, member: u8) -> bool {
        for i in 0..self.count as usize {
            if self.members[i] == member {
                return self.states[i] & (MEMBER_DRAINING | MEMBER_COLD) == 0;
            }
        }
        false
    }

    /// Is `member` in the cold tier?
    pub fn is_cold(&self, member: u8) -> bool {
        for i in 0..self.count as usize {
            if self.members[i] == member {
                return self.states[i] & MEMBER_COLD != 0;
            }
        }
        false
    }

    /// Members taking new writes — the hot, undrained ones.
    pub fn writable_count(&self) -> usize {
        self.states[..self.count as usize]
            .iter()
            .filter(|&&st| st & (MEMBER_DRAINING | MEMBER_COLD) == 0)
            .count()
    }

    /// Cold members that are not also draining — where a demotion
    /// can land.
    pub fn cold_count(&self) -> usize {
        self.states[..self.count as usize]
            .iter()
            .filter(|&&st| st & MEMBER_COLD != 0 && st & MEMBER_DRAINING == 0)
            .count()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.members[..self.count as usize]
    }

    pub fn domains_slice(&self) -> &[u8] {
        &self.domains[..self.count as usize]
    }

    /// The failure domain of `member`, or 0 if it is not in the
    /// fleet.
    pub fn domain_of(&self, member: u8) -> u8 {
        for i in 0..self.count as usize {
            if self.members[i] == member {
                return self.domains[i];
            }
        }
        0
    }

    /// How many distinct failure domains the fleet spans. The
    /// ceiling on how many replicas can be placed without two
    /// sharing a fate.
    pub fn domain_count(&self) -> usize {
        let mut seen = [false; 256];
        let mut n = 0;
        for i in 0..self.count as usize {
            let d = self.domains[i] as usize;
            if !seen[d] {
                seen[d] = true;
                n += 1;
            }
        }
        n
    }
}

/// FNV-1a 64-bit mixed weight of (key || member_id). Used as the
/// rendezvous-hash sort key. Stable across machines and across
/// fleet membership changes — when a member leaves, the remaining
/// members keep their relative ordering for every key.
fn weight(key: &[u8; DIGEST_LEN], member: u8) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut h: u64 = FNV_OFFSET;
    let mut i = 0;
    while i < DIGEST_LEN {
        h ^= key[i] as u64;
        h = h.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    h ^= member as u64;
    h.wrapping_mul(FNV_PRIME)
}

/// Pick `n` distinct fleet members for `key`, ranked by descending
/// rendezvous weight. Returns the number of targets actually
/// chosen (capped at `fleet.count`). Writes results into the
/// caller's `out` buffer; positions `out[result..]` are left
/// untouched.
///
/// `n == 0` returns 0. `fleet.count == 0` returns 0. Otherwise the
/// result count is `min(n, fleet.count)`.
pub fn pick_targets(key: &[u8; DIGEST_LEN], n: u8, fleet: &Fleet, out: &mut [u8]) -> usize {
    let take = (n as usize).min(fleet.count as usize).min(out.len());
    if take == 0 {
        return 0;
    }
    let cnt = fleet.count as usize;

    // Rank every member by rendezvous weight, exactly as before —
    // the ordering, and therefore the minimal-disruption property,
    // is unchanged. Topology only decides which of the ranked
    // members are TAKEN, never how they are ranked.
    let mut weights = [(0u64, 0u8, 0u8); MAX_FLEET];
    for i in 0..cnt {
        let m = fleet.members[i];
        weights[i] = (weight(key, m), m, fleet.domains[i]);
    }
    for i in 0..cnt {
        let mut max_idx = i;
        for j in (i + 1)..cnt {
            if weights[j].0 > weights[max_idx].0 {
                max_idx = j;
            }
        }
        if max_idx != i {
            weights.swap(i, max_idx);
        }
    }

    // Two passes over the ranked list.
    //
    // First, take the highest-ranked member of each domain not yet
    // used. That is what makes three replicas land in three
    // different racks rather than three times in one — the failure
    // the flat list could not see, and which reports full health
    // right up until the rack goes.
    //
    // Then, if the caller asked for more replicas than there are
    // domains, fill from what is left in rank order. UNDER-
    // replicating would be the worse answer: two copies in one
    // domain still survive a disk, where one copy survives nothing.
    // The shortfall is a topology fact the operator should see, not
    // a reason to refuse the write.
    let mut used = [false; 256];
    let mut taken = 0usize;
    for i in 0..cnt {
        if taken == take {
            break;
        }
        let d = weights[i].2 as usize;
        if !used[d] {
            used[d] = true;
            out[taken] = weights[i].1;
            taken += 1;
        }
    }
    if taken < take {
        for i in 0..cnt {
            if taken == take {
                break;
            }
            let m = weights[i].1;
            // An explicit scan, NOT `contains`. On a `[u8]` slice
            // `contains` lowers to `core::slice::memchr`, which the
            // bare-metal SDK does not stub — the linker fails with
            // an undefined symbol, and only on the PIC build. This
            // is the same rule the workspace lints already carve
            // out for `manual_find`; clippy's suggestion here is
            // correct for a host and wrong for this target.
            let mut already = false;
            for k in 0..taken {
                if out[k] == m {
                    already = true;
                    break;
                }
            }
            if already {
                continue;
            }
            out[taken] = m;
            taken += 1;
        }
    }
    taken
}

/// Pick targets for a NEW WRITE: like `pick_targets`, but skipping
/// members that are draining.
///
/// Reads must keep using `pick_targets` over the full fleet. A
/// draining member still holds data, and ranking it out of reads
/// would make every object that lives only there unavailable for
/// the duration of the drain — the outage draining exists to avoid.
///
/// If every member is draining this returns 0 rather than silently
/// placing on one anyway. A caller that cannot write should be told,
/// not quietly given the thing it asked not to have.
pub fn pick_write_targets(key: &[u8; DIGEST_LEN], n: u8, fleet: &Fleet, out: &mut [u8]) -> usize {
    let mut writable = Fleet {
        epoch: fleet.epoch,
        members: [0; MAX_FLEET],
        domains: [0; MAX_FLEET],
        states: [MEMBER_ACTIVE; MAX_FLEET],
        count: 0,
    };
    let mut k = 0usize;
    for i in 0..fleet.count as usize {
        if fleet.states[i] & (MEMBER_DRAINING | MEMBER_COLD) == 0 {
            writable.members[k] = fleet.members[i];
            writable.domains[k] = fleet.domains[i];
            k += 1;
        }
    }
    writable.count = k as u8;
    pick_targets(key, n, &writable, out)
}

/// Pick targets in the COLD tier, for a body being demoted.
///
/// Same ranking and the same failure-domain spread as any other
/// placement — a cold copy is still a copy, and three of them in one
/// rack is still one failure away from none. Draining cold members
/// are excluded: a member on its way out is not somewhere to put
/// data that was just moved for safekeeping.
///
/// Returns 0 when there is no cold tier, which a caller must treat
/// as "do not demote" rather than "demote anywhere".
pub fn pick_cold_targets(key: &[u8; DIGEST_LEN], n: u8, fleet: &Fleet, out: &mut [u8]) -> usize {
    let mut cold = Fleet {
        epoch: fleet.epoch,
        members: [0; MAX_FLEET],
        domains: [0; MAX_FLEET],
        states: [MEMBER_ACTIVE; MAX_FLEET],
        count: 0,
    };
    let mut k = 0usize;
    for i in 0..fleet.count as usize {
        if fleet.states[i] & MEMBER_COLD != 0 && fleet.states[i] & MEMBER_DRAINING == 0 {
            cold.members[k] = fleet.members[i];
            cold.domains[k] = fleet.domains[i];
            k += 1;
        }
    }
    cold.count = k as u8;
    pick_targets(key, n, &cold, out)
}

/// How many of `out[..n]` share a failure domain with an earlier
/// entry — the replicas that do not add independence.
///
/// This is what a health surface should report rather than a bare
/// replica count: three copies in one rack is not three-way
/// redundancy, and a system that says "3/3 healthy" there is lying
/// by omission.
pub fn colocated_count(out: &[u8], n: usize, fleet: &Fleet) -> usize {
    let mut seen = [false; 256];
    let mut dup = 0;
    for &m in out.iter().take(n) {
        let d = fleet.domain_of(m) as usize;
        if seen[d] {
            dup += 1;
        } else {
            seen[d] = true;
        }
    }
    dup
}
