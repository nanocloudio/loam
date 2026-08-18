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
    pub count: u8,
}

impl Fleet {
    pub const fn empty() -> Self {
        Self {
            epoch: 0,
            members: [0; MAX_FLEET],
            count: 0,
        }
    }

    pub fn from_slice(epoch: u64, members: &[u8]) -> Self {
        let mut buf = [0u8; MAX_FLEET];
        let n = members.len().min(MAX_FLEET);
        buf[..n].copy_from_slice(&members[..n]);
        Self {
            epoch,
            members: buf,
            count: n as u8,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.members[..self.count as usize]
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
    // Compute weight per member, then select top-`take` via a
    // single bounded-size partial sort. Storage on the stack —
    // MAX_FLEET is small.
    let mut weights = [(0u64, 0u8); MAX_FLEET];
    let cnt = fleet.count as usize;
    for i in 0..cnt {
        let m = fleet.members[i];
        weights[i] = (weight(key, m), m);
    }
    // Selection sort over the first `take` slots — bounded and
    // branch-friendly. For MAX_FLEET=16 this is at most 256
    // comparisons, well within the per-step budget.
    for i in 0..take {
        let mut max_idx = i;
        for j in (i + 1)..cnt {
            if weights[j].0 > weights[max_idx].0 {
                max_idx = j;
            }
        }
        if max_idx != i {
            weights.swap(i, max_idx);
        }
        out[i] = weights[i].1;
    }
    take
}
