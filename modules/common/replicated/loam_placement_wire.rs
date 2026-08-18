// Wire format for the `placement_router` PIC's output channel.
//
// Placement in Loam follows the "channels as state-surfaces"
// discipline: the router owns the fleet table and publishes the
// authoritative snapshot on its `placement_decisions` output.
// Consumers (admin_router today; future read-path PICs tomorrow)
// cache the latest epoch locally and compute per-object targets
// inline via `loam_placement::pick_targets`. There is no per-PUT
// RPC into the router — placement is a pure function of the
// cached fleet snapshot + the object's content digest.
//
// Layouts (multi-byte ints LE):
//
//   FleetEpoch   [op:u8=0x60][epoch:u64][count:u8][members:count u8]
//                  // `count` ≤ MAX_FLEET. Each `member` byte is a
//                  // fleet index (0..MAX_FLEET); duplicates are
//                  // a producer bug.
//
//   FleetUpdate  [op:u8=0x61][count:u8][members:count u8]
//                  // control-channel input. Replaces the entire
//                  // member list atomically; the router bumps
//                  // epoch and re-emits FleetEpoch on its next
//                  // step. count == 0 is a "no targets" state.
//
// The wire intentionally does NOT carry per-member health bits in
// v1 — the publish-on-change model means a member that goes dark
// is removed from the FleetUpdate, not flagged inline. This keeps
// the consumer-side `Fleet` snapshot tiny.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use core::convert::TryInto;

pub const OP_FLEET_EPOCH: u8 = 0x60;
pub const OP_FLEET_UPDATE: u8 = 0x61;

/// Hard cap on fleet size. Sized for a small cluster (16 body_store
/// instances is comfortably more than any single-rack deployment);
/// expanding requires bumping the per-record byte budgets in
/// every consumer.
pub const MAX_FLEET: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadOpcode { observed: u8 },
    FleetTooLarge { count: usize, max: usize },
    BufferTooSmall { needed: usize, actual: usize },
}

// ── FleetEpoch (router → consumers) ────────────────────────────────

pub fn encode_fleet_epoch(dst: &mut [u8], epoch: u64, members: &[u8]) -> Result<usize, WireError> {
    if members.len() > MAX_FLEET {
        return Err(WireError::FleetTooLarge {
            count: members.len(),
            max: MAX_FLEET,
        });
    }
    let needed = 1 + 8 + 1 + members.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_FLEET_EPOCH;
    dst[1..9].copy_from_slice(&epoch.to_le_bytes());
    dst[9] = members.len() as u8;
    dst[10..10 + members.len()].copy_from_slice(members);
    Ok(needed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedFleetEpoch<'a> {
    pub epoch: u64,
    pub members: &'a [u8],
}

pub fn decode_fleet_epoch(src: &[u8]) -> Result<DecodedFleetEpoch<'_>, WireError> {
    if src.len() < 10 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_FLEET_EPOCH {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let epoch = u64::from_le_bytes(src[1..9].try_into().unwrap());
    let count = src[9] as usize;
    if count > MAX_FLEET {
        return Err(WireError::FleetTooLarge {
            count,
            max: MAX_FLEET,
        });
    }
    if 10 + count > src.len() {
        return Err(WireError::Truncated);
    }
    Ok(DecodedFleetEpoch {
        epoch,
        members: &src[10..10 + count],
    })
}

// ── FleetUpdate (control → router) ─────────────────────────────────

pub fn encode_fleet_update(dst: &mut [u8], members: &[u8]) -> Result<usize, WireError> {
    if members.len() > MAX_FLEET {
        return Err(WireError::FleetTooLarge {
            count: members.len(),
            max: MAX_FLEET,
        });
    }
    let needed = 1 + 1 + members.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_FLEET_UPDATE;
    dst[1] = members.len() as u8;
    dst[2..2 + members.len()].copy_from_slice(members);
    Ok(needed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedFleetUpdate<'a> {
    pub members: &'a [u8],
}

pub fn decode_fleet_update(src: &[u8]) -> Result<DecodedFleetUpdate<'_>, WireError> {
    if src.len() < 2 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_FLEET_UPDATE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let count = src[1] as usize;
    if count > MAX_FLEET {
        return Err(WireError::FleetTooLarge {
            count,
            max: MAX_FLEET,
        });
    }
    if 2 + count > src.len() {
        return Err(WireError::Truncated);
    }
    Ok(DecodedFleetUpdate {
        members: &src[2..2 + count],
    })
}

pub fn peek_opcode(src: &[u8]) -> Option<u8> {
    src.first().copied()
}
