// Wire format for the `raft_metadata_client` proposal/commit
// protocol. no_std, layered into both the PIC mod.rs and host
// tests. Mirrors the structural decisions in
// `loam_wire.rs` / `loam_object_wire.rs` / `loam_block_wire.rs`:
// little-endian, length-prefixed, opcode-tagged, with a single
// reserved tag (0).
//
// A Propose record wraps one inner per-plane event verbatim — the
// inner bytes are exactly what the public PICs already accept on
// their `requests` channels. This lets `raft_metadata_client`
// emit the inner bytes directly downstream on `metadata_results`
// once it considers the proposal committed.
//
// Layout (multi-byte ints LE):
//
//   Propose      [op:u8=0x10][plane:u8][correlation_id:u32][inner_len:u16][inner:inner_len]
//   Committed    [op:u8=0x11][plane:u8][correlation_id:u32]
//                [witness_quorum:u8][witness_epoch:u64]
//                [inner_len:u16][inner:inner_len]
//   Aborted      [op:u8=0x12][correlation_id:u32]
//
// Plane bytes:
//   0x01 = namespace, 0x02 = object, 0x03 = block.
//
// The `Committed` witness fields carry a *summary* of the
// `ClustorFenceWitness` (quorum + epoch only); a full witness
// requires a participants list which is too large for the bounded
// per-record budget. Consumers that need the full witness can
// query the Clustor PIC directly via a separate channel — out of
// scope for this phase.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use core::convert::TryInto;

pub const OP_PROPOSE: u8 = 0x10;
pub const OP_COMMITTED: u8 = 0x11;
pub const OP_ABORTED: u8 = 0x12;
/// Proposer → consumers on `metadata_results`: every WAL-replayed
/// proposal has round-tripped its commit. Downstream read surfaces
/// (namespace lookups etc.) are stale until this arrives after a
/// restart; a fresh boot (empty WAL) emits it immediately. Record is
/// the single opcode byte.
pub const OP_REPLAY_DRAINED: u8 = 0x13;

pub const PLANE_NAMESPACE: u8 = 0x01;
pub const PLANE_OBJECT: u8 = 0x02;
pub const PLANE_BLOCK: u8 = 0x03;

/// Cap inner payload at the same limit as the public-PIC wire
/// formats — keeps Raft decisions strictly bounded.
pub const MAX_INNER: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    BufferTooSmall { needed: usize, actual: usize },
    Truncated,
    BadOpcode { observed: u8 },
    BadPlane { observed: u8 },
    InnerTooLarge { len: usize, max: usize },
}

// ── Propose ────────────────────────────────────────────────────────

pub fn encode_propose(
    dst: &mut [u8],
    plane: u8,
    correlation_id: u32,
    inner: &[u8],
) -> Result<usize, WireError> {
    if !matches!(plane, PLANE_NAMESPACE | PLANE_OBJECT | PLANE_BLOCK) {
        return Err(WireError::BadPlane { observed: plane });
    }
    if inner.len() > MAX_INNER {
        return Err(WireError::InnerTooLarge {
            len: inner.len(),
            max: MAX_INNER,
        });
    }
    let header = 1 + 1 + 4 + 2;
    let needed = header + inner.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PROPOSE;
    dst[1] = plane;
    dst[2..6].copy_from_slice(&correlation_id.to_le_bytes());
    dst[6..8].copy_from_slice(&(inner.len() as u16).to_le_bytes());
    dst[header..header + inner.len()].copy_from_slice(inner);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPropose<'a> {
    pub plane: u8,
    pub correlation_id: u32,
    pub inner: &'a [u8],
}

pub fn decode_propose(src: &[u8]) -> Result<DecodedPropose<'_>, WireError> {
    if src.len() < 8 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PROPOSE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let plane = src[1];
    if !matches!(plane, PLANE_NAMESPACE | PLANE_OBJECT | PLANE_BLOCK) {
        return Err(WireError::BadPlane { observed: plane });
    }
    let correlation_id = u32::from_le_bytes([src[2], src[3], src[4], src[5]]);
    let inner_len = u16::from_le_bytes([src[6], src[7]]) as usize;
    if 8 + inner_len > src.len() {
        return Err(WireError::Truncated);
    }
    Ok(DecodedPropose {
        plane,
        correlation_id,
        inner: &src[8..8 + inner_len],
    })
}

// ── Committed ──────────────────────────────────────────────────────

pub fn encode_committed(
    dst: &mut [u8],
    plane: u8,
    correlation_id: u32,
    witness_quorum: u8,
    witness_epoch: u64,
    inner: &[u8],
) -> Result<usize, WireError> {
    if !matches!(plane, PLANE_NAMESPACE | PLANE_OBJECT | PLANE_BLOCK) {
        return Err(WireError::BadPlane { observed: plane });
    }
    if inner.len() > MAX_INNER {
        return Err(WireError::InnerTooLarge {
            len: inner.len(),
            max: MAX_INNER,
        });
    }
    let header = 1 + 1 + 4 + 1 + 8 + 2;
    let needed = header + inner.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_COMMITTED;
    dst[1] = plane;
    dst[2..6].copy_from_slice(&correlation_id.to_le_bytes());
    dst[6] = witness_quorum;
    dst[7..15].copy_from_slice(&witness_epoch.to_le_bytes());
    dst[15..17].copy_from_slice(&(inner.len() as u16).to_le_bytes());
    dst[header..header + inner.len()].copy_from_slice(inner);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCommitted<'a> {
    pub plane: u8,
    pub correlation_id: u32,
    pub witness_quorum: u8,
    pub witness_epoch: u64,
    pub inner: &'a [u8],
}

pub fn decode_committed(src: &[u8]) -> Result<DecodedCommitted<'_>, WireError> {
    if src.len() < 17 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_COMMITTED {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let plane = src[1];
    if !matches!(plane, PLANE_NAMESPACE | PLANE_OBJECT | PLANE_BLOCK) {
        return Err(WireError::BadPlane { observed: plane });
    }
    let correlation_id = u32::from_le_bytes(src[2..6].try_into().unwrap());
    let witness_quorum = src[6];
    let witness_epoch = u64::from_le_bytes(src[7..15].try_into().unwrap());
    let inner_len = u16::from_le_bytes([src[15], src[16]]) as usize;
    let header = 17;
    if header + inner_len > src.len() {
        return Err(WireError::Truncated);
    }
    Ok(DecodedCommitted {
        plane,
        correlation_id,
        witness_quorum,
        witness_epoch,
        inner: &src[header..header + inner_len],
    })
}

// ── Aborted ────────────────────────────────────────────────────────

pub fn encode_aborted(dst: &mut [u8], correlation_id: u32) -> Result<usize, WireError> {
    if dst.len() < 5 {
        return Err(WireError::BufferTooSmall {
            needed: 5,
            actual: dst.len(),
        });
    }
    dst[0] = OP_ABORTED;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    Ok(5)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAborted {
    pub correlation_id: u32,
}

pub fn decode_aborted(src: &[u8]) -> Result<DecodedAborted, WireError> {
    if src.len() < 5 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_ABORTED {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let correlation_id = u32::from_le_bytes(src[1..5].try_into().unwrap());
    Ok(DecodedAborted { correlation_id })
}

// ── Opcode peek ────────────────────────────────────────────────────

pub fn peek_opcode(src: &[u8]) -> Option<u8> {
    src.first().copied()
}

// ── Stream splitting ───────────────────────────────────────────────

/// Length of the record at the front of `src`, or `None` when `src`
/// does not yet hold a whole one.
///
/// These records travel on byte-stream channels, so a reader gets
/// whatever bytes have arrived — a partial record, or several at once.
/// Every consumer that drains such a channel needs this, and deriving
/// it from the layouts at each call site is how the layouts drift.
///
/// `None` means "wait for more bytes", not "malformed": an unknown
/// opcode is reported as `Err` so a caller can resync rather than stall
/// forever on a stream it cannot parse.
pub fn record_len(src: &[u8]) -> Result<Option<usize>, WireError> {
    let opcode = match src.first() {
        Some(b) => *b,
        None => return Ok(None),
    };
    match opcode {
        OP_REPLAY_DRAINED => Ok(Some(1)),
        OP_ABORTED => Ok(if src.len() >= 5 { Some(5) } else { None }),
        OP_PROPOSE => {
            if src.len() < 8 {
                return Ok(None);
            }
            let inner_len = u16::from_le_bytes([src[6], src[7]]) as usize;
            let total = 8 + inner_len;
            Ok(if src.len() >= total {
                Some(total)
            } else {
                None
            })
        }
        OP_COMMITTED => {
            if src.len() < 17 {
                return Ok(None);
            }
            let inner_len = u16::from_le_bytes([src[15], src[16]]) as usize;
            let total = 17 + inner_len;
            Ok(if src.len() >= total {
                Some(total)
            } else {
                None
            })
        }
        observed => Err(WireError::BadOpcode { observed }),
    }
}
