// Wire format for the `block_log` PIC channel protocol. A PIC
// that needs durable append-only storage talks to block_log over
// a request/response channel pair instead of doing fs syscalls
// directly. This preserves the mesh discipline (channels are the
// state-surface) and lets the same consumer code work over
// different storage backends: the `fs` contract today, a block
// device directly in a follow-up.
//
// Layouts (multi-byte ints LE):
//
//   AppendReq          [op:u8=0x50][cid:u32][len:u16][bytes:len]
//   AppendResp(ok)     [op:u8=0x50][cid:u32][status:u8=1][offset:u64]
//   AppendResp(nak)    [op:u8=0x50][cid:u32][status:u8=0]
//
//   ReplayReq          [op:u8=0x51][cid:u32]
//                      // request a full forward scan from offset 0
//
//   ReplayRecord       [op:u8=0x52][cid:u32][offset:u64][len:u16][bytes:len]
//                      // one of these per record found
//
//   ReplayEnd          [op:u8=0x53][cid:u32][total_records:u32]
//                      // sentinel marking the end of a ReplayReq stream

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use core::convert::TryInto;

pub const OP_APPEND_REQ: u8 = 0x50;
pub const OP_REPLAY_REQ: u8 = 0x51;
pub const OP_REPLAY_RECORD: u8 = 0x52;
pub const OP_REPLAY_END: u8 = 0x53;

pub const STATUS_OK: u8 = 1;
pub const STATUS_NAK: u8 = 0;

/// Per-record payload cap. Same envelope as the public-PIC wire
/// formats so an AppendReq from any consumer fits comfortably.
pub const MAX_RECORD: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    BufferTooSmall { needed: usize, actual: usize },
    Truncated,
    BadOpcode { observed: u8 },
    RecordTooLarge { len: usize, max: usize },
}

// ── Append ─────────────────────────────────────────────────────────

pub fn encode_append_req(
    dst: &mut [u8],
    correlation_id: u32,
    payload: &[u8],
) -> Result<usize, WireError> {
    if payload.len() > MAX_RECORD {
        return Err(WireError::RecordTooLarge {
            len: payload.len(),
            max: MAX_RECORD,
        });
    }
    let needed = 1 + 4 + 2 + payload.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_APPEND_REQ;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..7].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    dst[7..7 + payload.len()].copy_from_slice(payload);
    Ok(needed)
}

pub fn decode_append_req(src: &[u8]) -> Result<(u32, &[u8]), WireError> {
    if src.len() < 7 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_APPEND_REQ {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let len = u16::from_le_bytes([src[5], src[6]]) as usize;
    if 7 + len > src.len() {
        return Err(WireError::Truncated);
    }
    Ok((cid, &src[7..7 + len]))
}

pub fn encode_append_resp(
    dst: &mut [u8],
    correlation_id: u32,
    offset: Option<u64>,
) -> Result<usize, WireError> {
    match offset {
        Some(off) => {
            let needed = 1 + 4 + 1 + 8;
            if dst.len() < needed {
                return Err(WireError::BufferTooSmall {
                    needed,
                    actual: dst.len(),
                });
            }
            dst[0] = OP_APPEND_REQ;
            dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
            dst[5] = STATUS_OK;
            dst[6..14].copy_from_slice(&off.to_le_bytes());
            Ok(needed)
        }
        None => {
            let needed = 1 + 4 + 1;
            if dst.len() < needed {
                return Err(WireError::BufferTooSmall {
                    needed,
                    actual: dst.len(),
                });
            }
            dst[0] = OP_APPEND_REQ;
            dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
            dst[5] = STATUS_NAK;
            Ok(needed)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedAppendResp {
    pub correlation_id: u32,
    pub offset: Option<u64>,
}

pub fn decode_append_resp(src: &[u8]) -> Result<DecodedAppendResp, WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_APPEND_REQ {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    match src[5] {
        STATUS_OK => {
            if src.len() < 14 {
                return Err(WireError::Truncated);
            }
            let off = u64::from_le_bytes(src[6..14].try_into().unwrap());
            Ok(DecodedAppendResp {
                correlation_id: cid,
                offset: Some(off),
            })
        }
        _ => Ok(DecodedAppendResp {
            correlation_id: cid,
            offset: None,
        }),
    }
}

// ── Replay ─────────────────────────────────────────────────────────

pub fn encode_replay_req(dst: &mut [u8], correlation_id: u32) -> Result<usize, WireError> {
    let needed = 1 + 4;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_REPLAY_REQ;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    Ok(needed)
}

pub fn decode_replay_req(src: &[u8]) -> Result<u32, WireError> {
    if src.len() < 5 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_REPLAY_REQ {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(u32::from_le_bytes(src[1..5].try_into().unwrap()))
}

pub fn encode_replay_record(
    dst: &mut [u8],
    correlation_id: u32,
    offset: u64,
    payload: &[u8],
) -> Result<usize, WireError> {
    if payload.len() > MAX_RECORD {
        return Err(WireError::RecordTooLarge {
            len: payload.len(),
            max: MAX_RECORD,
        });
    }
    let needed = 1 + 4 + 8 + 2 + payload.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_REPLAY_RECORD;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..13].copy_from_slice(&offset.to_le_bytes());
    dst[13..15].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    dst[15..15 + payload.len()].copy_from_slice(payload);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedReplayRecord<'a> {
    pub correlation_id: u32,
    pub offset: u64,
    pub payload: &'a [u8],
}

pub fn decode_replay_record(src: &[u8]) -> Result<DecodedReplayRecord<'_>, WireError> {
    if src.len() < 15 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_REPLAY_RECORD {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let off = u64::from_le_bytes(src[5..13].try_into().unwrap());
    let len = u16::from_le_bytes([src[13], src[14]]) as usize;
    if 15 + len > src.len() {
        return Err(WireError::Truncated);
    }
    Ok(DecodedReplayRecord {
        correlation_id: cid,
        offset: off,
        payload: &src[15..15 + len],
    })
}

pub fn encode_replay_end(
    dst: &mut [u8],
    correlation_id: u32,
    total_records: u32,
) -> Result<usize, WireError> {
    let needed = 1 + 4 + 4;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_REPLAY_END;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..9].copy_from_slice(&total_records.to_le_bytes());
    Ok(needed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedReplayEnd {
    pub correlation_id: u32,
    pub total_records: u32,
}

pub fn decode_replay_end(src: &[u8]) -> Result<DecodedReplayEnd, WireError> {
    if src.len() < 9 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_REPLAY_END {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let total = u32::from_le_bytes(src[5..9].try_into().unwrap());
    Ok(DecodedReplayEnd {
        correlation_id: cid,
        total_records: total,
    })
}

pub fn peek_opcode(src: &[u8]) -> Option<u8> {
    src.first().copied()
}
