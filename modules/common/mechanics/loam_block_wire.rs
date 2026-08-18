// Binary wire format for block-plane events. Three opcodes:
//
//   CreateVolume  [op:u8=7][volume_id_len:u16][class:u8]
//                 [logical_bytes:u64][block_size:u32]
//                 [thin_provisioned:u8][volume_id]
//   Allocate      [op:u8=8][volume_id_len:u16][count:u64][volume_id]
//   Release       [op:u8=9][volume_id_len:u16][count:u64][volume_id]
//
// Block classes:
//   0 = Local, 1 = ThinProvisioned, 2 = Replicated,
//   3 = ChainReplicated, 4 = Snapshot

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

// The Fluxor module Makefile defaults to Rust 2015 (no --edition
// flag). In 2015, `TryInto` is not in the prelude. The 2021 prelude
// includes it; this import is harmless in 2021 and required in 2015.
use core::convert::TryInto;

pub const OP_CREATE_VOLUME: u8 = 7;
pub const OP_ALLOCATE: u8 = 8;
pub const OP_RELEASE: u8 = 9;

pub const CLASS_LOCAL: u8 = 0;
pub const CLASS_THIN_PROVISIONED: u8 = 1;
pub const CLASS_REPLICATED: u8 = 2;
pub const CLASS_CHAIN_REPLICATED: u8 = 3;
pub const CLASS_SNAPSHOT: u8 = 4;

pub const MAX_STRING: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    BufferTooSmall { needed: usize, actual: usize },
    Truncated,
    BadOpcode { observed: u8 },
    BadClass { observed: u8 },
    StringTooLong { len: usize, max: usize },
}

const CREATE_HEADER: usize = 1 + 2 + 1 + 8 + 4 + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCreateVolume<'a> {
    pub volume_id: &'a [u8],
    pub class: u8,
    pub logical_bytes: u64,
    pub block_size: u32,
    pub thin_provisioned: bool,
}

pub fn encode_create_volume(
    dst: &mut [u8],
    volume_id: &[u8],
    class: u8,
    logical_bytes: u64,
    block_size: u32,
    thin_provisioned: bool,
) -> Result<usize, WireError> {
    if volume_id.len() > MAX_STRING {
        return Err(WireError::StringTooLong {
            len: volume_id.len(),
            max: MAX_STRING,
        });
    }
    if class > CLASS_SNAPSHOT {
        return Err(WireError::BadClass { observed: class });
    }
    let needed = CREATE_HEADER + volume_id.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_CREATE_VOLUME;
    dst[1..3].copy_from_slice(&(volume_id.len() as u16).to_le_bytes());
    dst[3] = class;
    dst[4..12].copy_from_slice(&logical_bytes.to_le_bytes());
    dst[12..16].copy_from_slice(&block_size.to_le_bytes());
    dst[16] = if thin_provisioned { 1 } else { 0 };
    dst[CREATE_HEADER..CREATE_HEADER + volume_id.len()].copy_from_slice(volume_id);
    Ok(needed)
}

pub fn decode_create_volume(src: &[u8]) -> Result<DecodedCreateVolume<'_>, WireError> {
    if src.len() < CREATE_HEADER {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_CREATE_VOLUME {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let id_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    let class = src[3];
    if class > CLASS_SNAPSHOT {
        return Err(WireError::BadClass { observed: class });
    }
    let logical_bytes = u64::from_le_bytes(src[4..12].try_into().unwrap());
    let block_size = u32::from_le_bytes(src[12..16].try_into().unwrap());
    let thin_provisioned = src[16] != 0;
    if src.len() < CREATE_HEADER + id_len {
        return Err(WireError::Truncated);
    }
    Ok(DecodedCreateVolume {
        volume_id: &src[CREATE_HEADER..CREATE_HEADER + id_len],
        class,
        logical_bytes,
        block_size,
        thin_provisioned,
    })
}

const COUNT_HEADER: usize = 1 + 2 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCountOp<'a> {
    pub volume_id: &'a [u8],
    pub count: u64,
}

fn encode_count_op(
    dst: &mut [u8],
    op: u8,
    volume_id: &[u8],
    count: u64,
) -> Result<usize, WireError> {
    if volume_id.len() > MAX_STRING {
        return Err(WireError::StringTooLong {
            len: volume_id.len(),
            max: MAX_STRING,
        });
    }
    let needed = COUNT_HEADER + volume_id.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = op;
    dst[1..3].copy_from_slice(&(volume_id.len() as u16).to_le_bytes());
    dst[3..11].copy_from_slice(&count.to_le_bytes());
    dst[COUNT_HEADER..COUNT_HEADER + volume_id.len()].copy_from_slice(volume_id);
    Ok(needed)
}

fn decode_count_op(src: &[u8], expected_op: u8) -> Result<DecodedCountOp<'_>, WireError> {
    if src.len() < COUNT_HEADER {
        return Err(WireError::Truncated);
    }
    if src[0] != expected_op {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let id_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    let count = u64::from_le_bytes(src[3..11].try_into().unwrap());
    if src.len() < COUNT_HEADER + id_len {
        return Err(WireError::Truncated);
    }
    Ok(DecodedCountOp {
        volume_id: &src[COUNT_HEADER..COUNT_HEADER + id_len],
        count,
    })
}

pub fn encode_allocate(dst: &mut [u8], volume_id: &[u8], count: u64) -> Result<usize, WireError> {
    encode_count_op(dst, OP_ALLOCATE, volume_id, count)
}

pub fn decode_allocate(src: &[u8]) -> Result<DecodedCountOp<'_>, WireError> {
    decode_count_op(src, OP_ALLOCATE)
}

pub fn encode_release(dst: &mut [u8], volume_id: &[u8], count: u64) -> Result<usize, WireError> {
    encode_count_op(dst, OP_RELEASE, volume_id, count)
}

pub fn decode_release(src: &[u8]) -> Result<DecodedCountOp<'_>, WireError> {
    decode_count_op(src, OP_RELEASE)
}

pub fn peek_opcode(src: &[u8]) -> Option<u8> {
    src.first().copied()
}

// ── Request stream splitting ───────────────────────────────────────

/// Length of the request record at the front of `src`, or `None` when
/// `src` does not yet hold a whole one.
///
/// See `loam_wire::request_record_len` for why a provider needs this:
/// its `requests` channel is a byte stream, so a batching producer's
/// records coalesce into one read and a read can end mid-record.
///
/// Every request here is a fixed header carrying one `volume_id`
/// length at offset 1, followed by that string.
pub fn request_record_len(src: &[u8]) -> Result<Option<usize>, WireError> {
    let opcode = match src.first() {
        Some(b) => *b,
        None => return Ok(None),
    };
    let header = match opcode {
        OP_CREATE_VOLUME => CREATE_HEADER,
        OP_ALLOCATE | OP_RELEASE => COUNT_HEADER,
        observed => return Err(WireError::BadOpcode { observed }),
    };
    if src.len() < header {
        return Ok(None);
    }
    let total = header + u16::from_le_bytes([src[1], src[2]]) as usize;
    Ok(if src.len() >= total {
        Some(total)
    } else {
        None
    })
}
