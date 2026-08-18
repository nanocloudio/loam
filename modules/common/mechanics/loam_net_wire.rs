// Loam's inter-node network contract: framed channel bridging
// over a byte stream. A loam graph's channels are its state
// surfaces; this wire carries named-channel messages between two
// nodes so a channel pair can span machines — e.g. an admin
// node's body_req/body_resp bridged to a body node's body_store.
//
// The stream starts with a HELLO from each side:
//
//   Hello:  [magic: u32 LE = "LOAM"][role: u8]
//
// then carries frames, each a single channel message:
//
//   Frame:  [len: u32 LE][tag: u16 LE][payload: len bytes]
//
// `tag` names the logical channel. Frames on one tag preserve
// order (the underlying stream is ordered), which is exactly the
// FIFO guarantee in-graph channels give — a bridged channel pair
// is indistinguishable from a local one to the PICs on either
// end. Message-per-frame framing is what makes that true: the
// stream may fragment arbitrarily, but a decoded frame is always
// one whole channel message.
//
// no_std vocabulary — host bridges (loam-server) and future
// PIC-side transports both speak it.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

pub const MAGIC: u32 = u32::from_le_bytes(*b"LOAM");
pub const HELLO_LEN: usize = 4 + 1;

/// Roles a peer announces in its HELLO.
pub const ROLE_BODY_CLIENT: u8 = 1; // forwards body_req, consumes body_resp
pub const ROLE_BODY_SERVER: u8 = 2; // hosts body_store

/// Channel tags.
pub const TAG_BODY_REQ: u16 = 1;
pub const TAG_BODY_RESP: u16 = 2;

pub const FRAME_HDR: usize = 4 + 2;

/// A frame payload is one channel message; the largest today is a
/// MAX_BODY put plus framing. Bounded so a corrupt length prefix
/// can't drive unbounded buffering.
pub const MAX_FRAME_PAYLOAD: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetWireError {
    Truncated,
    BadMagic { observed: u32 },
    FrameTooLarge { len: usize },
    BufferTooSmall { needed: usize, actual: usize },
}

pub fn encode_hello(dst: &mut [u8], role: u8) -> Result<usize, NetWireError> {
    if dst.len() < HELLO_LEN {
        return Err(NetWireError::BufferTooSmall {
            needed: HELLO_LEN,
            actual: dst.len(),
        });
    }
    dst[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    dst[4] = role;
    Ok(HELLO_LEN)
}

/// Returns the peer's role.
pub fn decode_hello(src: &[u8]) -> Result<u8, NetWireError> {
    if src.len() < HELLO_LEN {
        return Err(NetWireError::Truncated);
    }
    let magic = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
    if magic != MAGIC {
        return Err(NetWireError::BadMagic { observed: magic });
    }
    Ok(src[4])
}

pub fn encode_frame_header(
    dst: &mut [u8],
    tag: u16,
    payload_len: usize,
) -> Result<usize, NetWireError> {
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(NetWireError::FrameTooLarge { len: payload_len });
    }
    if dst.len() < FRAME_HDR {
        return Err(NetWireError::BufferTooSmall {
            needed: FRAME_HDR,
            actual: dst.len(),
        });
    }
    dst[0..4].copy_from_slice(&(payload_len as u32).to_le_bytes());
    dst[4..6].copy_from_slice(&tag.to_le_bytes());
    Ok(FRAME_HDR)
}

/// Returns (tag, payload_len).
pub fn decode_frame_header(src: &[u8]) -> Result<(u16, usize), NetWireError> {
    if src.len() < FRAME_HDR {
        return Err(NetWireError::Truncated);
    }
    let len = u32::from_le_bytes([src[0], src[1], src[2], src[3]]) as usize;
    if len > MAX_FRAME_PAYLOAD {
        return Err(NetWireError::FrameTooLarge { len });
    }
    let tag = u16::from_le_bytes([src[4], src[5]]);
    Ok((tag, len))
}
