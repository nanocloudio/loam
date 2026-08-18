// Wire format for the `body_store` PIC's channel protocol.
//
// Bodies are content-addressed by SHA-256; the 32-byte digest IS
// the ObjectId. Single-shot put/get capped at MAX_BODY bytes per
// op (channel-bounded). Streaming protocol for large bodies is a
// follow-up phase.
//
// Layouts (multi-byte ints LE):
//
//   PutReq          [op:u8=0x30][len:u32][bytes:len]
//   PutResp(ok)     [op:u8=0x30][digest:32]
//
//   GetReq          [op:u8=0x31][digest:32]
//   GetResp(ok)     [op:u8=0x31][len:u32][bytes:len]
//
//   HeadReq         [op:u8=0x32][digest:32]
//   HeadResp(ok)    [op:u8=0x32][size:u64]
//
//   DeleteReq       [op:u8=0x33][digest:32]
//   DeleteResp(ok)  [op:u8=0x33][existed:u8]   // 1 if removed, 0 if absent
//
//   ScanReq         [op:u8=0x34][cursor:u32][max:u8]
//   ScanResp(ok)    [op:u8=0x34][next_cursor:u32][count:u8][digests:count*32]
//                   // next_cursor 0 = enumeration wrapped; resume from 0
//
//   PutKeyedReq     [op:u8=0x35][key:32][len:u32][bytes:len]
//   PutKeyedResp    [op:u8=0x35][key:32]
//                   // store at an explicit key instead of the content
//                   // hash — used for EC shard blobs, whose key is
//                   // derived from (body_digest, shard index) so a
//                   // reader can address them without a manifest.
//                   // GET/HEAD/DELETE/SCAN treat keys and content
//                   // digests identically.
//
//   NakResp         [op:u8=0xFF][errno:u8]      // any op
//
// Errno values mirror the fluxor `errno` module enough that
// consumers can map common cases (NOT_FOUND, TOO_LARGE, IO_FAILED).

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use core::convert::TryInto;

pub const OP_PUT: u8 = 0x30;
pub const OP_GET: u8 = 0x31;
pub const OP_HEAD: u8 = 0x32;
pub const OP_DELETE: u8 = 0x33;
pub const OP_SCAN: u8 = 0x34;
pub const OP_PUT_KEYED: u8 = 0x35;

// ── Chunked (streaming) writes + ranged reads ─────────────────────
//
// Bodies past MAX_BODY stream in bounded chunks. The writer
// declares the content digest UP FRONT (it has the whole object —
// loam's gateways spool before writing), which is what keeps
// rendezvous placement and content addressing intact for streams:
// placement is computable at WOPEN, and the store verifies its
// incrementally-hashed bytes against the declared digest at
// WCOMMIT — a mismatch aborts, nothing is published.
//
//   WOpenReq     [op=0x36][digest:32][total_len:u64]
//   WOpenResp    [op=0x36][wid:u8]
//   WAppendReq   [op=0x37][wid:u8][len:u32][bytes:len]   len ≤ MAX_BODY
//   WAppendResp  [op=0x37][wid:u8]
//   WCommitReq   [op=0x38][wid:u8]
//   WCommitResp  [op=0x38][digest:32]
//   WAbortReq    [op=0x39][wid:u8]
//   WAbortResp   [op=0x39]
//
//   RangeReq     [op=0x3A][digest:32][off:u64][len:u32]  len ≤ MAX_BODY
//   RangeResp    [op=0x3A][len:u32][bytes:len]           len 0 = at/past EOF
//
// Ranged reads are stateless (open/seek/read/close per op) — no
// read sessions to leak. A range cannot digest-verify partial
// bytes; whole-object verification remains the full-GET path and
// the writer-side commit check.
pub const OP_WOPEN: u8 = 0x36;
pub const OP_WAPPEND: u8 = 0x37;
pub const OP_WCOMMIT: u8 = 0x38;
pub const OP_WABORT: u8 = 0x39;
pub const OP_RANGE: u8 = 0x3A;

/// Max total streamed body size (1 GiB) — a sanity bound on
/// WOpen's total_len, not an arena size (streams cost constant
/// arena).
pub const MAX_STREAM_TOTAL: u64 = 1 << 30;

pub const OP_NAK: u8 = 0xFF;

/// Max digests per ScanResp — keeps the response bounded and the
/// scanning consumer's per-step work small.
pub const MAX_SCAN_DIGESTS: usize = 4;

pub const DIGEST_LEN: usize = 32;

/// Max body length per single-shot put/get. Bounded so a put +
/// header + digest still fits in the per-step scratch buffer.
// Raised from 3072: consumers store region-journal-class blobs
// (tens of KiB) in a single shot. Buffers derive from this const.
pub const MAX_BODY: usize = 61440;

pub const ERR_NOT_FOUND: u8 = 1;
pub const ERR_TOO_LARGE: u8 = 2;
pub const ERR_IO: u8 = 3;
pub const ERR_BAD_REQ: u8 = 4;
pub const ERR_NO_ROOT: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadOpcode { observed: u8 },
    BodyTooLarge { len: usize, max: usize },
    BufferTooSmall { needed: usize, actual: usize },
}

// ── PutReq ─────────────────────────────────────────────────────────

pub fn encode_put_req(dst: &mut [u8], body: &[u8]) -> Result<usize, WireError> {
    if body.len() > MAX_BODY {
        return Err(WireError::BodyTooLarge {
            len: body.len(),
            max: MAX_BODY,
        });
    }
    let needed = 1 + 4 + body.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT;
    dst[1..5].copy_from_slice(&(body.len() as u32).to_le_bytes());
    dst[5..5 + body.len()].copy_from_slice(body);
    Ok(needed)
}

pub fn decode_put_req(src: &[u8]) -> Result<&[u8], WireError> {
    if src.len() < 5 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let len = u32::from_le_bytes([src[1], src[2], src[3], src[4]]) as usize;
    if len > MAX_BODY {
        return Err(WireError::BodyTooLarge { len, max: MAX_BODY });
    }
    if 5 + len > src.len() {
        return Err(WireError::Truncated);
    }
    Ok(&src[5..5 + len])
}

// ── PutResp (ok) ───────────────────────────────────────────────────

pub fn encode_put_resp(dst: &mut [u8], digest: &[u8; DIGEST_LEN]) -> Result<usize, WireError> {
    let needed = 1 + DIGEST_LEN;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT;
    dst[1..1 + DIGEST_LEN].copy_from_slice(digest);
    Ok(needed)
}

pub fn decode_put_resp(src: &[u8]) -> Result<&[u8], WireError> {
    if src.len() < 1 + DIGEST_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(&src[1..1 + DIGEST_LEN])
}

// ── GetReq / GetResp ───────────────────────────────────────────────

pub fn encode_get_req(dst: &mut [u8], digest: &[u8; DIGEST_LEN]) -> Result<usize, WireError> {
    let needed = 1 + DIGEST_LEN;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_GET;
    dst[1..1 + DIGEST_LEN].copy_from_slice(digest);
    Ok(needed)
}

pub fn decode_get_req(src: &[u8]) -> Result<&[u8], WireError> {
    if src.len() < 1 + DIGEST_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_GET {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(&src[1..1 + DIGEST_LEN])
}

pub fn encode_get_resp(dst: &mut [u8], body: &[u8]) -> Result<usize, WireError> {
    if body.len() > MAX_BODY {
        return Err(WireError::BodyTooLarge {
            len: body.len(),
            max: MAX_BODY,
        });
    }
    let needed = 1 + 4 + body.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_GET;
    dst[1..5].copy_from_slice(&(body.len() as u32).to_le_bytes());
    dst[5..5 + body.len()].copy_from_slice(body);
    Ok(needed)
}

pub fn decode_get_resp(src: &[u8]) -> Result<&[u8], WireError> {
    if src.len() < 5 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_GET {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let len = u32::from_le_bytes([src[1], src[2], src[3], src[4]]) as usize;
    if 5 + len > src.len() {
        return Err(WireError::Truncated);
    }
    Ok(&src[5..5 + len])
}

// ── HeadReq / HeadResp ─────────────────────────────────────────────

pub fn encode_head_req(dst: &mut [u8], digest: &[u8; DIGEST_LEN]) -> Result<usize, WireError> {
    let needed = 1 + DIGEST_LEN;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_HEAD;
    dst[1..1 + DIGEST_LEN].copy_from_slice(digest);
    Ok(needed)
}

pub fn decode_head_req(src: &[u8]) -> Result<&[u8], WireError> {
    if src.len() < 1 + DIGEST_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_HEAD {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(&src[1..1 + DIGEST_LEN])
}

pub fn encode_head_resp(dst: &mut [u8], size: u64) -> Result<usize, WireError> {
    let needed = 1 + 8;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_HEAD;
    dst[1..9].copy_from_slice(&size.to_le_bytes());
    Ok(needed)
}

pub fn decode_head_resp(src: &[u8]) -> Result<u64, WireError> {
    if src.len() < 9 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_HEAD {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let bytes: [u8; 8] = [
        src[1], src[2], src[3], src[4], src[5], src[6], src[7], src[8],
    ];
    Ok(u64::from_le_bytes(bytes))
}

// ── DeleteReq / DeleteResp ─────────────────────────────────────────

pub fn encode_delete_req(dst: &mut [u8], digest: &[u8; DIGEST_LEN]) -> Result<usize, WireError> {
    let needed = 1 + DIGEST_LEN;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_DELETE;
    dst[1..1 + DIGEST_LEN].copy_from_slice(digest);
    Ok(needed)
}

pub fn decode_delete_req(src: &[u8]) -> Result<&[u8], WireError> {
    if src.len() < 1 + DIGEST_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_DELETE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(&src[1..1 + DIGEST_LEN])
}

pub fn encode_delete_resp(dst: &mut [u8], existed: bool) -> Result<usize, WireError> {
    if dst.len() < 2 {
        return Err(WireError::BufferTooSmall {
            needed: 2,
            actual: dst.len(),
        });
    }
    dst[0] = OP_DELETE;
    dst[1] = if existed { 1 } else { 0 };
    Ok(2)
}

pub fn decode_delete_resp(src: &[u8]) -> Result<bool, WireError> {
    if src.len() < 2 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_DELETE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(src[1] != 0)
}

// ── PutKeyedReq / PutKeyedResp ─────────────────────────────────────

pub fn encode_put_keyed_req(
    dst: &mut [u8],
    key: &[u8; DIGEST_LEN],
    body: &[u8],
) -> Result<usize, WireError> {
    if body.len() > MAX_BODY {
        return Err(WireError::BodyTooLarge {
            len: body.len(),
            max: MAX_BODY,
        });
    }
    let needed = 1 + DIGEST_LEN + 4 + body.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_KEYED;
    dst[1..1 + DIGEST_LEN].copy_from_slice(key);
    let off = 1 + DIGEST_LEN;
    dst[off..off + 4].copy_from_slice(&(body.len() as u32).to_le_bytes());
    dst[off + 4..needed].copy_from_slice(body);
    Ok(needed)
}

pub fn decode_put_keyed_req(src: &[u8]) -> Result<(&[u8], &[u8]), WireError> {
    let hdr = 1 + DIGEST_LEN + 4;
    if src.len() < hdr {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_KEYED {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let off = 1 + DIGEST_LEN;
    let len = u32::from_le_bytes([src[off], src[off + 1], src[off + 2], src[off + 3]]) as usize;
    if len > MAX_BODY {
        return Err(WireError::BodyTooLarge { len, max: MAX_BODY });
    }
    if hdr + len > src.len() {
        return Err(WireError::Truncated);
    }
    Ok((&src[1..1 + DIGEST_LEN], &src[hdr..hdr + len]))
}

pub fn encode_put_keyed_resp(dst: &mut [u8], key: &[u8; DIGEST_LEN]) -> Result<usize, WireError> {
    let needed = 1 + DIGEST_LEN;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_KEYED;
    dst[1..needed].copy_from_slice(key);
    Ok(needed)
}

pub fn decode_put_keyed_resp(src: &[u8]) -> Result<&[u8], WireError> {
    if src.len() < 1 + DIGEST_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_KEYED {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(&src[1..1 + DIGEST_LEN])
}

// ── ScanReq / ScanResp ─────────────────────────────────────────────

pub fn encode_scan_req(dst: &mut [u8], cursor: u32, max: u8) -> Result<usize, WireError> {
    let needed = 1 + 4 + 1;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_SCAN;
    dst[1..5].copy_from_slice(&cursor.to_le_bytes());
    dst[5] = max;
    Ok(needed)
}

pub fn decode_scan_req(src: &[u8]) -> Result<(u32, u8), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_SCAN {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cursor = u32::from_le_bytes([src[1], src[2], src[3], src[4]]);
    Ok((cursor, src[5]))
}

/// Encode a ScanResp from a slice of digests. `digests.len()` must
/// be at most MAX_SCAN_DIGESTS.
/// Each scan entry carries a KEYED flag: 1 for blobs stored under
/// an explicit key (volume extents, EC shards — lifecycle owned by
/// their writers), 0 for content-addressed bodies (lifecycle owned
/// by namespace references / the orphan GC).
pub fn encode_scan_resp(
    dst: &mut [u8],
    next_cursor: u32,
    digests: &[[u8; DIGEST_LEN]],
    keyed: &[u8],
) -> Result<usize, WireError> {
    if digests.len() > MAX_SCAN_DIGESTS || keyed.len() != digests.len() {
        return Err(WireError::BodyTooLarge {
            len: digests.len(),
            max: MAX_SCAN_DIGESTS,
        });
    }
    let needed = 1 + 4 + 1 + digests.len() * (1 + DIGEST_LEN);
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_SCAN;
    dst[1..5].copy_from_slice(&next_cursor.to_le_bytes());
    dst[5] = digests.len() as u8;
    for (i, d) in digests.iter().enumerate() {
        let off = 6 + i * (1 + DIGEST_LEN);
        dst[off] = if keyed[i] != 0 { 1 } else { 0 };
        dst[off + 1..off + 1 + DIGEST_LEN].copy_from_slice(d);
    }
    Ok(needed)
}

/// Decode a ScanResp into (next_cursor, count); digests and keyed
/// flags land in the caller's fixed buffers.
pub fn decode_scan_resp(
    src: &[u8],
    digests: &mut [[u8; DIGEST_LEN]; MAX_SCAN_DIGESTS],
    keyed: &mut [u8; MAX_SCAN_DIGESTS],
) -> Result<(u32, usize), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_SCAN {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let next_cursor = u32::from_le_bytes([src[1], src[2], src[3], src[4]]);
    let count = src[5] as usize;
    if count > MAX_SCAN_DIGESTS {
        return Err(WireError::BodyTooLarge {
            len: count,
            max: MAX_SCAN_DIGESTS,
        });
    }
    if src.len() < 6 + count * (1 + DIGEST_LEN) {
        return Err(WireError::Truncated);
    }
    for i in 0..count {
        let off = 6 + i * (1 + DIGEST_LEN);
        keyed[i] = src[off];
        digests[i].copy_from_slice(&src[off + 1..off + 1 + DIGEST_LEN]);
    }
    Ok((next_cursor, count))
}

// ── Chunked write + range encoders/decoders ───────────────────────

pub fn encode_wopen_req(
    dst: &mut [u8],
    digest: &[u8; DIGEST_LEN],
    total_len: u64,
) -> Result<usize, WireError> {
    let needed = 1 + DIGEST_LEN + 8;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_WOPEN;
    dst[1..1 + DIGEST_LEN].copy_from_slice(digest);
    dst[1 + DIGEST_LEN..needed].copy_from_slice(&total_len.to_le_bytes());
    Ok(needed)
}

pub fn decode_wopen_req(src: &[u8]) -> Result<(&[u8], u64), WireError> {
    let needed = 1 + DIGEST_LEN + 8;
    if src.len() < needed {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_WOPEN {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let total = u64::from_le_bytes(src[1 + DIGEST_LEN..needed].try_into().unwrap());
    Ok((&src[1..1 + DIGEST_LEN], total))
}

pub fn encode_wopen_resp(dst: &mut [u8], wid: u8) -> Result<usize, WireError> {
    if dst.len() < 2 {
        return Err(WireError::BufferTooSmall {
            needed: 2,
            actual: dst.len(),
        });
    }
    dst[0] = OP_WOPEN;
    dst[1] = wid;
    Ok(2)
}

pub fn decode_wopen_resp(src: &[u8]) -> Result<u8, WireError> {
    if src.len() < 2 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_WOPEN {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(src[1])
}

pub fn encode_wappend_req(dst: &mut [u8], wid: u8, bytes: &[u8]) -> Result<usize, WireError> {
    if bytes.len() > MAX_BODY {
        return Err(WireError::BodyTooLarge {
            len: bytes.len(),
            max: MAX_BODY,
        });
    }
    let needed = 1 + 1 + 4 + bytes.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_WAPPEND;
    dst[1] = wid;
    dst[2..6].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    dst[6..needed].copy_from_slice(bytes);
    Ok(needed)
}

pub fn decode_wappend_req(src: &[u8]) -> Result<(u8, &[u8]), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_WAPPEND {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let len = u32::from_le_bytes(src[2..6].try_into().unwrap()) as usize;
    if len > MAX_BODY {
        return Err(WireError::BodyTooLarge { len, max: MAX_BODY });
    }
    if src.len() < 6 + len {
        return Err(WireError::Truncated);
    }
    Ok((src[1], &src[6..6 + len]))
}

pub fn encode_wappend_resp(dst: &mut [u8], wid: u8) -> Result<usize, WireError> {
    if dst.len() < 2 {
        return Err(WireError::BufferTooSmall {
            needed: 2,
            actual: dst.len(),
        });
    }
    dst[0] = OP_WAPPEND;
    dst[1] = wid;
    Ok(2)
}

pub fn encode_wcommit_req(dst: &mut [u8], wid: u8) -> Result<usize, WireError> {
    if dst.len() < 2 {
        return Err(WireError::BufferTooSmall {
            needed: 2,
            actual: dst.len(),
        });
    }
    dst[0] = OP_WCOMMIT;
    dst[1] = wid;
    Ok(2)
}

pub fn decode_wid_req(src: &[u8], op: u8) -> Result<u8, WireError> {
    if src.len() < 2 {
        return Err(WireError::Truncated);
    }
    if src[0] != op {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(src[1])
}

pub fn encode_wcommit_resp(dst: &mut [u8], digest: &[u8; DIGEST_LEN]) -> Result<usize, WireError> {
    let needed = 1 + DIGEST_LEN;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_WCOMMIT;
    dst[1..needed].copy_from_slice(digest);
    Ok(needed)
}

pub fn decode_wcommit_resp(src: &[u8]) -> Result<&[u8], WireError> {
    if src.len() < 1 + DIGEST_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_WCOMMIT {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(&src[1..1 + DIGEST_LEN])
}

pub fn encode_wabort_req(dst: &mut [u8], wid: u8) -> Result<usize, WireError> {
    if dst.len() < 2 {
        return Err(WireError::BufferTooSmall {
            needed: 2,
            actual: dst.len(),
        });
    }
    dst[0] = OP_WABORT;
    dst[1] = wid;
    Ok(2)
}

pub fn encode_wabort_resp(dst: &mut [u8]) -> Result<usize, WireError> {
    if dst.is_empty() {
        return Err(WireError::BufferTooSmall {
            needed: 1,
            actual: 0,
        });
    }
    dst[0] = OP_WABORT;
    Ok(1)
}

pub fn encode_range_req(
    dst: &mut [u8],
    digest: &[u8; DIGEST_LEN],
    off: u64,
    len: u32,
) -> Result<usize, WireError> {
    let needed = 1 + DIGEST_LEN + 8 + 4;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_RANGE;
    dst[1..1 + DIGEST_LEN].copy_from_slice(digest);
    dst[1 + DIGEST_LEN..1 + DIGEST_LEN + 8].copy_from_slice(&off.to_le_bytes());
    dst[1 + DIGEST_LEN + 8..needed].copy_from_slice(&len.to_le_bytes());
    Ok(needed)
}

pub fn decode_range_req(src: &[u8]) -> Result<(&[u8], u64, u32), WireError> {
    let needed = 1 + DIGEST_LEN + 8 + 4;
    if src.len() < needed {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_RANGE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let off = u64::from_le_bytes(src[1 + DIGEST_LEN..1 + DIGEST_LEN + 8].try_into().unwrap());
    let len = u32::from_le_bytes(src[1 + DIGEST_LEN + 8..needed].try_into().unwrap());
    Ok((&src[1..1 + DIGEST_LEN], off, len))
}

pub fn encode_range_resp(dst: &mut [u8], bytes: &[u8]) -> Result<usize, WireError> {
    if bytes.len() > MAX_BODY {
        return Err(WireError::BodyTooLarge {
            len: bytes.len(),
            max: MAX_BODY,
        });
    }
    let needed = 1 + 4 + bytes.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_RANGE;
    dst[1..5].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    dst[5..needed].copy_from_slice(bytes);
    Ok(needed)
}

pub fn decode_range_resp(src: &[u8]) -> Result<&[u8], WireError> {
    if src.len() < 5 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_RANGE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let len = u32::from_le_bytes(src[1..5].try_into().unwrap()) as usize;
    if src.len() < 5 + len {
        return Err(WireError::Truncated);
    }
    Ok(&src[5..5 + len])
}

// ── NAK ────────────────────────────────────────────────────────────

pub fn encode_nak(dst: &mut [u8], errno: u8) -> Result<usize, WireError> {
    if dst.len() < 2 {
        return Err(WireError::BufferTooSmall {
            needed: 2,
            actual: dst.len(),
        });
    }
    dst[0] = OP_NAK;
    dst[1] = errno;
    Ok(2)
}

pub fn peek_opcode(src: &[u8]) -> Option<u8> {
    src.first().copied()
}

// ── Hex helpers (used to build per-digest file names) ──────────────

/// Format a 32-byte digest as 64 lowercase hex chars into `out`.
/// Panics in debug if `out.len() < 64`; in release writes up to
/// `out.len()` bytes.
pub fn hex_lower_into(digest: &[u8; DIGEST_LEN], out: &mut [u8]) -> usize {
    const A: &[u8; 16] = b"0123456789abcdef";
    let max = out.len().min(64);
    let mut i = 0;
    let mut o = 0;
    while o + 2 <= max {
        let b = digest[i];
        out[o] = A[(b >> 4) as usize];
        out[o + 1] = A[(b & 0x0F) as usize];
        i += 1;
        o += 2;
    }
    o
}
