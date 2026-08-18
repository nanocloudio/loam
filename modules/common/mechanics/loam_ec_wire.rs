// Shard blob framing + key derivation for erasure-coded bodies.
// Consumed by the EC body router (builds/parses shard blobs) and
// by body_store (verifies a keyed shard blob on disk-fallback
// reads, where content-hash verification can't apply).
//
// A shard is stored in body_store as a KEYED blob whose key is
//
//   K_i = sha256("loam-ec-shard" || body_digest || [index: u8])
//
// — a pure function of (body_digest, index), so any consumer can
// address every shard of a body from the body digest alone: no
// manifest, no router state, nothing to lose in a restart. The
// blob itself is self-describing:
//
//   [magic: u16 LE = 0xEC5D]
//   [k: u8][m: u8][index: u8]
//   [body_len: u32 LE]
//   [body_digest: 32]
//   [shard_len: u32 LE]
//   [shard bytes: shard_len]
//
// Self-description is what makes the derived key verifiable: parse
// the header, re-derive K from (body_digest, index), compare with
// the key the blob is stored under. End-to-end integrity comes
// from the body digest — a reconstructed body must sha256 back to
// it. Requires `super::sha256::Sha256` from the including module.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

pub const SHARD_MAGIC: u16 = 0xEC5D;
pub const DIGEST_LEN: usize = 32;
pub const SHARD_HDR: usize = 2 + 1 + 1 + 1 + 4 + DIGEST_LEN + 4;

const KEY_TAG: &[u8] = b"loam-ec-shard";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardHeader {
    pub k: u8,
    pub m: u8,
    pub index: u8,
    pub body_len: u32,
    pub body_digest: [u8; DIGEST_LEN],
    pub shard_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardWireError {
    Truncated,
    BadMagic { observed: u16 },
    BufferTooSmall { needed: usize, actual: usize },
}

/// The body_store key shard `index` of `body_digest` is stored
/// under. Pure function — no state anywhere.
pub fn derive_shard_key(body_digest: &[u8; DIGEST_LEN], index: u8) -> [u8; DIGEST_LEN] {
    let mut h = super::sha256::Sha256::new();
    h.update(KEY_TAG);
    h.update(body_digest);
    h.update(&[index]);
    h.finalize()
}

pub fn encode_shard_blob(
    dst: &mut [u8],
    hdr: &ShardHeader,
    shard: &[u8],
) -> Result<usize, ShardWireError> {
    let needed = SHARD_HDR + shard.len();
    if dst.len() < needed {
        return Err(ShardWireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0..2].copy_from_slice(&SHARD_MAGIC.to_le_bytes());
    dst[2] = hdr.k;
    dst[3] = hdr.m;
    dst[4] = hdr.index;
    dst[5..9].copy_from_slice(&hdr.body_len.to_le_bytes());
    dst[9..9 + DIGEST_LEN].copy_from_slice(&hdr.body_digest);
    let off = 9 + DIGEST_LEN;
    dst[off..off + 4].copy_from_slice(&(shard.len() as u32).to_le_bytes());
    dst[SHARD_HDR..needed].copy_from_slice(shard);
    Ok(needed)
}

pub fn decode_shard_header(src: &[u8]) -> Result<ShardHeader, ShardWireError> {
    if src.len() < SHARD_HDR {
        return Err(ShardWireError::Truncated);
    }
    let magic = u16::from_le_bytes([src[0], src[1]]);
    if magic != SHARD_MAGIC {
        return Err(ShardWireError::BadMagic { observed: magic });
    }
    let mut body_digest = [0u8; DIGEST_LEN];
    body_digest.copy_from_slice(&src[9..9 + DIGEST_LEN]);
    let off = 9 + DIGEST_LEN;
    let shard_len = u32::from_le_bytes([src[off], src[off + 1], src[off + 2], src[off + 3]]);
    if src.len() < SHARD_HDR + shard_len as usize {
        return Err(ShardWireError::Truncated);
    }
    Ok(ShardHeader {
        k: src[2],
        m: src[3],
        index: src[4],
        body_len: u32::from_le_bytes([src[5], src[6], src[7], src[8]]),
        body_digest,
        shard_len,
    })
}

/// The shard bytes of a decoded blob.
pub fn shard_payload(src: &[u8]) -> Result<&[u8], ShardWireError> {
    let hdr = decode_shard_header(src)?;
    Ok(&src[SHARD_HDR..SHARD_HDR + hdr.shard_len as usize])
}

/// Is `blob` a well-formed shard blob correctly stored under
/// `key`? This is body_store's disk-fallback verification for
/// keyed blobs: the derived key ties the blob to its claimed
/// (body_digest, index) exactly as a content hash ties a body
/// blob to its bytes.
pub fn shard_blob_matches_key(blob: &[u8], key: &[u8; DIGEST_LEN]) -> bool {
    match decode_shard_header(blob) {
        Ok(hdr) => derive_shard_key(&hdr.body_digest, hdr.index) == *key,
        Err(_) => false,
    }
}
