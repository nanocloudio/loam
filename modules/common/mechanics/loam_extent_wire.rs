// Block-volume extent blobs and volume descriptors.
//
// A block volume is N fixed-size extents, each stored in the body
// plane under a DERIVED key (never a content hash):
//
//   extent_key(volume_id, index) =
//       sha256("loam-vol-extent" || volume_id || index_le)
//
// so placement is a pure function of (volume, index, fleet) — the
// same property EC shards rely on. Extent blobs are MUTABLE:
// PUT_KEYED overwrites, last write wins. Like shard blobs they are
// self-describing so a disk-fallback read can verify a blob really
// belongs to the key it was found under:
//
//   [magic "LVEX"][key:32][len:u32 LE][payload:len]
//
// The volume itself is described by an ordinary content-addressed
// FILE (put_file at the volume's path) so volume metadata rides
// the proven bind/replication/GC machinery:
//
//   [magic "LVOL"][volume_id:16][size_bytes:u64 LE]
//   [extent_size:u32 LE]
//
// Layered into PIC modules (no_std) and host tooling alike; the
// includer's scope must provide `super::sha256::Sha256`.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use core::convert::TryInto;

pub const DIGEST_LEN: usize = 32;
pub const VOLUME_ID_LEN: usize = 16;

pub const EXT_MAGIC: [u8; 4] = *b"LVEX";
pub const EXT_HDR: usize = 4 + DIGEST_LEN + 4;

pub const VOL_MAGIC: [u8; 4] = *b"LVOL";
pub const VOL_DESC_LEN: usize = 4 + VOLUME_ID_LEN + 8 + 4;

/// Extent payload cap: the blob (header + payload) must fit the
/// body plane's single-shot MAX_BODY (60 KiB).
pub const MAX_EXTENT_SIZE: usize = 60 * 1024 - EXT_HDR;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentError {
    BufferTooSmall,
    Malformed,
    TooLarge,
}

/// The derived body-plane key for one extent of one volume.
pub fn derive_extent_key(volume_id: &[u8; VOLUME_ID_LEN], index: u64) -> [u8; DIGEST_LEN] {
    let mut h = super::sha256::Sha256::new();
    h.update(b"loam-vol-extent");
    h.update(volume_id);
    h.update(&index.to_le_bytes());
    h.finalize()
}

pub fn encode_extent_blob(
    dst: &mut [u8],
    key: &[u8; DIGEST_LEN],
    payload: &[u8],
) -> Result<usize, ExtentError> {
    if payload.len() > MAX_EXTENT_SIZE {
        return Err(ExtentError::TooLarge);
    }
    let needed = EXT_HDR + payload.len();
    if dst.len() < needed {
        return Err(ExtentError::BufferTooSmall);
    }
    dst[..4].copy_from_slice(&EXT_MAGIC);
    dst[4..4 + DIGEST_LEN].copy_from_slice(key);
    dst[36..40].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    let mut i = 0;
    while i < payload.len() {
        dst[EXT_HDR + i] = payload[i];
        i += 1;
    }
    Ok(needed)
}

/// (key, payload) of a well-formed extent blob.
pub fn decode_extent_blob(blob: &[u8]) -> Result<(&[u8], &[u8]), ExtentError> {
    if blob.len() < EXT_HDR || blob[..4] != EXT_MAGIC {
        return Err(ExtentError::Malformed);
    }
    let len = u32::from_le_bytes([blob[36], blob[37], blob[38], blob[39]]) as usize;
    if blob.len() != EXT_HDR + len {
        return Err(ExtentError::Malformed);
    }
    Ok((&blob[4..4 + DIGEST_LEN], &blob[EXT_HDR..]))
}

/// Does this blob's self-declared key match the key it was found
/// under? (Disk-fallback integrity check, same role as
/// `shard_blob_matches_key`.)
pub fn extent_blob_matches_key(blob: &[u8], key: &[u8; DIGEST_LEN]) -> bool {
    match decode_extent_blob(blob) {
        Ok((declared, _)) => declared == key,
        Err(_) => false,
    }
}

/// Is this blob keyed (extent or EC shard) rather than a
/// content-addressed body? Magic sniff only — used by the disk
/// sweep, which never reads whole bodies. Shard blobs open with
/// SHARD_MAGIC (0xEC5D LE, see loam_ec_wire.rs).
pub fn blob_is_keyed_magic(prefix: &[u8]) -> bool {
    if prefix.len() < 4 {
        return false;
    }
    prefix[..4] == EXT_MAGIC || (prefix[0] == 0x5D && prefix[1] == 0xEC)
}

// ── Volume descriptor ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeDesc {
    pub volume_id: [u8; VOLUME_ID_LEN],
    pub size_bytes: u64,
    pub extent_size: u32,
}

/// Deterministic volume id from the volume's identity.
pub fn derive_volume_id(namespace_root: &[u8], path: &[u8]) -> [u8; VOLUME_ID_LEN] {
    let mut h = super::sha256::Sha256::new();
    h.update(b"loam-volume");
    h.update(namespace_root);
    h.update(&[0u8]);
    h.update(path);
    let full = h.finalize();
    let mut id = [0u8; VOLUME_ID_LEN];
    id.copy_from_slice(&full[..VOLUME_ID_LEN]);
    id
}

pub fn encode_volume_desc(dst: &mut [u8], desc: &VolumeDesc) -> Result<usize, ExtentError> {
    if dst.len() < VOL_DESC_LEN {
        return Err(ExtentError::BufferTooSmall);
    }
    if desc.extent_size == 0 || desc.extent_size as usize > MAX_EXTENT_SIZE {
        return Err(ExtentError::TooLarge);
    }
    dst[..4].copy_from_slice(&VOL_MAGIC);
    dst[4..20].copy_from_slice(&desc.volume_id);
    dst[20..28].copy_from_slice(&desc.size_bytes.to_le_bytes());
    dst[28..32].copy_from_slice(&desc.extent_size.to_le_bytes());
    Ok(VOL_DESC_LEN)
}

pub fn decode_volume_desc(src: &[u8]) -> Result<VolumeDesc, ExtentError> {
    if src.len() != VOL_DESC_LEN || src[..4] != VOL_MAGIC {
        return Err(ExtentError::Malformed);
    }
    let mut volume_id = [0u8; VOLUME_ID_LEN];
    volume_id.copy_from_slice(&src[4..20]);
    let size_bytes = u64::from_le_bytes(src[20..28].try_into().unwrap());
    let extent_size = u32::from_le_bytes(src[28..32].try_into().unwrap());
    if extent_size == 0 || extent_size as usize > MAX_EXTENT_SIZE {
        return Err(ExtentError::Malformed);
    }
    Ok(VolumeDesc {
        volume_id,
        size_bytes,
        extent_size,
    })
}
