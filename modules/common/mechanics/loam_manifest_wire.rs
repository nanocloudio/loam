// Snapshot manifest — the `(key, digest)` listing that describes
// what a snapshot contains.
//
// This file owns the bytes and nothing else: no I/O, no allocation,
// no opinion about where the blob lives or what pins the bodies it
// names.
//
// ## What a manifest is NOT responsible for
//
// It is not a reachability root. A snapshot pins its bodies by
// BINDING them under a snapshot root — ordinary bindings, which the
// orphan GC's existing reachability answer already covers. Nothing
// has to teach the collector to read this format, no per-body
// refcount appears, and there is no window in which a manifest
// exists but its bodies are collectable. That is why the format can
// stay this simple: it describes a snapshot for transport and
// restore, it does not defend it.
//
// The manifest is therefore read LINEARLY, once, by whoever is
// restoring or exporting. It needs no index and no binary search —
// so it has neither, and records are variable-width with no padding.
//
// ## Layout
//
//   header  [magic u32 "LMAN"][count u32][root_len u16][root]
//   record  [digest 32][key_len u16][key]      × count
//
// Little-endian throughout, like every other loam wire.
//
// Same include discipline as the other mechanics sources: no_std,
// no dependencies, `#[path]`-included by every consumer.

pub const MAGIC: u32 = u32::from_le_bytes(*b"LMAN");

/// Digest width. SHA-256, as everywhere else in the body plane.
pub const DIGEST_LEN: usize = 32;

/// Fixed part of the header, before the root bytes.
pub const HEADER: usize = 4 + 4 + 2;

/// Fixed part of a record, before the key bytes.
pub const REC_HEADER: usize = DIGEST_LEN + 2;

/// Largest manifest this format can describe.
///
/// The count field is a `u32`, so that is the format's own ceiling.
/// It does not bind: a manifest is an ordinary body, and
/// `MAX_STREAM_TOTAL` (1 GiB) over the smallest possible record
/// binds at roughly 31 million entries first, on every profile. The
/// id space is deliberately wider than the memory pool, which is
/// fluxor's rule for identifier widths.
///
/// Registered anyway, because a snapshot that silently stopped at
/// some count would be a snapshot that lies about what it contains —
/// `encode` refuses past it rather than truncating.
pub const MAX_ENTRIES: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    /// The output buffer is smaller than `encoded_len` said.
    BufferTooSmall { needed: usize, actual: usize },
    /// Not a manifest: the magic did not match.
    BadMagic,
    /// The blob ends inside a header or a record.
    Truncated,
    /// A root or key exceeded its ceiling in `loam_limits.rs`. A
    /// clipped root would name a namespace that does not exist, and
    /// a clipped key would name the wrong object — so both are
    /// refused rather than shortened.
    TooLong { len: usize, max: usize },
    /// More entries than the format can describe.
    TooManyEntries { count: usize, max: u32 },
}

/// Exact encoded size for `root` and `refs`. A caller allocates this
/// and passes it to `encode`; the two are kept in step by
/// construction rather than by an assertion, because they walk the
/// same records the same way.
pub fn encoded_len(root: &[u8], refs: &[(&[u8], [u8; DIGEST_LEN])]) -> usize {
    let mut n = HEADER + root.len();
    for (key, _) in refs {
        n += REC_HEADER + key.len();
    }
    n
}

/// Encode a manifest. Returns the bytes written.
///
/// Records are written in the order given. Order is the caller's
/// business: this format is read linearly, so nothing here depends
/// on a sort, and imposing one would only invite a reader to rely on
/// it.
pub fn encode(
    out: &mut [u8],
    root: &[u8],
    refs: &[(&[u8], [u8; DIGEST_LEN])],
) -> Result<usize, ManifestError> {
    if root.len() > super::limits::MAX_ROOT {
        return Err(ManifestError::TooLong {
            len: root.len(),
            max: super::limits::MAX_ROOT,
        });
    }
    if refs.len() > MAX_ENTRIES as usize {
        return Err(ManifestError::TooManyEntries {
            count: refs.len(),
            max: MAX_ENTRIES,
        });
    }
    for (key, _) in refs {
        if key.len() > super::limits::MAX_PATH {
            return Err(ManifestError::TooLong {
                len: key.len(),
                max: super::limits::MAX_PATH,
            });
        }
    }
    let needed = encoded_len(root, refs);
    if out.len() < needed {
        return Err(ManifestError::BufferTooSmall {
            needed,
            actual: out.len(),
        });
    }

    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&(refs.len() as u32).to_le_bytes());
    out[8..10].copy_from_slice(&(root.len() as u16).to_le_bytes());
    let mut o = HEADER;
    out[o..o + root.len()].copy_from_slice(root);
    o += root.len();

    for (key, digest) in refs {
        out[o..o + DIGEST_LEN].copy_from_slice(digest);
        o += DIGEST_LEN;
        out[o..o + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
        o += 2;
        out[o..o + key.len()].copy_from_slice(key);
        o += key.len();
    }
    Ok(o)
}

/// The root a manifest was taken under, and how many entries it
/// declares — without walking the records.
///
/// Cheap enough to call before deciding whether to read the rest,
/// which is what a receiver does when it is choosing whether to
/// accept a transfer at all.
pub fn peek(manifest: &[u8]) -> Result<(&[u8], u32), ManifestError> {
    let (root, count, _) = split_header(manifest)?;
    Ok((root, count))
}

fn split_header(manifest: &[u8]) -> Result<(&[u8], u32, usize), ManifestError> {
    if manifest.len() < HEADER {
        return Err(ManifestError::Truncated);
    }
    let mut m = [0u8; 4];
    m.copy_from_slice(&manifest[0..4]);
    if u32::from_le_bytes(m) != MAGIC {
        return Err(ManifestError::BadMagic);
    }
    let mut c = [0u8; 4];
    c.copy_from_slice(&manifest[4..8]);
    let count = u32::from_le_bytes(c);
    let root_len = u16::from_le_bytes([manifest[8], manifest[9]]) as usize;
    if root_len > super::limits::MAX_ROOT {
        return Err(ManifestError::TooLong {
            len: root_len,
            max: super::limits::MAX_ROOT,
        });
    }
    if manifest.len() < HEADER + root_len {
        return Err(ManifestError::Truncated);
    }
    Ok((
        &manifest[HEADER..HEADER + root_len],
        count,
        HEADER + root_len,
    ))
}

/// Visit every `(key, digest)` in order.
///
/// The whole manifest is validated as it is walked: a record that
/// runs past the end, or a declared count the bytes do not support,
/// is an error rather than a short iteration. A caller restoring a
/// snapshot must be able to tell "this snapshot has three entries"
/// from "this snapshot had more and I could only read three" — the
/// second silently restores an incomplete volume.
pub fn for_each(
    manifest: &[u8],
    mut f: impl FnMut(&[u8], &[u8; DIGEST_LEN]),
) -> Result<usize, ManifestError> {
    let (_, count, mut o) = split_header(manifest)?;
    for _ in 0..count {
        if o + REC_HEADER > manifest.len() {
            return Err(ManifestError::Truncated);
        }
        let mut digest = [0u8; DIGEST_LEN];
        digest.copy_from_slice(&manifest[o..o + DIGEST_LEN]);
        o += DIGEST_LEN;
        let key_len = u16::from_le_bytes([manifest[o], manifest[o + 1]]) as usize;
        o += 2;
        if key_len > super::limits::MAX_PATH {
            return Err(ManifestError::TooLong {
                len: key_len,
                max: super::limits::MAX_PATH,
            });
        }
        if o + key_len > manifest.len() {
            return Err(ManifestError::Truncated);
        }
        f(&manifest[o..o + key_len], &digest);
        o += key_len;
    }
    Ok(count as usize)
}
