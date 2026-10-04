// Snapshot manifest — the `(key, digest, kind)` listing that describes
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
//   record  [digest 32][key_len u16][kind u8][size u64][ctype_len u8]
//           [key][ctype]                                   × count
//
// A record carries what its binding records — kind, size, content type —
// so a restore binds each entry as what it was, and a clone reads back
// exactly as its source did. `kind` matters most. It matters for a volume: its entry is the digest of
// its map root, and the orphan GC walks the maps of VOLUME bindings
// only — a volume restored as a plain file would have its extents
// collected.
//
// Little-endian throughout, like every other loam wire.
//
// Same include discipline as the other mechanics sources: no_std,
// no dependencies, `#[path]`-included by every consumer.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

pub const MAGIC: u32 = u32::from_le_bytes(*b"LMAN");

/// Digest width. SHA-256, as everywhere else in the body plane.
pub const DIGEST_LEN: usize = 32;

/// Fixed part of the header, before the root bytes.
pub const HEADER: usize = 4 + 4 + 2;

/// Fixed part of a record, before the key and content-type bytes.
pub const REC_HEADER: usize = DIGEST_LEN + 2 + 1 + 8 + 1;

/// A plain file's kind (`loam_wire::KIND_FILE`). Restated so this
/// wire stays includable on its own.
pub const KIND_FILE: u8 = 0;

/// Highest namespace kind a record may carry (`loam_wire::KIND_SYMLINK`).
/// Restated so this wire stays includable on its own.
pub const LAST_KIND: u8 = 4;

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
    /// A record carries a kind no binding can have.
    BadKind { observed: u8 },
}

/// One manifest record: a key, the digest it was bound to, and what the
/// binding records — its namespace kind, size and content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    pub key: &'a [u8],
    pub digest: [u8; DIGEST_LEN],
    pub kind: u8,
    pub size: u64,
    pub content_type: &'a [u8],
}

/// Exact encoded size for `root` and `entries`. A caller allocates
/// this and passes it to `encode`; the two are kept in step by
/// construction rather than by an assertion, because they walk the
/// same records the same way.
pub fn encoded_len(root: &[u8], entries: &[Entry<'_>]) -> usize {
    let mut n = HEADER + root.len();
    for e in entries {
        n += REC_HEADER + e.key.len() + e.content_type.len();
    }
    n
}

/// Encode a manifest. Returns the bytes written.
///
/// Records are written in the order given. Order is the caller's
/// business: this format is read linearly, so nothing here depends
/// on a sort, and imposing one would only invite a reader to rely on
/// it.
pub fn encode(out: &mut [u8], root: &[u8], entries: &[Entry<'_>]) -> Result<usize, ManifestError> {
    if entries.len() > MAX_ENTRIES as usize {
        return Err(ManifestError::TooManyEntries {
            count: entries.len(),
            max: MAX_ENTRIES,
        });
    }
    for e in entries {
        check_record(e)?;
    }
    let needed = encoded_len(root, entries);
    if out.len() < needed {
        return Err(ManifestError::BufferTooSmall {
            needed,
            actual: out.len(),
        });
    }
    let mut o = encode_header(out, root, entries.len() as u32)?;
    for e in entries {
        o += encode_record(&mut out[o..], e)?;
    }
    Ok(o)
}

/// The largest record: the longest key and content type.
pub const RECORD_MAX: usize =
    REC_HEADER + super::limits::MAX_PATH + super::limits::CONTENT_TYPE_MAX;

/// The largest header: the longest root.
pub const HEADER_MAX: usize = HEADER + super::limits::MAX_ROOT;

fn check_record(e: &Entry<'_>) -> Result<(), ManifestError> {
    if e.key.len() > super::limits::MAX_PATH {
        return Err(ManifestError::TooLong {
            len: e.key.len(),
            max: super::limits::MAX_PATH,
        });
    }
    if e.content_type.len() > super::limits::CONTENT_TYPE_MAX {
        return Err(ManifestError::TooLong {
            len: e.content_type.len(),
            max: super::limits::CONTENT_TYPE_MAX,
        });
    }
    if e.kind > LAST_KIND {
        return Err(ManifestError::BadKind { observed: e.kind });
    }
    Ok(())
}

/// Write a manifest's header declaring `count` records. A writer that
/// learns the count only as it goes writes the header first and this
/// again over it at the end; the header's length does not depend on
/// the count.
pub fn encode_header(out: &mut [u8], root: &[u8], count: u32) -> Result<usize, ManifestError> {
    if root.len() > super::limits::MAX_ROOT {
        return Err(ManifestError::TooLong {
            len: root.len(),
            max: super::limits::MAX_ROOT,
        });
    }
    let needed = HEADER + root.len();
    if out.len() < needed {
        return Err(ManifestError::BufferTooSmall {
            needed,
            actual: out.len(),
        });
    }
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&count.to_le_bytes());
    out[8..10].copy_from_slice(&(root.len() as u16).to_le_bytes());
    let mut i = 0;
    while i < root.len() {
        out[HEADER + i] = root[i];
        i += 1;
    }
    Ok(needed)
}

/// Write one record; its length.
pub fn encode_record(out: &mut [u8], e: &Entry<'_>) -> Result<usize, ManifestError> {
    check_record(e)?;
    let needed = REC_HEADER + e.key.len() + e.content_type.len();
    if out.len() < needed {
        return Err(ManifestError::BufferTooSmall {
            needed,
            actual: out.len(),
        });
    }
    out[..DIGEST_LEN].copy_from_slice(&e.digest);
    let mut o = DIGEST_LEN;
    out[o..o + 2].copy_from_slice(&(e.key.len() as u16).to_le_bytes());
    out[o + 2] = e.kind;
    out[o + 3..o + 11].copy_from_slice(&e.size.to_le_bytes());
    out[o + 11] = e.content_type.len() as u8;
    o = REC_HEADER;
    for part in [e.key, e.content_type] {
        let mut i = 0;
        while i < part.len() {
            out[o + i] = part[i];
            i += 1;
        }
        o += part.len();
    }
    Ok(needed)
}

/// A manifest header: its root, declared count and length.
pub type Header<'a> = (&'a [u8], u32, usize);

/// The header at the front of `src`: its root, declared count and
/// length. `Ok(None)` until the whole header has arrived, for a reader
/// filling a buffer as it goes.
pub fn read_header(src: &[u8]) -> Result<Option<Header<'_>>, ManifestError> {
    match split_header(src) {
        Ok(h) => Ok(Some(h)),
        Err(ManifestError::Truncated) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The record at the front of `src` and its length. `Ok(None)` until the
/// whole record has arrived.
pub fn read_record(src: &[u8]) -> Result<Option<(Entry<'_>, usize)>, ManifestError> {
    if src.len() < REC_HEADER {
        return Ok(None);
    }
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(&src[..DIGEST_LEN]);
    let o = DIGEST_LEN;
    let key_len = u16::from_le_bytes([src[o], src[o + 1]]) as usize;
    let kind = src[o + 2];
    let mut size = [0u8; 8];
    size.copy_from_slice(&src[o + 3..o + 11]);
    let ct_len = src[o + 11] as usize;
    if key_len > super::limits::MAX_PATH {
        return Err(ManifestError::TooLong {
            len: key_len,
            max: super::limits::MAX_PATH,
        });
    }
    if ct_len > super::limits::CONTENT_TYPE_MAX {
        return Err(ManifestError::TooLong {
            len: ct_len,
            max: super::limits::CONTENT_TYPE_MAX,
        });
    }
    if kind > LAST_KIND {
        return Err(ManifestError::BadKind { observed: kind });
    }
    let n = REC_HEADER + key_len + ct_len;
    if src.len() < n {
        return Ok(None);
    }
    Ok(Some((
        Entry {
            key: &src[REC_HEADER..REC_HEADER + key_len],
            digest,
            kind,
            size: u64::from_le_bytes(size),
            content_type: &src[REC_HEADER + key_len..n],
        },
        n,
    )))
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

/// Visit every entry in order.
///
/// The whole manifest is validated as it is walked: a record that
/// runs past the end, or a declared count the bytes do not support,
/// is an error rather than a short iteration. A caller restoring a
/// snapshot must be able to tell "this snapshot has three entries"
/// from "this snapshot had more and I could only read three" — the
/// second silently restores an incomplete volume.
pub fn for_each(manifest: &[u8], mut f: impl FnMut(&Entry<'_>)) -> Result<usize, ManifestError> {
    let (_, count, mut o) = split_header(manifest)?;
    for _ in 0..count {
        match read_record(&manifest[o..])? {
            Some((e, n)) => {
                f(&e);
                o += n;
            }
            None => return Err(ManifestError::Truncated),
        }
    }
    Ok(count as usize)
}
