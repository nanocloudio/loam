// Block-volume extent maps: the pages a committed volume root names.
//
// A volume is a copy-on-write map of content-addressed extent bodies.
// Every extent version is an ordinary body named by its digest, and
// the map from extent index to digest is itself made of bodies:
//
//   depth 1   root ─► extent digests
//   depth 2   root ─► leaf pages ─► extent digests
//
// Each page holds up to `PAGE_ENTRIES` digests. The zero digest means
// "never written" and reads as zeros, so an all-zero extent and an
// all-zero leaf are never stored. The volume's committed state is the
// namespace binding of its path to the ROOT page's digest, at a
// revision; a flush writes new extents, the leaves on changed paths
// and a new root, then commits by binding the path to that root at
// the next revision. Nothing here is mutable, which is what makes the
// bind the single atomic point: before it readers resolve the old
// root, after it the new one, and a crash between leaves orphan
// bodies and never a mixed volume.
//
// The depth is fixed at creation: the smallest that covers the
// volume. One level addresses `PAGE_ENTRIES` extents, two address
// `PAGE_ENTRIES²`, so with 32 KiB extents a depth-1 volume is at most
// 32 MiB and a depth-2 volume at most 32 GiB. Past that the volume is
// refused at creation rather than given a third level nobody reads.
//
// Layouts (little-endian):
//
//   root  [magic "LVMR"][volume_id:16][size_bytes:u64][extent_size:u32]
//         [depth:u8][reserved:u8 = 0][count:u16][digest:32 × count]
//   leaf  [magic "LVML"][first_index:u64][count:u16][digest:32 × count]
//
// A root's children are its extents (depth 1) or its leaves (depth 2),
// and `count` is exactly the number the geometry needs — never "up
// to". A leaf covers `PAGE_ENTRIES` consecutive extents from a
// multiple of `PAGE_ENTRIES`; the last leaf is short when the volume
// is. The root carries no revision: the revision is the bind's, so two
// commits of the same content name the same root and deduplicate.
//
// Decoding is strict — a page that does not describe exactly one
// geometry is refused — and uses no runtime division, so it is safe in
// a PIC module (the orphan GC walks maps from inside `admin_router`).
// Every bound check is a multiplication that cannot overflow at the
// ceilings below.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

pub const DIGEST_LEN: usize = 32;
pub const VOLUME_ID_LEN: usize = 16;

/// Digests per map page (`P`). A power of two, so an index splits into
/// (leaf, slot) with a shift and a mask.
pub const PAGE_ENTRIES: usize = 1024;
const PAGE_SHIFT: u32 = 10;

/// Deepest map a volume may have.
pub const MAX_DEPTH: u8 = 2;

/// Largest extent: one extent is one body, so it cannot exceed what a
/// single-shot body PUT carries (`loam_body_wire::MAX_BODY`). Restated
/// rather than imported so this wire stays includable on its own;
/// `an_extent_fits_one_body` pins the two.
pub const MAX_EXTENT_SIZE: u32 = 61440;

pub const ROOT_MAGIC: [u8; 4] = *b"LVMR";
pub const LEAF_MAGIC: [u8; 4] = *b"LVML";

pub const ROOT_HDR: usize = 4 + VOLUME_ID_LEN + 8 + 4 + 1 + 1 + 2;
pub const LEAF_HDR: usize = 4 + 8 + 2;

/// The largest page either kind can be. Fits one body.
pub const MAX_PAGE_LEN: usize = ROOT_HDR + PAGE_ENTRIES * DIGEST_LEN;

/// "Never written": reads as zeros and names no body.
pub const ZERO_DIGEST: [u8; DIGEST_LEN] = [0u8; DIGEST_LEN];

const _: () = assert!(1usize << PAGE_SHIFT == PAGE_ENTRIES);
const _: () = assert!(MAX_PAGE_LEN <= MAX_EXTENT_SIZE as usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    BufferTooSmall,
    /// Not a page of this kind, or one whose fields disagree with each
    /// other or with the geometry they claim.
    Malformed,
    /// The volume's geometry is outside what a map can describe: an
    /// empty volume, an extent size of 0 or past `MAX_EXTENT_SIZE`, or
    /// more extents than `MAX_DEPTH` levels address.
    Unsupported,
}

/// The smallest depth whose map covers `size_bytes` in extents of
/// `extent_size`, or `Unsupported`.
pub fn select_depth(size_bytes: u64, extent_size: u32) -> Result<u8, MapError> {
    if size_bytes == 0 || extent_size == 0 || extent_size > MAX_EXTENT_SIZE {
        return Err(MapError::Unsupported);
    }
    let es = extent_size as u64;
    let p = PAGE_ENTRIES as u64;
    if size_bytes <= p * es {
        Ok(1)
    } else if size_bytes <= p * p * es {
        Ok(2)
    } else {
        Err(MapError::Unsupported)
    }
}

/// Largest volume a map can describe with extents of `extent_size`.
pub fn max_volume_size(extent_size: u32) -> u64 {
    let p = PAGE_ENTRIES as u64;
    p * p * extent_size as u64
}

/// Bytes one root child covers at `depth`.
fn child_span(extent_size: u32, depth: u8) -> u64 {
    let es = extent_size as u64;
    if depth == 1 {
        es
    } else {
        es * PAGE_ENTRIES as u64
    }
}

/// Does `count` children of `span` bytes cover `size` exactly — every
/// child needed, none spare? Multiplication only.
fn covers_exactly(size: u64, span: u64, count: u64) -> bool {
    count >= 1 && (count - 1) * span < size && size <= count * span
}

/// The root child holding extent `index`, and the slot inside that
/// child's leaf (always 0 at depth 1, where the child IS the extent).
pub fn locate(depth: u8, index: u64) -> (u64, usize) {
    if depth == 1 {
        (index, 0)
    } else {
        (
            index >> PAGE_SHIFT,
            (index & (PAGE_ENTRIES as u64 - 1)) as usize,
        )
    }
}

/// A decoded root page. `children` is `count × DIGEST_LEN` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootPage<'a> {
    pub volume_id: [u8; VOLUME_ID_LEN],
    pub size_bytes: u64,
    pub extent_size: u32,
    pub depth: u8,
    pub children: &'a [u8],
}

impl RootPage<'_> {
    pub fn count(&self) -> usize {
        self.children.len() / DIGEST_LEN
    }

    pub fn child(&self, i: usize) -> Option<[u8; DIGEST_LEN]> {
        digest_at(self.children, i)
    }
}

/// A decoded leaf page. `digests` is `count × DIGEST_LEN` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafPage<'a> {
    pub first_index: u64,
    pub digests: &'a [u8],
}

impl LeafPage<'_> {
    pub fn count(&self) -> usize {
        self.digests.len() / DIGEST_LEN
    }

    pub fn digest(&self, i: usize) -> Option<[u8; DIGEST_LEN]> {
        digest_at(self.digests, i)
    }
}

fn digest_at(table: &[u8], i: usize) -> Option<[u8; DIGEST_LEN]> {
    let at = i.checked_mul(DIGEST_LEN)?;
    let src = table.get(at..at.checked_add(DIGEST_LEN)?)?;
    let mut d = [0u8; DIGEST_LEN];
    d.copy_from_slice(src);
    Some(d)
}

/// Does `table` (a run of digests) contain `digest`? The orphan GC's
/// question of one page.
pub fn names_digest(table: &[u8], digest: &[u8; DIGEST_LEN]) -> bool {
    let mut at = 0usize;
    while at + DIGEST_LEN <= table.len() {
        if table[at..at + DIGEST_LEN] == digest[..] {
            return true;
        }
        at += DIGEST_LEN;
    }
    false
}

/// Encode a root page. `children` must be exactly the count the
/// geometry needs at the depth `select_depth` picks.
pub fn encode_root(
    dst: &mut [u8],
    volume_id: &[u8; VOLUME_ID_LEN],
    size_bytes: u64,
    extent_size: u32,
    children: &[[u8; DIGEST_LEN]],
) -> Result<usize, MapError> {
    let depth = select_depth(size_bytes, extent_size)?;
    if !covers_exactly(
        size_bytes,
        child_span(extent_size, depth),
        children.len() as u64,
    ) {
        return Err(MapError::Malformed);
    }
    let needed = ROOT_HDR + children.len() * DIGEST_LEN;
    if dst.len() < needed {
        return Err(MapError::BufferTooSmall);
    }
    dst[..4].copy_from_slice(&ROOT_MAGIC);
    dst[4..20].copy_from_slice(volume_id);
    dst[20..28].copy_from_slice(&size_bytes.to_le_bytes());
    dst[28..32].copy_from_slice(&extent_size.to_le_bytes());
    dst[32] = depth;
    dst[33] = 0;
    dst[34..36].copy_from_slice(&(children.len() as u16).to_le_bytes());
    let mut at = ROOT_HDR;
    for c in children {
        dst[at..at + DIGEST_LEN].copy_from_slice(c);
        at += DIGEST_LEN;
    }
    Ok(needed)
}

/// Decode a root page, refusing anything that is not exactly one
/// well-formed geometry: wrong magic, a nonzero reserved byte, a depth
/// that is not the smallest covering one, a child count the geometry
/// does not need, or a length that is not header plus children.
pub fn decode_root(src: &[u8]) -> Result<RootPage<'_>, MapError> {
    if src.len() < ROOT_HDR || src[..4] != ROOT_MAGIC {
        return Err(MapError::Malformed);
    }
    let mut volume_id = [0u8; VOLUME_ID_LEN];
    volume_id.copy_from_slice(&src[4..20]);
    let mut size = [0u8; 8];
    size.copy_from_slice(&src[20..28]);
    let size_bytes = u64::from_le_bytes(size);
    let extent_size = u32::from_le_bytes([src[28], src[29], src[30], src[31]]);
    let depth = src[32];
    if src[33] != 0 {
        return Err(MapError::Malformed);
    }
    let count = u16::from_le_bytes([src[34], src[35]]) as usize;
    match select_depth(size_bytes, extent_size) {
        Ok(d) if d == depth => {}
        _ => return Err(MapError::Malformed),
    }
    if count > PAGE_ENTRIES
        || !covers_exactly(size_bytes, child_span(extent_size, depth), count as u64)
    {
        return Err(MapError::Malformed);
    }
    if src.len() != ROOT_HDR + count * DIGEST_LEN {
        return Err(MapError::Malformed);
    }
    Ok(RootPage {
        volume_id,
        size_bytes,
        extent_size,
        depth,
        children: &src[ROOT_HDR..],
    })
}

/// Encode a leaf page covering `digests.len()` extents from
/// `first_index`, which must be a multiple of `PAGE_ENTRIES`.
pub fn encode_leaf(
    dst: &mut [u8],
    first_index: u64,
    digests: &[[u8; DIGEST_LEN]],
) -> Result<usize, MapError> {
    if digests.is_empty()
        || digests.len() > PAGE_ENTRIES
        || first_index & (PAGE_ENTRIES as u64 - 1) != 0
    {
        return Err(MapError::Malformed);
    }
    let needed = LEAF_HDR + digests.len() * DIGEST_LEN;
    if dst.len() < needed {
        return Err(MapError::BufferTooSmall);
    }
    dst[..4].copy_from_slice(&LEAF_MAGIC);
    dst[4..12].copy_from_slice(&first_index.to_le_bytes());
    dst[12..14].copy_from_slice(&(digests.len() as u16).to_le_bytes());
    let mut at = LEAF_HDR;
    for d in digests {
        dst[at..at + DIGEST_LEN].copy_from_slice(d);
        at += DIGEST_LEN;
    }
    Ok(needed)
}

/// Decode a leaf page on its own terms: magic, an aligned first index,
/// a count in `1..=PAGE_ENTRIES`, and an exact length. Whether it is
/// the leaf a particular root expects is `leaf_fits`.
pub fn decode_leaf(src: &[u8]) -> Result<LeafPage<'_>, MapError> {
    if src.len() < LEAF_HDR || src[..4] != LEAF_MAGIC {
        return Err(MapError::Malformed);
    }
    let mut first = [0u8; 8];
    first.copy_from_slice(&src[4..12]);
    let first_index = u64::from_le_bytes(first);
    let count = u16::from_le_bytes([src[12], src[13]]) as usize;
    if count == 0 || count > PAGE_ENTRIES || first_index & (PAGE_ENTRIES as u64 - 1) != 0 {
        return Err(MapError::Malformed);
    }
    if src.len() != LEAF_HDR + count * DIGEST_LEN {
        return Err(MapError::Malformed);
    }
    Ok(LeafPage {
        first_index,
        digests: &src[LEAF_HDR..],
    })
}

/// Is `leaf` exactly root child `child` of a depth-2 map over
/// `size_bytes` in `extent_size` extents: the right first index, and
/// every extent from it to the end of its span or of the volume?
pub fn leaf_fits(leaf: &LeafPage<'_>, child: u64, size_bytes: u64, extent_size: u32) -> bool {
    if leaf.first_index != child << PAGE_SHIFT {
        return false;
    }
    let es = extent_size as u64;
    let start = leaf.first_index * es;
    if start >= size_bytes {
        return false;
    }
    covers_exactly(size_bytes - start, es, leaf.count() as u64)
        || (leaf.count() == PAGE_ENTRIES && size_bytes - start > PAGE_ENTRIES as u64 * es)
}
