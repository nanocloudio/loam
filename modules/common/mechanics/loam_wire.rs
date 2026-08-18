// Pure-logic, no_std-friendly binary wire format for Loam's
// per-surface events: the format these records take both on a
// channel and in a PIC's WAL.
//
// Layered into both:
//   - PIC modules under `modules/*` (via `#[path]` include); no_std.
//   - Host tests; std.
//
// Format choices reflect Fluxor's existing replica_facade pattern:
// little-endian, length-prefixed for variable strings, fixed-size
// header per record type. Bounded: a record's serialized length is
// <= 4096 (the same bound `loam_decision_wire::MAX_INNER` puts
// on a record travelling through Raft).
//
// Layout (all multi-byte ints are LE):
//
//   Bind        [op:u8=1][ns_len:u16][path_len:u16][oid_len:u16]
//               [kind:u8][revision:u64]
//               [ns:ns_len][path:path_len][oid:oid_len]
//   Rename      [op:u8=2][ns_len:u16][from_len:u16][to_len:u16]
//               [new_revision:u64]
//               [ns:ns_len][from:from_len][to:to_len]
//   Unbind      [op:u8=3][ns_len:u16][path_len:u16]
//               [ns:ns_len][path:path_len]
//
// Opcode 0 is reserved (so a zeroed buffer is not a valid record).

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use core::convert::TryInto;

// Channel-wire operation set for the `storage.namespace` surface.
// These are loam's channel encoding of the CANONICAL namespace ops
// (fluxor `contracts/storage/namespace.rs`): OP_BIND ↔ BIND (0x1308,
// the op that mints a name — added to the canonical surface by
// rfc_storage_capability_symmetry phase 1; this wire predates it),
// OP_RENAME ↔ RENAME, OP_UNBIND ↔ DELETE, OP_LOOKUP ↔ LOOKUP,
// OP_LIST ↔ LIST. Same operations, channel-framed rather than
// provider_call-dispatched; a future wire unification maps 1:1.
pub const OP_BIND: u8 = 1;
pub const OP_RENAME: u8 = 2;
pub const OP_UNBIND: u8 = 3;
pub const OP_LOOKUP: u8 = 4;
pub const OP_LIST: u8 = 5;
pub const OP_REFERENCED: u8 = 6;

/// Max paths per OP_LIST response page.
pub const MAX_LIST_PAGE: usize = 16;

/// Lookup response status bytes.
pub const LOOKUP_FOUND: u8 = 1;
pub const LOOKUP_NOT_FOUND: u8 = 0;

pub const KIND_FILE: u8 = 0;
pub const KIND_DIRECTORY: u8 = 1;
pub const KIND_OBJECT: u8 = 2;
pub const KIND_VOLUME: u8 = 3;
pub const KIND_SYMLINK: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    BufferTooSmall { needed: usize, actual: usize },
    Truncated,
    BadOpcode { observed: u8 },
    BadKind { observed: u8 },
    StringTooLong { len: usize, max: usize },
}

pub const MAX_STRING: usize = 4096;

// ── Bind ───────────────────────────────────────────────────────────

pub fn encode_bind(
    dst: &mut [u8],
    namespace_root: &[u8],
    path: &[u8],
    object_id: &[u8],
    kind: u8,
    revision: u64,
) -> Result<usize, WireError> {
    if namespace_root.len() > MAX_STRING {
        return Err(WireError::StringTooLong {
            len: namespace_root.len(),
            max: MAX_STRING,
        });
    }
    if path.len() > MAX_STRING {
        return Err(WireError::StringTooLong {
            len: path.len(),
            max: MAX_STRING,
        });
    }
    if object_id.len() > MAX_STRING {
        return Err(WireError::StringTooLong {
            len: object_id.len(),
            max: MAX_STRING,
        });
    }
    let header = 1 + 2 + 2 + 2 + 1 + 8;
    let needed = header + namespace_root.len() + path.len() + object_id.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_BIND;
    dst[1..3].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[3..5].copy_from_slice(&(path.len() as u16).to_le_bytes());
    dst[5..7].copy_from_slice(&(object_id.len() as u16).to_le_bytes());
    dst[7] = kind;
    dst[8..16].copy_from_slice(&revision.to_le_bytes());
    let mut cursor = header;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + path.len()].copy_from_slice(path);
    cursor += path.len();
    dst[cursor..cursor + object_id.len()].copy_from_slice(object_id);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBind<'a> {
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub object_id: &'a [u8],
    pub kind: u8,
    pub revision: u64,
}

pub fn decode_bind(src: &[u8]) -> Result<DecodedBind<'_>, WireError> {
    if src.len() < 16 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_BIND {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    let path_len = u16::from_le_bytes([src[3], src[4]]) as usize;
    let oid_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let kind = src[7];
    if kind > KIND_SYMLINK {
        return Err(WireError::BadKind { observed: kind });
    }
    let revision = u64::from_le_bytes(src[8..16].try_into().unwrap());
    let header = 16;
    let total = header + ns_len + path_len + oid_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let ns = &src[header..header + ns_len];
    let path = &src[header + ns_len..header + ns_len + path_len];
    let oid = &src[header + ns_len + path_len..header + ns_len + path_len + oid_len];
    Ok(DecodedBind {
        namespace_root: ns,
        path,
        object_id: oid,
        kind,
        revision,
    })
}

// ── Rename ─────────────────────────────────────────────────────────

pub fn encode_rename(
    dst: &mut [u8],
    namespace_root: &[u8],
    from: &[u8],
    to: &[u8],
    new_revision: u64,
) -> Result<usize, WireError> {
    for s in [namespace_root, from, to] {
        if s.len() > MAX_STRING {
            return Err(WireError::StringTooLong {
                len: s.len(),
                max: MAX_STRING,
            });
        }
    }
    let header = 1 + 2 + 2 + 2 + 8;
    let needed = header + namespace_root.len() + from.len() + to.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_RENAME;
    dst[1..3].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[3..5].copy_from_slice(&(from.len() as u16).to_le_bytes());
    dst[5..7].copy_from_slice(&(to.len() as u16).to_le_bytes());
    dst[7..15].copy_from_slice(&new_revision.to_le_bytes());
    let mut cursor = header;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + from.len()].copy_from_slice(from);
    cursor += from.len();
    dst[cursor..cursor + to.len()].copy_from_slice(to);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRename<'a> {
    pub namespace_root: &'a [u8],
    pub from: &'a [u8],
    pub to: &'a [u8],
    pub new_revision: u64,
}

pub fn decode_rename(src: &[u8]) -> Result<DecodedRename<'_>, WireError> {
    if src.len() < 15 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_RENAME {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    let from_len = u16::from_le_bytes([src[3], src[4]]) as usize;
    let to_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let new_revision = u64::from_le_bytes(src[7..15].try_into().unwrap());
    let header = 15;
    let total = header + ns_len + from_len + to_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let ns = &src[header..header + ns_len];
    let from = &src[header + ns_len..header + ns_len + from_len];
    let to = &src[header + ns_len + from_len..header + ns_len + from_len + to_len];
    Ok(DecodedRename {
        namespace_root: ns,
        from,
        to,
        new_revision,
    })
}

// ── Unbind ─────────────────────────────────────────────────────────

pub fn encode_unbind(
    dst: &mut [u8],
    namespace_root: &[u8],
    path: &[u8],
) -> Result<usize, WireError> {
    for s in [namespace_root, path] {
        if s.len() > MAX_STRING {
            return Err(WireError::StringTooLong {
                len: s.len(),
                max: MAX_STRING,
            });
        }
    }
    let header = 1 + 2 + 2;
    let needed = header + namespace_root.len() + path.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_UNBIND;
    dst[1..3].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[3..5].copy_from_slice(&(path.len() as u16).to_le_bytes());
    let mut cursor = header;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + path.len()].copy_from_slice(path);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedUnbind<'a> {
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
}

pub fn decode_unbind(src: &[u8]) -> Result<DecodedUnbind<'_>, WireError> {
    if src.len() < 5 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_UNBIND {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    let path_len = u16::from_le_bytes([src[3], src[4]]) as usize;
    let header = 5;
    if src.len() < header + ns_len + path_len {
        return Err(WireError::Truncated);
    }
    let ns = &src[header..header + ns_len];
    let path = &src[header + ns_len..header + ns_len + path_len];
    Ok(DecodedUnbind {
        namespace_root: ns,
        path,
    })
}

// ── Lookup ─────────────────────────────────────────────────────────
//
//   Request:           [op:u8=4][ns_len:u16][path_len:u16][ns][path]
//   Response (found):  [op:u8=4][status:u8=1][object_id_len:u8][object_id]
//                      [revision:u64][kind:u8]
//   Response (absent): [op:u8=4][status:u8=0]

pub fn encode_lookup_req(
    dst: &mut [u8],
    namespace_root: &[u8],
    path: &[u8],
) -> Result<usize, WireError> {
    for s in [namespace_root, path] {
        if s.len() > MAX_STRING {
            return Err(WireError::StringTooLong {
                len: s.len(),
                max: MAX_STRING,
            });
        }
    }
    let header = 1 + 2 + 2;
    let needed = header + namespace_root.len() + path.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LOOKUP;
    dst[1..3].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[3..5].copy_from_slice(&(path.len() as u16).to_le_bytes());
    let mut cursor = header;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + path.len()].copy_from_slice(path);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLookupReq<'a> {
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
}

pub fn decode_lookup_req(src: &[u8]) -> Result<DecodedLookupReq<'_>, WireError> {
    if src.len() < 5 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LOOKUP {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    let path_len = u16::from_le_bytes([src[3], src[4]]) as usize;
    let header = 5;
    if src.len() < header + ns_len + path_len {
        return Err(WireError::Truncated);
    }
    let ns = &src[header..header + ns_len];
    let path = &src[header + ns_len..header + ns_len + path_len];
    Ok(DecodedLookupReq {
        namespace_root: ns,
        path,
    })
}

pub fn encode_lookup_found(
    dst: &mut [u8],
    object_id: &[u8],
    revision: u64,
    kind: u8,
) -> Result<usize, WireError> {
    if object_id.len() > 255 {
        return Err(WireError::StringTooLong {
            len: object_id.len(),
            max: 255,
        });
    }
    let needed = 1 + 1 + 1 + object_id.len() + 8 + 1;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LOOKUP;
    dst[1] = LOOKUP_FOUND;
    dst[2] = object_id.len() as u8;
    let mut cursor = 3;
    dst[cursor..cursor + object_id.len()].copy_from_slice(object_id);
    cursor += object_id.len();
    dst[cursor..cursor + 8].copy_from_slice(&revision.to_le_bytes());
    cursor += 8;
    dst[cursor] = kind;
    Ok(needed)
}

pub fn encode_lookup_not_found(dst: &mut [u8]) -> Result<usize, WireError> {
    if dst.len() < 2 {
        return Err(WireError::BufferTooSmall {
            needed: 2,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LOOKUP;
    dst[1] = LOOKUP_NOT_FOUND;
    Ok(2)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedLookupResp<'a> {
    Found {
        object_id: &'a [u8],
        revision: u64,
        kind: u8,
    },
    NotFound,
}

pub fn decode_lookup_resp(src: &[u8]) -> Result<DecodedLookupResp<'_>, WireError> {
    if src.len() < 2 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LOOKUP {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    match src[1] {
        LOOKUP_NOT_FOUND => Ok(DecodedLookupResp::NotFound),
        LOOKUP_FOUND => {
            if src.len() < 3 {
                return Err(WireError::Truncated);
            }
            let id_len = src[2] as usize;
            let needed = 3 + id_len + 8 + 1;
            if src.len() < needed {
                return Err(WireError::Truncated);
            }
            let object_id = &src[3..3 + id_len];
            let revision = u64::from_le_bytes(src[3 + id_len..3 + id_len + 8].try_into().unwrap());
            let kind = src[3 + id_len + 8];
            Ok(DecodedLookupResp::Found {
                object_id,
                revision,
                kind,
            })
        }
        other => Err(WireError::BadKind { observed: other }),
    }
}

// ── List (read op: enumerate a namespace's paths) ─────────────────
//
//   ListReq   [op=5][root_len:u16][cursor:u32][max:u8][root]
//   ListResp  [op=5][next_cursor:u32][count:u8][(path_len:u16,path)*]
//             // next_cursor 0 = enumeration wrapped; resume from 0

pub fn encode_list_req(
    dst: &mut [u8],
    namespace_root: &[u8],
    cursor: u32,
    max: u8,
) -> Result<usize, WireError> {
    if namespace_root.len() > MAX_STRING {
        return Err(WireError::StringTooLong {
            len: namespace_root.len(),
            max: MAX_STRING,
        });
    }
    let header = 1 + 2 + 4 + 1;
    let needed = header + namespace_root.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LIST;
    dst[1..3].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[3..7].copy_from_slice(&cursor.to_le_bytes());
    dst[7] = max;
    dst[header..needed].copy_from_slice(namespace_root);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedListReq<'a> {
    pub namespace_root: &'a [u8],
    pub cursor: u32,
    pub max: u8,
}

pub fn decode_list_req(src: &[u8]) -> Result<DecodedListReq<'_>, WireError> {
    let header = 8;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LIST {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let root_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    if src.len() < header + root_len {
        return Err(WireError::Truncated);
    }
    Ok(DecodedListReq {
        namespace_root: &src[header..header + root_len],
        cursor: u32::from_le_bytes(src[3..7].try_into().unwrap()),
        max: src[7],
    })
}

pub fn encode_list_resp(
    dst: &mut [u8],
    next_cursor: u32,
    paths: &[&[u8]],
) -> Result<usize, WireError> {
    if paths.len() > MAX_LIST_PAGE {
        return Err(WireError::StringTooLong {
            len: paths.len(),
            max: MAX_LIST_PAGE,
        });
    }
    let mut needed = 1 + 4 + 1;
    for p in paths {
        needed += 2 + p.len();
    }
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LIST;
    dst[1..5].copy_from_slice(&next_cursor.to_le_bytes());
    dst[5] = paths.len() as u8;
    let mut cursor = 6;
    for p in paths {
        dst[cursor..cursor + 2].copy_from_slice(&(p.len() as u16).to_le_bytes());
        cursor += 2;
        dst[cursor..cursor + p.len()].copy_from_slice(p);
        cursor += p.len();
    }
    Ok(needed)
}

/// Decode a ListResp, calling `emit` per path in order. Returns
/// (next_cursor, count).
pub fn decode_list_resp(
    src: &[u8],
    mut emit: impl FnMut(&[u8]),
) -> Result<(u32, usize), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LIST {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let next_cursor = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let count = src[5] as usize;
    if count > MAX_LIST_PAGE {
        return Err(WireError::Truncated);
    }
    let mut pos = 6usize;
    for _ in 0..count {
        if pos + 2 > src.len() {
            return Err(WireError::Truncated);
        }
        let plen = u16::from_le_bytes([src[pos], src[pos + 1]]) as usize;
        pos += 2;
        if pos + plen > src.len() {
            return Err(WireError::Truncated);
        }
        emit(&src[pos..pos + plen]);
        pos += plen;
    }
    Ok((next_cursor, count))
}

// ── Referenced (read op: is this object id bound anywhere?) ───────
//
//   ReferencedReq   [op=6][cursor:u32][oid_len:u16][oid]
//   ReferencedResp  [op=6][flag:u8][next_cursor:u32]
//
// The orphan-body GC's question, CURSOR-PAGED so the answer stays
// bounded per step at snapshot scale: flag=1 → referenced
// (definitive, stop); flag=0 + next_cursor=0 → definitively
// unreferenced; flag=0 + next_cursor≠0 → undecided, continue the
// snapshot scan from next_cursor.

pub fn encode_referenced_req(
    dst: &mut [u8],
    cursor: u32,
    object_id: &[u8],
) -> Result<usize, WireError> {
    if object_id.len() > MAX_STRING {
        return Err(WireError::StringTooLong {
            len: object_id.len(),
            max: MAX_STRING,
        });
    }
    let header = 1 + 4 + 2;
    let needed = header + object_id.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_REFERENCED;
    dst[1..5].copy_from_slice(&cursor.to_le_bytes());
    dst[5..7].copy_from_slice(&(object_id.len() as u16).to_le_bytes());
    dst[header..needed].copy_from_slice(object_id);
    Ok(needed)
}

pub fn decode_referenced_req(src: &[u8]) -> Result<(u32, &[u8]), WireError> {
    let header = 7;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_REFERENCED {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cursor = u32::from_le_bytes([src[1], src[2], src[3], src[4]]);
    let len = u16::from_le_bytes([src[5], src[6]]) as usize;
    if src.len() < header + len {
        return Err(WireError::Truncated);
    }
    Ok((cursor, &src[header..header + len]))
}

pub fn encode_referenced_resp(
    dst: &mut [u8],
    referenced: bool,
    next_cursor: u32,
) -> Result<usize, WireError> {
    if dst.len() < 6 {
        return Err(WireError::BufferTooSmall {
            needed: 6,
            actual: dst.len(),
        });
    }
    dst[0] = OP_REFERENCED;
    dst[1] = if referenced { 1 } else { 0 };
    dst[2..6].copy_from_slice(&next_cursor.to_le_bytes());
    Ok(6)
}

/// Returns (referenced, next_cursor).
pub fn decode_referenced_resp(src: &[u8]) -> Result<(bool, u32), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_REFERENCED {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((
        src[1] != 0,
        u32::from_le_bytes([src[2], src[3], src[4], src[5]]),
    ))
}

// ── Opcode peek ────────────────────────────────────────────────────

pub fn peek_opcode(src: &[u8]) -> Option<u8> {
    src.first().copied()
}

// ── Request stream splitting ───────────────────────────────────────

/// Length of the request record at the front of `src`, or `None` when
/// `src` does not yet hold a whole one.
///
/// A PIC's `requests` channel is a byte stream: a producer that batches
/// puts several records into one read, and a read can end mid-record.
/// A reader that assumes one read is one record silently discards
/// everything after the first — accepted off the channel and then gone,
/// with no NAK, which is indistinguishable downstream from a request
/// that was never sent.
///
/// Requests only. The response forms reuse the same opcodes with
/// different shapes, and a provider never reads its own responses.
///
/// `None` means "wait for more bytes". An unrecognised opcode is `Err`,
/// so a caller can resync rather than stall forever on a stream it
/// cannot parse.
pub fn request_record_len(src: &[u8]) -> Result<Option<usize>, WireError> {
    let opcode = match src.first() {
        Some(b) => *b,
        None => return Ok(None),
    };
    // Every variable-length request is a fixed header followed by the
    // strings its length fields describe.
    // Offsets are returned as scalars, not as a `&'static [usize]`
    // table. A static slice is a pointer into the module's own data,
    // and a position-independent module is loaded without anything to
    // relocate that pointer against: the read lands wherever the
    // pointer happened to be built for. It survives a host test, where
    // the same code is linked normally, and faults on the first record
    // in a real graph. `0` is the opcode's own byte, so it reads as
    // "no field here".
    let (header, lens_at): (usize, [usize; 3]) = match opcode {
        // [op][root_len:u16][path_len:u16][oid_len:u16][kind][rev:u64]
        OP_BIND => (16, [1, 3, 5]),
        // [op][root_len:u16][from_len:u16][to_len:u16][rev:u64]
        OP_RENAME => (15, [1, 3, 5]),
        // [op][root_len:u16][path_len:u16]
        OP_UNBIND => (5, [1, 3, 0]),
        // [op][root_len:u16][path_len:u16]
        OP_LOOKUP => (5, [1, 3, 0]),
        // [op][root_len:u16][cursor:u32][max]
        OP_LIST => (8, [1, 0, 0]),
        // [op][cursor:u32][oid_len:u16]
        OP_REFERENCED => (7, [5, 0, 0]),
        observed => return Err(WireError::BadOpcode { observed }),
    };
    if src.len() < header {
        return Ok(None);
    }
    let mut total = header;
    for at in lens_at {
        if at != 0 {
            total += u16::from_le_bytes([src[at], src[at + 1]]) as usize;
        }
    }
    Ok(if src.len() >= total {
        Some(total)
    } else {
        None
    })
}
