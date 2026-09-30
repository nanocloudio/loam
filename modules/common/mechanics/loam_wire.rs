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
// the op that mints a name), OP_RENAME ↔ RENAME, OP_UNBIND ↔ DELETE, OP_LOOKUP ↔ LOOKUP,
// OP_LIST ↔ LIST. Same operations, channel-framed rather than
// provider_call-dispatched; a future wire unification maps 1:1.
pub const OP_BIND: u8 = 1;
pub const OP_RENAME: u8 = 2;
pub const OP_UNBIND: u8 = 3;
pub const OP_LOOKUP: u8 = 4;
pub const OP_LIST: u8 = 5;
pub const OP_REFERENCED: u8 = 6;
pub const OP_GC_RESERVE: u8 = 7;
pub const OP_GC_RELEASE: u8 = 8;
pub const OP_LEASE: u8 = 9;
/// A lease-table entry carried verbatim into a rotated WAL. Never a
/// request: the namespace writes it into its own log and refuses it
/// on `requests`, so no producer can set a fence directly.
pub const OP_LEASE_RESTORE: u8 = 10;
pub const OP_VOLUME: u8 = 11;
pub const OP_VOLUME_ROOTS: u8 = 12;

/// Refusal bytes a public PIC answers with. Named here so the response
/// splitter can recognise them as complete one-byte records.
pub const NAK_GENERIC: u8 = 0xFF;
pub const NAK_RESERVED_BYTE: u8 = 0xFD;
/// A plain record refused because it would create, replace, move or
/// remove a volume binding, which only a fenced VOLUME record may do.
pub const NAK_FENCED: u8 = 0xFC;

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

/// Per-field key ceilings, from the single register in
/// `loam_limits.rs`. These are the numbers the arena slot and the
/// snapshot record are sized to, which is the whole point: the wire
/// accepts exactly what the store can hold whole, so an accepted
/// bind is always byte-comparable and always listable.
#[allow(
    unused_imports,
    reason = "re-exported so a consumer can ask this wire what it accepts; \
              the wire itself now delegates the check to loam_limits"
)]
pub use super::limits::{MAX_OBJECT_ID, MAX_PATH, MAX_ROOT};

/// Widest key-shaped field on this wire, for buffer sizing only.
/// Never use it as a per-field ceiling — that is what let a path
/// four times longer than the arena slot be accepted and then
/// silently dropped from every listing.
pub const MAX_STRING: usize = super::limits::MAX_KEY_STRING;

/// Refuse a key whose components exceed their ceilings. Called on
/// BOTH sides: encode so a local producer fails loudly, decode so a
/// remote frame cannot smuggle an oversize key past the ceiling.
pub fn check_key(namespace_root: &[u8], path: &[u8], object_id: &[u8]) -> Result<(), WireError> {
    // One implementation, in `loam_limits.rs` beside the ceilings it
    // enforces. Two copies drifting would mean two wires disagreeing
    // about what the store can hold — which is the class of bug this
    // check exists to prevent.
    super::limits::check_key(namespace_root, path, object_id).map_err(|e| {
        WireError::StringTooLong {
            len: e.len,
            max: e.max,
        }
    })
}

// ── Bind ───────────────────────────────────────────────────────────

pub fn encode_bind(
    dst: &mut [u8],
    namespace_root: &[u8],
    path: &[u8],
    object_id: &[u8],
    kind: u8,
    revision: u64,
) -> Result<usize, WireError> {
    check_key(namespace_root, path, object_id)?;
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
    check_key(ns, path, oid)?;
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
    check_key(namespace_root, from, &[])?;
    check_key(namespace_root, to, &[])?;
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
    check_key(namespace_root, path, &[])?;
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
    check_key(namespace_root, path, &[])?;
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
    check_key(namespace_root, &[], &[])?;
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

// ── GC reservation (control op: fence a descriptor's deletion) ────
//
//   GcReserveReq   [op=7][oid_len:u16][now_ms:u64][oid]
//   GcReserveResp  [op=7][flag:u8]     1 = reserved, 0 = refused
//   GcReleaseReq   [op=8][oid_len:u16][now_ms:u64][oid]
//   GcReleaseResp  [op=8]
//
// A lifecycle sweep proves an object id unbound and then deletes what
// backs it. Between those two points an ordinary BIND can commit, and
// the sweep would then delete something reachable. A reservation
// closes that window: while an id is reserved the namespace refuses to
// admit a BIND naming it, so absence stays proven up to the deletion.
// The refusal is transient and distinct, so a client retries rather
// than failing.
//
// Reservations are logged and, in replicated mode, proposed like any
// mutating record, so every replica admits or refuses a bind against
// the same set. They are NOT reinstated on replay: a reservation belongs
// to a sweep in the process that took it, and a restart has ended that
// sweep. An unfinished sweep leaves either the descriptor (collected on
// a later pass) or a refused bind the client re-issues.
//
// `now_ms` is the sweep's server clock, stamped by the admin router as
// for leases (0: none). A reservation decided at `now` also ends every
// volume flush whose writer's lease has expired by then: a deposed
// writer's commit is refused anyway, and its open flush would otherwise
// keep every body from the sweep for as long as nobody takes the volume
// over. The stamp is in the record, so replay ends the same flushes.
//
//   GcReserve  [op=OP_GC_RESERVE][oid_len:u16][now_ms:u64][oid]
//   GcRelease  [op=OP_GC_RELEASE][oid_len:u16][0:u64][oid]

const GC_RESERVE_HDR: usize = 1 + 2 + 8;

/// Reserve `object_id` for deletion, decided at the sweep's `now_ms`.
pub fn encode_gc_reserve_req(
    dst: &mut [u8],
    object_id: &[u8],
    now_ms: u64,
) -> Result<usize, WireError> {
    encode_gc_record(dst, OP_GC_RESERVE, object_id, now_ms)
}

/// Release a reservation. A release decides nothing about time, so it
/// carries none.
pub fn encode_gc_release_req(dst: &mut [u8], object_id: &[u8]) -> Result<usize, WireError> {
    encode_gc_record(dst, OP_GC_RELEASE, object_id, 0)
}

fn encode_gc_record(
    dst: &mut [u8],
    op: u8,
    object_id: &[u8],
    now_ms: u64,
) -> Result<usize, WireError> {
    check_key(&[], &[], object_id)?;
    let needed = GC_RESERVE_HDR + object_id.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = op;
    dst[1..3].copy_from_slice(&(object_id.len() as u16).to_le_bytes());
    dst[3..11].copy_from_slice(&now_ms.to_le_bytes());
    dst[GC_RESERVE_HDR..needed].copy_from_slice(object_id);
    Ok(needed)
}

/// Decode a reserve or release record. Returns `(object_id, now_ms)`;
/// `now_ms` is 0 on a release.
pub fn decode_gc_reserve_req(src: &[u8]) -> Result<(&[u8], u64), WireError> {
    if src.len() < GC_RESERVE_HDR {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_GC_RESERVE && src[0] != OP_GC_RELEASE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let len = u16::from_le_bytes([src[1], src[2]]) as usize;
    if src.len() < GC_RESERVE_HDR + len {
        return Err(WireError::Truncated);
    }
    Ok((
        &src[GC_RESERVE_HDR..GC_RESERVE_HDR + len],
        u64::from_le_bytes(src[3..11].try_into().unwrap()),
    ))
}

pub fn encode_gc_reserve_resp(dst: &mut [u8], reserved: bool) -> Result<usize, WireError> {
    if dst.len() < 2 {
        return Err(WireError::BufferTooSmall {
            needed: 2,
            actual: dst.len(),
        });
    }
    dst[0] = OP_GC_RESERVE;
    dst[1] = u8::from(reserved);
    Ok(2)
}

pub fn decode_gc_reserve_resp(src: &[u8]) -> Result<bool, WireError> {
    if src.len() < 2 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_GC_RESERVE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(src[1] != 0)
}

pub fn encode_referenced_req(
    dst: &mut [u8],
    cursor: u32,
    object_id: &[u8],
) -> Result<usize, WireError> {
    check_key(&[], &[], object_id)?;
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

// ── Volume writer lease (replicated control op) ───────────────────
//
//   LeaseReq      [op=9][mode:u8][root_len:u16][path_len:u16]
//                 [holder:16][now_ms:u64][ttl_ms:u32][root][path]
//   LeaseResp     [op=9][status:u8][fence:u64][expires_at_ms:u64]
//   LeaseRestore  [op=10][root_len:u16][path_len:u16][holder:16]
//                 [fence:u64][expires_at_ms:u64][stamp_ms:u64][flags:u8]
//                 [fence_floor:u64][stamp_floor:u64][root][path]
//                 flags: bit 0 live, bit 1 a volume flush is open
//
// One writer per volume, and a fence token that grows every time the
// writer changes, so a store can refuse a write from a holder that has
// since been replaced. The lease is decided where records are ORDERED —
// applied in log order on every replica, like a GC reservation — so
// two nodes cannot each grant it to a different holder.
//
// `now_ms` is part of the record because expiry is a comparison
// against time, and a replica that consulted its own clock at apply
// time would decide differently from the one that proposed it, and
// differently again on replay. The admin router stamps it from the
// server's wall clock; a client never supplies it.
//
// The response always has the same shape. On a refusal `fence` and
// `expires_at_ms` describe the lease that stands (zero when there is
// none), which is what a contender needs to know when to try again.

pub const LEASE_ACQUIRE: u8 = 1;
pub const LEASE_RENEW: u8 = 2;
pub const LEASE_RELEASE: u8 = 3;

/// Opaque identity of a lease holder, chosen by the writer.
pub const LEASE_HOLDER_LEN: usize = 16;

/// Lease response statuses.
pub const LEASE_GRANTED: u8 = 0;
/// Another holder's lease is live and unexpired.
pub const LEASE_HELD: u8 = 1;
/// The caller does not hold a live lease: never acquired, released,
/// expired, or taken over. A writer told this must stop writing.
pub const LEASE_LOST: u8 = 2;
/// The lease table is full of live leases. Retry later.
pub const LEASE_BUSY: u8 = 3;
/// Malformed: unknown mode, a TTL outside `1..=LEASE_TTL_MAX_MS`, or
/// no time to judge expiry against.
pub const LEASE_BAD_REQ: u8 = 4;
/// Stamped no later than a record already applied to this volume, so
/// it is either a redelivered duplicate or was stamped by a clock
/// behind the one that stamped its predecessor. Refused without effect;
/// a fresh request carries a fresh stamp.
pub const LEASE_STALE: u8 = 5;

const LEASE_REQ_HDR: usize = 1 + 1 + 2 + 2 + LEASE_HOLDER_LEN + 8 + 4;
pub const LEASE_RESP_LEN: usize = 1 + 1 + 8 + 8;
const LEASE_RESTORE_HDR: usize = 1 + 2 + 2 + LEASE_HOLDER_LEN + 8 + 8 + 8 + 1 + 8 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLeaseReq<'a> {
    pub mode: u8,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub holder: [u8; LEASE_HOLDER_LEN],
    pub now_ms: u64,
    pub ttl_ms: u32,
}

pub fn encode_lease_req(
    dst: &mut [u8],
    mode: u8,
    namespace_root: &[u8],
    path: &[u8],
    holder: &[u8; LEASE_HOLDER_LEN],
    now_ms: u64,
    ttl_ms: u32,
) -> Result<usize, WireError> {
    check_key(namespace_root, path, &[])?;
    let needed = LEASE_REQ_HDR + namespace_root.len() + path.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LEASE;
    dst[1] = mode;
    dst[2..4].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[4..6].copy_from_slice(&(path.len() as u16).to_le_bytes());
    dst[6..22].copy_from_slice(holder);
    dst[22..30].copy_from_slice(&now_ms.to_le_bytes());
    dst[30..34].copy_from_slice(&ttl_ms.to_le_bytes());
    let mut cursor = LEASE_REQ_HDR;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + path.len()].copy_from_slice(path);
    Ok(needed)
}

/// Decode a lease request. The mode and TTL are carried through
/// unjudged: refusing them is the state machine's answer
/// (`LEASE_BAD_REQ`), not a framing error.
pub fn decode_lease_req(src: &[u8]) -> Result<DecodedLeaseReq<'_>, WireError> {
    if src.len() < LEASE_REQ_HDR {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LEASE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[2], src[3]]) as usize;
    let path_len = u16::from_le_bytes([src[4], src[5]]) as usize;
    let total = LEASE_REQ_HDR + ns_len + path_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let ns = &src[LEASE_REQ_HDR..LEASE_REQ_HDR + ns_len];
    let path = &src[LEASE_REQ_HDR + ns_len..total];
    check_key(ns, path, &[])?;
    let mut holder = [0u8; LEASE_HOLDER_LEN];
    holder.copy_from_slice(&src[6..22]);
    Ok(DecodedLeaseReq {
        mode: src[1],
        namespace_root: ns,
        path,
        holder,
        now_ms: u64::from_le_bytes(src[22..30].try_into().unwrap()),
        ttl_ms: u32::from_le_bytes(src[30..34].try_into().unwrap()),
    })
}

pub fn encode_lease_resp(
    dst: &mut [u8],
    status: u8,
    fence: u64,
    expires_at_ms: u64,
) -> Result<usize, WireError> {
    if dst.len() < LEASE_RESP_LEN {
        return Err(WireError::BufferTooSmall {
            needed: LEASE_RESP_LEN,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LEASE;
    dst[1] = status;
    dst[2..10].copy_from_slice(&fence.to_le_bytes());
    dst[10..18].copy_from_slice(&expires_at_ms.to_le_bytes());
    Ok(LEASE_RESP_LEN)
}

/// Returns `(status, fence, expires_at_ms)`.
pub fn decode_lease_resp(src: &[u8]) -> Result<(u8, u64, u64), WireError> {
    if src.len() < LEASE_RESP_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LEASE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((
        src[1],
        u64::from_le_bytes(src[2..10].try_into().unwrap()),
        u64::from_le_bytes(src[10..18].try_into().unwrap()),
    ))
}

/// One lease-table entry plus the table's floors, as the record that
/// reinstates them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLeaseRestore<'a> {
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub holder: [u8; LEASE_HOLDER_LEN],
    pub fence: u64,
    pub expires_at_ms: u64,
    pub stamp_ms: u64,
    pub live: bool,
    pub fence_floor: u64,
    pub stamp_floor: u64,
}

pub fn encode_lease_restore(
    dst: &mut [u8],
    r: &DecodedLeaseRestore<'_>,
) -> Result<usize, WireError> {
    check_key(r.namespace_root, r.path, &[])?;
    let needed = LEASE_RESTORE_HDR + r.namespace_root.len() + r.path.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LEASE_RESTORE;
    dst[1..3].copy_from_slice(&(r.namespace_root.len() as u16).to_le_bytes());
    dst[3..5].copy_from_slice(&(r.path.len() as u16).to_le_bytes());
    dst[5..21].copy_from_slice(&r.holder);
    dst[21..29].copy_from_slice(&r.fence.to_le_bytes());
    dst[29..37].copy_from_slice(&r.expires_at_ms.to_le_bytes());
    dst[37..45].copy_from_slice(&r.stamp_ms.to_le_bytes());
    dst[45] = u8::from(r.live);
    dst[46..54].copy_from_slice(&r.fence_floor.to_le_bytes());
    dst[54..62].copy_from_slice(&r.stamp_floor.to_le_bytes());
    let mut cursor = LEASE_RESTORE_HDR;
    dst[cursor..cursor + r.namespace_root.len()].copy_from_slice(r.namespace_root);
    cursor += r.namespace_root.len();
    dst[cursor..cursor + r.path.len()].copy_from_slice(r.path);
    Ok(needed)
}

/// Restore-record flag bits (byte 45).
pub const LEASE_RESTORE_LIVE: u8 = 1;
pub const LEASE_RESTORE_FLUSHING: u8 = 2;

/// Mark an encoded restore record as carrying an open volume flush.
/// A flush open when the log rotates must still be open on replay: a
/// commit after the rotation was admitted because of it, and replay
/// must admit it too or the log would rebuild a different volume.
pub fn mark_lease_restore_flushing(record: &mut [u8]) -> bool {
    if record.first() != Some(&OP_LEASE_RESTORE) {
        return false;
    }
    match record.get_mut(45) {
        Some(b) => {
            *b |= LEASE_RESTORE_FLUSHING;
            true
        }
        None => false,
    }
}

/// Does a restore record carry an open volume flush?
pub fn lease_restore_flushing(src: &[u8]) -> bool {
    src.first() == Some(&OP_LEASE_RESTORE)
        && src.get(45).is_some_and(|b| b & LEASE_RESTORE_FLUSHING != 0)
}

pub fn decode_lease_restore(src: &[u8]) -> Result<DecodedLeaseRestore<'_>, WireError> {
    if src.len() < LEASE_RESTORE_HDR {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LEASE_RESTORE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    let path_len = u16::from_le_bytes([src[3], src[4]]) as usize;
    let total = LEASE_RESTORE_HDR + ns_len + path_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let ns = &src[LEASE_RESTORE_HDR..LEASE_RESTORE_HDR + ns_len];
    let path = &src[LEASE_RESTORE_HDR + ns_len..total];
    check_key(ns, path, &[])?;
    let mut holder = [0u8; LEASE_HOLDER_LEN];
    holder.copy_from_slice(&src[5..21]);
    Ok(DecodedLeaseRestore {
        namespace_root: ns,
        path,
        holder,
        fence: u64::from_le_bytes(src[21..29].try_into().unwrap()),
        expires_at_ms: u64::from_le_bytes(src[29..37].try_into().unwrap()),
        stamp_ms: u64::from_le_bytes(src[37..45].try_into().unwrap()),
        live: src[45] & LEASE_RESTORE_LIVE != 0,
        fence_floor: u64::from_le_bytes(src[46..54].try_into().unwrap()),
        stamp_floor: u64::from_le_bytes(src[54..62].try_into().unwrap()),
    })
}

// ── Volume commit (replicated control op) ─────────────────────────
//
//   VolumeReq   [op=11][mode:u8][root_len:u16][path_len:u16][oid_len:u16]
//               [holder:16][fence:u64][expected:u64][now_ms:u64]
//               [root][path][oid]
//   VolumeResp  [op=11][status:u8][revision:u64]
//
// A volume's committed state is its path bound to a map root digest
// (`loam_volume_map_wire.rs`). A writer moves it forward in three
// steps, each a record ordered with every bind, lease and GC
// reservation:
//
//   BEGIN   opens a flush: from here until COMMIT or ABORT the orphan
//           GC treats every body as referenced, because the flush is
//           writing bodies no bound root reaches yet. Refused while a
//           GC reservation stands, so a sweep that has proven a body
//           unreferenced deletes it before any flush can begin.
//   COMMIT  binds the path to `oid` at `expected + 1`, only if the
//           current revision is exactly `expected` (0: unbound), and
//           only for the holder of the volume's live lease under
//           `fence` with a flush open. Ends the flush either way.
//   ABORT   ends the holder's flush without binding.
//   DELETE  unbinds the path, under the same lease and CAS as COMMIT.
//
// A plain BIND, RENAME or UNBIND is refused when it would create,
// replace, move or remove a volume binding: those records carry no
// fence, and every change to a volume is fenced.
//
// `now_ms` is stamped by the admin router, as for leases: lease expiry
// is judged against it, so every replica and every replay agrees.
//
// `revision` in the response is the new revision on a commit, and the
// current one otherwise — on a CONFLICT it is what the writer lost to.

pub const VOLUME_BEGIN: u8 = 1;
pub const VOLUME_COMMIT: u8 = 2;
pub const VOLUME_ABORT: u8 = 3;
/// Unbind the volume's path, under its live lease and exact fence, only
/// if the current revision is `expected`. A plain UNBIND of a volume is
/// refused: deletion is fenced like any other change to a volume.
pub const VOLUME_DELETE: u8 = 4;

pub const VOLUME_OK: u8 = 0;
/// The current revision is not the one the commit was prepared on:
/// another commit landed first. The writer must reopen; its flush is
/// orphaned.
pub const VOLUME_CONFLICT: u8 = 1;
/// No live lease for this holder under this fence (never held,
/// expired, released, or taken over). The writer must stop.
pub const VOLUME_LEASE_LOST: u8 = 2;
/// A GC reservation is in force; retry the BEGIN shortly.
pub const VOLUME_RESERVED: u8 = 3;
/// Malformed: unknown mode, no stamped time, a commit with no flush
/// open, or a commit naming no object.
pub const VOLUME_BAD_REQ: u8 = 4;

const VOLUME_REQ_HDR: usize = 1 + 1 + 2 + 2 + 2 + LEASE_HOLDER_LEN + 8 + 8 + 8;
pub const VOLUME_RESP_LEN: usize = 1 + 1 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedVolumeReq<'a> {
    pub mode: u8,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub object_id: &'a [u8],
    pub holder: [u8; LEASE_HOLDER_LEN],
    pub fence: u64,
    pub expected: u64,
    pub now_ms: u64,
}

pub fn encode_volume_req(dst: &mut [u8], r: &DecodedVolumeReq<'_>) -> Result<usize, WireError> {
    check_key(r.namespace_root, r.path, r.object_id)?;
    let needed = VOLUME_REQ_HDR + r.namespace_root.len() + r.path.len() + r.object_id.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_VOLUME;
    dst[1] = r.mode;
    dst[2..4].copy_from_slice(&(r.namespace_root.len() as u16).to_le_bytes());
    dst[4..6].copy_from_slice(&(r.path.len() as u16).to_le_bytes());
    dst[6..8].copy_from_slice(&(r.object_id.len() as u16).to_le_bytes());
    dst[8..24].copy_from_slice(&r.holder);
    dst[24..32].copy_from_slice(&r.fence.to_le_bytes());
    dst[32..40].copy_from_slice(&r.expected.to_le_bytes());
    dst[40..48].copy_from_slice(&r.now_ms.to_le_bytes());
    let mut cursor = VOLUME_REQ_HDR;
    dst[cursor..cursor + r.namespace_root.len()].copy_from_slice(r.namespace_root);
    cursor += r.namespace_root.len();
    dst[cursor..cursor + r.path.len()].copy_from_slice(r.path);
    cursor += r.path.len();
    dst[cursor..cursor + r.object_id.len()].copy_from_slice(r.object_id);
    Ok(needed)
}

/// Decode a volume request. The mode is carried through unjudged:
/// refusing it is the namespace's verdict (`VOLUME_BAD_REQ`).
pub fn decode_volume_req(src: &[u8]) -> Result<DecodedVolumeReq<'_>, WireError> {
    if src.len() < VOLUME_REQ_HDR {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_VOLUME {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[2], src[3]]) as usize;
    let path_len = u16::from_le_bytes([src[4], src[5]]) as usize;
    let oid_len = u16::from_le_bytes([src[6], src[7]]) as usize;
    let total = VOLUME_REQ_HDR + ns_len + path_len + oid_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let ns = &src[VOLUME_REQ_HDR..VOLUME_REQ_HDR + ns_len];
    let path = &src[VOLUME_REQ_HDR + ns_len..VOLUME_REQ_HDR + ns_len + path_len];
    let oid = &src[VOLUME_REQ_HDR + ns_len + path_len..total];
    check_key(ns, path, oid)?;
    let mut holder = [0u8; LEASE_HOLDER_LEN];
    holder.copy_from_slice(&src[8..24]);
    Ok(DecodedVolumeReq {
        mode: src[1],
        namespace_root: ns,
        path,
        object_id: oid,
        holder,
        fence: u64::from_le_bytes(src[24..32].try_into().unwrap()),
        expected: u64::from_le_bytes(src[32..40].try_into().unwrap()),
        now_ms: u64::from_le_bytes(src[40..48].try_into().unwrap()),
    })
}

pub fn encode_volume_resp(dst: &mut [u8], status: u8, revision: u64) -> Result<usize, WireError> {
    if dst.len() < VOLUME_RESP_LEN {
        return Err(WireError::BufferTooSmall {
            needed: VOLUME_RESP_LEN,
            actual: dst.len(),
        });
    }
    dst[0] = OP_VOLUME;
    dst[1] = status;
    dst[2..10].copy_from_slice(&revision.to_le_bytes());
    Ok(VOLUME_RESP_LEN)
}

/// Returns `(status, revision)`.
pub fn decode_volume_resp(src: &[u8]) -> Result<(u8, u64), WireError> {
    if src.len() < VOLUME_RESP_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_VOLUME {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((src[1], u64::from_le_bytes(src[2..10].try_into().unwrap())))
}

// ── Volume roots (read op: the orphan GC's map walk) ──────────────
//
//   VolumeRootsReq   [op=12][cursor:u32]
//   VolumeRootsResp  [op=12][next_cursor:u32][view:u64][count:u8]
//                    [digest:32 × count]
//
// One page of the root digests every volume binding names, in any
// root — live volumes and snapshots alike, since a snapshot of a
// volume is a binding of its root digest. `next_cursor` 0 ends the
// walk. `view` names the on-disk snapshot generation the cursor walks;
// a walk whose pages disagree on it crossed a compaction and must not
// be trusted to have seen every binding. Each page examines a bounded
// number of slots, so it may come back empty with a cursor to resume.

/// Root digests per response page. Kept small enough that a page fits
/// the namespace's 256-byte reply.
pub const MAX_VOLUME_ROOTS: usize = 6;
pub const VOLUME_ROOTS_HDR: usize = 1 + 4 + 8 + 1;
const VOLUME_ROOT_DIGEST: usize = 32;

pub fn encode_volume_roots_req(dst: &mut [u8], cursor: u32) -> Result<usize, WireError> {
    if dst.len() < 5 {
        return Err(WireError::BufferTooSmall {
            needed: 5,
            actual: dst.len(),
        });
    }
    dst[0] = OP_VOLUME_ROOTS;
    dst[1..5].copy_from_slice(&cursor.to_le_bytes());
    Ok(5)
}

pub fn decode_volume_roots_req(src: &[u8]) -> Result<u32, WireError> {
    if src.len() < 5 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_VOLUME_ROOTS {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok(u32::from_le_bytes([src[1], src[2], src[3], src[4]]))
}

pub fn encode_volume_roots_resp(
    dst: &mut [u8],
    next_cursor: u32,
    view: u64,
    digests: &[[u8; VOLUME_ROOT_DIGEST]],
) -> Result<usize, WireError> {
    if digests.len() > MAX_VOLUME_ROOTS {
        return Err(WireError::StringTooLong {
            len: digests.len(),
            max: MAX_VOLUME_ROOTS,
        });
    }
    let needed = VOLUME_ROOTS_HDR + digests.len() * VOLUME_ROOT_DIGEST;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_VOLUME_ROOTS;
    dst[1..5].copy_from_slice(&next_cursor.to_le_bytes());
    dst[5..13].copy_from_slice(&view.to_le_bytes());
    dst[13] = digests.len() as u8;
    let mut at = VOLUME_ROOTS_HDR;
    for d in digests {
        dst[at..at + VOLUME_ROOT_DIGEST].copy_from_slice(d);
        at += VOLUME_ROOT_DIGEST;
    }
    Ok(needed)
}

/// Returns `(next_cursor, view, digests)`, `digests` being
/// `count × 32` bytes.
pub fn decode_volume_roots_resp(src: &[u8]) -> Result<(u32, u64, &[u8]), WireError> {
    if src.len() < VOLUME_ROOTS_HDR {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_VOLUME_ROOTS {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let count = src[13] as usize;
    if count > MAX_VOLUME_ROOTS {
        return Err(WireError::StringTooLong {
            len: count,
            max: MAX_VOLUME_ROOTS,
        });
    }
    let total = VOLUME_ROOTS_HDR + count * VOLUME_ROOT_DIGEST;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    Ok((
        u32::from_le_bytes([src[1], src[2], src[3], src[4]]),
        u64::from_le_bytes(src[5..13].try_into().unwrap()),
        &src[VOLUME_ROOTS_HDR..total],
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
/// Length of the response record at the head of `src`, `None` when
/// more bytes are needed to tell.
///
/// A response channel is a byte stream like any other: a producer that
/// answers several records before its consumer drains has its answers
/// coalesce into one read, and a consumer that treats one read as one
/// response silently drops every answer after the first — then
/// mis-attributes the rest, because its pending queue has shifted by
/// one. Every response shape here is self-delimiting from its opcode
/// byte, which is what makes splitting possible without tracking what
/// was asked.
pub fn response_record_len(src: &[u8]) -> Result<Option<usize>, WireError> {
    let opcode = match src.first() {
        Some(b) => *b,
        None => return Ok(None),
    };
    // `None` means "not yet", never "shorter than it is": callers take
    // the returned length as a whole record without re-checking, the
    // same contract `request_record_len` holds.
    let complete = |needed: usize| {
        if src.len() < needed {
            Ok(None)
        } else {
            Ok(Some(needed))
        }
    };
    match opcode {
        // Bare acks: the applied opcode echoed back, or a refusal.
        OP_BIND | OP_RENAME | OP_UNBIND | OP_GC_RELEASE | NAK_GENERIC | NAK_RESERVED_BYTE
        | NAK_FENCED => complete(1),
        // [op][flag]
        OP_GC_RESERVE => complete(2),
        // [op][status][fence:u64][expires_at:u64]
        OP_LEASE => complete(LEASE_RESP_LEN),
        // [op][status][revision:u64]
        OP_VOLUME => complete(VOLUME_RESP_LEN),
        // [op][next:u32][view:u64][count][digest:32 × count]
        OP_VOLUME_ROOTS => match src.get(13) {
            None => Ok(None),
            Some(&count) => complete(VOLUME_ROOTS_HDR + count as usize * VOLUME_ROOT_DIGEST),
        },
        // [op][status], and when FOUND: [oid_len][oid][rev:u64][kind]
        OP_LOOKUP => match src.get(1) {
            None => Ok(None),
            Some(&LOOKUP_NOT_FOUND) => complete(2),
            Some(_) => match src.get(2) {
                None => Ok(None),
                Some(&oid_len) => complete(3 + oid_len as usize + 9),
            },
        },
        // [op][referenced][cursor:u32]
        OP_REFERENCED => complete(6),
        // [op][next_cursor:u32][count][ (len:u16)(path) × count ]
        OP_LIST => {
            let count = match src.get(5) {
                Some(c) => *c as usize,
                None => return Ok(None),
            };
            let mut at = 6usize;
            for _ in 0..count {
                if src.len() < at + 2 {
                    return Ok(None);
                }
                let plen = u16::from_le_bytes([src[at], src[at + 1]]) as usize;
                at += 2 + plen;
            }
            complete(at)
        }
        observed => Err(WireError::BadOpcode { observed }),
    }
}

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
        // [op][oid_len:u16][now:u64]
        OP_GC_RESERVE | OP_GC_RELEASE => (GC_RESERVE_HDR, [1, 0, 0]),
        // [op][mode][root_len:u16][path_len:u16][holder:16][now:u64][ttl:u32]
        OP_LEASE => (LEASE_REQ_HDR, [2, 4, 0]),
        // [op][mode][root_len:u16][path_len:u16][oid_len:u16][holder:16]
        // [fence:u64][expected:u64][now:u64]
        OP_VOLUME => (VOLUME_REQ_HDR, [2, 4, 6]),
        // [op][cursor:u32]
        OP_VOLUME_ROOTS => (5, [0, 0, 0]),
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
