// Wire format for loam's admin plane: the requests a client sends
// `admin_gate` and the answers it gets back, which `admin_router`
// composes over the in-graph public-surface PICs.
//
// Each request carries a `correlation_id` the router pairs with
// the downstream PIC's response, so the caller can fire many
// concurrent requests without per-call state.
//
// Layouts (multi-byte ints LE):
//
//   AdminBind          [op:u8=0x40][cid:u32]
//                      [ns_len:u16][path_len:u16][oid_len:u16]
//                      [kind:u8][revision:u64][size:u64][ctype_len:u8]
//                      [ns:ns_len][path:path_len][oid:oid_len][ctype]
//
//                      `size` and the content type are what the binding
//                      records of the object it names, as a write
//                      records them; the router stamps the time.
//
//   AdminBindAck       [op:u8=0x40][cid:u32][status:u8]
//                      // status: 0x01 = OK (downstream OP_BIND ack)
//                      //         0xFF = NAK
//
// The remaining ops follow the same envelope: opcode byte, `cid`,
// then op-specific fields, with every reply carrying back the
// caller's `cid`.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use core::convert::TryInto;

pub const OP_BIND: u8 = 0x40;
pub const OP_PUT_BODY: u8 = 0x41;
pub const OP_GET_BODY: u8 = 0x42;
pub const OP_PUT_FILE: u8 = 0x43;
pub const OP_GET_FILE: u8 = 0x44;
pub const OP_DELETE_FILE: u8 = 0x45;
pub const OP_LIST_FILES: u8 = 0x46;
pub const OP_PUT_FILE_OPEN: u8 = 0x47;
pub const OP_PUT_FILE_CHUNK: u8 = 0x48;
pub const OP_PUT_FILE_COMMIT: u8 = 0x49;
pub const OP_READ_FILE_RANGE: u8 = 0x4A;
pub const OP_STAT_FILE: u8 = 0x4B;
pub const OP_PUT_BODY_KEYED: u8 = 0x4C;
pub const OP_DELETE_BODY: u8 = 0x4D;
/// Acquire, renew or release a volume's writer lease.
pub const OP_LEASE: u8 = 0x4F;
/// Begin, commit or abort a volume flush: the fenced, revisioned bind
/// of a volume's path to its map root.
pub const OP_VOLUME: u8 = 0x50;
/// Resolve a path to its binding — object id, revision and kind —
/// without reading the body.
pub const OP_LOOKUP: u8 = 0x51;

pub const STATUS_OK: u8 = 0x01;
pub const STATUS_NAK: u8 = 0xFF;
pub const STATUS_NOT_FOUND: u8 = 0x02;

/// The request was well-formed and would have been accepted, but a
/// bounded table is full. RETRY LATER.
///
/// Distinct from `STATUS_NAK` for the same reason `STATUS_NOT_FOUND`
/// is: a caller has to be able to branch. Refusing at a table
/// boundary is a DESIGNED condition in a store built from
/// fixed-size arenas — it is what back-pressure looks like — and
/// reporting it as a generic failure tells an S3 client to give up
/// where it should have backed off. The gateway maps this to 503,
/// not 500.
pub const STATUS_BUSY: u8 = 0x03;

/// The write would cross the namespace root's QUOTA.
///
/// Separate from `STATUS_BUSY` because the remedy is different and
/// the caller is different: busy resolves by waiting, a quota
/// resolves only by the tenant deleting their own data or an
/// operator raising the ceiling. Retrying a quota refusal forever is
/// exactly what a client told "busy" would do. The gateway maps this
/// to 507 Insufficient Storage.
pub const STATUS_QUOTA: u8 = 0x04;

/// A volume commit prepared against a revision that is no longer the
/// current one: another commit landed first.
///
/// Separate from `STATUS_NAK` because the remedy is the caller's:
/// reopen the volume at its current revision and decide again.
/// Retrying the same commit will never succeed.
pub const STATUS_CONFLICT: u8 = 0x05;

/// A lease acquire refused because another holder's lease is live.
///
/// The remedy is to wait for it to lapse or be released — the ack
/// carries its expiry — not to retry at once, and never to write.
pub const STATUS_LEASE_HELD: u8 = 0x06;

/// A renew, release or volume flush from a caller that no longer holds
/// the lease: it expired, was released, or passed to another holder. A
/// writer told this must stop writing; its fence is no longer the
/// newest.
pub const STATUS_LEASE_LOST: u8 = 0x07;

/// The caller's session holds no grant for this operation: no
/// capability it presented covers the key the operation names with the
/// permission it needs, or it names a write stream another session
/// opened.
///
/// Separate from `STATUS_NAK` because the remedy is an operator's, not
/// the caller's: a grant has to change before the same request can
/// succeed, so retrying it is pointless.
pub const STATUS_FORBIDDEN: u8 = 0x08;

/// A write made on condition that nothing was bound found a binding.
/// Distinct from `STATUS_CONFLICT` because the remedy differs: the key
/// exists, and only a write that means to replace it can proceed.
///
/// To `GET_BODY`: the body is held, but is larger than one answer — it
/// is read by range through a binding that names it.
pub const STATUS_EXISTS: u8 = 0x09;

/// How a composed write or delete decides against the key's current
/// binding. The router reads the binding just before it binds and binds
/// at the next revision, on condition that nothing moved in between, so
/// every mode is decided at the namespace's single point of order.
pub const WRITE_ANY: u8 = 0;
/// Only if nothing is bound (a create).
pub const WRITE_ABSENT: u8 = 1;
/// Only if the key is bound to the expected object id (an etag match).
pub const WRITE_IF: u8 = 2;

/// A write's condition: its mode and, for `WRITE_IF`, the object id the
/// key must be bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteCond<'a> {
    pub mode: u8,
    pub expect: &'a [u8],
}

impl WriteCond<'_> {
    pub const ANY: WriteCond<'static> = WriteCond {
        mode: WRITE_ANY,
        expect: &[],
    };
}

/// Longest content type a write carries.
pub use super::limits::CONTENT_TYPE_MAX;

fn check_cond(c: &WriteCond<'_>) -> Result<(), WireError> {
    if c.mode > WRITE_IF
        || c.expect.len() > MAX_OBJECT_ID
        || (c.mode == WRITE_IF) == c.expect.is_empty()
    {
        return Err(WireError::BadOpcode { observed: c.mode });
    }
    Ok(())
}

/// The largest request: a single-frame PUT_FILE of a whole body under
/// the longest key, expected object id and content type. What a
/// receiver assembling requests from a stream must hold, and past which
/// a request is refused.
pub const REQUEST_MAX: usize = 17
    + MAX_ROOT
    + MAX_PATH
    + MAX_OBJECT_ID
    + super::limits::CONTENT_TYPE_MAX
    + super::body_wire::MAX_BODY;

/// The largest answer: a whole body read back. A listing page is
/// bounded below it, which the assertion holds.
pub const RESPONSE_MAX: usize = 10 + super::body_wire::MAX_BODY;

/// Entries one listing page carries: the namespace's own page.
pub const LIST_PAGE_MAX: usize = 16;
const _: () = assert!(
    8 + LIST_PAGE_MAX
        * (2 + MAX_PATH + 8 + 1 + 1 + MAX_OBJECT_ID + 8 + 8 + 1 + super::limits::CONTENT_TYPE_MAX)
        <= RESPONSE_MAX
);

/// Per-field key ceilings, from the single register in
/// `loam_limits.rs` — the same numbers the namespace wire, the
/// arena slot and the snapshot record use. This wire fronts the S3
/// gateway, so these are what decide whether a legal S3 key is
/// storable: on the host profile MAX_PATH is 1024, exactly S3's own
/// key ceiling.
#[allow(
    unused_imports,
    reason = "re-exported so a consumer can ask this wire what it accepts; \
              the wire itself now delegates the check to loam_limits"
)]
pub use super::limits::{MAX_OBJECT_ID, MAX_PATH, MAX_ROOT};

/// Widest key-shaped field, for buffer sizing only — never as a
/// per-field ceiling. See `check_key`.
pub const MAX_STRING: usize = super::limits::MAX_KEY_STRING;

/// Refuse a key whose components exceed their ceilings, so an
/// oversize key is rejected at the front door with a distinct error
/// instead of being accepted and then dropped from every listing.
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
pub const DIGEST_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadOpcode { observed: u8 },
    BufferTooSmall { needed: usize, actual: usize },
    StringTooLong { len: usize, max: usize },
}

// ── Fences on write acks ───────────────────────────────────────────
//
// A write's ack (BIND, PUT_FILE, DELETE_FILE) ends with the fence the
// namespace achieved for it, `[fence_len:u8][fence]` in fluxor's fence
// wire form, empty when the write did not apply. A storage provider
// reports it onward instead of guessing.

/// The largest fence a write ack carries: fluxor's fence wire maximum.
pub const ACK_FENCE_MAX: usize = 62;

fn put_fence(dst: &mut [u8], at: usize, fence: &[u8]) -> Result<usize, WireError> {
    if fence.len() > ACK_FENCE_MAX {
        return Err(WireError::StringTooLong {
            len: fence.len(),
            max: ACK_FENCE_MAX,
        });
    }
    let n = at + 1 + fence.len();
    if dst.len() < n {
        return Err(WireError::BufferTooSmall {
            needed: n,
            actual: dst.len(),
        });
    }
    dst[at] = fence.len() as u8;
    dst[at + 1..n].copy_from_slice(fence);
    Ok(n)
}

fn get_fence(src: &[u8], at: usize) -> Result<&[u8], WireError> {
    let len = *src.get(at).ok_or(WireError::Truncated)? as usize;
    if len > ACK_FENCE_MAX {
        return Err(WireError::StringTooLong {
            len,
            max: ACK_FENCE_MAX,
        });
    }
    src.get(at + 1..at + 1 + len).ok_or(WireError::Truncated)
}

/// Length of a write ack whose fixed part is `fixed` bytes.
fn fenced_len(src: &[u8], fixed: usize) -> Result<usize, WireError> {
    let len = *src.get(fixed).ok_or(WireError::Truncated)? as usize;
    if len > ACK_FENCE_MAX {
        return Err(WireError::StringTooLong {
            len,
            max: ACK_FENCE_MAX,
        });
    }
    Ok(fixed + 1 + len)
}

// ── AdminBind ──────────────────────────────────────────────────────

const BIND_HDR: usize = 1 + 4 + 2 + 2 + 2 + 1 + 8 + 8 + 1;

#[allow(
    clippy::too_many_arguments,
    reason = "bounded no_std step functions pass explicit scalar params"
)]
pub fn encode_admin_bind(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
    object_id: &[u8],
    kind: u8,
    revision: u64,
    size: u64,
    content_type: &[u8],
) -> Result<usize, WireError> {
    check_key(namespace_root, path, object_id)?;
    if content_type.len() > CONTENT_TYPE_MAX {
        return Err(WireError::StringTooLong {
            len: content_type.len(),
            max: CONTENT_TYPE_MAX,
        });
    }
    let needed =
        BIND_HDR + namespace_root.len() + path.len() + object_id.len() + content_type.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_BIND;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..7].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[7..9].copy_from_slice(&(path.len() as u16).to_le_bytes());
    dst[9..11].copy_from_slice(&(object_id.len() as u16).to_le_bytes());
    dst[11] = kind;
    dst[12..20].copy_from_slice(&revision.to_le_bytes());
    dst[20..28].copy_from_slice(&size.to_le_bytes());
    dst[28] = content_type.len() as u8;
    let mut cursor = BIND_HDR;
    for part in [namespace_root, path, object_id, content_type] {
        dst[cursor..cursor + part.len()].copy_from_slice(part);
        cursor += part.len();
    }
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdminBind<'a> {
    pub correlation_id: u32,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub object_id: &'a [u8],
    pub kind: u8,
    pub revision: u64,
    pub size: u64,
    pub content_type: &'a [u8],
}

pub fn decode_admin_bind(src: &[u8]) -> Result<DecodedAdminBind<'_>, WireError> {
    if src.len() < BIND_HDR {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_BIND {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let correlation_id = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let ns_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let path_len = u16::from_le_bytes([src[7], src[8]]) as usize;
    let oid_len = u16::from_le_bytes([src[9], src[10]]) as usize;
    let kind = src[11];
    let revision = u64::from_le_bytes(src[12..20].try_into().unwrap());
    let size = u64::from_le_bytes(src[20..28].try_into().unwrap());
    let ct_len = src[28] as usize;
    if ct_len > CONTENT_TYPE_MAX {
        return Err(WireError::StringTooLong {
            len: ct_len,
            max: CONTENT_TYPE_MAX,
        });
    }
    let total = BIND_HDR + ns_len + path_len + oid_len + ct_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let mut at = BIND_HDR;
    let ns = &src[at..at + ns_len];
    at += ns_len;
    let path = &src[at..at + path_len];
    at += path_len;
    let oid = &src[at..at + oid_len];
    at += oid_len;
    let content_type = &src[at..at + ct_len];
    check_key(ns, path, oid)?;
    Ok(DecodedAdminBind {
        correlation_id,
        namespace_root: ns,
        path,
        object_id: oid,
        kind,
        revision,
        size,
        content_type,
    })
}

// ── AdminBindAck ───────────────────────────────────────────────────

/// `[op][cid][status][fence_len][fence]`.
pub fn encode_admin_bind_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    fence: &[u8],
) -> Result<usize, WireError> {
    if dst.len() < 6 {
        return Err(WireError::BufferTooSmall {
            needed: 6,
            actual: dst.len(),
        });
    }
    dst[0] = OP_BIND;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    put_fence(dst, 6, fence)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedAdminBindAck<'a> {
    pub correlation_id: u32,
    pub status: u8,
    /// The fence the bind achieved; empty when it did not apply.
    pub fence: &'a [u8],
}

pub fn decode_admin_bind_ack(src: &[u8]) -> Result<DecodedAdminBindAck<'_>, WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_BIND {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let correlation_id = u32::from_le_bytes(src[1..5].try_into().unwrap());
    Ok(DecodedAdminBindAck {
        correlation_id,
        status: src[5],
        fence: get_fence(src, 6)?,
    })
}

// ── AdminPutBody ──────────────────────────────────────────────────
//
//   Request:  [op=0x41][cid:u32][body_len:u32][body:body_len]
//   Response: [op=0x41][cid:u32][status:u8][digest:32] (status OK)
//          or [op=0x41][cid:u32][status:u8] (status NAK)

pub fn encode_admin_put_body(
    dst: &mut [u8],
    correlation_id: u32,
    body: &[u8],
) -> Result<usize, WireError> {
    let at = encode_admin_put_body_header(dst, correlation_id, body.len())?;
    dst[at..at + body.len()].copy_from_slice(body);
    Ok(at + body.len())
}

/// The fixed part of an AdminPutBody, for a caller that builds the body
/// in place at `dst[n..n + body_len]`, where `n` is the length returned.
/// A body assembled in the frame (a map page patched as it is written)
/// then needs no second buffer to be copied from.
pub fn encode_admin_put_body_header(
    dst: &mut [u8],
    correlation_id: u32,
    body_len: usize,
) -> Result<usize, WireError> {
    let needed = 1 + 4 + 4 + body_len;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_BODY;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..9].copy_from_slice(&(body_len as u32).to_le_bytes());
    Ok(9)
}

pub fn decode_admin_put_body(src: &[u8]) -> Result<(u32, &[u8]), WireError> {
    if src.len() < 9 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_BODY {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let len = u32::from_le_bytes(src[5..9].try_into().unwrap()) as usize;
    if 9 + len > src.len() {
        return Err(WireError::Truncated);
    }
    Ok((cid, &src[9..9 + len]))
}

pub fn encode_admin_put_body_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    digest: Option<&[u8; DIGEST_LEN]>,
) -> Result<usize, WireError> {
    if status == STATUS_OK {
        let digest = digest.ok_or(WireError::BufferTooSmall {
            needed: 0,
            actual: 0,
        })?;
        let needed = 1 + 4 + 1 + DIGEST_LEN;
        if dst.len() < needed {
            return Err(WireError::BufferTooSmall {
                needed,
                actual: dst.len(),
            });
        }
        dst[0] = OP_PUT_BODY;
        dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
        dst[5] = status;
        dst[6..6 + DIGEST_LEN].copy_from_slice(digest);
        Ok(needed)
    } else {
        let needed = 1 + 4 + 1;
        if dst.len() < needed {
            return Err(WireError::BufferTooSmall {
                needed,
                actual: dst.len(),
            });
        }
        dst[0] = OP_PUT_BODY;
        dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
        dst[5] = status;
        Ok(needed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdminPutBodyAck<'a> {
    pub correlation_id: u32,
    pub status: u8,
    pub digest: Option<&'a [u8]>,
}

pub fn decode_admin_put_body_ack(src: &[u8]) -> Result<DecodedAdminPutBodyAck<'_>, WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_BODY {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let status = src[5];
    let digest = if status == STATUS_OK {
        if src.len() < 6 + DIGEST_LEN {
            return Err(WireError::Truncated);
        }
        Some(&src[6..6 + DIGEST_LEN])
    } else {
        None
    };
    Ok(DecodedAdminPutBodyAck {
        correlation_id: cid,
        status,
        digest,
    })
}

// ── AdminGetBody ──────────────────────────────────────────────────
//
//   Request:  [op=0x42][cid:u32][digest:32]
//   Response: [op=0x42][cid:u32][status:u8][body_len:u32][body:body_len] (OK)
//          or [op=0x42][cid:u32][status:u8] (NOT_FOUND / NAK)

pub fn encode_admin_get_body(
    dst: &mut [u8],
    correlation_id: u32,
    digest: &[u8; DIGEST_LEN],
) -> Result<usize, WireError> {
    let needed = 1 + 4 + DIGEST_LEN;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_GET_BODY;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..5 + DIGEST_LEN].copy_from_slice(digest);
    Ok(needed)
}

pub fn decode_admin_get_body(src: &[u8]) -> Result<(u32, &[u8]), WireError> {
    if src.len() < 5 + DIGEST_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_GET_BODY {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    Ok((cid, &src[5..5 + DIGEST_LEN]))
}

pub fn encode_admin_get_body_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    body: Option<&[u8]>,
) -> Result<usize, WireError> {
    if status == STATUS_OK {
        let body = body.ok_or(WireError::BufferTooSmall {
            needed: 0,
            actual: 0,
        })?;
        let needed = 1 + 4 + 1 + 4 + body.len();
        if dst.len() < needed {
            return Err(WireError::BufferTooSmall {
                needed,
                actual: dst.len(),
            });
        }
        dst[0] = OP_GET_BODY;
        dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
        dst[5] = status;
        dst[6..10].copy_from_slice(&(body.len() as u32).to_le_bytes());
        dst[10..10 + body.len()].copy_from_slice(body);
        Ok(needed)
    } else {
        let needed = 1 + 4 + 1;
        if dst.len() < needed {
            return Err(WireError::BufferTooSmall {
                needed,
                actual: dst.len(),
            });
        }
        dst[0] = OP_GET_BODY;
        dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
        dst[5] = status;
        Ok(needed)
    }
}

pub fn decode_admin_get_body_ack(src: &[u8]) -> Result<(u32, u8, Option<&[u8]>), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_GET_BODY {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let status = src[5];
    if status == STATUS_OK {
        if src.len() < 10 {
            return Err(WireError::Truncated);
        }
        let len = u32::from_le_bytes(src[6..10].try_into().unwrap()) as usize;
        if 10 + len > src.len() {
            return Err(WireError::Truncated);
        }
        Ok((cid, status, Some(&src[10..10 + len])))
    } else {
        Ok((cid, status, None))
    }
}

// ── AdminPutFile (composed) ───────────────────────────────────────
//
// One-shot "create a file": admin_router runs a 3-stage state
// machine — PUT body → PUT object descriptor → BIND path. If any
// stage fails the whole op nak's.
//
//   Request:  [op=0x43][cid:u32][ns_len:u16][path_len:u16]
//             [kind:u8][mode:u8][expect_len:u8][ctype_len:u8]
//             [body_len:u32]
//             [ns][path][expect][ctype][body]
//
//   Response: [op=0x43][cid:u32][status:u8][digest:32]   (status OK)
//          or [op=0x43][cid:u32][status:u8]              (otherwise)
//
// The router chooses the revision: it reads the key's binding just
// before binding and binds at the next revision on condition that the
// key has not moved, so a write is ordered by the namespace, not by a
// writer's clock. `mode` / `expect` are the write's own condition
// (`WriteCond`); a failed one is `STATUS_EXISTS` (ABSENT) or
// `STATUS_CONFLICT` (IF).

const PUT_FILE_HDR: usize = 1 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + 4;

#[allow(
    clippy::too_many_arguments,
    reason = "bounded no_std step functions pass explicit scalar params"
)]
pub fn encode_admin_put_file(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
    kind: u8,
    cond: &WriteCond<'_>,
    content_type: &[u8],
    body: &[u8],
) -> Result<usize, WireError> {
    check_key(namespace_root, path, &[])?;
    check_cond(cond)?;
    if content_type.len() > CONTENT_TYPE_MAX {
        return Err(WireError::StringTooLong {
            len: content_type.len(),
            max: CONTENT_TYPE_MAX,
        });
    }
    let needed = PUT_FILE_HDR
        + namespace_root.len()
        + path.len()
        + cond.expect.len()
        + content_type.len()
        + body.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_FILE;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..7].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[7..9].copy_from_slice(&(path.len() as u16).to_le_bytes());
    dst[9] = kind;
    dst[10] = cond.mode;
    dst[11] = cond.expect.len() as u8;
    dst[12] = content_type.len() as u8;
    dst[13..17].copy_from_slice(&(body.len() as u32).to_le_bytes());
    let mut at = PUT_FILE_HDR;
    for part in [namespace_root, path, cond.expect, content_type, body] {
        dst[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdminPutFile<'a> {
    pub correlation_id: u32,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub kind: u8,
    pub cond: WriteCond<'a>,
    pub content_type: &'a [u8],
    pub body: &'a [u8],
}

pub fn decode_admin_put_file(src: &[u8]) -> Result<DecodedAdminPutFile<'_>, WireError> {
    if src.len() < PUT_FILE_HDR {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_FILE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let ns_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let path_len = u16::from_le_bytes([src[7], src[8]]) as usize;
    let kind = src[9];
    let mode = src[10];
    let expect_len = src[11] as usize;
    let ct_len = src[12] as usize;
    let body_len = u32::from_le_bytes(src[13..17].try_into().unwrap()) as usize;
    let total = PUT_FILE_HDR + ns_len + path_len + expect_len + ct_len + body_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let mut at = PUT_FILE_HDR;
    let mut take = |n: usize| {
        let p = &src[at..at + n];
        at += n;
        p
    };
    let ns = take(ns_len);
    let path = take(path_len);
    let expect = take(expect_len);
    let content_type = take(ct_len);
    let body = take(body_len);
    check_key(ns, path, &[])?;
    let cond = WriteCond { mode, expect };
    check_cond(&cond)?;
    if content_type.len() > CONTENT_TYPE_MAX {
        return Err(WireError::StringTooLong {
            len: content_type.len(),
            max: CONTENT_TYPE_MAX,
        });
    }
    Ok(DecodedAdminPutFile {
        correlation_id: cid,
        namespace_root: ns,
        path,
        kind,
        cond,
        content_type,
        body,
    })
}

/// `[op][cid][status][digest:32][fence_len][fence]` when the put
/// applied, `[op][cid][status][fence_len=0]` otherwise.
pub fn encode_admin_put_file_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    digest: Option<&[u8; DIGEST_LEN]>,
    fence: &[u8],
) -> Result<usize, WireError> {
    let fixed = if status == STATUS_OK {
        6 + DIGEST_LEN
    } else {
        6
    };
    if dst.len() < fixed {
        return Err(WireError::BufferTooSmall {
            needed: fixed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_FILE;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    if status == STATUS_OK {
        let digest = digest.ok_or(WireError::BufferTooSmall {
            needed: 0,
            actual: 0,
        })?;
        dst[6..6 + DIGEST_LEN].copy_from_slice(digest);
        put_fence(dst, fixed, fence)
    } else {
        put_fence(dst, fixed, &[])
    }
}

/// `(cid, status, digest, fence)`: the digest when the put applied, and
/// the fence it achieved (empty otherwise).
/// A put's answer: `(cid, status, digest, fence)`.
pub type PutFileAck<'a> = (u32, u8, Option<&'a [u8]>, &'a [u8]);

pub fn decode_admin_put_file_ack(src: &[u8]) -> Result<PutFileAck<'_>, WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_FILE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let status = src[5];
    if status == STATUS_OK {
        if src.len() < 6 + DIGEST_LEN {
            return Err(WireError::Truncated);
        }
        Ok((
            cid,
            status,
            Some(&src[6..6 + DIGEST_LEN]),
            get_fence(src, 6 + DIGEST_LEN)?,
        ))
    } else {
        Ok((cid, status, None, get_fence(src, 6)?))
    }
}

// ── AdminGetFile / AdminDeleteFile (composed path ops) ────────────
//
// GetFile: 2-stage — namespace LOOKUP resolves the path to its
// bound object id (the content digest), then a body_store GET
// fetches the bytes. A non-empty `expect` pins the read to that
// object id: a key bound to anything else answers STATUS_CONFLICT,
// so a reader that learned the binding first never gets bytes of a
// version it did not ask for.
//
//   Request:  [op=0x44][cid:u32][ns_len:u16][path_len:u16][expect_len:u8]
//             [ns][path][expect]
//   Response: [op=0x44][cid:u32][status=OK][len:u32][bytes:len]
//          or [op=0x44][cid:u32][status:u8]
//
// DeleteFile: namespace LOOKUP, then UNBIND at the next revision on
// condition the key has not moved. The body blob stays
// (content-addressed, possibly shared by other paths); orphan
// collection is a sweep concern. `mode` is WRITE_ANY or WRITE_IF.
//
//   Request:  [op=0x45][cid:u32][ns_len:u16][path_len:u16][mode:u8]
//             [expect_len:u8][ns][path][expect]
//   Response: [op=0x45][cid:u32][status:u8]

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdminPathReq<'a> {
    pub correlation_id: u32,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
}

fn encode_path_req(
    dst: &mut [u8],
    op: u8,
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
) -> Result<usize, WireError> {
    check_key(namespace_root, path, &[])?;
    let header = 1 + 4 + 2 + 2;
    let needed = header + namespace_root.len() + path.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = op;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..7].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[7..9].copy_from_slice(&(path.len() as u16).to_le_bytes());
    let mut cursor = header;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + path.len()].copy_from_slice(path);
    Ok(needed)
}

fn decode_path_req(src: &[u8], op: u8) -> Result<DecodedAdminPathReq<'_>, WireError> {
    let header = 9;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != op {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let ns_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let path_len = u16::from_le_bytes([src[7], src[8]]) as usize;
    if src.len() < header + ns_len + path_len {
        return Err(WireError::Truncated);
    }
    Ok(DecodedAdminPathReq {
        correlation_id: cid,
        namespace_root: &src[header..header + ns_len],
        path: &src[header + ns_len..header + ns_len + path_len],
    })
}

pub fn encode_admin_get_file(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
    expect: &[u8],
) -> Result<usize, WireError> {
    encode_pinned_req(
        dst,
        OP_GET_FILE,
        correlation_id,
        namespace_root,
        path,
        expect,
    )
}

pub fn decode_admin_get_file(src: &[u8]) -> Result<DecodedPinnedReq<'_>, WireError> {
    decode_pinned_req(src, OP_GET_FILE)
}

/// A path request that may be pinned to an expected object id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPinnedReq<'a> {
    pub correlation_id: u32,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    /// Empty: unpinned.
    pub expect: &'a [u8],
}

fn encode_pinned_req(
    dst: &mut [u8],
    op: u8,
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
    expect: &[u8],
) -> Result<usize, WireError> {
    check_key(namespace_root, path, expect)?;
    let header = 1 + 4 + 2 + 2 + 1;
    let needed = header + namespace_root.len() + path.len() + expect.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = op;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..7].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[7..9].copy_from_slice(&(path.len() as u16).to_le_bytes());
    dst[9] = expect.len() as u8;
    let mut at = header;
    for part in [namespace_root, path, expect] {
        dst[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Ok(needed)
}

fn decode_pinned_req(src: &[u8], op: u8) -> Result<DecodedPinnedReq<'_>, WireError> {
    let header = 10;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != op {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let ns_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let path_len = u16::from_le_bytes([src[7], src[8]]) as usize;
    let expect_len = src[9] as usize;
    if src.len() < header + ns_len + path_len + expect_len {
        return Err(WireError::Truncated);
    }
    let ns = &src[header..header + ns_len];
    let path = &src[header + ns_len..header + ns_len + path_len];
    let expect = &src[header + ns_len + path_len..header + ns_len + path_len + expect_len];
    check_key(ns, path, expect)?;
    Ok(DecodedPinnedReq {
        correlation_id: cid,
        namespace_root: ns,
        path,
        expect,
    })
}

pub fn encode_admin_get_file_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    body: Option<&[u8]>,
) -> Result<usize, WireError> {
    match body {
        Some(bytes) => {
            let needed = 1 + 4 + 1 + 4 + bytes.len();
            if dst.len() < needed {
                return Err(WireError::BufferTooSmall {
                    needed,
                    actual: dst.len(),
                });
            }
            dst[0] = OP_GET_FILE;
            dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
            dst[5] = STATUS_OK;
            dst[6..10].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
            dst[10..needed].copy_from_slice(bytes);
            Ok(needed)
        }
        None => {
            let needed = 1 + 4 + 1;
            if dst.len() < needed {
                return Err(WireError::BufferTooSmall {
                    needed,
                    actual: dst.len(),
                });
            }
            dst[0] = OP_GET_FILE;
            dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
            dst[5] = status;
            Ok(needed)
        }
    }
}

pub fn decode_admin_get_file_ack(src: &[u8]) -> Result<(u32, u8, Option<&[u8]>), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_GET_FILE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let status = src[5];
    if status != STATUS_OK {
        return Ok((cid, status, None));
    }
    if src.len() < 10 {
        return Err(WireError::Truncated);
    }
    let len = u32::from_le_bytes(src[6..10].try_into().unwrap()) as usize;
    if src.len() < 10 + len {
        return Err(WireError::Truncated);
    }
    Ok((cid, status, Some(&src[10..10 + len])))
}

pub fn encode_admin_delete_file(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
    cond: &WriteCond<'_>,
) -> Result<usize, WireError> {
    check_key(namespace_root, path, &[])?;
    check_cond(cond)?;
    if cond.mode == WRITE_ABSENT {
        return Err(WireError::BadOpcode {
            observed: cond.mode,
        });
    }
    let header = 1 + 4 + 2 + 2 + 1 + 1;
    let needed = header + namespace_root.len() + path.len() + cond.expect.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_DELETE_FILE;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..7].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[7..9].copy_from_slice(&(path.len() as u16).to_le_bytes());
    dst[9] = cond.mode;
    dst[10] = cond.expect.len() as u8;
    let mut at = header;
    for part in [namespace_root, path, cond.expect] {
        dst[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdminDeleteFile<'a> {
    pub correlation_id: u32,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub cond: WriteCond<'a>,
}

pub fn decode_admin_delete_file(src: &[u8]) -> Result<DecodedAdminDeleteFile<'_>, WireError> {
    let header = 11;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_DELETE_FILE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let ns_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let path_len = u16::from_le_bytes([src[7], src[8]]) as usize;
    let mode = src[9];
    let expect_len = src[10] as usize;
    if src.len() < header + ns_len + path_len + expect_len {
        return Err(WireError::Truncated);
    }
    let ns = &src[header..header + ns_len];
    let path = &src[header + ns_len..header + ns_len + path_len];
    let expect = &src[header + ns_len + path_len..header + ns_len + path_len + expect_len];
    check_key(ns, path, &[])?;
    let cond = WriteCond { mode, expect };
    check_cond(&cond)?;
    if mode == WRITE_ABSENT {
        return Err(WireError::BadOpcode { observed: mode });
    }
    Ok(DecodedAdminDeleteFile {
        correlation_id: cid,
        namespace_root: ns,
        path,
        cond,
    })
}

/// `[op][cid][status][fence_len][fence]`.
pub fn encode_admin_delete_file_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    fence: &[u8],
) -> Result<usize, WireError> {
    if dst.len() < 6 {
        return Err(WireError::BufferTooSmall {
            needed: 6,
            actual: dst.len(),
        });
    }
    dst[0] = OP_DELETE_FILE;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    put_fence(dst, 6, fence)
}

/// `(cid, status, fence)`.
pub fn decode_admin_delete_file_ack(src: &[u8]) -> Result<(u32, u8, &[u8]), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_DELETE_FILE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((
        u32::from_le_bytes(src[1..5].try_into().unwrap()),
        src[5],
        get_fence(src, 6)?,
    ))
}

// ── AdminListFiles ────────────────────────────────────────────────
//
// One page of a root's bindings under a prefix, in name order after a
// cursor, with what each binding records.
//
//   Request: [op=0x46][cid:u32][root_len:u16][prefix_len:u16][after_len:u16]
//            [max:u8][root][prefix][after]
//   Ack:     [op=0x46][cid:u32][status:u8], then on STATUS_OK
//            [count:u8][more:u8] and per entry [path_len:u16][path][binding]
//
// `binding` is the shape the lookup ack carries (`AdminBinding`). The
// next page asks with `after` = the last path; `more` 0 ends the
// listing.

pub fn encode_admin_list_files(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    prefix: &[u8],
    after: &[u8],
    max: u8,
) -> Result<usize, WireError> {
    check_key(namespace_root, prefix, &[])?;
    check_key(namespace_root, after, &[])?;
    let header = 12;
    let needed = header + namespace_root.len() + prefix.len() + after.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LIST_FILES;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..7].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[7..9].copy_from_slice(&(prefix.len() as u16).to_le_bytes());
    dst[9..11].copy_from_slice(&(after.len() as u16).to_le_bytes());
    dst[11] = max;
    let mut at = header;
    for part in [namespace_root, prefix, after] {
        dst[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdminListFiles<'a> {
    pub correlation_id: u32,
    pub namespace_root: &'a [u8],
    pub prefix: &'a [u8],
    pub after: &'a [u8],
    pub max: u8,
}

pub fn decode_admin_list_files(src: &[u8]) -> Result<DecodedAdminListFiles<'_>, WireError> {
    let header = 12;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LIST_FILES {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let root_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let prefix_len = u16::from_le_bytes([src[7], src[8]]) as usize;
    let after_len = u16::from_le_bytes([src[9], src[10]]) as usize;
    if src.len() < header + root_len + prefix_len + after_len {
        return Err(WireError::Truncated);
    }
    let root = &src[header..header + root_len];
    let prefix = &src[header + root_len..header + root_len + prefix_len];
    let after = &src[header + root_len + prefix_len..header + root_len + prefix_len + after_len];
    check_key(root, prefix, &[])?;
    check_key(root, after, &[])?;
    Ok(DecodedAdminListFiles {
        correlation_id: u32::from_le_bytes(src[1..5].try_into().unwrap()),
        namespace_root: root,
        prefix,
        after,
        max: src[11],
    })
}

/// Writes one listing ack, entry by entry.
pub struct ListFilesWriter<'a> {
    out: &'a mut [u8],
    at: usize,
    count: u8,
}

impl<'a> ListFilesWriter<'a> {
    /// A writer for a STATUS_OK page; `None` when `out` is too small for
    /// its header.
    pub fn new(out: &'a mut [u8], correlation_id: u32) -> Option<Self> {
        if out.len() < 8 {
            return None;
        }
        out[0] = OP_LIST_FILES;
        out[1..5].copy_from_slice(&correlation_id.to_le_bytes());
        out[5] = STATUS_OK;
        Some(ListFilesWriter {
            out,
            at: 8,
            count: 0,
        })
    }

    /// Append one entry; false when it does not fit.
    pub fn push(&mut self, path: &[u8], b: &AdminBinding<'_>) -> bool {
        let need = 2 + path.len() + binding_tail_len(b);
        if self.at + need > self.out.len() || self.count == u8::MAX {
            return false;
        }
        let at = self.at;
        self.out[at..at + 2].copy_from_slice(&(path.len() as u16).to_le_bytes());
        self.out[at + 2..at + 2 + path.len()].copy_from_slice(path);
        put_binding_tail(&mut self.out[at + 2 + path.len()..], b);
        self.at += need;
        self.count += 1;
        true
    }

    /// Close the page; its length.
    pub fn finish(self, more: bool) -> usize {
        self.out[6] = self.count;
        self.out[7] = u8::from(more);
        self.at
    }
}

/// A refused listing's ack.
pub fn encode_admin_list_files_status(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
) -> Result<usize, WireError> {
    if dst.len() < 6 {
        return Err(WireError::BufferTooSmall {
            needed: 6,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LIST_FILES;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    Ok(6)
}

/// Decode a listing ack, calling `emit` per entry in order. Returns
/// `(cid, status, more)`.
pub fn decode_admin_list_files_ack(
    src: &[u8],
    mut emit: impl FnMut(&[u8], &AdminBinding<'_>),
) -> Result<(u32, u8, bool), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LIST_FILES {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let status = src[5];
    if status != STATUS_OK {
        return Ok((cid, status, false));
    }
    if src.len() < 8 {
        return Err(WireError::Truncated);
    }
    let count = src[6] as usize;
    let mut at = 8usize;
    for _ in 0..count {
        let plen = u16::from_le_bytes(
            src.get(at..at + 2)
                .ok_or(WireError::Truncated)?
                .try_into()
                .unwrap(),
        ) as usize;
        at += 2;
        let path = src.get(at..at + plen).ok_or(WireError::Truncated)?;
        at += plen;
        let (b, n) = take_binding_tail(src.get(at..).ok_or(WireError::Truncated)?)
            .ok_or(WireError::Truncated)?;
        at += n;
        emit(path, &b);
    }
    Ok((cid, status, src[7] != 0))
}

// ── Streamed AdminPutFile (large bodies) ──────────────────────────
//
// The single-frame AdminPutFile carries the whole body; past the
// body-wire chunk cap the writer streams:
//
//   PutFileOpen    [op=0x47][cid][ns_len:u16][path_len:u16][kind:u8]
//                  [mode:u8][expect_len:u8][ctype_len:u8]
//                  [digest:32][total_len:u64][ns][path][expect][ctype]
//   PutFileOpenAck [op=0x47][cid][status][pfid:u8]
//   PutFileChunk   [op=0x48][cid][pfid:u8][len:u32][bytes]
//   PutFileChunkAck[op=0x48][cid][status]
//   PutFileCommit  [op=0x49][cid][pfid:u8]
//     → replies with a standard AdminPutFileAck (op 0x43): the
//       commit chains into the same object + bind stages a
//       single-frame PutFile runs.
//
// The digest is declared at OPEN (the caller has the whole object
// spooled) — the body plane verifies it at its own commit, so a
// corrupted stream publishes nothing and never reaches the bind.
//
//   ReadFileRange  [op=0x4A][cid][off:u64][len:u32]
//                  [ns_len:u16][path_len:u16][expect_len:u8]
//                  [ns][path][expect]       (expect pins, as GetFile)
//   ReadFileRangeAck [op=0x4A][cid][status][len:u32][bytes]
//   StatFile       [op=0x4B][cid][ns_len:u16][path_len:u16][ns][path]
//   StatFileAck    [op=0x4B][cid][status][size:u64]

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPutFileOpen<'a> {
    pub correlation_id: u32,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub kind: u8,
    pub cond: WriteCond<'a>,
    pub content_type: &'a [u8],
    pub digest: &'a [u8],
    pub total_len: u64,
}

#[allow(
    clippy::too_many_arguments,
    reason = "bounded no_std step functions pass explicit scalar params"
)]
pub fn encode_put_file_open(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
    kind: u8,
    cond: &WriteCond<'_>,
    content_type: &[u8],
    digest: &[u8; DIGEST_LEN],
    total_len: u64,
) -> Result<usize, WireError> {
    check_key(namespace_root, path, &[])?;
    check_cond(cond)?;
    if content_type.len() > CONTENT_TYPE_MAX {
        return Err(WireError::StringTooLong {
            len: content_type.len(),
            max: CONTENT_TYPE_MAX,
        });
    }
    let needed = PUT_FILE_OPEN_HDR
        + namespace_root.len()
        + path.len()
        + cond.expect.len()
        + content_type.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_FILE_OPEN;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..7].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[7..9].copy_from_slice(&(path.len() as u16).to_le_bytes());
    dst[9] = kind;
    dst[10] = cond.mode;
    dst[11] = cond.expect.len() as u8;
    dst[12] = content_type.len() as u8;
    dst[13..13 + DIGEST_LEN].copy_from_slice(digest);
    dst[13 + DIGEST_LEN..PUT_FILE_OPEN_HDR].copy_from_slice(&total_len.to_le_bytes());
    let mut at = PUT_FILE_OPEN_HDR;
    for part in [namespace_root, path, cond.expect, content_type] {
        dst[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Ok(needed)
}

const PUT_FILE_OPEN_HDR: usize = 1 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + DIGEST_LEN + 8;

pub fn decode_put_file_open(src: &[u8]) -> Result<DecodedPutFileOpen<'_>, WireError> {
    if src.len() < PUT_FILE_OPEN_HDR {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_FILE_OPEN {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let path_len = u16::from_le_bytes([src[7], src[8]]) as usize;
    let expect_len = src[11] as usize;
    let ct_len = src[12] as usize;
    if src.len() < PUT_FILE_OPEN_HDR + ns_len + path_len + expect_len + ct_len {
        return Err(WireError::Truncated);
    }
    let mut at = PUT_FILE_OPEN_HDR;
    let mut take = |n: usize| {
        let p = &src[at..at + n];
        at += n;
        p
    };
    let ns = take(ns_len);
    let path = take(path_len);
    let expect = take(expect_len);
    let content_type = take(ct_len);
    check_key(ns, path, &[])?;
    let cond = WriteCond {
        mode: src[10],
        expect,
    };
    check_cond(&cond)?;
    if content_type.len() > CONTENT_TYPE_MAX {
        return Err(WireError::StringTooLong {
            len: content_type.len(),
            max: CONTENT_TYPE_MAX,
        });
    }
    Ok(DecodedPutFileOpen {
        correlation_id: u32::from_le_bytes(src[1..5].try_into().unwrap()),
        namespace_root: ns,
        path,
        kind: src[9],
        cond,
        content_type,
        digest: &src[13..13 + DIGEST_LEN],
        total_len: u64::from_le_bytes(src[13 + DIGEST_LEN..PUT_FILE_OPEN_HDR].try_into().unwrap()),
    })
}

pub fn encode_put_file_open_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    pfid: u8,
) -> Result<usize, WireError> {
    let needed = 1 + 4 + 1 + 1;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_FILE_OPEN;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    dst[6] = pfid;
    Ok(needed)
}

pub fn decode_put_file_open_ack(src: &[u8]) -> Result<(u32, u8, u8), WireError> {
    if src.len() < 7 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_FILE_OPEN {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((
        u32::from_le_bytes(src[1..5].try_into().unwrap()),
        src[5],
        src[6],
    ))
}

pub fn encode_put_file_chunk(
    dst: &mut [u8],
    correlation_id: u32,
    pfid: u8,
    bytes: &[u8],
) -> Result<usize, WireError> {
    let header = 1 + 4 + 1 + 4;
    let needed = header + bytes.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_FILE_CHUNK;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = pfid;
    dst[6..10].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    dst[header..needed].copy_from_slice(bytes);
    Ok(needed)
}

pub fn decode_put_file_chunk(src: &[u8]) -> Result<(u32, u8, &[u8]), WireError> {
    let header = 10;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_FILE_CHUNK {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let len = u32::from_le_bytes(src[6..10].try_into().unwrap()) as usize;
    if src.len() < header + len {
        return Err(WireError::Truncated);
    }
    Ok((
        u32::from_le_bytes(src[1..5].try_into().unwrap()),
        src[5],
        &src[header..header + len],
    ))
}

pub fn encode_put_file_chunk_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
) -> Result<usize, WireError> {
    let needed = 1 + 4 + 1;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_FILE_CHUNK;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    Ok(needed)
}

pub fn decode_put_file_chunk_ack(src: &[u8]) -> Result<(u32, u8), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_FILE_CHUNK {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((u32::from_le_bytes(src[1..5].try_into().unwrap()), src[5]))
}

pub fn encode_put_file_commit(
    dst: &mut [u8],
    correlation_id: u32,
    pfid: u8,
) -> Result<usize, WireError> {
    let needed = 1 + 4 + 1;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_FILE_COMMIT;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = pfid;
    Ok(needed)
}

pub fn decode_put_file_commit(src: &[u8]) -> Result<(u32, u8), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_FILE_COMMIT {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((u32::from_le_bytes(src[1..5].try_into().unwrap()), src[5]))
}

#[allow(
    clippy::too_many_arguments,
    reason = "bounded no_std step functions pass explicit scalar params"
)]
pub fn encode_read_file_range(
    dst: &mut [u8],
    correlation_id: u32,
    off: u64,
    len: u32,
    namespace_root: &[u8],
    path: &[u8],
    expect: &[u8],
) -> Result<usize, WireError> {
    check_key(namespace_root, path, expect)?;
    let header = 1 + 4 + 8 + 4 + 2 + 2 + 1;
    let needed = header + namespace_root.len() + path.len() + expect.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_READ_FILE_RANGE;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..13].copy_from_slice(&off.to_le_bytes());
    dst[13..17].copy_from_slice(&len.to_le_bytes());
    dst[17..19].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[19..21].copy_from_slice(&(path.len() as u16).to_le_bytes());
    dst[21] = expect.len() as u8;
    let mut at = header;
    for part in [namespace_root, path, expect] {
        dst[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedReadFileRange<'a> {
    pub correlation_id: u32,
    pub off: u64,
    pub len: u32,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    /// Empty: unpinned.
    pub expect: &'a [u8],
}

pub fn decode_read_file_range(src: &[u8]) -> Result<DecodedReadFileRange<'_>, WireError> {
    let header = 22;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_READ_FILE_RANGE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[17], src[18]]) as usize;
    let path_len = u16::from_le_bytes([src[19], src[20]]) as usize;
    let expect_len = src[21] as usize;
    if src.len() < header + ns_len + path_len + expect_len {
        return Err(WireError::Truncated);
    }
    let ns = &src[header..header + ns_len];
    let path = &src[header + ns_len..header + ns_len + path_len];
    let expect = &src[header + ns_len + path_len..header + ns_len + path_len + expect_len];
    check_key(ns, path, expect)?;
    Ok(DecodedReadFileRange {
        correlation_id: u32::from_le_bytes(src[1..5].try_into().unwrap()),
        off: u64::from_le_bytes(src[5..13].try_into().unwrap()),
        len: u32::from_le_bytes(src[13..17].try_into().unwrap()),
        namespace_root: ns,
        path,
        expect,
    })
}

pub fn encode_read_file_range_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    bytes: Option<&[u8]>,
) -> Result<usize, WireError> {
    match bytes {
        Some(b) => {
            let needed = 1 + 4 + 1 + 4 + b.len();
            if dst.len() < needed {
                return Err(WireError::BufferTooSmall {
                    needed,
                    actual: dst.len(),
                });
            }
            dst[0] = OP_READ_FILE_RANGE;
            dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
            dst[5] = STATUS_OK;
            dst[6..10].copy_from_slice(&(b.len() as u32).to_le_bytes());
            dst[10..needed].copy_from_slice(b);
            Ok(needed)
        }
        None => {
            let needed = 1 + 4 + 1;
            if dst.len() < needed {
                return Err(WireError::BufferTooSmall {
                    needed,
                    actual: dst.len(),
                });
            }
            dst[0] = OP_READ_FILE_RANGE;
            dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
            dst[5] = status;
            Ok(needed)
        }
    }
}

pub fn decode_read_file_range_ack(src: &[u8]) -> Result<(u32, u8, Option<&[u8]>), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_READ_FILE_RANGE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let status = src[5];
    if status != STATUS_OK {
        return Ok((cid, status, None));
    }
    if src.len() < 10 {
        return Err(WireError::Truncated);
    }
    let len = u32::from_le_bytes(src[6..10].try_into().unwrap()) as usize;
    if src.len() < 10 + len {
        return Err(WireError::Truncated);
    }
    Ok((cid, status, Some(&src[10..10 + len])))
}

pub fn encode_stat_file(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
) -> Result<usize, WireError> {
    encode_path_req(dst, OP_STAT_FILE, correlation_id, namespace_root, path)
}

pub fn decode_stat_file(src: &[u8]) -> Result<DecodedAdminPathReq<'_>, WireError> {
    decode_path_req(src, OP_STAT_FILE)
}

pub fn encode_stat_file_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    size: u64,
) -> Result<usize, WireError> {
    let needed = 1 + 4 + 1 + 8;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_STAT_FILE;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    dst[6..14].copy_from_slice(&size.to_le_bytes());
    Ok(needed)
}

pub fn decode_stat_file_ack(src: &[u8]) -> Result<(u32, u8, u64), WireError> {
    if src.len() < 14 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_STAT_FILE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((
        u32::from_le_bytes(src[1..5].try_into().unwrap()),
        src[5],
        u64::from_le_bytes(src[6..14].try_into().unwrap()),
    ))
}

pub fn peek_opcode(src: &[u8]) -> Option<u8> {
    src.first().copied()
}

/// The length of the request frame at the front of `src`, read from its
/// header alone.
///
/// A stream transport delivers bytes, not frames, so a receiver has to
/// know where each request ends before it can check or forward it.
/// `Truncated` means the header is not all here yet; `BadOpcode` means
/// the byte in front names no request, and nothing after it can be
/// framed.
pub fn request_len(src: &[u8]) -> Result<usize, WireError> {
    let op = match src.first() {
        Some(op) => *op,
        None => return Err(WireError::Truncated),
    };
    let u16_at = |at: usize| -> Result<usize, WireError> {
        if src.len() < at + 2 {
            return Err(WireError::Truncated);
        }
        Ok(u16::from_le_bytes([src[at], src[at + 1]]) as usize)
    };
    let u32_at = |at: usize| -> Result<usize, WireError> {
        if src.len() < at + 4 {
            return Err(WireError::Truncated);
        }
        Ok(u32::from_le_bytes([src[at], src[at + 1], src[at + 2], src[at + 3]]) as usize)
    };
    let u8_at = |at: usize| -> Result<usize, WireError> {
        src.get(at).map(|b| *b as usize).ok_or(WireError::Truncated)
    };
    match op {
        OP_BIND => Ok(BIND_HDR + u16_at(5)? + u16_at(7)? + u16_at(9)? + u8_at(28)?),
        OP_PUT_BODY => Ok(9 + u32_at(5)?),
        OP_GET_BODY => Ok(5 + DIGEST_LEN),
        OP_PUT_FILE => {
            Ok(PUT_FILE_HDR + u16_at(5)? + u16_at(7)? + u8_at(11)? + u8_at(12)? + u32_at(13)?)
        }
        OP_GET_FILE => Ok(10 + u16_at(5)? + u16_at(7)? + u8_at(9)?),
        OP_DELETE_FILE => Ok(11 + u16_at(5)? + u16_at(7)? + u8_at(10)?),
        OP_STAT_FILE | OP_LOOKUP => Ok(9 + u16_at(5)? + u16_at(7)?),
        OP_LIST_FILES => Ok(12 + u16_at(5)? + u16_at(7)? + u16_at(9)?),
        OP_PUT_FILE_OPEN => {
            Ok(PUT_FILE_OPEN_HDR + u16_at(5)? + u16_at(7)? + u8_at(11)? + u8_at(12)?)
        }
        OP_PUT_FILE_CHUNK => Ok(10 + u32_at(6)?),
        OP_PUT_FILE_COMMIT => Ok(6),
        OP_READ_FILE_RANGE => Ok(22 + u16_at(17)? + u16_at(19)? + u8_at(21)?),
        OP_PUT_BODY_KEYED => Ok(1 + 4 + DIGEST_LEN + 4 + u32_at(37)?),
        OP_DELETE_BODY => Ok(1 + 4 + DIGEST_LEN),
        OP_LEASE => Ok(LEASE_REQ_HDR + u16_at(6)? + u16_at(8)?),
        OP_VOLUME => Ok(VOLUME_REQ_HDR + u16_at(6)? + u16_at(8)? + u16_at(10)?),
        observed => Err(WireError::BadOpcode { observed }),
    }
}

/// The length of the answer frame at the front of `src`, read from its
/// header alone — the client's counterpart of [`request_len`].
/// `Truncated` until enough of it has arrived to say; `BadOpcode` for a
/// byte that names no answer.
pub fn response_len(src: &[u8]) -> Result<usize, WireError> {
    let op = *src.first().ok_or(WireError::Truncated)?;
    let status = || src.get(5).copied().ok_or(WireError::Truncated);
    let u32_at = |at: usize| -> Result<usize, WireError> {
        let b = src.get(at..at + 4).ok_or(WireError::Truncated)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    match op {
        OP_BIND | OP_DELETE_FILE => fenced_len(src, 6),
        OP_PUT_FILE_CHUNK | OP_PUT_BODY_KEYED => Ok(6),
        OP_DELETE_BODY => Ok(7),
        OP_PUT_FILE_OPEN => Ok(7),
        OP_STAT_FILE => Ok(14),
        OP_LEASE => Ok(LEASE_ACK_LEN),
        OP_VOLUME => Ok(14),
        OP_PUT_BODY => Ok(if status()? == STATUS_OK {
            6 + DIGEST_LEN
        } else {
            6
        }),
        OP_PUT_FILE => fenced_len(
            src,
            if status()? == STATUS_OK {
                6 + DIGEST_LEN
            } else {
                6
            },
        ),
        OP_GET_BODY | OP_GET_FILE | OP_READ_FILE_RANGE => Ok(if status()? == STATUS_OK {
            10 + u32_at(6)?
        } else {
            6
        }),
        OP_LOOKUP => Ok(if status()? == STATUS_OK {
            6 + binding_tail_record_len(&src[6..])?
        } else {
            6
        }),
        OP_LIST_FILES => {
            if status()? != STATUS_OK {
                return Ok(6);
            }
            let count = *src.get(6).ok_or(WireError::Truncated)? as usize;
            let mut at = 8;
            for _ in 0..count {
                let b = src.get(at..at + 2).ok_or(WireError::Truncated)?;
                at += 2 + u16::from_le_bytes([b[0], b[1]]) as usize;
                at += binding_tail_record_len(src.get(at..).ok_or(WireError::Truncated)?)?;
            }
            Ok(at)
        }
        observed => Err(WireError::BadOpcode { observed }),
    }
}

/// Answer request `frame` with `status` in that op's own ack shape, so a
/// client decodes a refusal with the decoder it was already waiting on.
/// Returns the length written to `out` (at least 32 bytes).
pub fn refusal(frame: &[u8], status: u8, out: &mut [u8]) -> usize {
    let op = frame.first().copied().unwrap_or(0);
    let cid = if frame.len() >= 5 {
        u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]])
    } else {
        0
    };
    let n = match op {
        OP_BIND => encode_admin_bind_ack(out, cid, status, &[]),
        OP_PUT_BODY => encode_admin_put_body_ack(out, cid, status, None),
        OP_GET_BODY => encode_admin_get_body_ack(out, cid, status, None),
        // A streamed write's commit is answered as a whole-file put.
        OP_PUT_FILE | OP_PUT_FILE_COMMIT => encode_admin_put_file_ack(out, cid, status, None, &[]),
        OP_GET_FILE => encode_admin_get_file_ack(out, cid, status, None),
        OP_DELETE_FILE => encode_admin_delete_file_ack(out, cid, status, &[]),
        OP_LIST_FILES => encode_admin_list_files_status(out, cid, status),
        OP_PUT_FILE_OPEN => encode_put_file_open_ack(out, cid, status, 0),
        OP_PUT_FILE_CHUNK => encode_put_file_chunk_ack(out, cid, status),
        OP_READ_FILE_RANGE => encode_read_file_range_ack(out, cid, status, None),
        OP_STAT_FILE => encode_stat_file_ack(out, cid, status, 0),
        OP_PUT_BODY_KEYED => encode_admin_put_body_keyed_ack(out, cid, status),
        OP_DELETE_BODY => encode_admin_delete_body_ack(out, cid, status, false),
        OP_LEASE => encode_admin_lease_ack(out, cid, status, 0, 0),
        OP_VOLUME => encode_admin_volume_ack(out, cid, status, 0),
        OP_LOOKUP => encode_admin_lookup_ack(out, cid, status, None),
        _ => {
            // No ack shape to borrow: the common envelope.
            if out.len() < 6 {
                return 0;
            }
            out[0] = op;
            out[1..5].copy_from_slice(&cid.to_le_bytes());
            out[5] = status;
            Ok(6)
        }
    };
    n.unwrap_or(0)
}

/// What a request touches, for deciding whether a grant covers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope<'a> {
    /// A key under a namespace root: the grant's scope must be a prefix
    /// of `root/path`. A listing names its prefix as the path, so it is
    /// admitted only by a scope that covers every key the prefix can
    /// reach.
    Key { root: &'a [u8], path: &'a [u8] },
    /// The content-addressed body plane, which names no key: a body is
    /// reachable only by a digest a caller learned from a key it could
    /// read, and an unbound body is collected. Granted on
    /// [`BODY_PLANE_OBJECT`].
    Bodies,
    /// A write stream: decided by which session opened it.
    Stream(u8),
}

/// Which permission an operation needs on its scope, in mesh terms:
/// reads need `ReadState`, writes and leases `SendCommand`, and the raw
/// keyed body plane — which overwrites and deletes by key across every
/// root — `Admin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    Read,
    Write,
    Admin,
}

/// The object a capability over the content-addressed body plane names:
/// the first 16 bytes of SHA-256 of `"loam.body-plane\0"`. An operator
/// mints one with `fluxor modules cap mint --object <this, in hex>`.
pub const BODY_PLANE_DOMAIN: &[u8] = b"loam.body-plane\0";

/// What request `frame` touches and needs, or `None` for a frame that is
/// not a well-formed request.
pub fn request_scope(frame: &[u8]) -> Option<(Scope<'_>, Need)> {
    let op = *frame.first()?;
    Some(match op {
        OP_GET_FILE => {
            let r = decode_admin_get_file(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.path,
                },
                Need::Read,
            )
        }
        OP_STAT_FILE => {
            let r = decode_stat_file(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.path,
                },
                Need::Read,
            )
        }
        OP_LOOKUP => {
            let r = decode_admin_lookup(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.path,
                },
                Need::Read,
            )
        }
        OP_READ_FILE_RANGE => {
            let r = decode_read_file_range(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.path,
                },
                Need::Read,
            )
        }
        OP_LIST_FILES => {
            let r = decode_admin_list_files(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.prefix,
                },
                Need::Read,
            )
        }
        OP_BIND => {
            let r = decode_admin_bind(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.path,
                },
                Need::Write,
            )
        }
        OP_PUT_FILE => {
            let r = decode_admin_put_file(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.path,
                },
                Need::Write,
            )
        }
        OP_DELETE_FILE => {
            let r = decode_admin_delete_file(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.path,
                },
                Need::Write,
            )
        }
        OP_PUT_FILE_OPEN => {
            let r = decode_put_file_open(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.path,
                },
                Need::Write,
            )
        }
        OP_VOLUME => {
            let r = decode_admin_volume(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.path,
                },
                Need::Write,
            )
        }
        OP_LEASE => {
            let r = decode_admin_lease(frame).ok()?;
            (
                Scope::Key {
                    root: r.namespace_root,
                    path: r.path,
                },
                Need::Write,
            )
        }
        OP_PUT_FILE_CHUNK => (
            Scope::Stream(decode_put_file_chunk(frame).ok()?.1),
            Need::Write,
        ),
        OP_PUT_FILE_COMMIT => (
            Scope::Stream(decode_put_file_commit(frame).ok()?.1),
            Need::Write,
        ),
        OP_PUT_BODY => {
            decode_admin_put_body(frame).ok()?;
            (Scope::Bodies, Need::Write)
        }
        OP_GET_BODY => {
            decode_admin_get_body(frame).ok()?;
            (Scope::Bodies, Need::Read)
        }
        OP_PUT_BODY_KEYED => {
            decode_admin_put_body_keyed(frame).ok()?;
            (Scope::Bodies, Need::Admin)
        }
        OP_DELETE_BODY => {
            decode_admin_delete_body(frame).ok()?;
            (Scope::Bodies, Need::Admin)
        }
        _ => return None,
    })
}

// ── AdminLease (volume writer lease) ──────────────────────────────
//
//   LeaseReq  [op=0x4F][cid:u32][mode:u8][root_len:u16][path_len:u16]
//             [holder:16][ttl_ms:u32][root][path]
//   LeaseAck  [op=0x4F][cid:u32][status:u8][fence:u64][expires_at_ms:u64]
//
// `mode` is `LEASE_ACQUIRE` / `LEASE_RENEW` / `LEASE_RELEASE`. There is
// deliberately no time field: expiry is judged against the time the
// server stamps on the request, never one a client asserts — a client
// that could name `now` could name a moment at which any lease has
// lapsed.
//
// Status: `STATUS_OK` (granted; fence and expiry are the caller's),
// `STATUS_LEASE_HELD` / `STATUS_LEASE_LOST` (fence and expiry describe
// the lease that stands, zero when none does), `STATUS_BUSY` (the
// lease table is full, or the request was stamped no later than one
// already applied — retry), `STATUS_NAK` (malformed, a TTL out of
// range, or a server with no wall clock to judge expiry by).

/// Lease modes and holder width: the namespace wire's values, restated
/// because this wire is compiled without it. A test pins the two.
pub const LEASE_ACQUIRE: u8 = 1;
pub const LEASE_RENEW: u8 = 2;
pub const LEASE_RELEASE: u8 = 3;
pub const LEASE_HOLDER_LEN: usize = 16;
/// Where the holder sits in a `LeaseReq`.
pub const LEASE_HOLDER_AT: usize = 1 + 4 + 1 + 2 + 2;
const LEASE_REQ_HDR: usize = LEASE_HOLDER_AT + LEASE_HOLDER_LEN + 4;
const LEASE_ACK_LEN: usize = 1 + 4 + 1 + 8 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdminLease<'a> {
    pub correlation_id: u32,
    pub mode: u8,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub holder: [u8; LEASE_HOLDER_LEN],
    pub ttl_ms: u32,
}

pub fn encode_admin_lease(
    dst: &mut [u8],
    correlation_id: u32,
    mode: u8,
    namespace_root: &[u8],
    path: &[u8],
    holder: &[u8; LEASE_HOLDER_LEN],
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
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = mode;
    dst[6..8].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[8..10].copy_from_slice(&(path.len() as u16).to_le_bytes());
    dst[LEASE_HOLDER_AT..LEASE_HOLDER_AT + LEASE_HOLDER_LEN].copy_from_slice(holder);
    dst[LEASE_HOLDER_AT + LEASE_HOLDER_LEN..LEASE_REQ_HDR].copy_from_slice(&ttl_ms.to_le_bytes());
    let mut cursor = LEASE_REQ_HDR;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + path.len()].copy_from_slice(path);
    Ok(needed)
}

pub fn decode_admin_lease(src: &[u8]) -> Result<DecodedAdminLease<'_>, WireError> {
    if src.len() < LEASE_REQ_HDR {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LEASE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[6], src[7]]) as usize;
    let path_len = u16::from_le_bytes([src[8], src[9]]) as usize;
    let total = LEASE_REQ_HDR + ns_len + path_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let ns = &src[LEASE_REQ_HDR..LEASE_REQ_HDR + ns_len];
    let path = &src[LEASE_REQ_HDR + ns_len..total];
    check_key(ns, path, &[])?;
    let mut holder = [0u8; LEASE_HOLDER_LEN];
    holder.copy_from_slice(&src[LEASE_HOLDER_AT..LEASE_HOLDER_AT + LEASE_HOLDER_LEN]);
    let ttl_at = LEASE_HOLDER_AT + LEASE_HOLDER_LEN;
    Ok(DecodedAdminLease {
        correlation_id: u32::from_le_bytes(src[1..5].try_into().unwrap()),
        mode: src[5],
        namespace_root: ns,
        path,
        holder,
        ttl_ms: u32::from_le_bytes(src[ttl_at..LEASE_REQ_HDR].try_into().unwrap()),
    })
}

pub fn encode_admin_lease_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    fence: u64,
    expires_at_ms: u64,
) -> Result<usize, WireError> {
    if dst.len() < LEASE_ACK_LEN {
        return Err(WireError::BufferTooSmall {
            needed: LEASE_ACK_LEN,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LEASE;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    dst[6..14].copy_from_slice(&fence.to_le_bytes());
    dst[14..22].copy_from_slice(&expires_at_ms.to_le_bytes());
    Ok(LEASE_ACK_LEN)
}

/// Returns `(cid, status, fence, expires_at_ms)`.
pub fn decode_admin_lease_ack(src: &[u8]) -> Result<(u32, u8, u64, u64), WireError> {
    if src.len() < LEASE_ACK_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LEASE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((
        u32::from_le_bytes(src[1..5].try_into().unwrap()),
        src[5],
        u64::from_le_bytes(src[6..14].try_into().unwrap()),
        u64::from_le_bytes(src[14..22].try_into().unwrap()),
    ))
}

// ── AdminPutBodyKeyed / AdminDeleteBody (raw keyed body plane) ────
//
// The raw body plane by key: a keyed blob (an EC shard, whose key is
// derived from its body's digest and shard index) is stored under the
// key it names rather than its content hash, and never bound in the
// namespace. PutBodyKeyed stores (a re-put overwrites); DeleteBody
// removes a blob by key or digest.
//
//   PutBodyKeyedReq  [op=0x4C][cid:u32][key:32][len:u32][bytes]
//   PutBodyKeyedAck  [op=0x4C][cid:u32][status:u8]
//   DeleteBodyReq    [op=0x4D][cid:u32][key:32]
//   DeleteBodyAck    [op=0x4D][cid:u32][status:u8][existed:u8]

pub fn encode_admin_put_body_keyed(
    dst: &mut [u8],
    correlation_id: u32,
    key: &[u8; DIGEST_LEN],
    body: &[u8],
) -> Result<usize, WireError> {
    let header = 1 + 4 + DIGEST_LEN + 4;
    let needed = header + body.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_BODY_KEYED;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..5 + DIGEST_LEN].copy_from_slice(key);
    dst[37..41].copy_from_slice(&(body.len() as u32).to_le_bytes());
    dst[header..needed].copy_from_slice(body);
    Ok(needed)
}

pub fn decode_admin_put_body_keyed(src: &[u8]) -> Result<(u32, &[u8], &[u8]), WireError> {
    let header = 1 + 4 + DIGEST_LEN + 4;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_BODY_KEYED {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let len = u32::from_le_bytes(src[37..41].try_into().unwrap()) as usize;
    if src.len() < header + len {
        return Err(WireError::Truncated);
    }
    Ok((cid, &src[5..5 + DIGEST_LEN], &src[header..header + len]))
}

pub fn encode_admin_put_body_keyed_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
) -> Result<usize, WireError> {
    if dst.len() < 6 {
        return Err(WireError::BufferTooSmall {
            needed: 6,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_BODY_KEYED;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    Ok(6)
}

pub fn decode_admin_put_body_keyed_ack(src: &[u8]) -> Result<(u32, u8), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_BODY_KEYED {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((u32::from_le_bytes(src[1..5].try_into().unwrap()), src[5]))
}

pub fn encode_admin_delete_body(
    dst: &mut [u8],
    correlation_id: u32,
    key: &[u8; DIGEST_LEN],
) -> Result<usize, WireError> {
    let needed = 1 + 4 + DIGEST_LEN;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_DELETE_BODY;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..5 + DIGEST_LEN].copy_from_slice(key);
    Ok(needed)
}

pub fn decode_admin_delete_body(src: &[u8]) -> Result<(u32, &[u8]), WireError> {
    let needed = 1 + 4 + DIGEST_LEN;
    if src.len() < needed {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_DELETE_BODY {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((
        u32::from_le_bytes(src[1..5].try_into().unwrap()),
        &src[5..5 + DIGEST_LEN],
    ))
}

pub fn encode_admin_delete_body_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    existed: bool,
) -> Result<usize, WireError> {
    if dst.len() < 7 {
        return Err(WireError::BufferTooSmall {
            needed: 7,
            actual: dst.len(),
        });
    }
    dst[0] = OP_DELETE_BODY;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    dst[6] = if existed { 1 } else { 0 };
    Ok(7)
}

pub fn decode_admin_delete_body_ack(src: &[u8]) -> Result<(u32, u8, bool), WireError> {
    if src.len() < 7 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_DELETE_BODY {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((
        u32::from_le_bytes(src[1..5].try_into().unwrap()),
        src[5],
        src[6] != 0,
    ))
}

// ── AdminVolume (volume flush: begin / commit / abort / delete) ───
//
//   VolumeReq  [op=0x50][cid:u32][mode:u8][root_len:u16][path_len:u16]
//              [oid_len:u16][holder:16][fence:u64][expected:u64]
//              [root][path][oid]
//   VolumeAck  [op=0x50][cid:u32][status:u8][revision:u64]
//
// `mode` is `VOLUME_BEGIN` / `VOLUME_COMMIT` / `VOLUME_ABORT` /
// `VOLUME_DELETE` (unbind the path, fenced and CAS'd like a commit). A COMMIT
// binds the path to `oid` (the map root's `sha256:` id) at
// `expected + 1`, only when the current revision is `expected` (0:
// unbound) and the caller holds the volume's live lease under `fence`
// with a flush open. As with leases there is no time field: the server
// stamps it.
//
// Status: `STATUS_OK` (revision is the new one on a commit, the current
// one otherwise), `STATUS_CONFLICT` (another commit landed first;
// revision is the current one), `STATUS_LEASE_LOST`, `STATUS_BUSY`
// (a GC sweep holds a reservation — retry the BEGIN), `STATUS_NAK`.

/// Volume modes: the namespace wire's values, restated because this
/// wire is compiled without it. A test pins the two.
pub const VOLUME_BEGIN: u8 = 1;
pub const VOLUME_COMMIT: u8 = 2;
pub const VOLUME_ABORT: u8 = 3;
pub const VOLUME_DELETE: u8 = 4;
/// Where the holder sits in a `VolumeReq`.
pub const VOLUME_HOLDER_AT: usize = 1 + 4 + 1 + 2 + 2 + 2;
const VOLUME_REQ_HDR: usize = VOLUME_HOLDER_AT + LEASE_HOLDER_LEN + 8 + 8;

/// The holder bytes of a lease or volume request, for a host that has
/// to rewrite them without decoding the rest. `None` for any other op,
/// or a frame too short to carry one.
pub fn request_holder_mut(frame: &mut [u8]) -> Option<&mut [u8; LEASE_HOLDER_LEN]> {
    let at = match frame.first() {
        Some(&OP_LEASE) => LEASE_HOLDER_AT,
        Some(&OP_VOLUME) => VOLUME_HOLDER_AT,
        _ => return None,
    };
    frame
        .get_mut(at..at + LEASE_HOLDER_LEN)
        .and_then(|h| h.try_into().ok())
}
const VOLUME_ACK_LEN: usize = 1 + 4 + 1 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdminVolume<'a> {
    pub correlation_id: u32,
    pub mode: u8,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub object_id: &'a [u8],
    pub holder: [u8; LEASE_HOLDER_LEN],
    pub fence: u64,
    pub expected: u64,
}

pub fn encode_admin_volume(dst: &mut [u8], r: &DecodedAdminVolume<'_>) -> Result<usize, WireError> {
    check_key(r.namespace_root, r.path, r.object_id)?;
    let needed = VOLUME_REQ_HDR + r.namespace_root.len() + r.path.len() + r.object_id.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_VOLUME;
    dst[1..5].copy_from_slice(&r.correlation_id.to_le_bytes());
    dst[5] = r.mode;
    dst[6..8].copy_from_slice(&(r.namespace_root.len() as u16).to_le_bytes());
    dst[8..10].copy_from_slice(&(r.path.len() as u16).to_le_bytes());
    dst[10..12].copy_from_slice(&(r.object_id.len() as u16).to_le_bytes());
    let h = VOLUME_HOLDER_AT + LEASE_HOLDER_LEN;
    dst[VOLUME_HOLDER_AT..h].copy_from_slice(&r.holder);
    dst[h..h + 8].copy_from_slice(&r.fence.to_le_bytes());
    dst[h + 8..VOLUME_REQ_HDR].copy_from_slice(&r.expected.to_le_bytes());
    let mut cursor = VOLUME_REQ_HDR;
    dst[cursor..cursor + r.namespace_root.len()].copy_from_slice(r.namespace_root);
    cursor += r.namespace_root.len();
    dst[cursor..cursor + r.path.len()].copy_from_slice(r.path);
    cursor += r.path.len();
    dst[cursor..cursor + r.object_id.len()].copy_from_slice(r.object_id);
    Ok(needed)
}

pub fn decode_admin_volume(src: &[u8]) -> Result<DecodedAdminVolume<'_>, WireError> {
    if src.len() < VOLUME_REQ_HDR {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_VOLUME {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[6], src[7]]) as usize;
    let path_len = u16::from_le_bytes([src[8], src[9]]) as usize;
    let oid_len = u16::from_le_bytes([src[10], src[11]]) as usize;
    let total = VOLUME_REQ_HDR + ns_len + path_len + oid_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let ns = &src[VOLUME_REQ_HDR..VOLUME_REQ_HDR + ns_len];
    let path = &src[VOLUME_REQ_HDR + ns_len..VOLUME_REQ_HDR + ns_len + path_len];
    let oid = &src[VOLUME_REQ_HDR + ns_len + path_len..total];
    check_key(ns, path, oid)?;
    let mut holder = [0u8; LEASE_HOLDER_LEN];
    let h = VOLUME_HOLDER_AT + LEASE_HOLDER_LEN;
    holder.copy_from_slice(&src[VOLUME_HOLDER_AT..h]);
    Ok(DecodedAdminVolume {
        correlation_id: u32::from_le_bytes(src[1..5].try_into().unwrap()),
        mode: src[5],
        namespace_root: ns,
        path,
        object_id: oid,
        holder,
        fence: u64::from_le_bytes(src[h..h + 8].try_into().unwrap()),
        expected: u64::from_le_bytes(src[h + 8..VOLUME_REQ_HDR].try_into().unwrap()),
    })
}

pub fn encode_admin_volume_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    revision: u64,
) -> Result<usize, WireError> {
    if dst.len() < VOLUME_ACK_LEN {
        return Err(WireError::BufferTooSmall {
            needed: VOLUME_ACK_LEN,
            actual: dst.len(),
        });
    }
    dst[0] = OP_VOLUME;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    dst[6..14].copy_from_slice(&revision.to_le_bytes());
    Ok(VOLUME_ACK_LEN)
}

/// Returns `(cid, status, revision)`.
pub fn decode_admin_volume_ack(src: &[u8]) -> Result<(u32, u8, u64), WireError> {
    if src.len() < VOLUME_ACK_LEN {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_VOLUME {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((
        u32::from_le_bytes(src[1..5].try_into().unwrap()),
        src[5],
        u64::from_le_bytes(src[6..14].try_into().unwrap()),
    ))
}

// ── AdminLookup (a path's binding, without its body) ──────────────
//
//   LookupReq  [op=0x51][cid:u32][root_len:u16][path_len:u16][root][path]
//   LookupAck  [op=0x51][cid:u32][status:u8]
//              then, on STATUS_OK, the binding (`AdminBinding`)
//
// What a volume opener needs — the root digest and the revision a
// commit must name — and what a snapshot needs to bind an entry under
// the same kind.

pub fn encode_admin_lookup(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
) -> Result<usize, WireError> {
    encode_path_req(dst, OP_LOOKUP, correlation_id, namespace_root, path)
}

pub fn decode_admin_lookup(src: &[u8]) -> Result<DecodedAdminPathReq<'_>, WireError> {
    decode_path_req(src, OP_LOOKUP)
}

/// A binding as the lookup and listing acks carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminBinding<'a> {
    pub revision: u64,
    pub kind: u8,
    pub object_id: &'a [u8],
    /// Wall-clock milliseconds the write was admitted at.
    pub stamp_ms: u64,
    pub size: u64,
    pub content_type: &'a [u8],
}

/// `[revision:u64][kind][oid_len:u8][oid][stamp:u64][size:u64]
/// [ctype_len:u8][ctype]`
fn binding_tail_len(b: &AdminBinding<'_>) -> usize {
    8 + 1 + 1 + b.object_id.len() + 8 + 8 + 1 + b.content_type.len()
}

fn put_binding_tail(dst: &mut [u8], b: &AdminBinding<'_>) -> usize {
    dst[0..8].copy_from_slice(&b.revision.to_le_bytes());
    dst[8] = b.kind;
    dst[9] = b.object_id.len() as u8;
    let mut at = 10;
    dst[at..at + b.object_id.len()].copy_from_slice(b.object_id);
    at += b.object_id.len();
    dst[at..at + 8].copy_from_slice(&b.stamp_ms.to_le_bytes());
    dst[at + 8..at + 16].copy_from_slice(&b.size.to_le_bytes());
    at += 16;
    dst[at] = b.content_type.len() as u8;
    dst[at + 1..at + 1 + b.content_type.len()].copy_from_slice(b.content_type);
    at + 1 + b.content_type.len()
}

fn take_binding_tail(src: &[u8]) -> Option<(AdminBinding<'_>, usize)> {
    let revision = u64::from_le_bytes(src.get(0..8)?.try_into().ok()?);
    let kind = *src.get(8)?;
    let oid_len = *src.get(9)? as usize;
    let mut at = 10;
    let object_id = src.get(at..at + oid_len)?;
    at += oid_len;
    let stamp_ms = u64::from_le_bytes(src.get(at..at + 8)?.try_into().ok()?);
    let size = u64::from_le_bytes(src.get(at + 8..at + 16)?.try_into().ok()?);
    at += 16;
    let ct_len = *src.get(at)? as usize;
    let content_type = src.get(at + 1..at + 1 + ct_len)?;
    Some((
        AdminBinding {
            revision,
            kind,
            object_id,
            stamp_ms,
            size,
            content_type,
        },
        at + 1 + ct_len,
    ))
}

/// The length of a binding tail at the front of `src`, from its length
/// fields alone.
fn binding_tail_record_len(src: &[u8]) -> Result<usize, WireError> {
    let oid_len = *src.get(9).ok_or(WireError::Truncated)? as usize;
    let ct_at = 10 + oid_len + 16;
    let ct_len = *src.get(ct_at).ok_or(WireError::Truncated)? as usize;
    Ok(ct_at + 1 + ct_len)
}

pub fn encode_admin_lookup_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    binding: Option<&AdminBinding<'_>>,
) -> Result<usize, WireError> {
    let tail = match binding {
        Some(b) if status == STATUS_OK => {
            if b.object_id.len() > MAX_OBJECT_ID || b.content_type.len() > CONTENT_TYPE_MAX {
                return Err(WireError::StringTooLong {
                    len: b.object_id.len().max(b.content_type.len()),
                    max: MAX_OBJECT_ID,
                });
            }
            binding_tail_len(b)
        }
        _ => 0,
    };
    let needed = 1 + 4 + 1 + tail;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LOOKUP;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    if let Some(b) = binding {
        if tail != 0 {
            put_binding_tail(&mut dst[6..], b);
        }
    }
    Ok(needed)
}

/// Returns `(cid, status, binding)`; the binding is present exactly
/// when the status is `STATUS_OK`.
pub fn decode_admin_lookup_ack(
    src: &[u8],
) -> Result<(u32, u8, Option<AdminBinding<'_>>), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LOOKUP {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let status = src[5];
    if status != STATUS_OK {
        return Ok((cid, status, None));
    }
    let (b, _) = take_binding_tail(&src[6..]).ok_or(WireError::Truncated)?;
    Ok((cid, status, Some(b)))
}
