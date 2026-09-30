// Wire format for the `admin_router` PIC's request/response
// protocol. Mediates between external admin clients (e.g.
// `tools/loam-cli/` in a future phase) and the in-graph public-
// surface PICs.
//
// Each request carries a `correlation_id` the router pairs with
// the downstream PIC's response, so the caller can fire many
// concurrent requests without per-call state.
//
// Layouts (multi-byte ints LE):
//
//   AdminBind          [op:u8=0x40][cid:u32]
//                      [ns_len:u16][path_len:u16][oid_len:u16]
//                      [kind:u8][revision:u64]
//                      [ns:ns_len][path:path_len][oid:oid_len]
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
/// Authenticate a connection before any other op is accepted.
/// Connection-scoped, not per-request: the admin
/// surface can bind, read and delete anything in any namespace, so
/// the boundary that matters is who is on the far end of the socket,
/// established once.
pub const OP_AUTH: u8 = 0x4E;
/// Acquire, renew or release a volume's writer lease.
pub const OP_LEASE: u8 = 0x4F;
/// Begin, commit or abort a volume flush: the fenced, revisioned bind
/// of a volume's path to its map root.
pub const OP_VOLUME: u8 = 0x50;
/// Resolve a path to its binding — object id, revision and kind —
/// without reading the body.
pub const OP_LOOKUP: u8 = 0x51;

/// Longest accepted auth token. Long enough for a 512-bit secret in
/// hex with room to spare, short enough that an unauthenticated peer
/// cannot make the server hold much.
pub const MAX_TOKEN: usize = 256;

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

/// The caller's identity holds no grant for this operation: the op
/// class on the namespace root it names, or a write stream it did not
/// open.
///
/// Separate from `STATUS_NAK` because the remedy is an operator's, not
/// the caller's: a grant has to change before the same request can
/// succeed, so retrying it is pointless.
pub const STATUS_FORBIDDEN: u8 = 0x08;

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

/// `AdminAuth  [op:u8=0x4E][cid:u32][token_len:u16][token]`
///
/// Answered with the ordinary ack shape: `[op][cid][status]`, where
/// `STATUS_OK` means the connection may proceed and `STATUS_NAK`
/// means it may not — and the server closes it rather than leaving a
/// rejected peer holding an open socket to retry on.
pub fn encode_admin_auth(dst: &mut [u8], cid: u32, token: &[u8]) -> Result<usize, WireError> {
    if token.len() > MAX_TOKEN {
        return Err(WireError::StringTooLong {
            len: token.len(),
            max: MAX_TOKEN,
        });
    }
    let need = 1 + 4 + 2 + token.len();
    if dst.len() < need {
        return Err(WireError::BufferTooSmall {
            needed: need,
            actual: dst.len(),
        });
    }
    dst[0] = OP_AUTH;
    dst[1..5].copy_from_slice(&cid.to_le_bytes());
    dst[5..7].copy_from_slice(&(token.len() as u16).to_le_bytes());
    dst[7..need].copy_from_slice(token);
    Ok(need)
}

/// Decode an auth request. Returns `(cid, token)`.
pub fn decode_admin_auth(src: &[u8]) -> Result<(u32, &[u8]), WireError> {
    if src.len() < 7 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_AUTH {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes([src[1], src[2], src[3], src[4]]);
    let len = u16::from_le_bytes([src[5], src[6]]) as usize;
    if len > MAX_TOKEN {
        return Err(WireError::StringTooLong {
            len,
            max: MAX_TOKEN,
        });
    }
    if src.len() < 7 + len {
        return Err(WireError::Truncated);
    }
    Ok((cid, &src[7..7 + len]))
}

/// The ack for any connection-scoped op: `[op][cid][status]`.
pub fn encode_admin_auth_ack(dst: &mut [u8], cid: u32, status: u8) -> Result<usize, WireError> {
    if dst.len() < 6 {
        return Err(WireError::BufferTooSmall {
            needed: 6,
            actual: dst.len(),
        });
    }
    dst[0] = OP_AUTH;
    dst[1..5].copy_from_slice(&cid.to_le_bytes());
    dst[5] = status;
    Ok(6)
}

pub fn decode_admin_auth_ack(src: &[u8]) -> Result<(u32, u8), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_AUTH {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((u32::from_le_bytes([src[1], src[2], src[3], src[4]]), src[5]))
}

/// Constant-time byte equality.
///
/// A token check with `==` leaks its answer through timing: an
/// attacker who can measure the reply learns how many leading bytes
/// they guessed right, which turns a 256-bit secret into 32
/// independent one-byte searches. The comparison must therefore look
/// at every byte regardless, and combine the results without
/// branching.
pub fn tokens_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadOpcode { observed: u8 },
    BufferTooSmall { needed: usize, actual: usize },
    StringTooLong { len: usize, max: usize },
}

// ── AdminBind ──────────────────────────────────────────────────────

pub fn encode_admin_bind(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
    object_id: &[u8],
    kind: u8,
    revision: u64,
) -> Result<usize, WireError> {
    check_key(namespace_root, path, object_id)?;
    let header = 1 + 4 + 2 + 2 + 2 + 1 + 8;
    let needed = header + namespace_root.len() + path.len() + object_id.len();
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
    let mut cursor = header;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + path.len()].copy_from_slice(path);
    cursor += path.len();
    dst[cursor..cursor + object_id.len()].copy_from_slice(object_id);
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
}

pub fn decode_admin_bind(src: &[u8]) -> Result<DecodedAdminBind<'_>, WireError> {
    if src.len() < 20 {
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
    let header = 20;
    let total = header + ns_len + path_len + oid_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let ns = &src[header..header + ns_len];
    let path = &src[header + ns_len..header + ns_len + path_len];
    let oid = &src[header + ns_len + path_len..header + ns_len + path_len + oid_len];
    Ok(DecodedAdminBind {
        correlation_id,
        namespace_root: ns,
        path,
        object_id: oid,
        kind,
        revision,
    })
}

// ── AdminBindAck ───────────────────────────────────────────────────

pub fn encode_admin_bind_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
) -> Result<usize, WireError> {
    let needed = 6;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_BIND;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    Ok(needed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedAdminBindAck {
    pub correlation_id: u32,
    pub status: u8,
}

pub fn decode_admin_bind_ack(src: &[u8]) -> Result<DecodedAdminBindAck, WireError> {
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
//             [kind:u8][revision:u64][body_len:u32]
//             [ns:ns_len][path:path_len][body:body_len]
//
//   Response: [op=0x43][cid:u32][status:u8][digest:32]   (status OK)
//          or [op=0x43][cid:u32][status:u8]              (NAK)
//
// `revision` gates the final BIND stage: binds are revision-gated
// upserts, so overwriting a path (S3 PUT semantics) requires a
// strictly higher revision than the one currently bound. Callers
// that overwrite pass a monotone value (e.g. wall-clock millis).

pub fn encode_admin_put_file(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    path: &[u8],
    kind: u8,
    revision: u64,
    body: &[u8],
) -> Result<usize, WireError> {
    check_key(namespace_root, path, &[])?;
    let header = 1 + 4 + 2 + 2 + 1 + 8 + 4;
    let needed = header + namespace_root.len() + path.len() + body.len();
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
    dst[10..18].copy_from_slice(&revision.to_le_bytes());
    dst[18..22].copy_from_slice(&(body.len() as u32).to_le_bytes());
    let mut cursor = header;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + path.len()].copy_from_slice(path);
    cursor += path.len();
    dst[cursor..cursor + body.len()].copy_from_slice(body);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdminPutFile<'a> {
    pub correlation_id: u32,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub kind: u8,
    pub revision: u64,
    pub body: &'a [u8],
}

pub fn decode_admin_put_file(src: &[u8]) -> Result<DecodedAdminPutFile<'_>, WireError> {
    let header = 22;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_FILE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let ns_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let path_len = u16::from_le_bytes([src[7], src[8]]) as usize;
    let kind = src[9];
    let revision = u64::from_le_bytes(src[10..18].try_into().unwrap());
    let body_len = u32::from_le_bytes(src[18..22].try_into().unwrap()) as usize;
    let total = header + ns_len + path_len + body_len;
    if src.len() < total {
        return Err(WireError::Truncated);
    }
    let ns = &src[header..header + ns_len];
    let path = &src[header + ns_len..header + ns_len + path_len];
    let body = &src[header + ns_len + path_len..header + ns_len + path_len + body_len];
    Ok(DecodedAdminPutFile {
        correlation_id: cid,
        namespace_root: ns,
        path,
        kind,
        revision,
        body,
    })
}

pub fn encode_admin_put_file_ack(
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
        dst[0] = OP_PUT_FILE;
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
        dst[0] = OP_PUT_FILE;
        dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
        dst[5] = status;
        Ok(needed)
    }
}

pub fn decode_admin_put_file_ack(src: &[u8]) -> Result<(u32, u8, Option<&[u8]>), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_FILE {
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
    Ok((cid, status, digest))
}

// ── AdminGetFile / AdminDeleteFile (composed path ops) ────────────
//
// GetFile: 2-stage — namespace LOOKUP resolves the path to its
// bound object id (the content digest), then a body_store GET
// fetches the bytes.
//
//   Request:  [op=0x44][cid:u32][ns_len:u16][path_len:u16]
//             [ns:ns_len][path:path_len]
//   Response: [op=0x44][cid:u32][status=OK][len:u32][bytes:len]
//          or [op=0x44][cid:u32][status:u8]        (NOT_FOUND/NAK)
//
// DeleteFile: 1-stage — namespace UNBIND of the path. The body
// blob stays (content-addressed, possibly shared by other paths);
// orphan collection is a scrub concern.
//
//   Request:  [op=0x45][cid:u32][ns_len:u16][path_len:u16]
//             [ns:ns_len][path:path_len]
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
) -> Result<usize, WireError> {
    encode_path_req(dst, OP_GET_FILE, correlation_id, namespace_root, path)
}

pub fn decode_admin_get_file(src: &[u8]) -> Result<DecodedAdminPathReq<'_>, WireError> {
    decode_path_req(src, OP_GET_FILE)
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
) -> Result<usize, WireError> {
    encode_path_req(dst, OP_DELETE_FILE, correlation_id, namespace_root, path)
}

pub fn decode_admin_delete_file(src: &[u8]) -> Result<DecodedAdminPathReq<'_>, WireError> {
    decode_path_req(src, OP_DELETE_FILE)
}

pub fn encode_admin_delete_file_ack(
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
    dst[0] = OP_DELETE_FILE;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = status;
    Ok(needed)
}

pub fn decode_admin_delete_file_ack(src: &[u8]) -> Result<(u32, u8), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_DELETE_FILE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    Ok((u32::from_le_bytes(src[1..5].try_into().unwrap()), src[5]))
}

// ── AdminListFiles ────────────────────────────────────────────────
//
// Cursor-paged enumeration of a namespace root's bound paths
// (forwarded to the namespace_router's OP_LIST).
//
//   Request:  [op=0x46][cid:u32][root_len:u16][cursor:u32][max:u8]
//             [root:root_len]
//   Response: [op=0x46][cid:u32][status:u8][next_cursor:u32]
//             [count:u8][(path_len:u16,path)*]      (status OK)
//          or [op=0x46][cid:u32][status:u8]          (NAK)

pub fn encode_admin_list_files(
    dst: &mut [u8],
    correlation_id: u32,
    namespace_root: &[u8],
    cursor: u32,
    max: u8,
) -> Result<usize, WireError> {
    check_key(namespace_root, &[], &[])?;
    let header = 1 + 4 + 2 + 4 + 1;
    let needed = header + namespace_root.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LIST_FILES;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..7].copy_from_slice(&(namespace_root.len() as u16).to_le_bytes());
    dst[7..11].copy_from_slice(&cursor.to_le_bytes());
    dst[11] = max;
    dst[header..needed].copy_from_slice(namespace_root);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdminListFiles<'a> {
    pub correlation_id: u32,
    pub namespace_root: &'a [u8],
    pub cursor: u32,
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
    if src.len() < header + root_len {
        return Err(WireError::Truncated);
    }
    Ok(DecodedAdminListFiles {
        correlation_id: u32::from_le_bytes(src[1..5].try_into().unwrap()),
        namespace_root: &src[header..header + root_len],
        cursor: u32::from_le_bytes(src[7..11].try_into().unwrap()),
        max: src[11],
    })
}

/// Encode an OK list ack by embedding the namespace ListResp's
/// entry section verbatim (`entries` = the bytes after the ns
/// resp header, `count` entries, next cursor as given).
pub fn encode_admin_list_files_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    next_cursor: u32,
    count: u8,
    entries: &[u8],
) -> Result<usize, WireError> {
    if status != STATUS_OK {
        let needed = 1 + 4 + 1;
        if dst.len() < needed {
            return Err(WireError::BufferTooSmall {
                needed,
                actual: dst.len(),
            });
        }
        dst[0] = OP_LIST_FILES;
        dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
        dst[5] = status;
        return Ok(needed);
    }
    let needed = 1 + 4 + 1 + 4 + 1 + entries.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_LIST_FILES;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5] = STATUS_OK;
    dst[6..10].copy_from_slice(&next_cursor.to_le_bytes());
    dst[10] = count;
    dst[11..needed].copy_from_slice(entries);
    Ok(needed)
}

/// Decode a list ack, calling `emit` per path. Returns
/// (cid, status, next_cursor, count).
pub fn decode_admin_list_files_ack(
    src: &[u8],
    mut emit: impl FnMut(&[u8]),
) -> Result<(u32, u8, u32, usize), WireError> {
    if src.len() < 6 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_LIST_FILES {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let cid = u32::from_le_bytes(src[1..5].try_into().unwrap());
    let status = src[5];
    if status != STATUS_OK {
        return Ok((cid, status, 0, 0));
    }
    if src.len() < 11 {
        return Err(WireError::Truncated);
    }
    let next_cursor = u32::from_le_bytes(src[6..10].try_into().unwrap());
    let count = src[10] as usize;
    let mut pos = 11usize;
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
    Ok((cid, status, next_cursor, count))
}

// ── Streamed AdminPutFile (large bodies) ──────────────────────────
//
// The single-frame AdminPutFile carries the whole body; past the
// body-wire chunk cap the writer streams:
//
//   PutFileOpen    [op=0x47][cid][ns_len:u16][path_len:u16][kind:u8]
//                  [revision:u64][digest:32][total_len:u64][ns][path]
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
//                  [ns_len:u16][path_len:u16][ns][path]
//   ReadFileRangeAck [op=0x4A][cid][status][len:u32][bytes]
//   StatFile       [op=0x4B][cid][ns_len:u16][path_len:u16][ns][path]
//   StatFileAck    [op=0x4B][cid][status][size:u64]

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPutFileOpen<'a> {
    pub correlation_id: u32,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
    pub kind: u8,
    pub revision: u64,
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
    revision: u64,
    digest: &[u8; DIGEST_LEN],
    total_len: u64,
) -> Result<usize, WireError> {
    check_key(namespace_root, path, &[])?;
    let header = 1 + 4 + 2 + 2 + 1 + 8 + DIGEST_LEN + 8;
    let needed = header + namespace_root.len() + path.len();
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
    dst[10..18].copy_from_slice(&revision.to_le_bytes());
    dst[18..18 + DIGEST_LEN].copy_from_slice(digest);
    dst[18 + DIGEST_LEN..header].copy_from_slice(&total_len.to_le_bytes());
    let mut cursor = header;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + path.len()].copy_from_slice(path);
    Ok(needed)
}

pub fn decode_put_file_open(src: &[u8]) -> Result<DecodedPutFileOpen<'_>, WireError> {
    let header = 1 + 4 + 2 + 2 + 1 + 8 + DIGEST_LEN + 8;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_PUT_FILE_OPEN {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let path_len = u16::from_le_bytes([src[7], src[8]]) as usize;
    if src.len() < header + ns_len + path_len {
        return Err(WireError::Truncated);
    }
    Ok(DecodedPutFileOpen {
        correlation_id: u32::from_le_bytes(src[1..5].try_into().unwrap()),
        namespace_root: &src[header..header + ns_len],
        path: &src[header + ns_len..header + ns_len + path_len],
        kind: src[9],
        revision: u64::from_le_bytes(src[10..18].try_into().unwrap()),
        digest: &src[18..18 + DIGEST_LEN],
        total_len: u64::from_le_bytes(src[18 + DIGEST_LEN..header].try_into().unwrap()),
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

pub fn encode_read_file_range(
    dst: &mut [u8],
    correlation_id: u32,
    off: u64,
    len: u32,
    namespace_root: &[u8],
    path: &[u8],
) -> Result<usize, WireError> {
    check_key(namespace_root, path, &[])?;
    let header = 1 + 4 + 8 + 4 + 2 + 2;
    let needed = header + namespace_root.len() + path.len();
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
    let mut cursor = header;
    dst[cursor..cursor + namespace_root.len()].copy_from_slice(namespace_root);
    cursor += namespace_root.len();
    dst[cursor..cursor + path.len()].copy_from_slice(path);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedReadFileRange<'a> {
    pub correlation_id: u32,
    pub off: u64,
    pub len: u32,
    pub namespace_root: &'a [u8],
    pub path: &'a [u8],
}

pub fn decode_read_file_range(src: &[u8]) -> Result<DecodedReadFileRange<'_>, WireError> {
    let header = 21;
    if src.len() < header {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_READ_FILE_RANGE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let ns_len = u16::from_le_bytes([src[17], src[18]]) as usize;
    let path_len = u16::from_le_bytes([src[19], src[20]]) as usize;
    if src.len() < header + ns_len + path_len {
        return Err(WireError::Truncated);
    }
    Ok(DecodedReadFileRange {
        correlation_id: u32::from_le_bytes(src[1..5].try_into().unwrap()),
        off: u64::from_le_bytes(src[5..13].try_into().unwrap()),
        len: u32::from_le_bytes(src[13..17].try_into().unwrap()),
        namespace_root: &src[header..header + ns_len],
        path: &src[header + ns_len..header + ns_len + path_len],
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
    match op {
        OP_AUTH => Ok(7 + u16_at(5)?),
        OP_BIND => Ok(20 + u16_at(5)? + u16_at(7)? + u16_at(9)?),
        OP_PUT_BODY => Ok(9 + u32_at(5)?),
        OP_GET_BODY => Ok(5 + DIGEST_LEN),
        OP_PUT_FILE => Ok(22 + u16_at(5)? + u16_at(7)? + u32_at(18)?),
        OP_GET_FILE | OP_DELETE_FILE | OP_STAT_FILE | OP_LOOKUP => Ok(9 + u16_at(5)? + u16_at(7)?),
        OP_LIST_FILES => Ok(12 + u16_at(5)?),
        OP_PUT_FILE_OPEN => Ok(1 + 4 + 2 + 2 + 1 + 8 + DIGEST_LEN + 8 + u16_at(5)? + u16_at(7)?),
        OP_PUT_FILE_CHUNK => Ok(10 + u32_at(6)?),
        OP_PUT_FILE_COMMIT => Ok(6),
        OP_READ_FILE_RANGE => Ok(21 + u16_at(17)? + u16_at(19)?),
        OP_PUT_BODY_KEYED => Ok(1 + 4 + DIGEST_LEN + 4 + u32_at(37)?),
        OP_DELETE_BODY => Ok(1 + 4 + DIGEST_LEN),
        OP_LEASE => Ok(LEASE_REQ_HDR + u16_at(6)? + u16_at(8)?),
        OP_VOLUME => Ok(VOLUME_REQ_HDR + u16_at(6)? + u16_at(8)? + u16_at(10)?),
        observed => Err(WireError::BadOpcode { observed }),
    }
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
//              then, on STATUS_OK: [revision:u64][kind:u8][oid_len:u8][oid]
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

/// A binding as the lookup ack carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminBinding<'a> {
    pub revision: u64,
    pub kind: u8,
    pub object_id: &'a [u8],
}

pub fn encode_admin_lookup_ack(
    dst: &mut [u8],
    correlation_id: u32,
    status: u8,
    binding: Option<&AdminBinding<'_>>,
) -> Result<usize, WireError> {
    let tail = match binding {
        Some(b) if status == STATUS_OK => {
            if b.object_id.len() > MAX_OBJECT_ID {
                return Err(WireError::StringTooLong {
                    len: b.object_id.len(),
                    max: MAX_OBJECT_ID,
                });
            }
            8 + 1 + 1 + b.object_id.len()
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
            dst[6..14].copy_from_slice(&b.revision.to_le_bytes());
            dst[14] = b.kind;
            dst[15] = b.object_id.len() as u8;
            dst[16..16 + b.object_id.len()].copy_from_slice(b.object_id);
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
    if src.len() < 16 {
        return Err(WireError::Truncated);
    }
    let oid_len = src[15] as usize;
    if src.len() < 16 + oid_len {
        return Err(WireError::Truncated);
    }
    Ok((
        cid,
        status,
        Some(AdminBinding {
            revision: u64::from_le_bytes(src[6..14].try_into().unwrap()),
            kind: src[14],
            object_id: &src[16..16 + oid_len],
        }),
    ))
}
