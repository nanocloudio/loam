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
// Future ops (deliberately out of scope for the Phase 4a slice):
//   0x41 PutBody, 0x42 GetBody, 0x43 PutFile (composed), 0x44 Read, …

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

pub const STATUS_OK: u8 = 0x01;
pub const STATUS_NAK: u8 = 0xFF;
pub const STATUS_NOT_FOUND: u8 = 0x02;

pub const MAX_STRING: usize = 1024;
pub const DIGEST_LEN: usize = 32;

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
    for s in [namespace_root, path, object_id] {
        if s.len() > MAX_STRING {
            return Err(WireError::StringTooLong {
                len: s.len(),
                max: MAX_STRING,
            });
        }
    }
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
    let needed = 1 + 4 + 4 + body.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_PUT_BODY;
    dst[1..5].copy_from_slice(&correlation_id.to_le_bytes());
    dst[5..9].copy_from_slice(&(body.len() as u32).to_le_bytes());
    dst[9..9 + body.len()].copy_from_slice(body);
    Ok(needed)
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
    for s in [namespace_root, path] {
        if s.len() > MAX_STRING {
            return Err(WireError::StringTooLong {
                len: s.len(),
                max: MAX_STRING,
            });
        }
    }
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
    for s in [namespace_root, path] {
        if s.len() > MAX_STRING {
            return Err(WireError::StringTooLong {
                len: s.len(),
                max: MAX_STRING,
            });
        }
    }
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
    if namespace_root.len() > MAX_STRING {
        return Err(WireError::StringTooLong {
            len: namespace_root.len(),
            max: MAX_STRING,
        });
    }
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
    for s in [namespace_root, path] {
        if s.len() > MAX_STRING {
            return Err(WireError::StringTooLong {
                len: s.len(),
                max: MAX_STRING,
            });
        }
    }
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
    for s in [namespace_root, path] {
        if s.len() > MAX_STRING {
            return Err(WireError::StringTooLong {
                len: s.len(),
                max: MAX_STRING,
            });
        }
    }
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

// ── AdminPutBodyKeyed / AdminDeleteBody (raw keyed body plane) ────
//
// The block-volume extent surface: extents live in the body plane
// under DERIVED keys (see loam_extent_wire.rs), never bound in the
// namespace. PutBodyKeyed stores (overwrites — keyed blobs are
// mutable); DeleteBody removes a blob by key/digest, the volume
// delete path's per-extent cleanup.
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
