// Binary wire format for object-plane events. Same design as
// loam_namespace_wire.rs: little-endian, fixed headers + length-prefixed
// strings, no_std-friendly, bounded under `loam_decision_wire::MAX_INNER`.
//
// Layout (LE):
//
//   ObjPut     [op:u8=4]
//              [id_len:u16][ns_len:u16][key_len:u16][hash_len:u16]
//              [size_bytes:u64][revision:u64]
//              [data_class:u8][replica_count:u8]
//              [has_erasure:u8][data_shards:u8][parity_shards:u8]
//              [id][ns][key][hash]
//   ObjUpdate  same as Put (the PIC doesn't enforce prior_revision —
//              that's the proposer's job; apply path is deterministic)
//   ObjRemove  [op:u8=6][id_len:u16][id]

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use core::convert::TryInto;

pub const OP_OBJ_PUT: u8 = 4;
pub const OP_OBJ_UPDATE: u8 = 5;
pub const OP_OBJ_REMOVE: u8 = 6;
pub const OP_OBJ_GET: u8 = 7;

pub const OBJ_FOUND: u8 = 1;
pub const OBJ_NOT_FOUND: u8 = 0;

pub const DATA_CLASS_LOCAL: u8 = 0;
pub const DATA_CLASS_REPLICATED: u8 = 1;
pub const DATA_CLASS_ERASURE_CODED: u8 = 2;
pub const DATA_CLASS_REMOTE_CACHED: u8 = 3;

pub const MAX_STRING: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    BufferTooSmall { needed: usize, actual: usize },
    Truncated,
    BadOpcode { observed: u8 },
    BadDataClass { observed: u8 },
    StringTooLong { len: usize, max: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutFields<'a> {
    pub id: &'a [u8],
    pub namespace: &'a [u8],
    pub key: &'a [u8],
    pub content_hash: &'a [u8],
    pub size_bytes: u64,
    pub revision: u64,
    pub data_class: u8,
    pub replica_count: u8,
    pub erasure: Option<(u8, u8)>,
}

fn check_strings(strs: &[&[u8]]) -> Result<(), WireError> {
    for s in strs {
        if s.len() > MAX_STRING {
            return Err(WireError::StringTooLong {
                len: s.len(),
                max: MAX_STRING,
            });
        }
    }
    Ok(())
}

const PUT_HEADER: usize = 1 + 2 + 2 + 2 + 2 + 8 + 8 + 1 + 1 + 1 + 1 + 1;

fn encode_put_inner(dst: &mut [u8], op: u8, p: &PutFields<'_>) -> Result<usize, WireError> {
    check_strings(&[p.id, p.namespace, p.key, p.content_hash])?;
    let body = p.id.len() + p.namespace.len() + p.key.len() + p.content_hash.len();
    let needed = PUT_HEADER + body;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = op;
    dst[1..3].copy_from_slice(&(p.id.len() as u16).to_le_bytes());
    dst[3..5].copy_from_slice(&(p.namespace.len() as u16).to_le_bytes());
    dst[5..7].copy_from_slice(&(p.key.len() as u16).to_le_bytes());
    dst[7..9].copy_from_slice(&(p.content_hash.len() as u16).to_le_bytes());
    dst[9..17].copy_from_slice(&p.size_bytes.to_le_bytes());
    dst[17..25].copy_from_slice(&p.revision.to_le_bytes());
    dst[25] = p.data_class;
    dst[26] = p.replica_count;
    match p.erasure {
        Some((d, q)) => {
            dst[27] = 1;
            dst[28] = d;
            dst[29] = q;
        }
        None => {
            dst[27] = 0;
            dst[28] = 0;
            dst[29] = 0;
        }
    }
    let mut cursor = PUT_HEADER;
    dst[cursor..cursor + p.id.len()].copy_from_slice(p.id);
    cursor += p.id.len();
    dst[cursor..cursor + p.namespace.len()].copy_from_slice(p.namespace);
    cursor += p.namespace.len();
    dst[cursor..cursor + p.key.len()].copy_from_slice(p.key);
    cursor += p.key.len();
    dst[cursor..cursor + p.content_hash.len()].copy_from_slice(p.content_hash);
    Ok(needed)
}

fn decode_put_inner(src: &[u8], expected_op: u8) -> Result<PutFields<'_>, WireError> {
    if src.len() < PUT_HEADER {
        return Err(WireError::Truncated);
    }
    if src[0] != expected_op {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let id_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    let ns_len = u16::from_le_bytes([src[3], src[4]]) as usize;
    let key_len = u16::from_le_bytes([src[5], src[6]]) as usize;
    let hash_len = u16::from_le_bytes([src[7], src[8]]) as usize;
    let size_bytes = u64::from_le_bytes(src[9..17].try_into().unwrap());
    let revision = u64::from_le_bytes(src[17..25].try_into().unwrap());
    let data_class = src[25];
    if data_class > DATA_CLASS_REMOTE_CACHED {
        return Err(WireError::BadDataClass {
            observed: data_class,
        });
    }
    let replica_count = src[26];
    let has_erasure = src[27];
    let erasure = if has_erasure != 0 {
        Some((src[28], src[29]))
    } else {
        None
    };
    let body_len = id_len + ns_len + key_len + hash_len;
    if src.len() < PUT_HEADER + body_len {
        return Err(WireError::Truncated);
    }
    let mut c = PUT_HEADER;
    let id = &src[c..c + id_len];
    c += id_len;
    let ns = &src[c..c + ns_len];
    c += ns_len;
    let key = &src[c..c + key_len];
    c += key_len;
    let hash = &src[c..c + hash_len];
    Ok(PutFields {
        id,
        namespace: ns,
        key,
        content_hash: hash,
        size_bytes,
        revision,
        data_class,
        replica_count,
        erasure,
    })
}

pub fn encode_put(dst: &mut [u8], p: &PutFields<'_>) -> Result<usize, WireError> {
    encode_put_inner(dst, OP_OBJ_PUT, p)
}
pub fn decode_put(src: &[u8]) -> Result<PutFields<'_>, WireError> {
    decode_put_inner(src, OP_OBJ_PUT)
}

pub fn encode_update(dst: &mut [u8], p: &PutFields<'_>) -> Result<usize, WireError> {
    encode_put_inner(dst, OP_OBJ_UPDATE, p)
}
pub fn decode_update(src: &[u8]) -> Result<PutFields<'_>, WireError> {
    decode_put_inner(src, OP_OBJ_UPDATE)
}

pub fn encode_remove(dst: &mut [u8], id: &[u8]) -> Result<usize, WireError> {
    check_strings(&[id])?;
    let header = 1 + 2;
    let needed = header + id.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_OBJ_REMOVE;
    dst[1..3].copy_from_slice(&(id.len() as u16).to_le_bytes());
    dst[header..header + id.len()].copy_from_slice(id);
    Ok(needed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRemove<'a> {
    pub id: &'a [u8],
}

pub fn decode_remove(src: &[u8]) -> Result<DecodedRemove<'_>, WireError> {
    if src.len() < 3 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_OBJ_REMOVE {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let id_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    if src.len() < 3 + id_len {
        return Err(WireError::Truncated);
    }
    Ok(DecodedRemove {
        id: &src[3..3 + id_len],
    })
}

// ── ObjGet ─────────────────────────────────────────────────────────
//
//   Request:           [op:u8=7][id_len:u16][id]
//   Response (found):  [op:u8=7][status:u8=1][size:u64][revision:u64]
//                      [data_class:u8][replica_count:u8]
//                      [has_erasure:u8][data_shards:u8][parity_shards:u8]
//   Response (absent): [op:u8=7][status:u8=0]

pub fn encode_get_req(dst: &mut [u8], id: &[u8]) -> Result<usize, WireError> {
    if id.len() > MAX_STRING {
        return Err(WireError::StringTooLong {
            len: id.len(),
            max: MAX_STRING,
        });
    }
    let needed = 1 + 2 + id.len();
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_OBJ_GET;
    dst[1..3].copy_from_slice(&(id.len() as u16).to_le_bytes());
    dst[3..3 + id.len()].copy_from_slice(id);
    Ok(needed)
}

pub fn decode_get_req(src: &[u8]) -> Result<&[u8], WireError> {
    if src.len() < 3 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_OBJ_GET {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    let id_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    if src.len() < 3 + id_len {
        return Err(WireError::Truncated);
    }
    Ok(&src[3..3 + id_len])
}

#[allow(
    clippy::too_many_arguments,
    reason = "bounded no_std step functions pass explicit scalar params"
)]
pub fn encode_get_found(
    dst: &mut [u8],
    size_bytes: u64,
    revision: u64,
    data_class: u8,
    replica_count: u8,
    erasure: Option<(u8, u8)>,
) -> Result<usize, WireError> {
    let needed = 1 + 1 + 8 + 8 + 1 + 1 + 1 + 1 + 1;
    if dst.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = OP_OBJ_GET;
    dst[1] = OBJ_FOUND;
    dst[2..10].copy_from_slice(&size_bytes.to_le_bytes());
    dst[10..18].copy_from_slice(&revision.to_le_bytes());
    dst[18] = data_class;
    dst[19] = replica_count;
    match erasure {
        Some((d, q)) => {
            dst[20] = 1;
            dst[21] = d;
            dst[22] = q;
        }
        None => {
            dst[20] = 0;
            dst[21] = 0;
            dst[22] = 0;
        }
    }
    Ok(needed)
}

pub fn encode_get_not_found(dst: &mut [u8]) -> Result<usize, WireError> {
    if dst.len() < 2 {
        return Err(WireError::BufferTooSmall {
            needed: 2,
            actual: dst.len(),
        });
    }
    dst[0] = OP_OBJ_GET;
    dst[1] = OBJ_NOT_FOUND;
    Ok(2)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedGetResp {
    Found {
        size_bytes: u64,
        revision: u64,
        data_class: u8,
        replica_count: u8,
        erasure: Option<(u8, u8)>,
    },
    NotFound,
}

pub fn decode_get_resp(src: &[u8]) -> Result<DecodedGetResp, WireError> {
    if src.len() < 2 {
        return Err(WireError::Truncated);
    }
    if src[0] != OP_OBJ_GET {
        return Err(WireError::BadOpcode { observed: src[0] });
    }
    match src[1] {
        OBJ_NOT_FOUND => Ok(DecodedGetResp::NotFound),
        OBJ_FOUND => {
            if src.len() < 23 {
                return Err(WireError::Truncated);
            }
            let size_bytes = u64::from_le_bytes(src[2..10].try_into().unwrap());
            let revision = u64::from_le_bytes(src[10..18].try_into().unwrap());
            let data_class = src[18];
            let replica_count = src[19];
            let has_erasure = src[20];
            let erasure = if has_erasure != 0 {
                Some((src[21], src[22]))
            } else {
                None
            };
            Ok(DecodedGetResp::Found {
                size_bytes,
                revision,
                data_class,
                replica_count,
                erasure,
            })
        }
        other => Err(WireError::BadDataClass { observed: other }),
    }
}

pub fn peek_opcode(src: &[u8]) -> Option<u8> {
    src.first().copied()
}

// ── Request stream splitting ───────────────────────────────────────

/// Length of the request record at the front of `src`, or `None` when
/// `src` does not yet hold a whole one.
///
/// See `loam_wire::request_record_len` for why a provider needs this:
/// its `requests` channel is a byte stream, so a batching producer's
/// records coalesce into one read and a read can end mid-record.
///
/// Requests only — the response forms reuse these opcodes with
/// different shapes, and a provider never reads its own responses.
pub fn request_record_len(src: &[u8]) -> Result<Option<usize>, WireError> {
    let opcode = match src.first() {
        Some(b) => *b,
        None => return Ok(None),
    };
    match opcode {
        // PUT and UPDATE share one header whose four length fields
        // describe the strings that follow it.
        OP_OBJ_PUT | OP_OBJ_UPDATE => {
            if src.len() < PUT_HEADER {
                return Ok(None);
            }
            let mut total = PUT_HEADER;
            for at in [1usize, 3, 5, 7] {
                total += u16::from_le_bytes([src[at], src[at + 1]]) as usize;
            }
            Ok(if src.len() >= total {
                Some(total)
            } else {
                None
            })
        }
        // [op][id_len:u16][id]
        OP_OBJ_REMOVE | OP_OBJ_GET => {
            if src.len() < 3 {
                return Ok(None);
            }
            let total = 3 + u16::from_le_bytes([src[1], src[2]]) as usize;
            Ok(if src.len() >= total {
                Some(total)
            } else {
                None
            })
        }
        observed => Err(WireError::BadOpcode { observed }),
    }
}
