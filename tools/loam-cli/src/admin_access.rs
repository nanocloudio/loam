//! Who may do what on the admin surface.
//!
//! Every admin request is checked here, on the host, before it reaches
//! `admin_router`. The router is a PIC module that sees channel frames,
//! never the transport they came over, so it cannot know which
//! certificate a request was sent under. The host server can: it
//! terminates TLS, holds the verified identity for the life of the
//! connection, and already frames every request it forwards. Checking
//! here keeps the grant table and the identity out of the graph, where
//! they would have to be threaded through every channel as data.
//!
//! The rule is default deny. An identity with no grant can do nothing,
//! a request is checked against the class its opcode belongs to, and an
//! opcode this table does not name is refused and the connection
//! closed, because nothing after an unknown opcode can be framed.

use crate::runtime::admin_wire as wire;
use crate::runtime::sha256::Sha256;
use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::collections::HashMap;

/// Identities one grant file may name. The table is searched once per
/// request, and a deployment grants per device or per service, not per
/// user.
pub const MAX_GRANTS: usize = 1024;
/// Namespace roots one grant may list. More than this is a grant that
/// wants `"*"`.
pub const MAX_GRANT_ROOTS: usize = 256;
/// Longest identity a certificate may carry. Identities are hashed into
/// every lease holder their owner uses, and they are grant-table keys.
pub const MAX_IDENTITY: usize = 256;

/// The identity the unix socket's peer acts as. It is not in the grant
/// table and cannot be put there: the name is reserved so no
/// certificate can be issued that reads as the local operator.
pub const LOCAL_OPERATOR: &str = "local-operator";

/// Operation classes. A grant holds a set of them.
pub const CLASS_READ: u8 = 1 << 0;
pub const CLASS_WRITE: u8 = 1 << 1;
pub const CLASS_LEASE: u8 = 1 << 2;
pub const CLASS_ADMIN: u8 = 1 << 3;

/// Who sent a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// The unix socket, under the admin token when one is configured.
    /// Full authority, and holders pass through unchanged.
    LocalOperator,
    /// A verified client certificate's identity.
    Remote(String),
}

// ── Grant table ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantFile {
    grants: Vec<GrantEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantEntry {
    identity: String,
    roots: Vec<String>,
    ops: Vec<String>,
}

#[derive(Debug, Clone)]
struct Grant {
    any_root: bool,
    roots: Vec<Vec<u8>>,
    classes: u8,
}

impl Grant {
    fn covers_root(&self, root: &[u8]) -> bool {
        self.any_root || self.roots.iter().any(|r| r.as_slice() == root)
    }
}

/// Identity → allowed roots and op classes.
#[derive(Debug, Default)]
pub struct Grants {
    by_identity: HashMap<String, Grant>,
}

impl Grants {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("reading {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| anyhow!("{}: {e}", path.display()))
    }

    /// Parse a grant file. Every refusal names the entry, because a
    /// grant an operator believes is in force but is not is worse than
    /// a server that will not start.
    pub fn parse(text: &str) -> Result<Self> {
        let file: GrantFile = serde_json::from_str(text).map_err(|e| anyhow!("{e}"))?;
        if file.grants.len() > MAX_GRANTS {
            return Err(anyhow!(
                "{} grants; at most {MAX_GRANTS} identities",
                file.grants.len()
            ));
        }
        let mut by_identity = HashMap::new();
        for entry in file.grants {
            let id = entry.identity;
            check_identity(&id).map_err(|e| anyhow!("grant {id:?}: {e}"))?;
            if id == LOCAL_OPERATOR {
                return Err(anyhow!(
                    "grant {id:?}: the name is reserved for the unix socket, \
                     which needs no grant"
                ));
            }
            if entry.roots.is_empty() || entry.roots.len() > MAX_GRANT_ROOTS {
                return Err(anyhow!(
                    "grant {id:?}: {} roots; between 1 and {MAX_GRANT_ROOTS}",
                    entry.roots.len()
                ));
            }
            let mut grant = Grant {
                any_root: false,
                roots: Vec::new(),
                classes: 0,
            };
            for root in entry.roots {
                if root == "*" {
                    grant.any_root = true;
                } else if root.is_empty() || root.len() > wire::MAX_ROOT {
                    return Err(anyhow!(
                        "grant {id:?}: root {root:?} is not 1..={} bytes",
                        wire::MAX_ROOT
                    ));
                } else {
                    grant.roots.push(root.into_bytes());
                }
            }
            if entry.ops.is_empty() {
                return Err(anyhow!("grant {id:?}: no ops"));
            }
            for op in &entry.ops {
                grant.classes |= match op.as_str() {
                    "read" => CLASS_READ,
                    "write" => CLASS_WRITE,
                    "lease" => CLASS_LEASE,
                    "admin" => CLASS_ADMIN,
                    other => {
                        return Err(anyhow!(
                            "grant {id:?}: op {other:?} is not read, write, lease or admin"
                        ))
                    }
                };
            }
            if by_identity.insert(id.clone(), grant).is_some() {
                return Err(anyhow!(
                    "grant {id:?} appears twice; one identity has one grant"
                ));
            }
        }
        Ok(Grants { by_identity })
    }

    pub fn len(&self) -> usize {
        self.by_identity.len()
    }

    /// Whether `identity` holds `class` on `root`, or, for an op that
    /// names no root, on at least one root.
    fn allows(&self, identity: &str, class: u8, root: Option<&[u8]>) -> bool {
        match self.by_identity.get(identity) {
            Some(g) if g.classes & class != 0 => match root {
                Some(r) => g.covers_root(r),
                None => true,
            },
            _ => false,
        }
    }
}

/// An identity the grant table and the lease holder can both carry.
pub fn check_identity(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_IDENTITY {
        return Err(anyhow!("identity is not 1..={MAX_IDENTITY} bytes"));
    }
    Ok(())
}

// ── Per-request check ──────────────────────────────────────────────

/// What to do with one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Forward it to the router.
    Allow,
    /// Answer it here with this status, in the op's own ack shape, and
    /// keep the connection.
    Refuse(u8),
    /// Refuse it and close the connection: its opcode names no request,
    /// so where the next one starts is unknown.
    Close,
}

/// Check one complete request frame from `principal`.
///
/// `owns_stream(pfid)` says whether this connection opened streamed
/// write `pfid`: a chunk or commit names only the stream, and the
/// grant was checked when the stream was opened on a named root.
pub fn authorize(
    principal: &Principal,
    grants: &Grants,
    frame: &[u8],
    owns_stream: impl Fn(u8) -> bool,
) -> Verdict {
    let id = match principal {
        Principal::LocalOperator => return Verdict::Allow,
        Principal::Remote(id) => id.as_str(),
    };
    let op = match frame.first() {
        Some(op) => *op,
        None => return Verdict::Close,
    };
    let rooted = |class: u8, root: Result<&[u8], wire::WireError>| match root {
        Ok(root) if grants.allows(id, class, Some(root)) => Verdict::Allow,
        Ok(_) => Verdict::Refuse(wire::STATUS_FORBIDDEN),
        Err(_) => Verdict::Refuse(wire::STATUS_NAK),
    };
    let rootless = |class: u8| {
        if grants.allows(id, class, None) {
            Verdict::Allow
        } else {
            Verdict::Refuse(wire::STATUS_FORBIDDEN)
        }
    };
    match op {
        // Reads name their root.
        wire::OP_GET_FILE => rooted(
            CLASS_READ,
            wire::decode_admin_get_file(frame).map(|r| r.namespace_root),
        ),
        wire::OP_STAT_FILE => rooted(
            CLASS_READ,
            wire::decode_stat_file(frame).map(|r| r.namespace_root),
        ),
        wire::OP_LOOKUP => rooted(
            CLASS_READ,
            wire::decode_admin_lookup(frame).map(|r| r.namespace_root),
        ),
        wire::OP_LIST_FILES => rooted(
            CLASS_READ,
            wire::decode_admin_list_files(frame).map(|r| r.namespace_root),
        ),
        wire::OP_READ_FILE_RANGE => rooted(
            CLASS_READ,
            wire::decode_read_file_range(frame).map(|r| r.namespace_root),
        ),
        // Writes name their root.
        wire::OP_BIND => rooted(
            CLASS_WRITE,
            wire::decode_admin_bind(frame).map(|r| r.namespace_root),
        ),
        wire::OP_PUT_FILE => rooted(
            CLASS_WRITE,
            wire::decode_admin_put_file(frame).map(|r| r.namespace_root),
        ),
        wire::OP_DELETE_FILE => rooted(
            CLASS_WRITE,
            wire::decode_admin_delete_file(frame).map(|r| r.namespace_root),
        ),
        wire::OP_PUT_FILE_OPEN => rooted(
            CLASS_WRITE,
            wire::decode_put_file_open(frame).map(|r| r.namespace_root),
        ),
        wire::OP_VOLUME => rooted(
            CLASS_WRITE,
            wire::decode_admin_volume(frame).map(|r| r.namespace_root),
        ),
        wire::OP_LEASE => rooted(
            CLASS_LEASE,
            wire::decode_admin_lease(frame).map(|r| r.namespace_root),
        ),
        // A stream's chunks and commit belong to whoever opened it.
        wire::OP_PUT_FILE_CHUNK => match wire::decode_put_file_chunk(frame) {
            Ok((_, pfid, _)) if owns_stream(pfid) => Verdict::Allow,
            Ok(_) => Verdict::Refuse(wire::STATUS_FORBIDDEN),
            Err(_) => Verdict::Refuse(wire::STATUS_NAK),
        },
        wire::OP_PUT_FILE_COMMIT => match wire::decode_put_file_commit(frame) {
            Ok((_, pfid)) if owns_stream(pfid) => Verdict::Allow,
            Ok(_) => Verdict::Refuse(wire::STATUS_FORBIDDEN),
            Err(_) => Verdict::Refuse(wire::STATUS_NAK),
        },
        // Content-addressed bodies name no root. A put cannot change
        // bytes anyone else reads (the same digest is the same bytes)
        // and is an unreferenced orphan until a bind or a volume commit
        // on a granted root names it; a get needs the digest, which a
        // caller learns from a root it can read.
        wire::OP_PUT_BODY => rootless(CLASS_WRITE),
        wire::OP_GET_BODY => rootless(CLASS_READ),
        // The raw keyed plane overwrites and deletes by key, across
        // every root at once: store-wide authority.
        wire::OP_PUT_BODY_KEYED | wire::OP_DELETE_BODY => rootless(CLASS_ADMIN),
        // A TLS connection authenticated in its handshake; the token is
        // the unix socket's, and presenting it here gains nothing.
        wire::OP_AUTH => Verdict::Refuse(wire::STATUS_FORBIDDEN),
        _ => Verdict::Close,
    }
}

// ── Lease holders bound to identity ────────────────────────────────

/// The holder the store records for `identity` writing as `chosen`.
///
/// Keyed by identity, so no identity can produce another's holder; and
/// keyed by the caller's own choice, so one identity can still run
/// several writers that exclude each other. A client never needs to
/// know the result: it names its writer with `chosen` on every lease
/// and volume request, and the server maps it the same way each time.
pub fn bind_holder(identity: &str, chosen: &[u8]) -> [u8; wire::LEASE_HOLDER_LEN] {
    let mut h = Sha256::new();
    h.update(b"loam-lease-holder\0");
    h.update(&(identity.len() as u16).to_le_bytes());
    h.update(identity.as_bytes());
    h.update(chosen);
    let d = h.finalize();
    let mut out = [0u8; wire::LEASE_HOLDER_LEN];
    out.copy_from_slice(&d[..wire::LEASE_HOLDER_LEN]);
    out
}

/// Replace the holder in an authorised lease or volume request with the
/// one bound to `principal`. The local operator's pass through: it has
/// full authority, including over a stuck writer's lease.
pub fn bind_request_holder(principal: &Principal, frame: &mut [u8]) {
    let Principal::Remote(id) = principal else {
        return;
    };
    if let Some(holder) = wire::request_holder_mut(frame) {
        *holder = bind_holder(id, holder);
    }
}

// ── Refusals, in each op's own ack shape ───────────────────────────

/// The ack `status` for request `frame`, shaped as that op's own ack so
/// a client decodes it with the decoder it was already waiting on.
pub fn refusal(frame: &[u8], status: u8) -> Vec<u8> {
    let op = frame.first().copied().unwrap_or(0);
    let cid = if frame.len() >= 5 {
        u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]])
    } else {
        0
    };
    let mut buf = [0u8; 32];
    let n = match op {
        wire::OP_AUTH => wire::encode_admin_auth_ack(&mut buf, cid, status),
        wire::OP_BIND => wire::encode_admin_bind_ack(&mut buf, cid, status),
        wire::OP_PUT_BODY => wire::encode_admin_put_body_ack(&mut buf, cid, status, None),
        wire::OP_GET_BODY => wire::encode_admin_get_body_ack(&mut buf, cid, status, None),
        // A streamed write's commit is answered as a whole-file put.
        wire::OP_PUT_FILE | wire::OP_PUT_FILE_COMMIT => {
            wire::encode_admin_put_file_ack(&mut buf, cid, status, None)
        }
        wire::OP_GET_FILE => wire::encode_admin_get_file_ack(&mut buf, cid, status, None),
        wire::OP_DELETE_FILE => wire::encode_admin_delete_file_ack(&mut buf, cid, status),
        wire::OP_LIST_FILES => wire::encode_admin_list_files_ack(&mut buf, cid, status, 0, 0, &[]),
        wire::OP_PUT_FILE_OPEN => wire::encode_put_file_open_ack(&mut buf, cid, status, 0),
        wire::OP_PUT_FILE_CHUNK => wire::encode_put_file_chunk_ack(&mut buf, cid, status),
        wire::OP_READ_FILE_RANGE => wire::encode_read_file_range_ack(&mut buf, cid, status, None),
        wire::OP_STAT_FILE => wire::encode_stat_file_ack(&mut buf, cid, status, 0),
        wire::OP_PUT_BODY_KEYED => wire::encode_admin_put_body_keyed_ack(&mut buf, cid, status),
        wire::OP_DELETE_BODY => wire::encode_admin_delete_body_ack(&mut buf, cid, status, false),
        wire::OP_LEASE => wire::encode_admin_lease_ack(&mut buf, cid, status, 0, 0),
        wire::OP_VOLUME => wire::encode_admin_volume_ack(&mut buf, cid, status, 0),
        wire::OP_LOOKUP => wire::encode_admin_lookup_ack(&mut buf, cid, status, None),
        // No ack shape to borrow: the common envelope, so a client
        // that sent it learns the verdict before the close.
        _ => {
            buf[0] = op;
            buf[1..5].copy_from_slice(&cid.to_le_bytes());
            buf[5] = status;
            Ok(6)
        }
    };
    n.map(|n| buf[..n].to_vec()).unwrap_or_default()
}
