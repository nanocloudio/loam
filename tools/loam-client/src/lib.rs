//! Client for loam's admin surface: the unix-socket protocol
//! `loam-server --socket` serves. One struct, blocking calls, no
//! dependencies — the crate a volume backend (nanocloud's
//! CsiPlugin), a tool, or a test links instead of re-implementing
//! the wire.
//!
//! The wire itself is the same `#[path]`-included
//! `modules/common/mechanics/loam_admin_wire.rs` the PIC modules compile —
//! there is exactly one encoding in the tree. Requests carry a
//! client-chosen correlation id; replies echo it. This client
//! runs one request at a time per connection, so cids are a
//! monotonic counter and replies are read until the frame's own
//! decode reports completion (every ack decode returns
//! `Truncated` on a partial buffer).

#[allow(
    dead_code,
    unused_imports,
    reason = "shared fluxor SDK include; each includer uses a subset"
)]
pub(crate) mod sha256_impl {
    include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
}
use sha256_impl::Sha256;

#[path = "../../../modules/common/mechanics/loam_admin_wire.rs"]
pub mod admin_wire;

/// Scope wrapper: extent_wire expects `super::sha256::Sha256`.
pub mod wire_scope {
    pub mod sha256 {
        pub use crate::sha256_impl::Sha256;
    }
    #[path = "../../../../modules/common/mechanics/loam_extent_wire.rs"]
    pub mod extent_wire;
}
pub use wire_scope::extent_wire;

use admin_wire::WireError;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Chunk size for streamed writes and ranged reads. Below the
/// body plane's single-shot MAX_BODY (60 KiB) with frame headroom.
pub const IO_CHUNK: usize = 48 * 1024;

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    /// The server answered, but with a NAK status.
    Nak(u8),
    /// A reply that doesn't decode as the expected ack.
    Protocol(WireError),
    /// A reply whose correlation id isn't the request's.
    CorrelationMismatch {
        expected: u32,
        observed: u32,
    },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::Nak(s) => write!(f, "server nak (status 0x{s:02x})"),
            ClientError::Protocol(e) => write!(f, "protocol: {e:?}"),
            ClientError::CorrelationMismatch { expected, observed } => {
                write!(f, "correlation mismatch: sent {expected}, got {observed}")
            }
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// A blocking connection to a loam-server admin socket.
pub struct LoamClient {
    conn: UnixStream,
    next_cid: u32,
}

impl LoamClient {
    /// Connect to the unix admin socket at `path`.
    pub fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let conn = UnixStream::connect(path)?;
        conn.set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok(LoamClient { conn, next_cid: 1 })
    }

    fn cid(&mut self) -> u32 {
        let c = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        c
    }

    /// Send `frame`, then read until `decode` accepts the reply.
    /// `decode` returns the reply's correlation id plus the value.
    fn round_trip<T>(
        &mut self,
        frame: &[u8],
        decode: impl Fn(&[u8]) -> std::result::Result<(u32, T), WireError>,
        expected_cid: u32,
    ) -> Result<T> {
        self.conn.write_all(frame)?;
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 64 * 1024];
        loop {
            match decode(&buf) {
                Ok((cid, v)) => {
                    if cid != expected_cid {
                        return Err(ClientError::CorrelationMismatch {
                            expected: expected_cid,
                            observed: cid,
                        });
                    }
                    return Ok(v);
                }
                Err(WireError::Truncated) => {}
                Err(e) => return Err(ClientError::Protocol(e)),
            }
            let n = self.conn.read(&mut chunk)?;
            if n == 0 {
                return Err(ClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-reply",
                )));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Write `body` to `(namespace_root, path)` at `revision`.
    /// Single-shot for small bodies, digest-first streamed past
    /// IO_CHUNK. Returns the content digest (sha256).
    pub fn put_file(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        revision: u64,
        body: &[u8],
    ) -> Result<[u8; 32]> {
        if body.len() <= IO_CHUNK {
            let cid = self.cid();
            let mut buf = vec![0u8; body.len() + namespace_root.len() + path.len() + 64];
            let n = admin_wire::encode_admin_put_file(
                &mut buf,
                cid,
                namespace_root,
                path,
                0,
                revision,
                body,
            )
            .map_err(ClientError::Protocol)?;
            let (status, digest) = self.round_trip(
                &buf[..n],
                |b| {
                    admin_wire::decode_admin_put_file_ack(b)
                        .map(|(cid, status, d)| (cid, (status, d.map(|d| d.to_vec()))))
                },
                cid,
            )?;
            return match (status, digest) {
                (admin_wire::STATUS_OK, Some(d)) if d.len() == 32 => {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&d);
                    Ok(out)
                }
                (s, _) => Err(ClientError::Nak(s)),
            };
        }

        // Streamed: digest first, then open/chunk/commit.
        let mut h = Sha256::new();
        h.update(body);
        let digest = h.finalize();

        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 128];
        let n = admin_wire::encode_put_file_open(
            &mut buf,
            cid,
            namespace_root,
            path,
            0,
            revision,
            &digest,
            body.len() as u64,
        )
        .map_err(ClientError::Protocol)?;
        let (status, pfid) = self.round_trip(
            &buf[..n],
            |b| admin_wire::decode_put_file_open_ack(b).map(|(c, s, p)| (c, (s, p))),
            cid,
        )?;
        if status != admin_wire::STATUS_OK {
            return Err(ClientError::Nak(status));
        }

        for chunk in body.chunks(IO_CHUNK) {
            let cid = self.cid();
            let mut buf = vec![0u8; chunk.len() + 32];
            let n = admin_wire::encode_put_file_chunk(&mut buf, cid, pfid, chunk)
                .map_err(ClientError::Protocol)?;
            let status = self.round_trip(&buf[..n], admin_wire::decode_put_file_chunk_ack, cid)?;
            if status != admin_wire::STATUS_OK {
                return Err(ClientError::Nak(status));
            }
        }

        let cid = self.cid();
        let mut buf = vec![0u8; 16];
        let n = admin_wire::encode_put_file_commit(&mut buf, cid, pfid)
            .map_err(ClientError::Protocol)?;
        let (status, committed) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_admin_put_file_ack(b)
                    .map(|(c, s, d)| (c, (s, d.map(|d| d.to_vec()))))
            },
            cid,
        )?;
        match (status, committed) {
            (admin_wire::STATUS_OK, Some(d)) if d.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&d);
                Ok(out)
            }
            (s, _) => Err(ClientError::Nak(s)),
        }
    }

    /// Fetch the whole body at `(namespace_root, path)`. `None` if
    /// the path is not bound. Bodies past the single-shot cap are
    /// assembled from ranged reads (the body plane never serves
    /// more than one chunk per frame).
    pub fn get_file(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<Option<Vec<u8>>> {
        let size = match self.stat_file(namespace_root, path)? {
            Some(s) => s,
            None => return Ok(None),
        };
        if size as usize > IO_CHUNK {
            let mut out = Vec::with_capacity(size as usize);
            while (out.len() as u64) < size {
                let want = ((size - out.len() as u64) as usize).min(IO_CHUNK) as u32;
                match self.read_range(namespace_root, path, out.len() as u64, want)? {
                    Some(bytes) if !bytes.is_empty() => out.extend_from_slice(&bytes),
                    _ => {
                        return Err(ClientError::Io(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "ranged read came back short",
                        )))
                    }
                }
            }
            return Ok(Some(out));
        }
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 32];
        let n = admin_wire::encode_admin_get_file(&mut buf, cid, namespace_root, path)
            .map_err(ClientError::Protocol)?;
        let (status, body) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_admin_get_file_ack(b)
                    .map(|(c, s, d)| (c, (s, d.map(|d| d.to_vec()))))
            },
            cid,
        )?;
        match status {
            admin_wire::STATUS_OK => Ok(body),
            admin_wire::STATUS_NOT_FOUND => Ok(None),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// Read `[offset, offset+len)` of the file. `None` if the path
    /// is not bound. `len` is capped at IO_CHUNK per call.
    pub fn read_range(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        offset: u64,
        len: u32,
    ) -> Result<Option<Vec<u8>>> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 64];
        let n = admin_wire::encode_read_file_range(
            &mut buf,
            cid,
            offset,
            len.min(IO_CHUNK as u32),
            namespace_root,
            path,
        )
        .map_err(ClientError::Protocol)?;
        let (status, bytes) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_read_file_range_ack(b)
                    .map(|(c, s, d)| (c, (s, d.map(|d| d.to_vec()))))
            },
            cid,
        )?;
        match status {
            admin_wire::STATUS_OK => Ok(bytes),
            admin_wire::STATUS_NOT_FOUND => Ok(None),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// Size of the file, without transferring the body. `None` if
    /// the path is not bound.
    pub fn stat_file(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<Option<u64>> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 32];
        let n = admin_wire::encode_stat_file(&mut buf, cid, namespace_root, path)
            .map_err(ClientError::Protocol)?;
        let (status, size) = self.round_trip(
            &buf[..n],
            |b| admin_wire::decode_stat_file_ack(b).map(|(c, s, sz)| (c, (s, sz))),
            cid,
        )?;
        match status {
            admin_wire::STATUS_OK => Ok(Some(size)),
            admin_wire::STATUS_NOT_FOUND => Ok(None),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// Unbind `(namespace_root, path)`. Returns whether the binding
    /// existed. The body blob stays (content-addressed, possibly
    /// shared); orphan GC collects it when nothing references it.
    pub fn delete_file(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<bool> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 32];
        let n = admin_wire::encode_admin_delete_file(&mut buf, cid, namespace_root, path)
            .map_err(ClientError::Protocol)?;
        let status = self.round_trip(&buf[..n], admin_wire::decode_admin_delete_file_ack, cid)?;
        match status {
            admin_wire::STATUS_OK => Ok(true),
            admin_wire::STATUS_NOT_FOUND => Ok(false),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// Every bound path under `namespace_root` (cursor paging is
    /// internal).
    pub fn list_files(&mut self, namespace_root: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut cursor = 0u32;
        loop {
            let cid = self.cid();
            let mut buf = vec![0u8; namespace_root.len() + 32];
            let n = admin_wire::encode_admin_list_files(&mut buf, cid, namespace_root, cursor, 16)
                .map_err(ClientError::Protocol)?;
            let (status, next, page) = self.round_trip(
                &buf[..n],
                |b| {
                    let mut page = Vec::new();
                    admin_wire::decode_admin_list_files_ack(b, |p| page.push(p.to_vec()))
                        .map(|(c, s, next, _)| (c, (s, next, page)))
                },
                cid,
            )?;
            if status != admin_wire::STATUS_OK {
                return Err(ClientError::Nak(status));
            }
            out.extend(page);
            if next == 0 {
                break;
            }
            cursor = next;
        }
        Ok(out)
    }
}

// ── Block volumes ──────────────────────────────────────────────────
//
// A volume is a content-addressed DESCRIPTOR file (put_file at the
// volume's path — replicated, listable, GC-referenced like any
// file) plus N fixed-size extents in the body plane under derived
// keys (loam_extent_wire). Extents are mutable keyed blobs;
// sub-extent writes read-modify-write client-side, which is sound
// under the single-attacher discipline block volumes get from
// their consumer (one NBD/ublk/FUSE publisher at a time).

/// An open volume handle: the decoded descriptor plus identity.
#[derive(Debug, Clone)]
pub struct Volume {
    pub namespace_root: Vec<u8>,
    pub path: Vec<u8>,
    pub desc: extent_wire::VolumeDesc,
}

impl Volume {
    fn extent_count(&self) -> u64 {
        let es = self.desc.extent_size as u64;
        self.desc.size_bytes.div_ceil(es)
    }
    /// Payload length of extent `idx` (the tail extent is short
    /// when the volume size isn't a multiple of the extent size).
    fn extent_len(&self, idx: u64) -> usize {
        let es = self.desc.extent_size as u64;
        let start = idx * es;
        ((self.desc.size_bytes - start).min(es)) as usize
    }
    fn key(&self, idx: u64) -> [u8; 32] {
        extent_wire::derive_extent_key(&self.desc.volume_id, idx)
    }
}

impl LoamClient {
    /// Raw keyed body write (mutable, last write wins).
    pub fn put_body_keyed(&mut self, key: &[u8; 32], blob: &[u8]) -> Result<()> {
        let cid = self.cid();
        let mut buf = vec![0u8; blob.len() + 64];
        let n = admin_wire::encode_admin_put_body_keyed(&mut buf, cid, key, blob)
            .map_err(ClientError::Protocol)?;
        let status =
            self.round_trip(&buf[..n], admin_wire::decode_admin_put_body_keyed_ack, cid)?;
        if status != admin_wire::STATUS_OK {
            return Err(ClientError::Nak(status));
        }
        Ok(())
    }

    /// Raw body read by key/digest. `None` when the blob doesn't
    /// exist anywhere in the fleet.
    pub fn get_body(&mut self, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let cid = self.cid();
        let mut buf = vec![0u8; 64];
        let n =
            admin_wire::encode_admin_get_body(&mut buf, cid, key).map_err(ClientError::Protocol)?;
        let (status, body) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_admin_get_body_ack(b)
                    .map(|(c, s, d)| (c, (s, d.map(|d| d.to_vec()))))
            },
            cid,
        )?;
        match status {
            admin_wire::STATUS_OK => Ok(body),
            admin_wire::STATUS_NOT_FOUND => Ok(None),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// Raw body delete by key/digest. Returns whether it existed.
    pub fn delete_body(&mut self, key: &[u8; 32]) -> Result<bool> {
        let cid = self.cid();
        let mut buf = vec![0u8; 64];
        let n = admin_wire::encode_admin_delete_body(&mut buf, cid, key)
            .map_err(ClientError::Protocol)?;
        let (status, existed) = self.round_trip(
            &buf[..n],
            |b| admin_wire::decode_admin_delete_body_ack(b).map(|(c, s, e)| (c, (s, e))),
            cid,
        )?;
        if status != admin_wire::STATUS_OK {
            return Err(ClientError::Nak(status));
        }
        Ok(existed)
    }

    /// Create a volume: writes the descriptor file. Extents
    /// materialize lazily on first write (unwritten ranges read as
    /// zeros).
    pub fn create_volume(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        size_bytes: u64,
        extent_size: u32,
    ) -> Result<Volume> {
        let desc = extent_wire::VolumeDesc {
            volume_id: extent_wire::derive_volume_id(namespace_root, path),
            size_bytes,
            extent_size,
        };
        let mut buf = [0u8; extent_wire::VOL_DESC_LEN];
        let n = encode_desc(&mut buf, &desc)?;
        self.put_file(namespace_root, path, 1, &buf[..n])?;
        Ok(Volume {
            namespace_root: namespace_root.to_vec(),
            path: path.to_vec(),
            desc,
        })
    }

    /// Open an existing volume by its descriptor file. `None` if
    /// the path isn't bound; a bound path that doesn't hold a
    /// volume descriptor is a protocol error.
    pub fn open_volume(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<Option<Volume>> {
        let bytes = match self.get_file(namespace_root, path)? {
            Some(b) => b,
            None => return Ok(None),
        };
        let desc = extent_wire::decode_volume_desc(&bytes)
            .map_err(|_| ClientError::Nak(admin_wire::STATUS_NAK))?;
        Ok(Some(Volume {
            namespace_root: namespace_root.to_vec(),
            path: path.to_vec(),
            desc,
        }))
    }

    /// Read `buf.len()` bytes at `offset`. Unwritten extents read
    /// as zeros. Errors if the range exceeds the volume.
    pub fn volume_read(&mut self, vol: &Volume, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(vol, offset, buf.len())?;
        let es = vol.desc.extent_size as u64;
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let idx = pos / es;
            let in_ext = (pos % es) as usize;
            let take = (buf.len() - done).min(vol.extent_len(idx) - in_ext);
            match self.get_body(&vol.key(idx))? {
                Some(blob) => {
                    let (_, payload) = extent_wire::decode_extent_blob(&blob)
                        .map_err(|_| ClientError::Nak(admin_wire::STATUS_NAK))?;
                    // A short stored payload (never written past
                    // its tail) zero-fills the remainder.
                    for i in 0..take {
                        buf[done + i] = payload.get(in_ext + i).copied().unwrap_or(0);
                    }
                }
                None => buf[done..done + take].fill(0),
            }
            done += take;
        }
        Ok(())
    }

    /// Write `data` at `offset`, read-modify-writing partially
    /// covered extents. Errors if the range exceeds the volume.
    pub fn volume_write(&mut self, vol: &Volume, offset: u64, data: &[u8]) -> Result<()> {
        check_range(vol, offset, data.len())?;
        let es = vol.desc.extent_size as u64;
        let mut done = 0usize;
        while done < data.len() {
            let pos = offset + done as u64;
            let idx = pos / es;
            let in_ext = (pos % es) as usize;
            let ext_len = vol.extent_len(idx);
            let take = (data.len() - done).min(ext_len - in_ext);
            let key = vol.key(idx);
            let mut payload = vec![0u8; ext_len];
            if in_ext != 0 || take != ext_len {
                // Partial cover: merge over the current bytes.
                if let Some(blob) = self.get_body(&key)? {
                    let (_, existing) = extent_wire::decode_extent_blob(&blob)
                        .map_err(|_| ClientError::Nak(admin_wire::STATUS_NAK))?;
                    payload[..existing.len().min(ext_len)]
                        .copy_from_slice(&existing[..existing.len().min(ext_len)]);
                }
            }
            payload[in_ext..in_ext + take].copy_from_slice(&data[done..done + take]);
            let mut blob = vec![0u8; extent_wire::EXT_HDR + payload.len()];
            let n = extent_wire::encode_extent_blob(&mut blob, &key, &payload)
                .map_err(|_| ClientError::Nak(admin_wire::STATUS_NAK))?;
            self.put_body_keyed(&key, &blob[..n])?;
            done += take;
        }
        Ok(())
    }

    /// Delete a volume: every extent, then the descriptor binding.
    pub fn delete_volume(&mut self, vol: &Volume) -> Result<()> {
        for idx in 0..vol.extent_count() {
            let _ = self.delete_body(&vol.key(idx))?;
        }
        self.delete_file(&vol.namespace_root.clone(), &vol.path.clone())?;
        Ok(())
    }
}

fn check_range(vol: &Volume, offset: u64, len: usize) -> Result<()> {
    if offset
        .checked_add(len as u64)
        .map(|end| end <= vol.desc.size_bytes)
        != Some(true)
    {
        return Err(ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "range exceeds volume size",
        )));
    }
    Ok(())
}

fn encode_desc(dst: &mut [u8], desc: &extent_wire::VolumeDesc) -> Result<usize> {
    extent_wire::encode_volume_desc(dst, desc).map_err(|_| ClientError::Nak(admin_wire::STATUS_NAK))
}
