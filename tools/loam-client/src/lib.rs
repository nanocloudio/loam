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

#[path = "../../../modules/common/mechanics/loam_limits.rs"]
mod limits;

#[path = "../../../modules/common/mechanics/loam_manifest_wire.rs"]
pub mod manifest_wire;

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

use admin_wire as wire;
use admin_wire::WireError;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Chunk size for streamed writes and ranged reads. Below the
/// body plane's single-shot MAX_BODY (60 KiB) with frame headroom.
pub const IO_CHUNK: usize = 48 * 1024;

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    /// A manifest could not be encoded or decoded.
    Manifest(String),
    /// The server requires authentication and this connection has
    /// not provided it, or the token was wrong. The server closes
    /// the connection either way, so recovery is to reconnect —
    /// not to retry on this one.
    Unauthenticated,
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
            ClientError::Manifest(m) => write!(f, "manifest: {m}"),
            ClientError::Unauthenticated => write!(
                f,
                "not authenticated — the server requires --admin-token; \
                 call authenticate() first, and reconnect after a failure"
            ),
            ClientError::Nak(s) => write!(f, "server nak (status 0x{s:02x})"),
            ClientError::Protocol(e) => write!(f, "protocol: {e:?}"),
            ClientError::CorrelationMismatch { expected, observed } => {
                write!(f, "correlation mismatch: sent {expected}, got {observed}")
            }
        }
    }
}

impl std::error::Error for ClientError {}

impl From<WireError> for ClientError {
    fn from(e: WireError) -> Self {
        ClientError::Protocol(e)
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// What the admin wire is carried over.
///
/// An enum rather than a `Box<dyn Read + Write>`: there are exactly
/// two transports, the dispatch is on the hot path of every frame,
/// and a concrete type keeps the error surface honest — a unix
/// socket and a TCP socket fail in different ways and the caller can
/// tell which it has.
enum Transport {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Unix(s) => s.read(buf),
            Transport::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Unix(s) => s.write(buf),
            Transport::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Unix(s) => s.flush(),
            Transport::Tcp(s) => s.flush(),
        }
    }
}

/// A blocking connection to a loam-server admin surface.
pub struct LoamClient {
    conn: Transport,
    next_cid: u32,
}

impl LoamClient {
    /// Connect to the unix admin socket at `path`.
    pub fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let conn = UnixStream::connect(path)?;
        conn.set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok(LoamClient {
            conn: Transport::Unix(conn),
            next_cid: 1,
        })
    }

    /// Connect to a remote admin surface over TCP.
    ///
    /// This is what lets a volume backend run somewhere other than
    /// the storage node. It is deliberately paired
    /// with [`authenticate`](Self::authenticate) in the docs and in
    /// every example, because the admin surface can bind, read and
    /// delete anything in any namespace: a server started without
    /// `--admin-token` will accept this connection and everything
    /// sent over it, and exposing THAT off-box is worse than having
    /// no remote transport at all.
    pub fn connect_tcp(addr: impl std::net::ToSocketAddrs) -> Result<Self> {
        let conn = TcpStream::connect(addr)?;
        conn.set_read_timeout(Some(Duration::from_secs(30)))?;
        conn.set_nodelay(true).ok();
        Ok(LoamClient {
            conn: Transport::Tcp(conn),
            next_cid: 1,
        })
    }

    /// Present `token` to the server. Must succeed before any other
    /// call when the server was started with `--admin-token`.
    ///
    /// A server that requires auth closes the connection on a wrong
    /// token rather than letting it be guessed again, so a failure
    /// here means reconnecting, not retrying.
    pub fn authenticate(&mut self, token: &[u8]) -> Result<()> {
        let cid = self.cid();
        let mut buf = vec![0u8; 8 + token.len()];
        let n = wire::encode_admin_auth(&mut buf, cid, token)?;
        let status = self.round_trip(&buf[..n], wire::decode_admin_auth_ack, cid)?;
        if status == wire::STATUS_OK {
            Ok(())
        } else {
            Err(ClientError::Unauthenticated)
        }
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
    /// Raw content-addressed body write. Returns the digest the
    /// store named it by, which is a fact about the bytes and not a
    /// choice — so two writers storing the same bytes get the same
    /// answer, on any cluster.
    pub fn put_body(&mut self, blob: &[u8]) -> Result<[u8; 32]> {
        let cid = self.cid();
        let mut buf = vec![0u8; blob.len() + 64];
        let n = admin_wire::encode_admin_put_body(&mut buf, cid, blob)
            .map_err(ClientError::Protocol)?;
        let (status, digest) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_admin_put_body_ack(b)
                    .map(|a| (a.correlation_id, (a.status, a.digest.map(|d| d.to_vec()))))
            },
            cid,
        )?;
        if status != admin_wire::STATUS_OK {
            return Err(ClientError::Nak(status));
        }
        let d = digest.ok_or(ClientError::Nak(status))?;
        let mut out = [0u8; 32];
        if d.len() != 32 {
            return Err(ClientError::Nak(status));
        }
        out.copy_from_slice(&d);
        Ok(out)
    }

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

// ── Snapshots, clones and portable export ────────────────────────
//
// Content addressing gives these away almost free, and the design
// exploits that rather than building a parallel mechanism:
//
//   snapshot = the same object ids bound under a second root
//   clone    = a snapshot restored into a writable root
//   export   = the manifest blob plus the bodies it names
//
// The consequence worth stating: **the orphan GC needs no changes at
// all.** It already asks "is this object id bound by anything?", and
// a snapshot's bindings are bindings. A design that instead
// reference-counted bodies would have needed a new durable counter,
// a new crash model for it, and a new way to be wrong.
//
// A snapshot costs N bindings, which is what the namespace's hot
// cache over a compacted snapshot file exists to absorb.

impl LoamClient {
    /// Bind `(namespace_root, path)` to an existing `object_id`
    /// without moving any bytes.
    ///
    /// This is the primitive a clone is built from: the body is
    /// already stored under its content digest, so a second name for
    /// it is a metadata write and nothing more.
    pub fn bind(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        object_id: &[u8],
        revision: u64,
    ) -> Result<()> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + object_id.len() + 64];
        let n = admin_wire::encode_admin_bind(
            &mut buf,
            cid,
            namespace_root,
            path,
            object_id,
            0,
            revision,
        )?;
        let status = self.round_trip(
            &buf[..n],
            |b| admin_wire::decode_admin_bind_ack(b).map(|a| (a.correlation_id, a.status)),
            cid,
        )?;
        if status == admin_wire::STATUS_OK {
            Ok(())
        } else {
            Err(ClientError::Nak(status))
        }
    }

    /// The content digest of the object bound at `path`, or `None`.
    ///
    /// COST: this reads the body to hash it. The descriptor already
    /// holds the digest and `STAT_FILE` could return it — that is the
    /// obvious optimisation and it is a wire change, deliberately not
    /// bundled into the feature that revealed the need. Snapshotting
    /// a large namespace therefore reads it once.
    pub fn digest_of(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<Option<[u8; 32]>> {
        let Some(body) = self.get_file(namespace_root, path)? else {
            return Ok(None);
        };
        let mut h = Sha256::new();
        h.update(&body);
        Ok(Some(h.finalize()))
    }

    /// Freeze everything under `src_root` as a snapshot bound under
    /// `snap_root`, and return the manifest describing it.
    ///
    /// Every entry is bound, not copied, so the snapshot shares its
    /// bodies with the live namespace — and pins them against the
    /// orphan GC by the ordinary means. The manifest is returned
    /// rather than stored, so the caller decides whether it is worth
    /// keeping; `put_file` it wherever you like, and it becomes an
    /// ordinary content-addressed object with binding, replication
    /// and GC unchanged.
    pub fn snapshot_create(&mut self, src_root: &[u8], snap_root: &[u8]) -> Result<Vec<u8>> {
        let keys = self.list_files(src_root)?;
        let mut digests: Vec<(Vec<u8>, [u8; 32])> = Vec::with_capacity(keys.len());
        for key in &keys {
            // A key that vanished between the listing and here is
            // simply not in the snapshot. A snapshot is of a moment,
            // and this is that moment's honest content — better than
            // failing the whole operation over one concurrent delete.
            if let Some(d) = self.digest_of(src_root, key)? {
                digests.push((key.clone(), d));
            }
        }
        for (key, digest) in &digests {
            let oid = object_id_for(digest);
            self.bind(snap_root, key, oid.as_bytes(), 1)?;
        }
        let refs: Vec<(&[u8], [u8; 32])> =
            digests.iter().map(|(k, d)| (k.as_slice(), *d)).collect();
        let mut out = vec![0u8; manifest_wire::encoded_len(src_root, &refs)];
        let n = manifest_wire::encode(&mut out, src_root, &refs)
            .map_err(|e| ClientError::Manifest(format!("{e:?}")))?;
        out.truncate(n);
        Ok(out)
    }

    /// Restore a manifest into `dst_root`, binding every entry to the
    /// body it names. With a fresh `dst_root` this is a CLONE: no
    /// bytes move, because the bodies are already there under their
    /// content digests.
    ///
    /// Returns how many entries were bound.
    pub fn snapshot_restore(&mut self, manifest: &[u8], dst_root: &[u8]) -> Result<usize> {
        let mut entries: Vec<(Vec<u8>, [u8; 32])> = Vec::new();
        manifest_wire::for_each(manifest, |key, digest| {
            entries.push((key.to_vec(), *digest));
        })
        .map_err(|e| ClientError::Manifest(format!("{e:?}")))?;
        for (key, digest) in &entries {
            let oid = object_id_for(digest);
            self.bind(dst_root, key, oid.as_bytes(), 1)?;
        }
        Ok(entries.len())
    }

    /// Drop every binding under `snap_root`.
    ///
    /// The bodies are NOT deleted here, and that is the point: they
    /// may still be named by the live namespace or another snapshot.
    /// Whatever is left unreferenced is the orphan GC's to reclaim,
    /// by the same rule it already applies to everything else.
    pub fn snapshot_delete(&mut self, snap_root: &[u8]) -> Result<usize> {
        let keys = self.list_files(snap_root)?;
        let mut n = 0;
        for key in &keys {
            if self.delete_file(snap_root, key)? {
                n += 1;
            }
        }
        Ok(n)
    }

    /// The digests a destination would need in order to receive this
    /// manifest — every digest it does not already hold.
    ///
    /// This is what makes a portable export cheap: the receiver asks
    /// only for what it lacks, and deduplication across the transfer
    /// is free because the names are content digests on both sides.
    pub fn manifest_missing_here(&mut self, manifest: &[u8]) -> Result<Vec<[u8; 32]>> {
        let mut want: Vec<[u8; 32]> = Vec::new();
        manifest_wire::for_each(manifest, |_, d| want.push(*d))
            .map_err(|e| ClientError::Manifest(format!("{e:?}")))?;
        want.sort_unstable();
        want.dedup();
        let mut missing = Vec::new();
        for d in want {
            if self.get_body(&d)?.is_none() {
                missing.push(d);
            }
        }
        Ok(missing)
    }
}

/// Copy a snapshot from `src` to `dst`, transferring only the
/// bodies `dst` lacks, then binding the manifest's entries under
/// `dst_root`.
///
/// It is deliberately a FUNCTION OVER TWO CLIENTS rather than a
/// protocol. The manifest is encryption-agnostic and its digests are
/// over plaintext, so a manifest means the same thing on both sides
/// whatever
/// keys each cluster holds — which is what lets the whole transfer
/// be ordinary reads and writes.
///
/// Deduplication across the transfer is free: the receiver is asked
/// what it lacks, and "lacks" is decided by content digest, so
/// bytes it already holds under any other name are never sent.
///
/// ORDER MATTERS and is the one invariant here. Every body lands
/// BEFORE any binding names it. A binding whose body has not
/// arrived is a dangling name — a reader gets a not-found for
/// something the namespace says exists — and on an interrupted
/// transfer that state would persist. Bodies first means an
/// interrupted export leaves unreferenced blobs, which the orphan
/// sweep reclaims, rather than broken names, which nothing repairs.
///
/// Returns `(bodies_sent, entries_bound)`.
pub fn export_snapshot(
    src: &mut LoamClient,
    dst: &mut LoamClient,
    manifest: &[u8],
    dst_root: &[u8],
) -> Result<(usize, usize)> {
    // 1. Ask the DESTINATION what it lacks. Asking the source would
    //    send everything.
    let missing = dst.manifest_missing_here(manifest)?;

    // 2. Ship exactly those, verifying as we go. A digest the source
    //    cannot produce is a broken manifest, not something to skip
    //    quietly — skipping would produce a snapshot at the
    //    destination that silently contains less than it claims.
    let mut sent = 0usize;
    for digest in &missing {
        let body = src.get_body(digest)?.ok_or_else(|| {
            ClientError::Manifest(format!(
                "source does not hold {}, so this manifest cannot be exported whole",
                hex_digest(digest)
            ))
        })?;
        let landed = dst.put_body(&body)?;
        if &landed != digest {
            // Content addressing makes this checkable for free, and
            // it is worth checking: it catches a corrupted transfer
            // and a store that named the bytes differently.
            return Err(ClientError::Manifest(format!(
                "destination named the body {} where the manifest says {}",
                hex_digest(&landed),
                hex_digest(digest)
            )));
        }
        sent += 1;
    }

    // 3. Only now bind. See ORDER MATTERS above.
    let bound = dst.snapshot_restore(manifest, dst_root)?;
    Ok((sent, bound))
}

fn hex_digest(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The content-derived object id for a digest: `sha256:<64 hex>`.
/// The one form `object_index` treats as enumerable, because it is
/// the one whose lifecycle the storage substrate owns.
pub fn object_id_for(digest: &[u8; 32]) -> String {
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256:");
    for b in digest {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}
