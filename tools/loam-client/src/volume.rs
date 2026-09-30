//! Block volumes: copy-on-write maps of content-addressed extents,
//! committed by a fenced, revisioned bind.
//!
//! A volume's committed state is its path bound to the digest of a map
//! root (`loam_volume_map_wire`) at a revision. Every extent version is
//! an ordinary body named by its digest, and so is every map page, so
//! nothing a reader resolves is ever overwritten. A writer holds the
//! volume's lease, stages changed extents in memory, and flushes them
//! as one commit: the new extent bodies, the leaves on the changed
//! paths, a new root, then the bind of the path to that root at the
//! next revision — refused unless the current revision is still the
//! one the writer started from and its lease is still the live one.
//! Before the bind every reader sees the old root; after it, the new
//! one. A crash in between leaves orphan bodies for the GC and the old
//! volume intact.
//!
//! Map pages are immutable, so the page cache is keyed by digest and
//! can never serve a stale page.

use crate::{admin_wire, map_wire, object_id_for, ClientError, Lease, LoamClient, Result, Sha256};
use crate::{digest_of_object_id, KIND_VOLUME};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Map pages one [`Volume`] keeps decoded. A page is at most 32 KiB of
/// digests, so the cache is at most 2 MiB per open volume; a depth-2
/// volume of 32 GiB has 1024 leaves, of which a working set of 64
/// covers 2 GiB of hot data without a map read.
pub const PAGE_CACHE_PAGES: usize = 64;

/// Extents a [`VolumeWriter`] holds staged before a write forces a
/// flush. At 32 KiB extents that is 8 MiB of dirty data. The writer
/// flushes on its own when a write would stage one more, so a caller
/// that never flushes still commits in bounded steps; a caller that
/// needs a durability point calls [`VolumeWriter::flush`].
pub const STAGED_EXTENTS_MAX: usize = 256;

/// How long a flush waits for a GC sweep's reservation to lift before
/// giving up. A sweep holds one for a single body's proof and deletion.
const BEGIN_PATIENCE: Duration = Duration::from_secs(10);
const BEGIN_RETRY: Duration = Duration::from_millis(5);

/// A binding as `lookup` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub object_id: Vec<u8>,
    pub revision: u64,
    pub kind: u8,
}

/// A fresh 16-byte lease holder identity: distinct per call, per process
/// and per start. Nothing about it is secret; it only has to differ
/// from every other attachment's.
pub fn random_holder() -> [u8; admin_wire::LEASE_HOLDER_LEN] {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut h = Sha256::new();
    h.update(b"loam-lease-holder");
    h.update(&std::process::id().to_le_bytes());
    h.update(&SEQ.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(&nanos.to_le_bytes());
    let mut rs = std::collections::hash_map::RandomState::new().build_hasher();
    rs.write_u64(nanos as u64);
    h.update(&rs.finish().to_le_bytes());
    let full = h.finalize();
    let mut out = [0u8; admin_wire::LEASE_HOLDER_LEN];
    out.copy_from_slice(&full[..admin_wire::LEASE_HOLDER_LEN]);
    out
}

fn volume_err(msg: impl Into<String>) -> ClientError {
    ClientError::Volume(msg.into())
}

/// A decoded leaf: the extent digests it holds.
type LeafDigests = Arc<Vec<[u8; 32]>>;

/// Leaf digests by page digest, bounded, oldest out first.
#[derive(Debug, Default)]
struct PageCache {
    pages: HashMap<[u8; 32], Arc<Vec<[u8; 32]>>>,
    order: VecDeque<[u8; 32]>,
}

impl PageCache {
    fn get(&self, digest: &[u8; 32]) -> Option<Arc<Vec<[u8; 32]>>> {
        self.pages.get(digest).cloned()
    }

    fn insert(&mut self, digest: [u8; 32], page: Arc<Vec<[u8; 32]>>) {
        if self.pages.insert(digest, page).is_some() {
            return;
        }
        self.order.push_back(digest);
        while self.order.len() > PAGE_CACHE_PAGES {
            if let Some(old) = self.order.pop_front() {
                self.pages.remove(&old);
            }
        }
    }
}

/// A volume at one committed revision: its geometry, its root, and a
/// cache of the leaf pages read through it.
#[derive(Debug)]
pub struct Volume {
    pub namespace_root: Vec<u8>,
    pub path: Vec<u8>,
    /// The revision of the binding this view resolved. A commit from
    /// this view is refused unless it is still the current one.
    pub revision: u64,
    /// The digest of the committed map root.
    pub root_digest: [u8; 32],
    pub volume_id: [u8; map_wire::VOLUME_ID_LEN],
    pub size_bytes: u64,
    pub extent_size: u32,
    pub depth: u8,
    children: Vec<[u8; 32]>,
    cache: PageCache,
}

impl Volume {
    fn from_root(
        namespace_root: &[u8],
        path: &[u8],
        revision: u64,
        root_digest: [u8; 32],
        page: &[u8],
    ) -> Result<Volume> {
        let root = map_wire::decode_root(page)
            .map_err(|e| volume_err(format!("map root does not decode: {e:?}")))?;
        let children = (0..root.count())
            .map(|i| root.child(i).unwrap_or(map_wire::ZERO_DIGEST))
            .collect();
        Ok(Volume {
            namespace_root: namespace_root.to_vec(),
            path: path.to_vec(),
            revision,
            root_digest,
            volume_id: root.volume_id,
            size_bytes: root.size_bytes,
            extent_size: root.extent_size,
            depth: root.depth,
            children,
            cache: PageCache::default(),
        })
    }

    pub fn extent_count(&self) -> u64 {
        self.size_bytes.div_ceil(self.extent_size as u64)
    }

    /// Payload length of extent `idx`: the tail extent is short when the
    /// size is not a multiple of the extent size.
    fn extent_len(&self, idx: u64) -> usize {
        let es = self.extent_size as u64;
        (self.size_bytes - idx * es).min(es) as usize
    }

    /// Extents leaf `child` covers.
    fn leaf_len(&self, child: u64) -> usize {
        let first = child * map_wire::PAGE_ENTRIES as u64;
        (self.extent_count() - first).min(map_wire::PAGE_ENTRIES as u64) as usize
    }

    fn check_range(&self, offset: u64, len: usize) -> Result<()> {
        if offset
            .checked_add(len as u64)
            .map(|end| end <= self.size_bytes)
            != Some(true)
        {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "range exceeds volume size",
            )));
        }
        Ok(())
    }

    /// The digests leaf `child` holds, from the cache or the store.
    fn leaf(&mut self, client: &mut LoamClient, child: u64) -> Result<Arc<Vec<[u8; 32]>>> {
        let digest = *self
            .children
            .get(child as usize)
            .ok_or_else(|| volume_err("leaf index past the map"))?;
        if digest == map_wire::ZERO_DIGEST {
            return Ok(Arc::new(vec![map_wire::ZERO_DIGEST; self.leaf_len(child)]));
        }
        if let Some(page) = self.cache.get(&digest) {
            return Ok(page);
        }
        let bytes = client
            .get_body(&digest)?
            .ok_or_else(|| volume_err("a committed leaf page is missing from the store"))?;
        let leaf = map_wire::decode_leaf(&bytes)
            .map_err(|e| volume_err(format!("leaf page does not decode: {e:?}")))?;
        if !map_wire::leaf_fits(&leaf, child, self.size_bytes, self.extent_size) {
            return Err(volume_err("leaf page does not fit its place in the map"));
        }
        let page: Arc<Vec<[u8; 32]>> = Arc::new(
            (0..leaf.count())
                .map(|i| leaf.digest(i).unwrap_or(map_wire::ZERO_DIGEST))
                .collect(),
        );
        self.cache.insert(digest, page.clone());
        Ok(page)
    }

    /// The committed digest of extent `idx`.
    fn extent_digest(&mut self, client: &mut LoamClient, idx: u64) -> Result<[u8; 32]> {
        let (child, slot) = map_wire::locate(self.depth, idx);
        if self.depth == 1 {
            return self
                .children
                .get(child as usize)
                .copied()
                .ok_or_else(|| volume_err("extent index past the map"));
        }
        let leaf = self.leaf(client, child)?;
        leaf.get(slot)
            .copied()
            .ok_or_else(|| volume_err("extent index past its leaf"))
    }

    /// The committed bytes of extent `idx`, `extent_len(idx)` long.
    fn extent(&mut self, client: &mut LoamClient, idx: u64) -> Result<Vec<u8>> {
        let len = self.extent_len(idx);
        let digest = self.extent_digest(client, idx)?;
        if digest == map_wire::ZERO_DIGEST {
            return Ok(vec![0u8; len]);
        }
        let mut bytes = client
            .get_body(&digest)?
            .ok_or_else(|| volume_err("a committed extent is missing from the store"))?;
        if bytes.len() > len {
            return Err(volume_err("a committed extent is longer than its slot"));
        }
        bytes.resize(len, 0);
        Ok(bytes)
    }

    /// Read `buf.len()` bytes at `offset` from this committed revision.
    /// Never-written extents read as zeros.
    pub fn read(&mut self, client: &mut LoamClient, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_with(client, offset, buf, |_| None)
    }

    fn read_with<'s>(
        &mut self,
        client: &mut LoamClient,
        offset: u64,
        buf: &mut [u8],
        staged: impl Fn(u64) -> Option<&'s [u8]>,
    ) -> Result<()> {
        self.check_range(offset, buf.len())?;
        let es = self.extent_size as u64;
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let idx = pos / es;
            let in_ext = (pos % es) as usize;
            let take = (buf.len() - done).min(self.extent_len(idx) - in_ext);
            match staged(idx) {
                Some(bytes) => {
                    buf[done..done + take].copy_from_slice(&bytes[in_ext..in_ext + take])
                }
                None => {
                    let bytes = self.extent(client, idx)?;
                    buf[done..done + take].copy_from_slice(&bytes[in_ext..in_ext + take]);
                }
            }
            done += take;
        }
        Ok(())
    }
}

impl LoamClient {
    /// The binding at `(namespace_root, path)` — object id, revision and
    /// kind — or `None` when the path is unbound. Reads no body.
    pub fn lookup(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<Option<Binding>> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + 32];
        let n = admin_wire::encode_admin_lookup(&mut buf, cid, namespace_root, path)?;
        let (status, binding) = self.round_trip(
            &buf[..n],
            |b| {
                admin_wire::decode_admin_lookup_ack(b).map(|(c, s, bd)| {
                    (
                        c,
                        (
                            s,
                            bd.map(|x| Binding {
                                object_id: x.object_id.to_vec(),
                                revision: x.revision,
                                kind: x.kind,
                            }),
                        ),
                    )
                })
            },
            cid,
        )?;
        match status {
            admin_wire::STATUS_OK => Ok(binding),
            admin_wire::STATUS_NOT_FOUND => Ok(None),
            s => Err(ClientError::Nak(s)),
        }
    }

    /// One volume record: `(status, revision)` exactly as the server
    /// answered. [`VolumeWriter`] is the intended user; this is public so
    /// a test or a tool can drive the protocol step by step.
    pub fn volume_record(
        &mut self,
        mode: u8,
        namespace_root: &[u8],
        path: &[u8],
        holder: &[u8; admin_wire::LEASE_HOLDER_LEN],
        fence: u64,
        expected: u64,
        object_id: &[u8],
    ) -> Result<(u8, u64)> {
        let cid = self.cid();
        let mut buf = vec![0u8; namespace_root.len() + path.len() + object_id.len() + 64];
        let n = admin_wire::encode_admin_volume(
            &mut buf,
            &admin_wire::DecodedAdminVolume {
                correlation_id: cid,
                mode,
                namespace_root,
                path,
                object_id,
                holder: *holder,
                fence,
                expected,
            },
        )?;
        self.round_trip(
            &buf[..n],
            |b| admin_wire::decode_admin_volume_ack(b).map(|(c, s, r)| (c, (s, r))),
            cid,
        )
    }

    /// Open a flush, waiting out a GC sweep's reservation.
    fn volume_begin(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        holder: &[u8; admin_wire::LEASE_HOLDER_LEN],
        fence: u64,
    ) -> Result<()> {
        let started = Instant::now();
        loop {
            let (status, _) = self.volume_record(
                admin_wire::VOLUME_BEGIN,
                namespace_root,
                path,
                holder,
                fence,
                0,
                &[],
            )?;
            match status {
                admin_wire::STATUS_OK => return Ok(()),
                admin_wire::STATUS_BUSY if started.elapsed() < BEGIN_PATIENCE => {
                    std::thread::sleep(BEGIN_RETRY)
                }
                s => return Err(ClientError::Nak(s)),
            }
        }
    }

    /// Create a volume of `size_bytes` in extents of `extent_size`: an
    /// empty map root, committed at revision 1.
    ///
    /// Creation is a commit like any other, under a lease taken and
    /// released here, from revision 0 — so it cannot overwrite a volume
    /// that exists (`Nak(STATUS_CONFLICT)`), and while another writer
    /// holds the path's lease it is refused `Nak(STATUS_LEASE_HELD)`.
    pub fn create_volume(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        size_bytes: u64,
        extent_size: u32,
    ) -> Result<Volume> {
        let depth = map_wire::select_depth(size_bytes, extent_size).map_err(|_| {
            volume_err(format!(
                "no map describes {size_bytes} bytes in {extent_size}-byte extents \
                 (extent size 1..={}, at most {} extents)",
                map_wire::MAX_EXTENT_SIZE,
                map_wire::PAGE_ENTRIES * map_wire::PAGE_ENTRIES
            ))
        })?;
        let extents = size_bytes.div_ceil(extent_size as u64);
        let children = if depth == 1 {
            extents
        } else {
            extents.div_ceil(map_wire::PAGE_ENTRIES as u64)
        };
        let mut volume_id = [0u8; map_wire::VOLUME_ID_LEN];
        volume_id.copy_from_slice(&random_holder());
        let zeros = vec![map_wire::ZERO_DIGEST; children as usize];
        let mut page = vec![0u8; map_wire::MAX_PAGE_LEN];
        let n = map_wire::encode_root(&mut page, &volume_id, size_bytes, extent_size, &zeros)
            .map_err(|e| volume_err(format!("root page: {e:?}")))?;
        page.truncate(n);

        let (revision, digest) =
            self.bind_new_volume(namespace_root, path, |c| c.put_body(&page))?;
        Volume::from_root(namespace_root, path, revision, digest, &page)
    }

    /// Bind a map root at `(namespace_root, path)`, which must be
    /// unbound, as a volume at revision 1 — the one way a volume binding
    /// comes to exist. Under a lease taken and released here, with a
    /// flush opened before `root` stores anything, so the orphan GC
    /// cannot collect what the bind is about to name. Answers the
    /// revision and the root digest.
    fn bind_new_volume(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        root: impl FnOnce(&mut LoamClient) -> Result<[u8; 32]>,
    ) -> Result<(u64, [u8; 32])> {
        let holder = random_holder();
        let lease = self.acquire_lease(namespace_root, path, &holder, 30_000)?;
        let committed = (|| -> Result<(u64, [u8; 32])> {
            self.volume_begin(namespace_root, path, &holder, lease.fence)?;
            let digest = root(self)?;
            let (status, revision) = self.volume_record(
                admin_wire::VOLUME_COMMIT,
                namespace_root,
                path,
                &holder,
                lease.fence,
                0,
                object_id_for(&digest).as_bytes(),
            )?;
            if status != admin_wire::STATUS_OK {
                return Err(ClientError::Nak(status));
            }
            Ok((revision, digest))
        })();
        let _ = self.release_lease(namespace_root, path, &holder);
        committed
    }

    /// Bind an existing map root at an unbound path, as a volume: a
    /// snapshot, or a clone. No bytes move.
    pub fn bind_volume_root(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        root_digest: &[u8; 32],
    ) -> Result<u64> {
        let digest = *root_digest;
        self.bind_new_volume(namespace_root, path, |_| Ok(digest))
            .map(|(revision, _)| revision)
    }

    /// Open the volume at `(namespace_root, path)` at its committed
    /// revision. `None` when the path is unbound; a path bound to
    /// anything but a volume map root is an error.
    pub fn open_volume(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<Option<Volume>> {
        let binding = match self.lookup(namespace_root, path)? {
            Some(b) => b,
            None => return Ok(None),
        };
        if binding.kind != KIND_VOLUME {
            return Err(volume_err("the path is bound, but not to a volume"));
        }
        let digest = digest_of_object_id(&binding.object_id)
            .ok_or_else(|| volume_err("a volume binding names no content digest"))?;
        let page = self
            .get_body(&digest)?
            .ok_or_else(|| volume_err("the committed map root is missing from the store"))?;
        if crate::content_digest(&page) != digest {
            return Err(volume_err("the map root's bytes do not match its digest"));
        }
        Volume::from_root(namespace_root, path, binding.revision, digest, &page).map(Some)
    }

    /// Read `buf.len()` bytes at `offset` from `vol`'s committed
    /// revision. Unwritten extents read as zeros.
    pub fn volume_read(&mut self, vol: &mut Volume, offset: u64, buf: &mut [u8]) -> Result<()> {
        vol.read(self, offset, buf)
    }

    /// Delete a volume: unbind its path, under a lease taken and
    /// released here and at the revision it has now — so it is refused
    /// `Nak(STATUS_LEASE_HELD)` while a writer holds the volume, and
    /// `Nak(STATUS_CONFLICT)` if a commit lands between the look and the
    /// delete. Its pages and extents are left to the orphan GC, which
    /// collects whatever no other binding — a snapshot, a clone — still
    /// reaches. Returns whether a volume was bound there; a path bound
    /// to anything else is an error.
    pub fn delete_volume(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<bool> {
        let binding = match self.lookup(namespace_root, path)? {
            Some(b) => b,
            None => return Ok(false),
        };
        if binding.kind != KIND_VOLUME {
            return Err(volume_err("the path is bound, but not to a volume"));
        }
        let holder = random_holder();
        let lease = self.acquire_lease(namespace_root, path, &holder, 30_000)?;
        let deleted = self.volume_record(
            admin_wire::VOLUME_DELETE,
            namespace_root,
            path,
            &holder,
            lease.fence,
            binding.revision,
            &[],
        );
        let _ = self.release_lease(namespace_root, path, &holder);
        match deleted? {
            (admin_wire::STATUS_OK, _) => Ok(true),
            (s, _) => Err(ClientError::Nak(s)),
        }
    }

    /// Every body the map root `root_digest` reaches: its leaf pages
    /// and written extents (not the root itself).
    pub fn volume_bodies(&mut self, root_digest: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let page = self
            .get_body(root_digest)?
            .ok_or_else(|| volume_err("map root missing from the store"))?;
        let root = map_wire::decode_root(&page)
            .map_err(|e| volume_err(format!("map root does not decode: {e:?}")))?;
        let mut out = Vec::new();
        for i in 0..root.count() {
            let child = root.child(i).unwrap_or(map_wire::ZERO_DIGEST);
            if child == map_wire::ZERO_DIGEST {
                continue;
            }
            out.push(child);
            if root.depth == 2 {
                let bytes = self
                    .get_body(&child)?
                    .ok_or_else(|| volume_err("leaf page missing from the store"))?;
                let leaf = map_wire::decode_leaf(&bytes)
                    .map_err(|e| volume_err(format!("leaf page does not decode: {e:?}")))?;
                for j in 0..leaf.count() {
                    let d = leaf.digest(j).unwrap_or(map_wire::ZERO_DIGEST);
                    if d != map_wire::ZERO_DIGEST {
                        out.push(d);
                    }
                }
            }
        }
        Ok(out)
    }
}

/// A flush whose bodies are written and whose commit is not yet asked.
#[derive(Debug)]
struct Prepared {
    root_digest: [u8; 32],
    children: Vec<[u8; 32]>,
    leaves: Vec<([u8; 32], LeafDigests)>,
}

/// The one writer of a volume.
///
/// Holds the volume's lease for its lifetime. Writes are staged in
/// memory, whole extents at a time, reading the committed version of
/// an extent a write only partly covers. [`flush`](Self::flush) makes
/// them durable and visible in one commit, or not at all.
///
/// A commit refused `STATUS_CONFLICT` (another commit landed on the
/// revision this writer started from) or `STATUS_LEASE_LOST` (the lease
/// has passed on) ENDS the writer: every later call fails, and the
/// staged writes are gone with it. There is deliberately no merge — the
/// writer's view of the volume is no longer the volume, and writing on
/// top of what it has not read is the corruption the commit exists to
/// refuse. Reopen and re-acquire instead.
///
/// The writer takes a `&mut LoamClient` per call rather than owning
/// one, so several writers — or a writer and a reader — can share one
/// admin connection.
#[derive(Debug)]
pub struct VolumeWriter {
    vol: Volume,
    holder: [u8; admin_wire::LEASE_HOLDER_LEN],
    lease: Lease,
    ttl_ms: u32,
    renewed_at: Instant,
    staged: BTreeMap<u64, Vec<u8>>,
    prepared: Option<Prepared>,
    ended: Option<String>,
}

impl VolumeWriter {
    /// Take `vol`'s writer lease as `holder` for `ttl_ms`, and write on
    /// top of `vol`'s revision. `Nak(STATUS_LEASE_HELD)` while another
    /// holder's lease is live.
    pub fn open(
        client: &mut LoamClient,
        vol: Volume,
        holder: [u8; admin_wire::LEASE_HOLDER_LEN],
        ttl_ms: u32,
    ) -> Result<VolumeWriter> {
        let lease = client.acquire_lease(&vol.namespace_root, &vol.path, &holder, ttl_ms)?;
        Ok(VolumeWriter {
            vol,
            holder,
            lease,
            ttl_ms,
            renewed_at: Instant::now(),
            staged: BTreeMap::new(),
            prepared: None,
            ended: None,
        })
    }

    /// The committed view this writer builds on.
    pub fn volume(&self) -> &Volume {
        &self.vol
    }

    pub fn lease(&self) -> Lease {
        self.lease
    }

    pub fn holder(&self) -> [u8; admin_wire::LEASE_HOLDER_LEN] {
        self.holder
    }

    /// Extents written and not yet committed.
    pub fn staged_extents(&self) -> usize {
        self.staged.len()
    }

    fn live(&self) -> Result<()> {
        match &self.ended {
            Some(why) => Err(volume_err(format!(
                "writer ended: {why}; reopen the volume"
            ))),
            None => Ok(()),
        }
    }

    fn end(&mut self, status: u8) -> ClientError {
        self.ended = Some(format!("commit refused (status 0x{status:02x})"));
        self.staged.clear();
        self.prepared = None;
        ClientError::Nak(status)
    }

    /// Extend the lease by its TTL. `Nak(STATUS_LEASE_LOST)` ends the
    /// writer: the lease has expired or passed on.
    pub fn renew(&mut self, client: &mut LoamClient) -> Result<()> {
        self.live()?;
        match client.renew_lease(
            &self.vol.namespace_root,
            &self.vol.path,
            &self.holder,
            self.ttl_ms,
        ) {
            Ok(l) => {
                self.lease = l;
                self.renewed_at = Instant::now();
                Ok(())
            }
            Err(ClientError::Nak(s)) if s == admin_wire::STATUS_LEASE_LOST => Err(self.end(s)),
            Err(e) => Err(e),
        }
    }

    /// Renew once half the TTL has passed since the last grant.
    fn renew_if_due(&mut self, client: &mut LoamClient) -> Result<()> {
        if self.renewed_at.elapsed() >= Duration::from_millis(self.ttl_ms as u64 / 2) {
            self.renew(client)?;
        }
        Ok(())
    }

    /// Stage `data` at `offset`. Nothing is visible to any other reader,
    /// or durable, until [`flush`](Self::flush) commits it. When one more
    /// extent would pass [`STAGED_EXTENTS_MAX`], what is staged is
    /// flushed first.
    pub fn write(&mut self, client: &mut LoamClient, offset: u64, data: &[u8]) -> Result<()> {
        self.live()?;
        if self.prepared.is_some() {
            return Err(volume_err(
                "a prepared flush is waiting for its commit; commit or abort it first",
            ));
        }
        self.vol.check_range(offset, data.len())?;
        let es = self.vol.extent_size as u64;
        let mut done = 0usize;
        while done < data.len() {
            let pos = offset + done as u64;
            let idx = pos / es;
            let in_ext = (pos % es) as usize;
            let ext_len = self.vol.extent_len(idx);
            let take = (data.len() - done).min(ext_len - in_ext);
            if !self.staged.contains_key(&idx) {
                if self.staged.len() >= STAGED_EXTENTS_MAX {
                    self.flush(client)?;
                }
                let base = if in_ext == 0 && take == ext_len {
                    vec![0u8; ext_len]
                } else {
                    self.vol.extent(client, idx)?
                };
                self.staged.insert(idx, base);
            }
            if let Some(ext) = self.staged.get_mut(&idx) {
                ext[in_ext..in_ext + take].copy_from_slice(&data[done..done + take]);
            }
            done += take;
        }
        Ok(())
    }

    /// Read through this writer: its own staged writes, over the
    /// committed revision it builds on.
    pub fn read(&mut self, client: &mut LoamClient, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.live()?;
        let staged = &self.staged;
        self.vol.read_with(client, offset, buf, |idx| {
            staged.get(&idx).map(|v| v.as_slice())
        })
    }

    /// Write everything staged into the store without committing it:
    /// open the flush, then the new extent bodies, the leaf pages on
    /// the changed paths, and the new root. Until [`commit`](Self::commit)
    /// nothing is visible, and a crash leaves only orphans.
    ///
    /// The flush is opened first so the orphan GC keeps these bodies:
    /// none of them is reachable from a bound root until the commit.
    pub fn prepare(&mut self, client: &mut LoamClient) -> Result<()> {
        self.live()?;
        if self.prepared.is_some() || self.staged.is_empty() {
            return Ok(());
        }
        self.renew_if_due(client)?;
        let (root, path) = (self.vol.namespace_root.clone(), self.vol.path.clone());
        match client.volume_begin(&root, &path, &self.holder, self.lease.fence) {
            Ok(()) => {}
            Err(ClientError::Nak(s)) if s == admin_wire::STATUS_LEASE_LOST => {
                return Err(self.end(s))
            }
            Err(e) => return Err(e),
        }
        match self.write_bodies(client) {
            Ok(p) => {
                self.prepared = Some(p);
                Ok(())
            }
            Err(e) => {
                // The open flush would keep the GC from every orphan
                // until the next commit; end it now.
                let _ = client.volume_record(
                    admin_wire::VOLUME_ABORT,
                    &root,
                    &path,
                    &self.holder,
                    self.lease.fence,
                    0,
                    &[],
                );
                Err(e)
            }
        }
    }

    fn write_bodies(&mut self, client: &mut LoamClient) -> Result<Prepared> {
        let mut extents: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
        for (idx, bytes) in &self.staged {
            let digest = if bytes.iter().all(|&b| b == 0) {
                map_wire::ZERO_DIGEST
            } else {
                client.put_body(bytes)?
            };
            extents.insert(*idx, digest);
        }
        let mut children = self.vol.children.clone();
        let mut leaves = Vec::new();
        if self.vol.depth == 1 {
            for (idx, digest) in &extents {
                children[*idx as usize] = *digest;
            }
        } else {
            let mut by_leaf: BTreeMap<u64, Vec<(usize, [u8; 32])>> = BTreeMap::new();
            for (idx, digest) in &extents {
                let (child, slot) = map_wire::locate(2, *idx);
                by_leaf.entry(child).or_default().push((slot, *digest));
            }
            let mut page = vec![0u8; map_wire::MAX_PAGE_LEN];
            for (child, changes) in by_leaf {
                let mut digests = (*self.vol.leaf(client, child)?).clone();
                for (slot, digest) in changes {
                    digests[slot] = digest;
                }
                if digests.iter().all(|d| *d == map_wire::ZERO_DIGEST) {
                    children[child as usize] = map_wire::ZERO_DIGEST;
                    continue;
                }
                let first = child * map_wire::PAGE_ENTRIES as u64;
                let n = map_wire::encode_leaf(&mut page, first, &digests)
                    .map_err(|e| volume_err(format!("leaf page: {e:?}")))?;
                let digest = client.put_body(&page[..n])?;
                children[child as usize] = digest;
                leaves.push((digest, Arc::new(digests)));
            }
        }
        let mut page = vec![0u8; map_wire::MAX_PAGE_LEN];
        let n = map_wire::encode_root(
            &mut page,
            &self.vol.volume_id,
            self.vol.size_bytes,
            self.vol.extent_size,
            &children,
        )
        .map_err(|e| volume_err(format!("root page: {e:?}")))?;
        let root_digest = client.put_body(&page[..n])?;
        Ok(Prepared {
            root_digest,
            children,
            leaves,
        })
    }

    /// Commit the prepared flush: bind the volume's path to the new root
    /// at the next revision. Answers the new revision, or the current
    /// one when nothing was prepared.
    ///
    /// Refused `Nak(STATUS_CONFLICT)` when another commit landed first
    /// and `Nak(STATUS_LEASE_LOST)` when this writer's lease is no longer
    /// the live one; both end the writer.
    pub fn commit(&mut self, client: &mut LoamClient) -> Result<u64> {
        self.live()?;
        let prepared = match self.prepared.take() {
            Some(p) => p,
            None => return Ok(self.vol.revision),
        };
        let oid = object_id_for(&prepared.root_digest);
        let (status, revision) = match client.volume_record(
            admin_wire::VOLUME_COMMIT,
            &self.vol.namespace_root,
            &self.vol.path,
            &self.holder,
            self.lease.fence,
            self.vol.revision,
            oid.as_bytes(),
        ) {
            Ok(v) => v,
            Err(e) => {
                // Unanswered: the commit may or may not have landed, so
                // keep it prepared — asking again is answered as done if
                // it did.
                self.prepared = Some(prepared);
                return Err(e);
            }
        };
        match status {
            admin_wire::STATUS_OK => {
                self.vol.revision = revision;
                self.vol.root_digest = prepared.root_digest;
                self.vol.children = prepared.children;
                for (digest, page) in prepared.leaves {
                    self.vol.cache.insert(digest, page);
                }
                self.staged.clear();
                Ok(revision)
            }
            admin_wire::STATUS_CONFLICT | admin_wire::STATUS_LEASE_LOST => Err(self.end(status)),
            s => Err(self.end(s)),
        }
    }

    /// Prepare and commit: every staged write becomes durable and
    /// visible at once, or none does.
    pub fn flush(&mut self, client: &mut LoamClient) -> Result<u64> {
        self.prepare(client)?;
        self.commit(client)
    }

    /// Discard what is staged and prepared, and close any open flush.
    pub fn abort(&mut self, client: &mut LoamClient) -> Result<()> {
        self.staged.clear();
        self.prepared = None;
        let (status, _) = client.volume_record(
            admin_wire::VOLUME_ABORT,
            &self.vol.namespace_root,
            &self.vol.path,
            &self.holder,
            self.lease.fence,
            0,
            &[],
        )?;
        if status == admin_wire::STATUS_OK || status == admin_wire::STATUS_LEASE_LOST {
            Ok(())
        } else {
            Err(ClientError::Nak(status))
        }
    }

    /// Give the lease up, discarding anything not committed. The next
    /// writer need not wait out the TTL.
    pub fn release(mut self, client: &mut LoamClient) -> Result<()> {
        self.staged.clear();
        self.prepared = None;
        client.release_lease(&self.vol.namespace_root, &self.vol.path, &self.holder)
    }
}
