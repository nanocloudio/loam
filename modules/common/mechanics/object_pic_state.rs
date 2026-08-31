// In-arena object-plane state machine. The PIC stores only the
// fields it needs for routing and counting; full descriptors stay on
// the WAL / Raft log. Same FNV-1a hashing approach as
// namespace_pic_state.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectSlot {
    pub object_id_hash: u64,
    pub namespace_hash: u64,
    pub size_bytes: u64,
    pub revision: u64,
    /// The content digest when the object id carries the
    /// content-derived form `sha256:<64 lowercase hex>`. Only such
    /// descriptors are enumerable, because only they have a
    /// lifecycle the storage substrate owns; an id from anywhere else
    /// belongs to whoever minted it, the same rule keyed body blobs
    /// follow.
    pub content_digest: [u8; DIGEST_LEN],
    pub id_derived: bool,
    pub data_class: u8,
    pub replica_count: u8,
    pub erasure: Option<(u8, u8)>,
    pub occupied: bool,
    /// The object id, stored whole. Identity is these bytes; the
    /// hash above only narrows the scan. FNV-1a is non-cryptographic
    /// and trivially collidable, so a hash-only match would let a
    /// caller who can name their own ids reach a descriptor that is
    /// not theirs. `loam_limits::MAX_OBJECT_ID` is enforced at the
    /// wire, so the id always fits and the comparison is always
    /// definitive.
    pub object_id_bytes: [u8; super::limits::MAX_OBJECT_ID],
    pub object_id_len: u8,
}

/// Content-derived object ids are `"sha256:"` plus 64 lowercase hex.
pub const DIGEST_LEN: usize = 32;
const ID_PREFIX: &[u8] = b"sha256:";
const DERIVED_ID_LEN: usize = 7 + 64;

/// Decode the content-derived object-id form, or `None` for any other
/// id shape.
pub fn derived_digest(object_id: &[u8]) -> Option<[u8; DIGEST_LEN]> {
    if object_id.len() != DERIVED_ID_LEN || &object_id[..7] != ID_PREFIX {
        return None;
    }
    let mut out = [0u8; DIGEST_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_val(object_id[7 + 2 * i])?;
        let lo = hex_val(object_id[8 + 2 * i])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

pub use super::hash::hex_val;

impl ObjectSlot {
    pub const fn empty() -> Self {
        Self {
            object_id_hash: 0,
            namespace_hash: 0,
            size_bytes: 0,
            revision: 0,
            content_digest: [0u8; DIGEST_LEN],
            id_derived: false,
            data_class: 0,
            replica_count: 0,
            erasure: None,
            occupied: false,
            object_id_bytes: [0u8; super::limits::MAX_OBJECT_ID],
            object_id_len: 0,
        }
    }

    /// The slot's stored object id.
    pub fn object_id(&self) -> &[u8] {
        &self.object_id_bytes[..self.object_id_len as usize]
    }

    /// Hash-narrowed, byte-decided identity. Never match on the hash
    /// alone.
    pub fn matches(&self, object_id_hash: u64, object_id: &[u8]) -> bool {
        self.occupied && self.object_id_hash == object_id_hash && self.object_id() == object_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyError {
    /// The object id exceeded `loam_limits::MAX_OBJECT_ID`. The wire
    /// refuses these first; this keeps a partial id unrepresentable
    /// even if a caller bypasses the wire.
    IdTooLong,
    /// The write would cross the root's ceiling. Distinct from
    /// `OutOfCapacity`, which is the DEVICE being full: one is this
    /// tenant's own limit and is fixed by deleting their own data or
    /// raising their quota, the other is everyone's problem. A
    /// caller that cannot tell them apart cannot act on either.
    QuotaExceeded,
    AlreadyPresent,
    NotPresent,
    OutOfCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOk {
    Put,
    Updated,
    Removed,
}

/// FNV-1a, from the one shared implementation. Three byte-identical
/// copies of a hash that narrows every identity scan is a drift
/// hazard, not a line count — see `loam_hash.rs`.
pub use super::hash::fnv1a64;

/// Per-root usage and its ceiling.
///
/// A bucket is already a tenancy boundary — the key domain, and the
/// SigV4 scope at the gateway — but a boundary with
/// no ceiling is a shared fate: one tenant fills the device and
/// every other tenant's writes start failing for reasons they cannot
/// see or fix.
///
/// Usage is DERIVED, not configured: it is recomputed by the same
/// mutations that change it, so it cannot drift from the slots the
/// way a separately-maintained counter would. WAL replay reruns
/// those mutations, so it reconstructs too.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RootUsage {
    pub namespace_hash: u64,
    pub objects: u64,
    pub bytes: u64,
    /// Ceilings. 0 means unlimited, which is what every root has
    /// until an operator says otherwise — a store that silently
    /// imposed one would be worse than one with none.
    pub max_objects: u64,
    pub max_bytes: u64,
    pub in_use: bool,
}

impl RootUsage {
    pub const fn empty() -> Self {
        Self {
            namespace_hash: 0,
            objects: 0,
            bytes: 0,
            max_objects: 0,
            max_bytes: 0,
            in_use: false,
        }
    }

    /// Would `add_bytes` more, in one more object, cross a ceiling?
    pub fn would_exceed(&self, add_bytes: u64) -> bool {
        (self.max_objects != 0 && self.objects.saturating_add(1) > self.max_objects)
            || (self.max_bytes != 0 && self.bytes.saturating_add(add_bytes) > self.max_bytes)
    }
}

/// Roots that can carry a quota at once. A root appears here only
/// once it holds an object or has a ceiling set, so this bounds
/// TENANTS, not keys.
pub const MAX_QUOTA_ROOTS: usize = 32;

pub struct PicObjectState<const N: usize> {
    slots: [ObjectSlot; N],
    roots: [RootUsage; MAX_QUOTA_ROOTS],
}

impl<const N: usize> PicObjectState<N> {
    pub const fn new() -> Self {
        Self {
            slots: [ObjectSlot::empty(); N],
            roots: [RootUsage::empty(); MAX_QUOTA_ROOTS],
        }
    }

    /// Usage for a root, if it has any.
    pub fn usage(&self, namespace: &[u8]) -> Option<&RootUsage> {
        let h = fnv1a64(namespace);
        self.roots
            .iter()
            .find(|r| r.in_use && r.namespace_hash == h)
    }

    /// Set a root's ceilings. 0 means unlimited. Setting a ceiling
    /// BELOW current usage is allowed and does not delete anything:
    /// it stops growth, which is what an operator reducing a quota
    /// means. Refusing would leave them no way to say it.
    pub fn set_quota(
        &mut self,
        namespace: &[u8],
        max_objects: u64,
        max_bytes: u64,
    ) -> Result<(), ApplyError> {
        let h = fnv1a64(namespace);
        let idx = self.root_slot(h).ok_or(ApplyError::OutOfCapacity)?;
        self.roots[idx].max_objects = max_objects;
        self.roots[idx].max_bytes = max_bytes;
        Ok(())
    }

    /// Find or claim the usage slot for a root hash.
    fn root_slot(&mut self, h: u64) -> Option<usize> {
        for i in 0..MAX_QUOTA_ROOTS {
            if self.roots[i].in_use && self.roots[i].namespace_hash == h {
                return Some(i);
            }
        }
        for i in 0..MAX_QUOTA_ROOTS {
            if !self.roots[i].in_use {
                self.roots[i] = RootUsage {
                    namespace_hash: h,
                    in_use: true,
                    ..RootUsage::empty()
                };
                return Some(i);
            }
        }
        None
    }

    fn credit(&mut self, h: u64, bytes: u64) {
        if let Some(i) = self.root_slot(h) {
            self.roots[i].objects = self.roots[i].objects.saturating_add(1);
            self.roots[i].bytes = self.roots[i].bytes.saturating_add(bytes);
        }
    }

    fn debit(&mut self, h: u64, bytes: u64) {
        for i in 0..MAX_QUOTA_ROOTS {
            if self.roots[i].in_use && self.roots[i].namespace_hash == h {
                self.roots[i].objects = self.roots[i].objects.saturating_sub(1);
                self.roots[i].bytes = self.roots[i].bytes.saturating_sub(bytes);
                return;
            }
        }
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < N {
            if self.slots[i].occupied {
                n += 1;
            }
            i += 1;
        }
        n
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lookup(&self, object_id: &[u8]) -> Option<&ObjectSlot> {
        self.lookup_hashed(fnv1a64(object_id), object_id)
    }

    /// Resolve an id whose hash the caller already has. The id bytes
    /// are still required and still decide the match; there is no
    /// hash-only variant, by design.
    pub fn lookup_hashed(&self, object_id_hash: u64, object_id: &[u8]) -> Option<&ObjectSlot> {
        for s in &self.slots {
            if s.matches(object_id_hash, object_id) {
                return Some(s);
            }
        }
        None
    }

    /// Insert an entry. Object ids are content digests — immutable
    /// facts — so re-inserting an id with the SAME size is
    /// idempotent success (the composed PutFile path hits this
    /// whenever identical bytes are bound at a second path: dedup,
    /// not an error). The same id with a DIFFERENT size is a real
    /// conflict and errors.
    pub fn put_new(
        &mut self,
        object_id: &[u8],
        namespace: &[u8],
        size_bytes: u64,
        revision: u64,
        data_class: u8,
        replica_count: u8,
        erasure: Option<(u8, u8)>,
    ) -> Result<ApplyOk, ApplyError> {
        if object_id.len() > super::limits::MAX_OBJECT_ID {
            return Err(ApplyError::IdTooLong);
        }
        let id_h = fnv1a64(object_id);
        if let Some(existing) = self.lookup_hashed(id_h, object_id) {
            if existing.size_bytes == size_bytes {
                // Dedup, not a write: identical bytes bound at a
                // second path store one object. It must not be
                // charged twice, or a tenant's usage would grow
                // without their footprint growing.
                return Ok(ApplyOk::Put);
            }
            return Err(ApplyError::AlreadyPresent);
        }
        let ns_h = fnv1a64(namespace);
        // Checked BEFORE the slot is taken, so a refused write leaves
        // nothing behind.
        if let Some(u) = self
            .roots
            .iter()
            .find(|r| r.in_use && r.namespace_hash == ns_h)
        {
            if u.would_exceed(size_bytes) {
                return Err(ApplyError::QuotaExceeded);
            }
        }
        let derived = derived_digest(object_id);
        for s in self.slots.iter_mut() {
            if !s.occupied {
                *s = ObjectSlot {
                    object_id_hash: id_h,
                    namespace_hash: fnv1a64(namespace),
                    size_bytes,
                    revision,
                    content_digest: derived.unwrap_or([0u8; DIGEST_LEN]),
                    id_derived: derived.is_some(),
                    data_class,
                    replica_count,
                    erasure,
                    occupied: true,
                    object_id_bytes: {
                        let mut b = [0u8; super::limits::MAX_OBJECT_ID];
                        b[..object_id.len()].copy_from_slice(object_id);
                        b
                    },
                    object_id_len: object_id.len() as u8,
                };
                self.credit(ns_h, size_bytes);
                return Ok(ApplyOk::Put);
            }
        }
        Err(ApplyError::OutOfCapacity)
    }

    /// Overwrite an existing entry. The PIC apply path is permissive
    /// (quorum has validated); we do not enforce monotone revisions
    /// here — the proposer's quota and check pipeline did.
    pub fn update(
        &mut self,
        object_id: &[u8],
        namespace: &[u8],
        size_bytes: u64,
        revision: u64,
        data_class: u8,
        replica_count: u8,
        erasure: Option<(u8, u8)>,
    ) -> Result<ApplyOk, ApplyError> {
        let id_h = fnv1a64(object_id);
        let ns_h = fnv1a64(namespace);
        // Find the slot first so the old charge can be reversed
        // before the new one lands. An update that moved a root, or
        // changed a size, must leave both roots' usage correct.
        let mut prev: Option<(u64, u64)> = None;
        for s in self.slots.iter_mut() {
            if s.matches(id_h, object_id) {
                prev = Some((s.namespace_hash, s.size_bytes));
                s.namespace_hash = ns_h;
                s.size_bytes = size_bytes;
                s.revision = revision;
                s.data_class = data_class;
                s.replica_count = replica_count;
                s.erasure = erasure;
                break;
            }
        }
        match prev {
            Some((old_ns, old_bytes)) => {
                self.debit(old_ns, old_bytes);
                self.credit(ns_h, size_bytes);
                Ok(ApplyOk::Updated)
            }
            None => Err(ApplyError::NotPresent),
        }
    }

    pub fn remove(&mut self, object_id: &[u8]) -> Result<ApplyOk, ApplyError> {
        let id_h = fnv1a64(object_id);
        let mut freed: Option<(u64, u64)> = None;
        for s in self.slots.iter_mut() {
            if s.matches(id_h, object_id) {
                freed = Some((s.namespace_hash, s.size_bytes));
                *s = ObjectSlot::empty();
                break;
            }
        }
        match freed {
            Some((ns_h, bytes)) => {
                self.debit(ns_h, bytes);
                Ok(ApplyOk::Removed)
            }
            None => Err(ApplyError::NotPresent),
        }
    }

    /// One page of the descriptor inventory. Walks slots from
    /// `cursor`, writing the content digest of each occupied slot whose
    /// id is content-derived into `out`. Returns
    /// `(next_cursor, count)`; `next_cursor == 0` means the sweep
    /// wrapped, so a caller pages until it sees zero.
    ///
    /// Slot order is arena order, which changes as slots are reused.
    /// That makes the page boundary approximate: a descriptor can be
    /// missed or repeated across one pass. Both are safe — the sweep
    /// that consumes this proves absence again before deleting
    /// anything, and a missed descriptor is collected on a later pass.
    pub fn scan(&self, cursor: u32, out: &mut [[u8; DIGEST_LEN]]) -> (u32, usize) {
        let mut idx = cursor as usize;
        let mut count = 0usize;
        while idx < N && count < out.len() {
            let s = &self.slots[idx];
            if s.occupied && s.id_derived {
                out[count] = s.content_digest;
                count += 1;
            }
            idx += 1;
        }
        let next = if idx >= N { 0 } else { idx as u32 };
        (next, count)
    }

    /// Sum of `size_bytes` across all occupied slots — what a body
    /// quota would consult.
    pub fn total_size_bytes(&self) -> u64 {
        let mut total: u64 = 0;
        for s in &self.slots {
            if s.occupied {
                total = total.saturating_add(s.size_bytes);
            }
        }
        total
    }

    /// Count of slots belonging to a specific namespace.
    pub fn count_in_namespace(&self, namespace: &[u8]) -> usize {
        let ns_h = fnv1a64(namespace);
        let mut n = 0;
        for s in &self.slots {
            if s.occupied && s.namespace_hash == ns_h {
                n += 1;
            }
        }
        n
    }
}

impl<const N: usize> Default for PicObjectState<N> {
    fn default() -> Self {
        Self::new()
    }
}
