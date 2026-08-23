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

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

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
        }
    }
    pub fn matches(&self, object_id_hash: u64) -> bool {
        self.occupied && self.object_id_hash == object_id_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyError {
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

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

pub struct PicObjectState<const N: usize> {
    slots: [ObjectSlot; N],
}

impl<const N: usize> PicObjectState<N> {
    pub const fn new() -> Self {
        Self {
            slots: [ObjectSlot::empty(); N],
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
        self.lookup_hashed(fnv1a64(object_id))
    }

    pub fn lookup_hashed(&self, object_id_hash: u64) -> Option<&ObjectSlot> {
        for s in &self.slots {
            if s.matches(object_id_hash) {
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
        let id_h = fnv1a64(object_id);
        if let Some(existing) = self.lookup_hashed(id_h) {
            if existing.size_bytes == size_bytes {
                return Ok(ApplyOk::Put);
            }
            return Err(ApplyError::AlreadyPresent);
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
                };
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
        for s in self.slots.iter_mut() {
            if s.matches(id_h) {
                s.namespace_hash = fnv1a64(namespace);
                s.size_bytes = size_bytes;
                s.revision = revision;
                s.data_class = data_class;
                s.replica_count = replica_count;
                s.erasure = erasure;
                return Ok(ApplyOk::Updated);
            }
        }
        Err(ApplyError::NotPresent)
    }

    pub fn remove(&mut self, object_id: &[u8]) -> Result<ApplyOk, ApplyError> {
        let id_h = fnv1a64(object_id);
        for s in self.slots.iter_mut() {
            if s.matches(id_h) {
                *s = ObjectSlot::empty();
                return Ok(ApplyOk::Removed);
            }
        }
        Err(ApplyError::NotPresent)
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
