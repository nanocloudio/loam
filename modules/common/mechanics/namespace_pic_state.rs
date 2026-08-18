// In-arena namespace state machine for the namespace_router PIC.
//
// PIC modules are no_std and arena-bounded. Real namespaces have
// millions of bindings; a PIC arena holds tens to hundreds. The PIC
// is therefore a HOT-PATH CACHE of recently-committed bindings, not
// the durable state — that lives in WAL + Raft log, accessible via
// other modules or host paths.
//
// State shape: a fixed-size array of binding slots. Each slot is
// (path_hash, object_id_hash, revision, kind, occupied). Lookups are
// O(N) linear scan (N small, branch-predictable). Inserts and
// removes mutate in place. Capacity is set at compile time via the
// const generic so different PIC builds can pick different sizes.
//
// Path strings aren't stored — only their FNV-1a 64-bit hash. The
// PIC answers questions of the form "does this path-hash currently
// resolve to an object_id_hash?". A higher-level module (or the
// host) holds the path→hash mapping for queries that need the full
// path.
//
// Same code compiles under no_std (PIC) and under std (host tests).

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceKindCode {
    File,
    Directory,
    Object,
    Volume,
    Symlink,
}

impl NamespaceKindCode {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::File),
            1 => Some(Self::Directory),
            2 => Some(Self::Object),
            3 => Some(Self::Volume),
            4 => Some(Self::Symlink),
            _ => None,
        }
    }
    pub fn to_u8(self) -> u8 {
        match self {
            Self::File => 0,
            Self::Directory => 1,
            Self::Object => 2,
            Self::Volume => 3,
            Self::Symlink => 4,
        }
    }
}

/// Max inline ObjectId length stored alongside a binding. Covers
/// `sha256:<64 hex chars>` (71 bytes) with generous headroom for
/// other identity schemes.
pub const MAX_OBJECT_ID: usize = 96;

/// Max inline path / root bytes stored for LIST enumeration.
/// Bindings with longer paths still bind/lookup/unbind normally
/// (hashes are authoritative) but don't appear in listings —
/// `path_len = 0` marks them unlistable.
pub const MAX_LIST_PATH: usize = 160;
pub const MAX_LIST_ROOT: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingSlot {
    pub namespace_hash: u64,
    pub path_hash: u64,
    pub object_id_hash: u64,
    pub revision: u64,
    pub kind: u8,
    pub occupied: bool,
    /// Full ObjectId bytes, stored inline so OP_LOOKUP can return
    /// the original id (not just its hash). `object_id_len = 0`
    /// when the binder didn't supply one (legacy WAL replay) or
    /// the id exceeded MAX_OBJECT_ID — the hash is still authoritative.
    pub object_id_bytes: [u8; MAX_OBJECT_ID],
    pub object_id_len: u8,
    /// Inline path bytes for OP_LIST (0 = unlistable, hash-only).
    pub path_bytes: [u8; MAX_LIST_PATH],
    pub path_len: u8,
    pub root_bytes: [u8; MAX_LIST_ROOT],
    pub root_len: u8,
    /// 1 = this slot's CURRENT revision is covered by the DURABLE
    /// on-disk snapshot, making it evictable. Any mutation clears
    /// it.
    pub snapshotted: u8,
    /// Compactor emit tag: set to the running compaction's
    /// generation byte when this slot's key has been merged into
    /// the not-yet-durable new snapshot; promoted to `snapshotted`
    /// only at durable finish. Any mutation clears it, so a slot
    /// freed and reused mid-compaction can never be mismarked.
    pub cmp_emitted: u8,
}

/// `kind` marking a deletion that must mask an on-disk snapshot
/// record until the next compaction drops both.
pub const KIND_TOMBSTONE: u8 = 0xFE;

impl BindingSlot {
    pub const fn empty() -> Self {
        Self {
            namespace_hash: 0,
            path_hash: 0,
            object_id_hash: 0,
            revision: 0,
            kind: 0,
            occupied: false,
            object_id_bytes: [0u8; MAX_OBJECT_ID],
            object_id_len: 0,
            path_bytes: [0u8; MAX_LIST_PATH],
            path_len: 0,
            root_bytes: [0u8; MAX_LIST_ROOT],
            root_len: 0,
            snapshotted: 0,
            cmp_emitted: 0,
        }
    }

    pub fn matches(&self, namespace_hash: u64, path_hash: u64) -> bool {
        self.occupied && self.namespace_hash == namespace_hash && self.path_hash == path_hash
    }

    /// Borrow the inline ObjectId bytes (empty slice if length == 0).
    pub fn object_id(&self) -> &[u8] {
        let len = self.object_id_len as usize;
        if len == 0 || len > MAX_OBJECT_ID {
            &[]
        } else {
            &self.object_id_bytes[..len]
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyError {
    /// `bind` against a slot that's already occupied for that key.
    AlreadyBound,
    /// `rename`/`unbind` against an empty key.
    NotBound,
    /// `rename` destination is already occupied.
    DestinationOccupied,
    /// Capacity exhausted — no free slot to use for a `bind` or
    /// `rename`.
    OutOfCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOk {
    Bound { revision: u64 },
    Renamed { new_revision: u64 },
    Unbound,
}

/// FNV-1a 64-bit. Same algorithm as `partition_assignment`; suitable
/// for non-cryptographic identity hashes.
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

pub fn key_hash(namespace_root: &[u8], path: &[u8]) -> (u64, u64) {
    (fnv1a64(namespace_root), fnv1a64(path))
}

/// Fixed-capacity binding table. `N` must be a compile-time
/// constant. Lookups + mutations are O(N) — N is meant to be small
/// (16…256) for PIC use; the host runtime uses LoamInstance instead.
pub struct PicNamespaceState<const N: usize> {
    slots: [BindingSlot; N],
}

impl<const N: usize> PicNamespaceState<N> {
    pub const fn new() -> Self {
        Self {
            slots: [BindingSlot::empty(); N],
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

    pub fn lookup(&self, namespace_root: &[u8], path: &[u8]) -> Option<&BindingSlot> {
        let (ns_h, p_h) = key_hash(namespace_root, path);
        self.lookup_hashed(ns_h, p_h)
    }

    pub fn lookup_hashed(&self, namespace_hash: u64, path_hash: u64) -> Option<&BindingSlot> {
        for s in &self.slots {
            if s.matches(namespace_hash, path_hash) {
                return Some(s);
            }
        }
        None
    }

    pub fn bind(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        object_id: &[u8],
        kind: u8,
        revision: u64,
    ) -> Result<ApplyOk, ApplyError> {
        let (ns_h, p_h) = key_hash(namespace_root, path);
        let oid_h = fnv1a64(object_id);
        // Rebind-as-upsert, gated on a STRICTLY higher revision:
        // producers that advance a pointer (key → new content digest)
        // pass a monotone revision per write; replays of older binds
        // (e.g. WAL/commit-stream replay) land on the AlreadyBound arm
        // and cannot regress the pointer. Same-revision re-binds are
        // idempotent duplicates — also rejected, arena unchanged.
        for s in self.slots.iter_mut() {
            if s.occupied && s.matches(ns_h, p_h) {
                if revision > s.revision {
                    s.object_id_hash = oid_h;
                    s.revision = revision;
                    s.kind = kind;
                    s.snapshotted = 0;
                    s.cmp_emitted = 0;
                    s.object_id_len = 0;
                    if !object_id.is_empty() && object_id.len() <= MAX_OBJECT_ID {
                        s.object_id_bytes[..object_id.len()].copy_from_slice(object_id);
                        s.object_id_len = object_id.len() as u8;
                    }
                    return Ok(ApplyOk::Bound { revision });
                }
                return Err(ApplyError::AlreadyBound);
            }
        }
        for s in self.slots.iter_mut() {
            if !s.occupied {
                let mut slot = BindingSlot {
                    namespace_hash: ns_h,
                    path_hash: p_h,
                    object_id_hash: oid_h,
                    revision,
                    kind,
                    occupied: true,
                    ..BindingSlot::empty()
                };
                if !object_id.is_empty() && object_id.len() <= MAX_OBJECT_ID {
                    slot.object_id_bytes[..object_id.len()].copy_from_slice(object_id);
                    slot.object_id_len = object_id.len() as u8;
                }
                // Inline path/root for LIST — oversize keys stay
                // bindable but unlistable (len 0).
                if !path.is_empty() && path.len() <= MAX_LIST_PATH {
                    slot.path_bytes[..path.len()].copy_from_slice(path);
                    slot.path_len = path.len() as u8;
                }
                if !namespace_root.is_empty() && namespace_root.len() <= MAX_LIST_ROOT {
                    slot.root_bytes[..namespace_root.len()].copy_from_slice(namespace_root);
                    slot.root_len = namespace_root.len() as u8;
                }
                *s = slot;
                return Ok(ApplyOk::Bound { revision });
            }
        }
        Err(ApplyError::OutOfCapacity)
    }

    pub fn rename(
        &mut self,
        namespace_root: &[u8],
        from: &[u8],
        to: &[u8],
        new_revision: u64,
    ) -> Result<ApplyOk, ApplyError> {
        let (ns_h, from_h) = key_hash(namespace_root, from);
        let (_, to_h) = key_hash(namespace_root, to);
        if self.lookup_hashed(ns_h, to_h).is_some() {
            return Err(ApplyError::DestinationOccupied);
        }
        for s in self.slots.iter_mut() {
            if s.matches(ns_h, from_h) {
                s.path_hash = to_h;
                s.revision = new_revision;
                s.snapshotted = 0;
                s.cmp_emitted = 0;
                s.path_len = 0;
                if !to.is_empty() && to.len() <= MAX_LIST_PATH {
                    s.path_bytes[..to.len()].copy_from_slice(to);
                    s.path_len = to.len() as u8;
                }
                return Ok(ApplyOk::Renamed { new_revision });
            }
        }
        Err(ApplyError::NotBound)
    }

    /// Is `object_id` bound by ANY occupied slot, in any root?
    /// Used by orphan-body GC. Conservative in the safe direction:
    /// a slot that matches by hash but stored no id bytes counts
    /// as a reference (keeping a blob is always safe; deleting a
    /// referenced one never is).
    pub fn object_id_referenced(&self, object_id: &[u8]) -> bool {
        let h = fnv1a64(object_id);
        self.slots.iter().any(|s| {
            s.occupied
                && s.object_id_hash == h
                && (s.object_id_len == 0 || s.object_id() == object_id)
        })
    }

    /// Replace (or insert) a binding with a TOMBSTONE at
    /// `revision` — a deletion that must keep masking the on-disk
    /// snapshot until compaction drops both.
    pub fn tombstone(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        revision: u64,
    ) -> Result<ApplyOk, ApplyError> {
        let (ns_h, p_h) = key_hash(namespace_root, path);
        for s in self.slots.iter_mut() {
            if s.matches(ns_h, p_h) {
                s.kind = KIND_TOMBSTONE;
                s.revision = revision;
                s.object_id_len = 0;
                s.snapshotted = 0;
                s.cmp_emitted = 0;
                return Ok(ApplyOk::Unbound);
            }
        }
        for s in self.slots.iter_mut() {
            if !s.occupied {
                let mut slot = BindingSlot::empty();
                slot.namespace_hash = ns_h;
                slot.path_hash = p_h;
                slot.revision = revision;
                slot.kind = KIND_TOMBSTONE;
                slot.occupied = true;
                *s = slot;
                return Ok(ApplyOk::Unbound);
            }
        }
        Err(ApplyError::OutOfCapacity)
    }

    /// Free ONE slot whose current revision the snapshot covers
    /// (never a tombstone — those mask the snapshot). Returns
    /// whether a slot was freed.
    pub fn evict_one_snapshotted(&mut self) -> bool {
        for s in self.slots.iter_mut() {
            if s.occupied && s.snapshotted != 0 && s.kind != KIND_TOMBSTONE {
                *s = BindingSlot::empty();
                return true;
            }
        }
        false
    }

    pub fn occupied_count(&self) -> usize {
        self.slots.iter().filter(|s| s.occupied).count()
    }

    /// Occupied slots the snapshot does NOT cover (fresh writes +
    /// unprocessed tombstones) — the compactor's re-trigger fuel.
    pub fn dirty_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.occupied && s.snapshotted == 0)
            .count()
    }

    pub fn slot_ref(&self, i: usize) -> Option<&BindingSlot> {
        self.slots.get(i)
    }

    /// The compactor merged slot `i`'s key into the in-progress
    /// snapshot generation `tag`.
    pub fn mark_emitted(&mut self, i: usize, tag: u8) {
        if let Some(s) = self.slots.get_mut(i) {
            s.cmp_emitted = tag;
        }
    }

    /// The generation tagged `tag` is DURABLE: emitted live slots
    /// become snapshot-covered (evictable), emitted tombstones are
    /// fully superseded (freed). Slots mutated since their emit
    /// cleared the tag and are untouched.
    pub fn finalize_emitted(&mut self, tag: u8) {
        for s in self.slots.iter_mut() {
            if s.occupied && s.cmp_emitted == tag {
                if s.kind == KIND_TOMBSTONE {
                    *s = BindingSlot::empty();
                } else {
                    s.snapshotted = 1;
                    s.cmp_emitted = 0;
                }
            }
        }
    }

    /// Smallest (ns_hash, path_hash) strictly greater than `after`
    /// among occupied slots — the compactor's merge cursor over
    /// the (unsorted) arena. O(N) per call, bounded per step.
    pub fn min_key_above(&self, after: Option<(u64, u64)>) -> Option<(usize, (u64, u64))> {
        let mut best: Option<(usize, (u64, u64))> = None;
        for (i, s) in self.slots.iter().enumerate() {
            if !s.occupied {
                continue;
            }
            let key = (s.namespace_hash, s.path_hash);
            if let Some(a) = after {
                if key <= a {
                    continue;
                }
            }
            match best {
                Some((_, bk)) if bk <= key => {}
                _ => best = Some((i, key)),
            }
        }
        best
    }

    /// One page of the namespace's listable paths, in slot order.
    /// `emit` is called once per path (at most `max` times);
    /// returns the next cursor, 0 when the enumeration wrapped.
    /// Bindings whose paths exceeded MAX_LIST_PATH are skipped —
    /// they're bindable but unlistable.
    pub fn list_page(
        &self,
        namespace_root: &[u8],
        cursor: u32,
        max: usize,
        mut emit: impl FnMut(&[u8]),
    ) -> u32 {
        let ns_h = fnv1a64(namespace_root);
        let mut idx = cursor as usize;
        let mut count = 0usize;
        while idx < N && count < max {
            let s = &self.slots[idx];
            if s.occupied
                && s.namespace_hash == ns_h
                && s.path_len != 0
                && (s.root_len == 0 || &s.root_bytes[..s.root_len as usize] == namespace_root)
            {
                emit(&s.path_bytes[..s.path_len as usize]);
                count += 1;
            }
            idx += 1;
        }
        if idx >= N {
            0
        } else {
            idx as u32
        }
    }

    pub fn unbind(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<ApplyOk, ApplyError> {
        let (ns_h, p_h) = key_hash(namespace_root, path);
        for s in self.slots.iter_mut() {
            if s.matches(ns_h, p_h) {
                *s = BindingSlot::empty();
                return Ok(ApplyOk::Unbound);
            }
        }
        Err(ApplyError::NotBound)
    }
}

impl<const N: usize> Default for PicNamespaceState<N> {
    fn default() -> Self {
        Self::new()
    }
}
