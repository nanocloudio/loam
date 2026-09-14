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
// IDENTITY IS THE KEY BYTES, not their hash. Each slot stores the
// full root and path, and a lookup compares them after matching the
// hashes — the hash narrows the scan, the bytes decide. FNV-1a is a
// non-cryptographic hash and is trivially collidable by
// construction, so a hash-only match would let anyone who can name
// their own keys reach a binding that is not theirs. The ceilings in
// `loam_limits.rs` are what make this affordable: a key that is
// accepted is a key that fits inline, enforced by refusal at the
// wire, so the comparison is always definitive and every bound key
// is listable.
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

/// Key ceilings. These are `loam_limits.rs`'s numbers, re-exported
/// under the names this module's consumers already use; they are
/// not independent knobs. Every one of them is enforced by refusal
/// at the wire, so a key that reaches this state machine always
/// fits inline.
pub use super::limits::{MAX_OBJECT_ID, MAX_PATH as MAX_LIST_PATH, MAX_ROOT as MAX_LIST_ROOT};

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
    /// when the binder supplied no id at all — the hash is still
    /// authoritative.
    pub object_id_bytes: [u8; MAX_OBJECT_ID],
    pub object_id_len: u8,
    /// Inline path bytes. Always the whole path of a bound key —
    /// `path_len = 0` means the slot is free or a tombstone, never
    /// "bound but too long to store", which is a state the wire's
    /// refusal makes unreachable. `u16` because MAX_LIST_PATH is
    /// 1024 on the host profile.
    pub path_bytes: [u8; MAX_LIST_PATH],
    pub path_len: u16,
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
    /// Absolute expiry, in whatever millisecond epoch the operator's
    /// own nodes use. 0 means never.
    ///
    /// The PIC does NOT decide when this has passed — it has no
    /// clock it should be asserting into a durability record. It
    /// stores the number and compares it against a `now` the SWEEP
    /// DRIVER supplies, which is the host that already stamps
    /// `now_millis()` onto composed writes. So the store enforces
    /// "expire at T"; whose clock T is measured against stays the
    /// operator's problem, stated rather than hidden.
    pub expires_at: u64,
    /// Object lock. While set, this binding refuses rebind and
    /// deletion.
    ///
    /// GOVERNANCE mode, not time-based retention: an explicit
    /// `set_lock(.., false)` clears it, and there is no
    /// retain-until. That is deliberate — a PIC has no clock it
    /// should be asserting into a durability record, and a retention
    /// window enforced against a caller-supplied "now" is only as
    /// strong as the caller's clock, which is not a property worth
    /// claiming. What this DOES defend is the failure that actually
    /// happens: an accidental overwrite or a runaway delete loop.
    pub locked: u8,
    /// Position of this slot's LAST mutation in the arena's change
    /// stream — a single monotone counter across every key, stamped
    /// automatically by the mutating methods below.
    ///
    /// Distinct from `revision`, which is the producer's per-key
    /// pointer version and is NOT comparable across keys: a freshly
    /// bound path starts at revision 1 whatever else has happened, so
    /// a `CHANGES(since=N)` window filtered on `revision` would drop
    /// every new key. `namespace::CHANGES` orders on this instead,
    /// which is what makes a delta window mean "everything that has
    /// happened since you last looked".
    pub change_rev: u64,
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
            expires_at: 0,
            locked: 0,
            change_rev: 0,
        }
    }

    /// Hash-narrowed, byte-decided key equality. The hashes are a
    /// cheap filter; `root` and `path` are what actually identify
    /// the binding. Never match on the hashes alone — see the
    /// module header.
    pub fn matches(&self, namespace_hash: u64, path_hash: u64, root: &[u8], path: &[u8]) -> bool {
        self.occupied
            && self.namespace_hash == namespace_hash
            && self.path_hash == path_hash
            && self.root() == root
            && self.path() == path
    }

    /// The slot's stored namespace root.
    pub fn root(&self) -> &[u8] {
        &self.root_bytes[..self.root_len as usize]
    }

    /// The slot's stored path.
    pub fn path(&self) -> &[u8] {
        &self.path_bytes[..self.path_len as usize]
    }

    /// True when this slot already points at exactly `object_id` with
    /// exactly `kind`. Compares the inline bytes when the slot kept
    /// them (an oversize ObjectId is not inlined) and the hash
    /// otherwise, so a duplicate is never mistaken for a conflict and
    /// a conflict is never mistaken for a duplicate on a hash
    /// collision alone.
    pub fn binds_same(&self, object_id_hash: u64, object_id: &[u8], kind: u8) -> bool {
        if self.kind != kind || self.object_id_hash != object_id_hash {
            return false;
        }
        let inline = self.object_id();
        if inline.is_empty() {
            return true;
        }
        inline == object_id
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
    /// The binding is locked and the operation would have changed
    /// or removed it. Distinct from every other refusal here because
    /// the remedy is distinct: unlock it deliberately, which is the
    /// whole point of the lock.
    Locked,
    /// A key component exceeded its ceiling in `loam_limits.rs`.
    /// The wire refuses these before they reach the state machine,
    /// so this is defence in depth: it keeps "accepted but not
    /// storable" unrepresentable even if a future caller forgets
    /// the wire check, rather than silently storing a prefix or a
    /// hash-only slot.
    KeyTooLong,
}

/// True when every component of a key fits its ceiling. The wire
/// enforces this at decode; the state machine re-checks so that a
/// slot can never hold a partial key.
pub fn key_fits(namespace_root: &[u8], path: &[u8], object_id: &[u8]) -> bool {
    namespace_root.len() <= MAX_LIST_ROOT
        && path.len() <= MAX_LIST_PATH
        && object_id.len() <= MAX_OBJECT_ID
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOk {
    Bound { revision: u64 },
    Renamed { new_revision: u64 },
    Unbound,
}

/// FNV-1a 64-bit. Same algorithm as `partition_assignment`; suitable
/// for non-cryptographic identity hashes.
/// FNV-1a, from the one shared implementation. Three byte-identical
/// copies of a hash that narrows every identity scan is a drift
/// hazard, not a line count — see `loam_hash.rs`.
pub use super::hash::fnv1a64;

pub fn key_hash(namespace_root: &[u8], path: &[u8]) -> (u64, u64) {
    (fnv1a64(namespace_root), fnv1a64(path))
}

/// Fixed-capacity binding table. `N` must be a compile-time
/// constant. Lookups + mutations are O(N) — N is meant to be small
/// (16…256) for PIC use; the host runtime uses LoamInstance instead.
pub struct PicNamespaceState<const N: usize> {
    slots: [BindingSlot; N],
    /// Monotone position in this arena's change stream. Bumped and
    /// stamped by every mutating method, so a caller cannot forget to
    /// order a change it just made.
    change_seq: u64,
    /// The newest change this arena can no longer account for,
    /// because the slot carrying it was evicted or its tombstone was
    /// dropped by compaction.
    ///
    /// `CHANGES(since)` below this must answer LOST. Without it a
    /// window would come back silently incomplete — the arena is a
    /// hot cache, so "what changed since N" is only answerable for
    /// as long as the evidence is still resident, and a consumer
    /// that trusted a short window would diverge with no way to
    /// notice.
    change_horizon: u64,
}

impl<const N: usize> PicNamespaceState<N> {
    pub const fn new() -> Self {
        Self {
            slots: [BindingSlot::empty(); N],
            change_seq: 0,
            change_horizon: 0,
        }
    }

    /// The newest change this arena can no longer account for. A
    /// `CHANGES(since)` at or below it must answer LOST.
    pub fn change_horizon(&self) -> u64 {
        self.change_horizon
    }

    /// Record that a change at `rev` has left the arena.
    fn forget_change(&mut self, rev: u64) {
        if rev > self.change_horizon {
            self.change_horizon = rev;
        }
    }

    /// The newest change-stream position this arena has issued. A
    /// `CHANGES` caller resumes from it.
    pub fn change_seq(&self) -> u64 {
        self.change_seq
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
        self.lookup_hashed(ns_h, p_h, namespace_root, path)
    }

    /// Resolve a key whose hashes the caller has already computed.
    /// The key bytes are still required and still decide the match
    /// — the hashes only narrow the scan. There is deliberately no
    /// hash-only variant: one would reintroduce the aliasing this
    /// signature exists to prevent.
    pub fn lookup_hashed(
        &self,
        namespace_hash: u64,
        path_hash: u64,
        root: &[u8],
        path: &[u8],
    ) -> Option<&BindingSlot> {
        for s in &self.slots {
            if s.matches(namespace_hash, path_hash, root, path) {
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
        if !key_fits(namespace_root, path, object_id) {
            return Err(ApplyError::KeyTooLong);
        }
        let (ns_h, p_h) = key_hash(namespace_root, path);
        let oid_h = fnv1a64(object_id);
        // The change-stream position this call will occupy IF it
        // mutates. Allocated before the scan because the scan borrows
        // the slots; unused values simply leave a gap, and a gap in a
        // monotone counter costs a consumer nothing.
        let seq = self.change_seq.wrapping_add(1);
        // Rebind-as-upsert, gated on a STRICTLY higher revision:
        // producers that advance a pointer (key → new content digest)
        // pass a monotone revision per write; replays of older binds
        // (e.g. WAL/commit-stream replay) land on the AlreadyBound arm
        // and cannot regress the pointer.
        //
        // A re-bind at the SAME revision to the SAME object is the
        // same write arriving twice — a composed PUT_FILE retried
        // after a crash between the bind and its reply, or a
        // commit-stream duplicate. It succeeds without mutating:
        // refusing it would make retry of an interrupted write
        // indistinguishable from a genuine conflict. Same revision,
        // DIFFERENT object is a genuine conflict and is refused.
        for s in self.slots.iter_mut() {
            if s.occupied && s.matches(ns_h, p_h, namespace_root, path) {
                if s.locked != 0 && !s.binds_same(oid_h, object_id, kind) {
                    // A rebind to the SAME object is not a change, so
                    // an idempotent retry still succeeds against a
                    // locked binding — refusing it would make a
                    // crash-retry indistinguishable from an attempt
                    // to overwrite.
                    return Err(ApplyError::Locked);
                }
                if revision == s.revision && s.binds_same(oid_h, object_id, kind) {
                    return Ok(ApplyOk::Bound { revision });
                }
                if revision > s.revision {
                    s.object_id_hash = oid_h;
                    s.revision = revision;
                    s.kind = kind;
                    s.snapshotted = 0;
                    s.cmp_emitted = 0;
                    s.object_id_len = 0;
                    if !object_id.is_empty() {
                        s.object_id_bytes[..object_id.len()].copy_from_slice(object_id);
                        s.object_id_len = object_id.len() as u8;
                    }
                    s.change_rev = seq;
                    self.change_seq = seq;
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
                if !object_id.is_empty() {
                    slot.object_id_bytes[..object_id.len()].copy_from_slice(object_id);
                    slot.object_id_len = object_id.len() as u8;
                }
                // Inline path/root, always in full: `key_fits` above
                // refused anything that would not fit, so there is no
                // oversize branch to take. This is what makes every
                // bound key listable and every lookup byte-decided.
                if !path.is_empty() {
                    slot.path_bytes[..path.len()].copy_from_slice(path);
                    slot.path_len = path.len() as u16;
                }
                if !namespace_root.is_empty() {
                    slot.root_bytes[..namespace_root.len()].copy_from_slice(namespace_root);
                    slot.root_len = namespace_root.len() as u8;
                }
                slot.change_rev = seq;
                *s = slot;
                self.change_seq = seq;
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
        if !key_fits(namespace_root, from, &[]) || !key_fits(namespace_root, to, &[]) {
            return Err(ApplyError::KeyTooLong);
        }
        let seq = self.change_seq.wrapping_add(1);
        let (ns_h, from_h) = key_hash(namespace_root, from);
        let (_, to_h) = key_hash(namespace_root, to);
        if self.lookup_hashed(ns_h, to_h, namespace_root, to).is_some() {
            return Err(ApplyError::DestinationOccupied);
        }
        for s in self.slots.iter_mut() {
            if s.matches(ns_h, from_h, namespace_root, from) {
                if s.locked != 0 {
                    // A move is a delete plus a create as far as the
                    // old name is concerned, so a lock has to stop it
                    // or the lock is trivially bypassed by renaming.
                    return Err(ApplyError::Locked);
                }
                s.path_hash = to_h;
                s.revision = new_revision;
                s.snapshotted = 0;
                s.cmp_emitted = 0;
                s.path_len = 0;
                if !to.is_empty() {
                    s.path_bytes[..to.len()].copy_from_slice(to);
                    s.path_len = to.len() as u16;
                }
                s.change_rev = seq;
                self.change_seq = seq;
                return Ok(ApplyOk::Renamed { new_revision });
            }
        }
        Err(ApplyError::NotBound)
    }

    /// Is `object_id` bound by ANY occupied slot, in any root?
    /// Used by orphan-body GC. Hash-narrowed and byte-decided like
    /// every other identity question here. A slot with no id bytes
    /// still counts as a reference: that is a binding whose binder
    /// supplied no id at all, and keeping a blob is always safe
    /// where deleting a referenced one never is.
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
        if !key_fits(namespace_root, path, &[]) {
            return Err(ApplyError::KeyTooLong);
        }
        let seq = self.change_seq.wrapping_add(1);
        let (ns_h, p_h) = key_hash(namespace_root, path);
        for s in self.slots.iter_mut() {
            if s.matches(ns_h, p_h, namespace_root, path) {
                if s.locked != 0 {
                    return Err(ApplyError::Locked);
                }
                s.kind = KIND_TOMBSTONE;
                s.revision = revision;
                s.object_id_len = 0;
                s.snapshotted = 0;
                s.cmp_emitted = 0;
                s.change_rev = seq;
                self.change_seq = seq;
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
                // A fresh tombstone carries its key bytes like any
                // other slot. It has to: `matches` decides on bytes,
                // so a keyless tombstone would never be found again
                // and would mask the snapshot record forever.
                if !path.is_empty() {
                    slot.path_bytes[..path.len()].copy_from_slice(path);
                    slot.path_len = path.len() as u16;
                }
                if !namespace_root.is_empty() {
                    slot.root_bytes[..namespace_root.len()].copy_from_slice(namespace_root);
                    slot.root_len = namespace_root.len() as u8;
                }
                slot.change_rev = seq;
                *s = slot;
                self.change_seq = seq;
                return Ok(ApplyOk::Unbound);
            }
        }
        Err(ApplyError::OutOfCapacity)
    }

    /// Set or clear a binding's expiry. `at == 0` means never.
    ///
    /// Like `set_lock`, this changes no content and so does not
    /// stamp the change stream: a consumer's table is identical
    /// after applying it. The DELETION when it expires is a change,
    /// and that one does.
    pub fn set_expiry(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        at: u64,
    ) -> Result<ApplyOk, ApplyError> {
        let (ns_h, p_h) = key_hash(namespace_root, path);
        for s in self.slots.iter_mut() {
            if s.matches(ns_h, p_h, namespace_root, path) && s.kind != KIND_TOMBSTONE {
                s.expires_at = at;
                return Ok(ApplyOk::Bound {
                    revision: s.revision,
                });
            }
        }
        Err(ApplyError::NotBound)
    }

    /// One page of bindings that have expired as of `now`.
    ///
    /// Cursor-paged and bounded per call, like every other sweep
    /// question here, so a driver can walk a service-class arena
    /// without holding the lane. `emit` receives `(root, path)`;
    /// the caller does the deleting, because the caller is the one
    /// that knows whether the deletion should replicate.
    ///
    /// A LOCKED binding never appears, whatever its expiry. Lock
    /// beats TTL: a retention hold that a lifecycle rule could
    /// silently overrule would not be a hold. That is also S3's
    /// rule, and it is the safe direction — the failure of keeping
    /// data too long is recoverable and the other is not.
    pub fn expired_page(
        &self,
        now: u64,
        cursor: u32,
        max: usize,
        mut emit: impl FnMut(&[u8], &[u8]),
    ) -> u32 {
        let mut idx = cursor as usize;
        let mut count = 0usize;
        while idx < N && count < max {
            let s = &self.slots[idx];
            if s.occupied
                && s.kind != KIND_TOMBSTONE
                && s.locked == 0
                && s.expires_at != 0
                && s.expires_at <= now
            {
                emit(s.root(), s.path());
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

    /// Has this binding expired as of `now`? False for a locked one,
    /// for the reason in `expired_page`.
    pub fn is_expired(&self, namespace_root: &[u8], path: &[u8], now: u64) -> bool {
        self.lookup(namespace_root, path)
            .map(|s| s.locked == 0 && s.expires_at != 0 && s.expires_at <= now)
            .unwrap_or(false)
    }

    /// Set or clear a binding's lock.
    ///
    /// Clearing is an ordinary operation, not a privileged one —
    /// this is governance mode. The protection it gives is that
    /// unlocking is a DELIBERATE, separately-auditable act rather
    /// than a side effect of an overwrite, which is the failure that
    /// actually destroys data.
    ///
    /// Locking does not stamp the change stream: the binding's
    /// content has not changed, and a consumer's table would be
    /// identical after applying it.
    pub fn set_lock(
        &mut self,
        namespace_root: &[u8],
        path: &[u8],
        locked: bool,
    ) -> Result<ApplyOk, ApplyError> {
        let (ns_h, p_h) = key_hash(namespace_root, path);
        for s in self.slots.iter_mut() {
            if s.matches(ns_h, p_h, namespace_root, path) && s.kind != KIND_TOMBSTONE {
                s.locked = u8::from(locked);
                return Ok(ApplyOk::Bound {
                    revision: s.revision,
                });
            }
        }
        Err(ApplyError::NotBound)
    }

    /// Is this binding locked?
    pub fn is_locked(&self, namespace_root: &[u8], path: &[u8]) -> bool {
        self.lookup(namespace_root, path)
            .map(|s| s.locked != 0)
            .unwrap_or(false)
    }

    /// Free ONE slot whose current revision the snapshot covers
    /// (never a tombstone — those mask the snapshot). Returns
    /// whether a slot was freed.
    pub fn evict_one_snapshotted(&mut self) -> bool {
        let mut evicted = None;
        for s in self.slots.iter_mut() {
            // A locked binding is never evicted. The arena is a hot
            // cache over the snapshot, and the snapshot record does
            // not carry the lock — so evicting one would silently
            // unlock it on the next lookup. Pinning it costs a cache
            // slot; the alternative costs the guarantee.
            if s.locked != 0 {
                continue;
            }
            if s.occupied && s.snapshotted != 0 && s.kind != KIND_TOMBSTONE {
                evicted = Some(s.change_rev);
                *s = BindingSlot::empty();
                break;
            }
        }
        match evicted {
            Some(rev) => {
                // The slot's record survives in the snapshot, but its
                // POSITION in the change stream does not — a delta
                // window can no longer prove what happened at it.
                self.forget_change(rev);
                true
            }
            None => false,
        }
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
        let mut dropped = 0u64;
        for s in self.slots.iter_mut() {
            if s.occupied && s.cmp_emitted == tag {
                if s.kind == KIND_TOMBSTONE {
                    // The deletion is now durably absent from the
                    // snapshot, so the tombstone goes — and with it
                    // the only evidence that the deletion happened at
                    // its change position.
                    if s.change_rev > dropped {
                        dropped = s.change_rev;
                    }
                    *s = BindingSlot::empty();
                } else {
                    s.snapshotted = 1;
                    s.cmp_emitted = 0;
                }
            }
        }
        if dropped > 0 {
            self.forget_change(dropped);
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

    /// One page of the keys under `namespace_root` whose path begins
    /// with `prefix`, in slot order.
    ///
    /// `emit` is called once per matching key, with its path and its
    /// kind, and answers whether it TOOK the entry. A `false` stops
    /// the walk without consuming that entry, so the cursor returned
    /// points AT it and the next page offers it again — which is what
    /// lets a caller fill a fixed buffer and come back for the rest
    /// instead of refusing the listing.
    ///
    /// The answer is where to resume, or `None` once every slot has
    /// been examined. `None` rather than a zero sentinel because slot
    /// 0 is a valid place to resume: a caller whose buffer could not
    /// hold even the first entry must be told "resume at 0", and a
    /// sentinel would tell it "finished" instead.
    ///
    /// Every bound key appears: the wire refuses anything that would
    /// not fit inline, so there is no "bound but unlistable" state
    /// for a listing to skip. The root is compared on BYTES — a
    /// root-hash match alone would enumerate one tenant's keys under
    /// another tenant's root. The prefix is a byte prefix of the path
    /// and nothing else: this state holds no notion of a separator,
    /// so a caller that means "children" says so in the bytes it
    /// sends.
    pub fn list_page_prefixed(
        &self,
        namespace_root: &[u8],
        prefix: &[u8],
        cursor: u32,
        max: usize,
        mut emit: impl FnMut(&[u8], u8) -> bool,
    ) -> Option<u32> {
        let ns_h = fnv1a64(namespace_root);
        let mut idx = cursor as usize;
        let mut count = 0usize;
        while idx < N {
            if count >= max {
                return Some(idx as u32);
            }
            let s = &self.slots[idx];
            if s.occupied
                && s.kind != KIND_TOMBSTONE
                && s.namespace_hash == ns_h
                && s.path_len != 0
                && s.root() == namespace_root
                && s.path().starts_with(prefix)
            {
                if !emit(s.path(), s.kind) {
                    return Some(idx as u32);
                }
                count += 1;
            }
            idx += 1;
        }
        None
    }

    /// One page of the namespace's paths, in slot order. `emit` is
    /// called once per path (at most `max` times); returns the next
    /// cursor, 0 when the enumeration wrapped.
    ///
    /// The empty prefix matches every path, so this is
    /// `list_page_prefixed` with the filter open and the kind
    /// dropped. One walk, one set of match rules: a second copy of
    /// them is a second place for a tenant's keys to leak from.
    pub fn list_page(
        &self,
        namespace_root: &[u8],
        cursor: u32,
        max: usize,
        mut emit: impl FnMut(&[u8]),
    ) -> u32 {
        // `None` is "every slot examined", which this surface reports
        // as the 0 its own contract calls "wrapped".
        self.list_page_prefixed(namespace_root, &[], cursor, max, |path, _kind| {
            emit(path);
            true
        })
        .unwrap_or_default()
    }

    pub fn unbind(&mut self, namespace_root: &[u8], path: &[u8]) -> Result<ApplyOk, ApplyError> {
        let seq = self.change_seq.wrapping_add(1);
        let (ns_h, p_h) = key_hash(namespace_root, path);
        for s in self.slots.iter_mut() {
            if s.matches(ns_h, p_h, namespace_root, path) {
                if s.locked != 0 {
                    return Err(ApplyError::Locked);
                }
                *s = BindingSlot::empty();
                self.change_seq = seq;
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
