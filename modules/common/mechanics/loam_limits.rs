// The limit register in code. Every deliberate ceiling loam holds
// itself to is declared here once, per capacity profile, and every
// other module derives its buffers and its refusals from these
// names rather than restating a number.
//
// The rule, inherited from fluxor's limit register: no identifier
// space may become the binding limit before a memory pool does on
// any targeted deployment class. A ceiling that appears in source
// but not here is a bug, and `docs/limit_register.md` carries the
// prose row for each name below — the register and the source move
// in the same change.
//
// PROFILE SELECTION. A deployment's capacity is a property of the
// DEPLOYMENT, not of where the code happens to compile. So the
// profile is an explicit input:
//
//     rustc --cfg 'loam_profile="server"' …
//
// and the build target is only the FALLBACK when nothing says
// otherwise — `target_os = "none"` means embedded, anything else
// means node. Selecting on the target alone is what made a laptop
// dev graph and a 64-core fleet member carry identical arenas, and
// left no way to build a small host or a large bare-metal image at
// all.
//
// Four profiles, in increasing order of what the machine affords:
//
//   minimal   MCU-class, <=256 KiB arena. Namespace + WAL only.
//   embedded  pi5 / CM5 bare metal. Today's bare-metal budget.
//   node      a single host daemon. Full features, modest concurrency.
//   server    a fleet member, server class. Wide concurrency.
//
// The selector is deliberately the only `cfg` in this file — a
// profiled constant anywhere else in the tree is a drift bug, and
// `tools/ci/limit_guard.sh` fails the build on one.
//
// Same include discipline as the other mechanics sources: no_std,
// no dependencies, `#[path]`-included by every consumer.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

// ── The selector ──────────────────────────────────────────────────
//
// An explicit ladder rather than a match, so an unrecognised
// `--cfg loam_profile="typo"` falls through to the target default
// instead of silently selecting whichever arm happened to be last.

/// The one place `loam_profile` is read, fenced so that only it is
/// excused from cfg checking.
///
/// Cargo declares `loam_profile` and its values (see `Cargo.toml`), so
/// a host build checks this ladder and would catch a misspelt value.
/// The PIC build is raw `rustc`, and it declares only the cfgs fluxor
/// itself defines, so there every arm here reads as an unknown name.
/// The excuse is `allow` rather than `expect` because it is
/// target-conditional: an `expect` would fail every cargo build, where
/// the lint rightly does not fire.
#[allow(
    unexpected_cfgs,
    reason = "the PIC build does not declare loam's own cfg; cargo builds do, and check it"
)]
mod selector {
    /// Human-readable profile name. Diagnostics and the health surface
    /// read it; nothing parses it.
    #[cfg(loam_profile = "minimal")]
    pub const PROFILE: &str = "minimal";
    #[cfg(loam_profile = "embedded")]
    pub const PROFILE: &str = "embedded";
    #[cfg(loam_profile = "node")]
    pub const PROFILE: &str = "node";
    #[cfg(loam_profile = "server")]
    pub const PROFILE: &str = "server";
    /// Fallback: nothing was declared, so the build target decides.
    #[cfg(all(
        not(any(
            loam_profile = "minimal",
            loam_profile = "embedded",
            loam_profile = "node",
            loam_profile = "server"
        )),
        target_os = "none"
    ))]
    pub const PROFILE: &str = "embedded";
    #[cfg(all(
        not(any(
            loam_profile = "minimal",
            loam_profile = "embedded",
            loam_profile = "node",
            loam_profile = "server"
        )),
        not(target_os = "none")
    ))]
    pub const PROFILE: &str = "node";
}
pub use selector::PROFILE;

/// True on the two constrained profiles. Every profiled constant
/// below branches on these three predicates rather than on the raw
/// cfgs, so adding a profile is one edit here, not thirty through
/// the file.
pub const CONSTRAINED: bool = matches!(PROFILE.as_bytes(), b"minimal" | b"embedded");

/// True on the smallest profile, where optional machinery — erasure
/// coding, background scrub, streaming sessions, the snapshot
/// compactor — is compiled out rather than merely bounded.
pub const MINIMAL: bool = matches!(PROFILE.as_bytes(), b"minimal");

/// True on the widest profile, which affords server-class
/// concurrency.
pub const SERVER: bool = matches!(PROFILE.as_bytes(), b"server");

// ── Feature tiers ─────────────────────────────────────────────────
//
// Capacity is not the only axis a constrained device cares about.
// The `minimal` profile is defined by what it does NOT carry: the
// optional machinery below compiles down to nothing there, because a
// `const false` guard at each entry point is what lets the optimiser
// drop the body rather than merely never take the branch.

/// Whether this build carries the namespace SNAPSHOT tier — the
/// compacted on-disk generations, the incremental compactor and
/// arena eviction that let the arena be a hot cache instead of the
/// whole set.
///
/// Off on `minimal`, where it would not pay for itself: an MCU-class
/// namespace holds a small fixed key set, the arena IS the whole
/// set, and a compactor that cannot keep pace with a 64-slot arena
/// turns a full arena into refused binds. Off means the arena is
/// authoritative and the WAL is the durable record, which is exactly
/// the pre-snapshot design and is correct at that scale.
pub const SNAPSHOT_TIER: bool = !MINIMAL;

// There is deliberately no `REPLICATION_TIER` flag.
//
// Erasure coding, the background scrub and the fan-out path do not
// live inside a module the constrained profiles run — they ARE
// modules: `ec_body_router`, `body_fanout_router`,
// `placement_router`. A graph that does not want them does not wire
// them, and nothing of them is compiled, loaded or scheduled. That
// is fluxor's module granularity doing the job a feature flag would
// have duplicated, less well: a flag would have to be kept in step
// with the graph, and the two could disagree.
//
// The rule this leaves, which is the one worth stating: **gate what
// lives INSIDE a module every profile runs; let the graph exclude
// whole modules.** `SNAPSHOT_TIER` above passes that test — the
// compactor is inside `namespace_router`, which every profile runs.
// A replication flag would not.

// ── Key material ──────────────────────────────────────────────────
//
// These three are the KEY CEILINGS: the longest root, path and
// object id loam will accept. They are enforced by refusal at the
// wire, and every store that holds key bytes — arena slot, snapshot
// record — is sized to exactly them. That equality is the whole
// point: a key that is accepted is a key that can be stored whole,
// so it can be compared byte-for-byte on lookup and enumerated by
// LIST. A ceiling that accepted more than it could store would put
// a binding in the arena that no listing could ever return.

/// Longest accepted namespace root. S3 bucket names cap at 63
/// bytes, so 64 covers the gateway's tenancy boundary exactly on
/// both profiles; nothing has asked for more.
pub const MAX_ROOT: usize = 64;

/// Longest accepted object id. The content-derived form
/// `sha256:<64 lowercase hex>` is 71 bytes; 96 leaves headroom for
/// other identity schemes without a profile split.
pub const MAX_OBJECT_ID: usize = 96;

/// Longest accepted path within a root — the one profiled key
/// ceiling.
///
/// The host figure is 1024 because that is the longest legal S3
/// object key, and the S3 gateway is a first-class surface: a key
/// a client may legally send must be a key loam can store, look up
/// and list. The embedded figure is 160 because the path dominates
/// the arena slot (see `BindingSlot`) and a bare-metal namespace
/// instance is budgeted against a 256 KiB arena. A longer key on
/// the embedded profile is REFUSED at the wire, not silently
/// accepted and hidden from listings.
pub const MAX_PATH: usize = if CONSTRAINED { 160 } else { 1024 };

/// Longest accepted key-shaped string on any wire, for buffer
/// sizing at decode. Derived, not chosen: the widest of the three
/// ceilings above.
pub const MAX_KEY_STRING: usize = if MAX_PATH > MAX_OBJECT_ID {
    if MAX_PATH > MAX_ROOT {
        MAX_PATH
    } else {
        MAX_ROOT
    }
} else if MAX_OBJECT_ID > MAX_ROOT {
    MAX_OBJECT_ID
} else {
    MAX_ROOT
};

// There are deliberately no reserved namespace roots. A snapshot
// protects its bodies by BINDING them under whatever root the
// caller names, and the orphan GC's reachability answer already
// covers ordinary bindings — so no root needs store-level meaning,
// and the collector needs no snapshot-shaped query to go with one.

/// Why a key was refused. Each wire wraps this in its own error
/// type; the CHECK lives here because the ceilings do, and two
/// copies of it drifting would mean two wires disagreeing about
/// what the store can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyTooLong {
    pub len: usize,
    pub max: usize,
}

/// Refuse a key whose components exceed their ceilings.
///
/// Called on BOTH sides of every wire that carries a key: encode so
/// a local producer fails loudly, decode so a remote frame cannot
/// smuggle an oversize key past the ceiling. Pass `&[]` for a
/// component an operation does not carry.
///
/// This is the check that makes "accepted implies storable implies
/// listable" true. It has one home so it cannot become two
/// answers.
pub fn check_key(namespace_root: &[u8], path: &[u8], object_id: &[u8]) -> Result<(), KeyTooLong> {
    if namespace_root.len() > MAX_ROOT {
        return Err(KeyTooLong {
            len: namespace_root.len(),
            max: MAX_ROOT,
        });
    }
    if path.len() > MAX_PATH {
        return Err(KeyTooLong {
            len: path.len(),
            max: MAX_PATH,
        });
    }
    if object_id.len() > MAX_OBJECT_ID {
        return Err(KeyTooLong {
            len: object_id.len(),
            max: MAX_OBJECT_ID,
        });
    }
    Ok(())
}

// ── Arena capacity ────────────────────────────────────────────────
//
// The per-instance live-record budget. The namespace arena is a hot
// cache over the durable snapshot, so its figure is a cache-sizing
// knob; the object and block arenas are whole-set, so theirs are
// true capacity ceilings: raising one raises that module's memory
// budget linearly, and no amount of disk makes room for another
// object descriptor.

/// Namespace binding slots per `namespace_router` instance.
pub const NAMESPACE_SLOTS: usize = if MINIMAL {
    64
} else if CONSTRAINED {
    256
} else {
    8192
};

/// Object descriptor slots per `object_index` instance.
pub const OBJECT_SLOTS: usize = if MINIMAL {
    64
} else if CONSTRAINED {
    256
} else {
    8192
};

/// Volume slots per `block_allocator` instance. Volumes are
/// coarse-grained — one per logical disk or image — so the budget
/// is far smaller than the per-binding and per-object arenas.
pub const BLOCK_SLOTS: usize = if MINIMAL {
    8
} else if CONSTRAINED {
    64
} else {
    1024
};

/// Body slots per `body_store` instance. The slot table is an index
/// over the on-disk inventory, not the inventory itself — a cursor-0
/// SCAN rehydrates it from the root directory — so this bounds
/// working-set lookup, not how many bodies a node may hold.
pub const BODY_SLOTS: usize = if MINIMAL {
    16
} else if CONSTRAINED {
    64
} else {
    8192
};

// ── Concurrency and step budget ───────────────────────────────────
//
// WHY THESE AND NOT THE OTHERS. Every ceiling here is LOCAL: it sizes
// an arena or a step budget inside one module instance, and no other
// node can observe it. That is precisely what makes it safe to
// profile.
//
// `MAX_BODY`, `MAX_FLEET` and `MAX_STREAM_TOTAL` are deliberately NOT
// here, and never will be. They are WIRE commitments — a frame size,
// a fixed-width broadcast record, a declared stream total — and a
// mixed fleet is the product: a pi5 and a server in one deployment
// have to agree about them byte for byte. A per-profile wire ceiling
// would mean two nodes that cannot talk, which is a worse failure
// than a number being too small on one of them. If they need to move
// they move for everyone, in one change, and the register records
// the new value once.
//
// The rule, stated so it survives the next person who wants to
// profile something: **an arena ceiling may vary by profile; a wire
// ceiling may not.**

/// Concurrent streamed writes per `body_store` instance. Each holds
/// a temp-file handle and an incremental hash, so this is memory and
/// descriptors, not protocol — and the only in-flight table where
/// the per-slot cost is large enough for `minimal` to be worth
/// distinguishing.
pub const WRITE_SESSIONS: usize = if MINIMAL {
    2
} else if CONSTRAINED {
    4
} else if SERVER {
    64
} else {
    8
};

/// Proposals in flight in `raft_metadata_client`. One past the table
/// is REFUSED to the producer, never dropped, so this bounds how
/// deep a leader-loss window can get before back-pressure reaches
/// the writer.
///
/// Server-vs-rest only. The rule from `OPS_PER_STEP` applies to
/// every in-flight table and I did not apply it consistently the
/// first time: these tables hold tens of bytes per slot, so
/// shrinking them on `minimal` saves single-digit kilobytes against
/// a 256 KiB arena and caps real concurrency on a surface that has
/// to keep working. What makes a constrained profile is arena
/// capacity, key width, and which feature tiers it carries.
pub const PROPOSER_PENDING: usize = if SERVER { 1024 } else { 256 };

/// Outstanding upstream requests per body router, and per-request
/// fan-out join records. `ROUTER_PENDING` is per fleet member, so
/// the table is `MAX_FLEET × ROUTER_PENDING` entries — the largest
/// of these, and still only a few kilobytes. Server-vs-rest, for
/// the reason above.
pub const ROUTER_PENDING: usize = if SERVER { 256 } else { 64 };

/// Per-request fan-out join records held by a body router.
pub const ROUTER_JOINS: usize = if SERVER { 128 } else { 32 };

/// Admin ops in flight, composed writes in flight, and streamed
/// composed writes in flight — the three `admin_router` tables.
///
/// Deliberately NOT reduced on `minimal`, for the same reason
/// `OPS_PER_STEP` is not: at the constrained key ceiling the whole
/// composed-write table is about 4 KiB against a 256 KiB arena, so
/// cutting it to two slots saves under 2% while capping the S3
/// gateway at two concurrent uploads. A device small enough for the
/// `minimal` arena is not the device fronting an HTTP gateway, and
/// sizing these for one that is costs almost nothing.
///
/// The lesson generalises and is worth keeping: profile a ceiling
/// where the saving is decisive, not everywhere it is possible.
pub const ADMIN_PENDING: usize = if SERVER { 256 } else { 64 };
pub const ADMIN_PUTFILE: usize = if SERVER { 64 } else { 16 };
pub const ADMIN_STREAMED_PUTFILE: usize = if SERVER { 32 } else { 4 };

/// Cooperative step budget: operations one `module_step` handles
/// before yielding.
///
/// Raised only on `server`, and only to 8. This is a FAIRNESS knob
/// as much as a throughput one — every module in the graph shares
/// the lane, and one that takes sixteen expensive ops per step
/// starves the others just as surely as an unbounded loop would.
///
/// Deliberately NOT lowered on `minimal`. The reassembly buffers
/// are sized from it
/// (`READ_BUF × (budget + 1)`), so dropping 4 to 2 saves about 512
/// bytes on the namespace PIC — nothing against a 256 KiB arena —
/// while halving the throughput of a device that is already the
/// slowest. What makes a microcontroller profile is arena capacity
/// and which feature tiers it carries, not how many records it
/// drains per step. Profiling a knob that buys nothing costs
/// something: every test that reasons about pacing has to reason
/// about four values instead of two.
pub const OPS_PER_STEP: u32 = if SERVER { 8 } else { 4 };

// ── Const assertions ──────────────────────────────────────────────
//
// The invariants that make the key ceilings safe to store inline.
// A length is carried in a u8 alongside its bytes in both the arena
// slot and the snapshot record, so every ceiling must fit one.

const _: () = assert!(MAX_ROOT <= u8::MAX as usize);
const _: () = assert!(MAX_OBJECT_ID <= u8::MAX as usize);
const _: () = assert!(MAX_PATH <= u16::MAX as usize);
const _: () = assert!(MAX_KEY_STRING >= MAX_PATH);
const _: () = assert!(MAX_KEY_STRING >= MAX_ROOT);
const _: () = assert!(MAX_KEY_STRING >= MAX_OBJECT_ID);
