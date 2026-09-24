# Limit register

The complete list of loam's deliberate hard ceilings. This is the peer
of [fluxor's register](../../fluxor/docs/architecture/limit_register.md)
and inherits its rules:

- **The register and the source move together.** Editing a ceiling
  means editing its row here in the same change.
- **No identifier space may become the binding limit before a memory
  pool does** on any targeted deployment class. A ceiling found in
  source but absent here is a bug.
- **A ceiling that is per-profile is stated per profile.** Loam has
  four capacity profiles, selected by an explicit
  `--cfg loam_profile="…"`, with the build target as the fallback
  (`target_os = "none"` → `embedded`, otherwise `node`). Every
  profiled constant lives in
  [`modules/common/mechanics/loam_limits.rs`](../modules/common/mechanics/loam_limits.rs)
  and nowhere else — a `cfg(target_os)` on a capacity constant
  anywhere else in the tree is drift, not a feature, and
  `tools/ci/limit_guard.sh` fails the build on one.

## Profiles

| Profile | Target machine | Selected by |
|---|---|---|
| `minimal` | MCU-class, ≤256 KiB arena | `--cfg loam_profile="minimal"` |
| `embedded` | pi5 / CM5 bare metal | the flag, or `target_os = "none"` |
| `node` | a single host daemon | the flag, or any other target |
| `server` | a fleet member, server class | `--cfg loam_profile="server"` |

Capacity is not the only axis. Two FEATURE TIERS are compiled out
on `minimal`, so the code shrinks rather than merely staying
bounded:

| Tier | Symbol | Off on | What it carries |
|---|---|---|---|
| Namespace snapshot | `SNAPSHOT_TIER` | `minimal` | Compacted on-disk generations, the incremental compactor, arena eviction — what makes the arena a hot cache rather than the whole set. Off, the arena IS the set and the WAL is its durable record, which is correct at MCU scale: a compactor that cannot keep pace with a 64-slot arena turns a full arena into refused binds |
| — | — | — | There is deliberately no replication flag. Erasure coding, scrub and fan-out are separate MODULES (`ec_body_router`, `body_fanout_router`, `placement_router`), so a graph that does not want them does not wire them and nothing of them is compiled or scheduled. Fluxor's module granularity already does this job; a flag would duplicate it and could disagree with the graph. The rule: gate what lives inside a module every profile runs, and let the graph exclude whole modules |

`tools/ci/profile_matrix.sh` runs the whole suite against all four,
so a profile is proven rather than declared.

## Key ceilings

The three that decide what loam will accept as a name. They are load
bearing in a way the other rows are not, so they get their own
section and their own invariant:

> **Accepted implies storable implies listable.** The wire refuses
> exactly what the arena slot and the snapshot record cannot hold
> whole. There is no state in which a key was bound but cannot be
> compared byte-for-byte or returned by a listing.

The invariant exists because the alternative is a class of silent
data loss. Let the wire accept a key wider than the arena slot can
inline and the overflow has to go somewhere: stored as
`path_len = 0`, it is "bindable but unlistable" — a legal S3 key
accepted by `PUT`, returned by `GET`, and absent from every
`ListObjectsV2`. Nothing errors, and the gap is visible only to a
client that lists what it wrote. So the ceilings are one set of
names, checked identically at every door.

Identity follows the same rule. A key is compared by its bytes, and
where a digest stands in for those bytes it is SHA-256
(`mechanics/loam_hash.rs`) — not a hash pair narrow enough for a
tenant who names their own keys to collide by construction.

| Cap | Symbol | Source | embedded | host | Reason |
|---|---|---|---|---|---|
| Namespace root | `MAX_ROOT` | `mechanics/loam_limits.rs` | 64 | 64 | S3 bucket names cap at 63 bytes, and a bucket is the gateway's tenancy boundary, so 64 covers the surface exactly on both profiles. Not profiled because nothing has asked for more |
| Object id | `MAX_OBJECT_ID` | `mechanics/loam_limits.rs` | 96 | 96 | The content-derived form `sha256:<64 lowercase hex>` is 71 bytes; 96 leaves headroom for other identity schemes without a profile split. Also the volume-id ceiling on the block surface |
| Path within a root | `MAX_PATH` | `mechanics/loam_limits.rs` | 160 (`minimal`, `embedded`) | 1024 (`node`, `server`) | The one profiled key ceiling. Host is 1024 because that is the longest legal S3 object key and a key a client may legally send must be one loam can store, look up and list. Embedded is 160 because the path dominates `BindingSlot` and a bare-metal namespace instance is budgeted against a 256 KiB arena; a longer key there is REFUSED at the wire, never accepted and hidden |
| Widest key-shaped wire field | `MAX_KEY_STRING` | `mechanics/loam_limits.rs` | 160 | 1024 | Derived, not chosen: the widest of the three above. For buffer sizing only. It is NOT a per-field ceiling: using it as one would let an object id run to `MAX_PATH`, so the wires call `check_key`, which picks the right ceiling per field |

Enforcement sites, all deriving from the four names above — a
hand-written number at any of these is the drift this register exists
to catch:

| Site | Symbol | What it is |
|---|---|---|
| Namespace wire | `loam_wire::check_key` | Refuses on BOTH encode (a local producer fails loudly) and decode (a remote frame cannot smuggle an oversize key past the ceiling) |
| Admin wire | `loam_admin_wire::check_key` | The S3 gateway's front door |
| Object wire | `loam_object_wire::MAX_STRING` | `= MAX_OBJECT_ID`. Object ids are the only key-shaped field on this wire |
| Block wire | `loam_block_wire::MAX_STRING` | `= MAX_OBJECT_ID`. Volume ids share the object-id ceiling |
| Arena slot | `BindingSlot::{root_bytes,path_bytes,object_id_bytes}` | Sized to the ceilings; `path_len` is `u16` because `MAX_PATH` exceeds `u8` on host |
| Snapshot record | `loam_snapshot::REC_SIZE` | Derived: 349 B embedded, 1213 B host |
| Composed write | `admin_router_body::{NS_PATH_BUF,NS_ROOT_BUF}` | Sized from `MAX_PATH`/`MAX_ROOT`. An independent buffer here would be a second, smaller, undeclared ceiling refusing a key the namespace accepts |
| State machine | `state::key_fits`, `ApplyError::KeyTooLong` | Defence in depth: keeps "accepted but not storable" unrepresentable even if a caller bypasses the wire |

## Arena capacity

The per-instance live-record budget. `ModuleState` is heap-allocated
by the fluxor kernel, so raising one of these raises that module's
memory budget linearly.

| Cap | Symbol | embedded | host | Binds instead / notes |
|---|---|---|---|---|
| Namespace bindings | `NAMESPACE_SLOTS` | 64 `minimal` / 256 `embedded` | 8192 | NOT a capacity ceiling while the snapshot tier is on: the arena is a hot cache over the durable snapshot, so a bind into a full arena retries behind an eviction of one snapshot-covered slot, and more bindings than slots is a working-set question — `ns_scales_past_arena_capacity_via_snapshot` drives `NAMESPACE_SLOTS + 512` through the real step loop. With no active snapshot to evict against — and on `minimal`, where the tier is compiled out — the arena IS the set and a bind past it is refused. Slot is 384 B embedded, 1248 B host — the host arena is therefore 10,223,616 B (9.75 MiB) per instance, the direct cost of storing a full-length S3 key inline. Pinned by `binding_slot_matches_the_size_the_limit_register_quotes` |
| Object descriptors | `OBJECT_SLOTS` | 64 `minimal` / 256 `embedded` | 8192 | A true ceiling — whole-set arena, so object count is hard-capped per node. The snapshot treatment that makes `NAMESPACE_SLOTS` a cache has no counterpart here yet |
| Block volumes | `BLOCK_SLOTS` | 8 `minimal` / 64 `embedded` | 1024 | A true ceiling. Volumes are coarse-grained (one per logical disk or image), so the budget is far smaller than the per-binding and per-object arenas |
| Body slots | `BODY_SLOTS` | 16 `minimal` / 64 `embedded` | 8192 | NOT a ceiling on bodies held: the slot table is an index over the on-disk inventory, and a cursor-0 `OP_SCAN` rehydrates it from the root directory. It bounds working-set lookup |

## Deliberate caps

Policy ceilings and sanity bounds. Values are the same on both
profiles unless a row says otherwise — which is itself worth
recording: several of these are correct for a Pi and wrong for a
server, and are listed under Known gaps below.

| Cap | Symbol | Source | Value | Reason |
|---|---|---|---|---|
| Single-shot body | `MAX_BODY` | `mechanics/loam_body_wire.rs` | 61440 | Policy: the largest body one PUT/GET carries, and the chunk size of the streaming family. **Serves two masters** — a throughput knob on a server, the routers' largest arena allocation on a Pi (`READ_BUF` and `SCRATCH` are `MAX_BODY + 64` in the body and fan-out routers, `+ 128` in `admin_router`). Un-profiled |
| Largest object, ever | `MAX_STREAM_TOTAL` | `mechanics/loam_body_wire.rs` | 1 GiB | Policy: the declared total a streamed write may reach. This is a **product ceiling** — no object of any kind exceeds it — and is un-profiled |
| Fleet members | `MAX_FLEET` | `replicated/loam_placement_wire.rs` | 16 | Policy: the fleet-epoch snapshot is a fixed-size broadcast record. This caps a cluster at sixteen members on every profile, which is the real ceiling behind any "scales to cloud volumes" claim |
| EC shards | `MAX_SHARDS` | `mechanics/loam_ec.rs` | 16 | Policy: k+m for one body. Bounds the Cauchy matrix and the shard tables; 16 shards over a 16-member fleet is the widest geometry the placement can distribute |
| Concurrent streamed writes | `WRITE_SESSIONS` | `mechanics/loam_limits.rs` | 2 `minimal` / 4 `embedded` / 8 `node` / 64 `server` | Policy: each session holds a temp-file handle and an incremental hash |
| Proposals in flight | `PROPOSER_PENDING` | `mechanics/loam_limits.rs` | 256, or 1024 on `server` | Policy: a proposal past the table is REFUSED to the producer, never dropped. Bounds how deep a leader-loss window gets before back-pressure reaches the writer |
| Router joins in flight | `ROUTER_PENDING` / `ROUTER_JOINS` | `mechanics/loam_limits.rs` | 64·32, or 256·128 on `server` | Policy: outstanding upstream requests per fleet member (the table is `MAX_FLEET × ROUTER_PENDING`) and the per-request fan-out join records |
| Admin ops in flight | `ADMIN_PENDING` | `mechanics/loam_limits.rs` | 64, or 256 on `server` | Policy: bounds the correlation table on the front door |
| Composed writes in flight | `ADMIN_PUTFILE` | `mechanics/loam_limits.rs` | 16, or 64 on `server` | Policy: concurrent three-stage `PUT_FILE` state machines |
| Streamed composed writes | `ADMIN_STREAMED_PUTFILE` | `mechanics/loam_limits.rs` | 4, or 32 on `server` | Policy: concurrent streaming `PUT_FILE` sessions; pairs with `WRITE_SESSIONS` |
| Ops per step | `OPS_PER_STEP` | `mechanics/loam_limits.rs` | 4 everywhere except 8 on `server` | Policy: the cooperative step budget. A FAIRNESS knob as much as a throughput one — every module shares the lane. Deliberately NOT lowered on `minimal`: it would save ~512 bytes against a 256 KiB arena while halving the throughput of the slowest device, and what makes a constrained profile is arena capacity and feature tiers, not pacing. `loam_load_gen` is paced separately, by the row below |
| Stub ops per step | `STUB_OPS_PER_STEP` | `mechanics/stub_body.rs` | 4 everywhere | Policy: the reserved-name stub's step budget. A literal rather than the register's value because the body does nothing per op, so its budget is not a tuning decision and it has no reason to mount the limits module |
| Load-generator ops per step | `LOAD_GEN_OPS_PER_STEP` | `app/loam_load_gen/mod.rs` | 8 everywhere | Policy: records the generator offers per step. Deliberately independent of `OPS_PER_STEP` and un-profiled — the generator's job is to outrun the plane it measures, so pacing it with the plane would make the generator the thing under test, and a load figure that moved with the profile would not be comparable across profiles |
| Decision-record payload | `MAX_INNER` | `mechanics/loam_decision_wire.rs` | 4096 | Policy: the largest loam record a Propose carries across the clustor envelope. Every metadata wire record is bounded under it by construction. A `Committed` record adds `COMMITTED_HDR` (73 B of commit proof and framing) on top, which is what the reassembly buffers on that path are sized against |
| WAL record | `MAX_WAL_REC` | `mechanics/wal_io.rs` | 4096 | Policy: matches `MAX_INNER`, since a WAL record is the same wire payload |
| Log record | `MAX_RECORD` | `mechanics/loam_log_wire.rs` | 4096 | Policy: `block_log`'s append payload; matches the WAL for the same reason |
| Net frame payload | `MAX_FRAME_PAYLOAD` | `mechanics/loam_net_wire.rs` | 131072 | Sanity bound: one channel message per TCP frame; catches a corrupt length prefix before it allocates |
| Extent size | `MAX_EXTENT_SIZE` | `mechanics/loam_extent_wire.rs` | 61400 (`MAX_BODY` − `EXT_HDR`) | An extent is a keyed body, so it cannot exceed what one keyed PUT carries. Written as a literal because that wire is `#[path]`-included by six consumers that name the body wire differently; `an_extent_blob_fits_inside_one_keyed_body` pins the derivation instead |
| List page | `MAX_LIST_PAGE` | `mechanics/loam_wire.rs` | 16 | Policy: paths per LIST response, so one response stays under the 4 KiB record bound at any key length |
| Object scan page | `MAX_OBJ_SCAN` | `mechanics/loam_object_wire.rs` | 16 | Policy: descriptors per scan page, for the orphan GC's bounded sweep |
| Body scan page | `MAX_SCAN_DIGESTS` | `mechanics/loam_body_wire.rs` | 4 | Policy: digests per `OP_SCAN` page — the unit of both GC and scrub progress |
| Compaction records per step | `CMP_RECORDS_PER_STEP` | `mechanics/namespace_pic_body.rs` | 32 | Policy: snapshot records one step merges before yielding. An unbounded merge would stall every module sharing the lane |
| Counter drain per step | `MAX_DRAIN_PER_STEP` | `app/loam_throughput_counter/mod.rs` | 32 | Policy: records the counter consumes per step, so a fast producer cannot monopolise it |
| Open namespace handles | `NS_OPEN_MAX` | `mechanics/namespace_pic_body.rs` | 16 | Policy: an open past the table is refused; each handle costs cursor state |
| Change window | `change_horizon` | `mechanics/namespace_pic_state.rs` | dynamic | Not a constant but a ceiling all the same, and it belongs here for the same reason the others do: it bounds what `namespace::CHANGES` can answer. The arena is a hot cache, so a delta window is serviceable only while the evidence is resident; below the horizon — a slot evicted, a tombstone compacted away — the answer is LOST, never a silently short window |
| Snapshot manifest entries | `MAX_ENTRIES` | `mechanics/loam_manifest_wire.rs` | `u32::MAX` | The format's own ceiling — the count field is a `u32` — and deliberately NOT the binding one: a manifest is an ordinary body, so `MAX_STREAM_TOTAL` binds first, at roughly 31 million entries on every profile. Registered because `encode` refuses past it rather than truncating; a manifest that silently stopped at some count would lie about what the snapshot contains |
| Admin auth token | `MAX_TOKEN` | `mechanics/loam_admin_wire.rs` | 256 | Policy: a 512-bit secret in hex is 128 bytes, so 256 is generous. Bounded deliberately low because it is the ONE field an UNAUTHENTICATED peer can make the server hold — everything else on this wire is behind the auth gate |
| Quota-bearing roots | `MAX_QUOTA_ROOTS` | `mechanics/object_pic_state.rs` | 32 | Policy: roots that can carry usage or a ceiling at once. Bounds TENANTS, not keys — a root appears only once it holds an object or has a quota set. A `set_quota` past the table is REFUSED rather than silently not applied: a quota an operator believes is in force but is not is worse than no quota |
| Change subscriptions | `NS_SUB_MAX` | `mechanics/namespace_pic_body.rs` | 8 | Policy: live `namespace::SUBSCRIBE` registrations per instance. Each slot holds its prefix inline (`MAX_PATH`), and a graph wires a bounded consumer set. A subscribe past the table is refused `EMFILE` — never accepted and silently not delivered, which would look to a reconciler exactly like a quiet namespace |
| Change record | `REC_MAX` | `mechanics/loam_change_wire.rs` | derived | Derived, not chosen: `REC_HEADER + MAX_PATH + MAX_OBJECT_ID`. Moves when either key ceiling moves |
| Pushed change event | `EVENT_MAX` | `mechanics/loam_change_wire.rs` | derived | Derived: `EVENT_HEADER_SIZE + REC_MAX`. Sizes the module's one event scratch buffer |
| GC reservations | `GC_RESERVE_MAX` | `mechanics/namespace_pic_body.rs` | 4 | Policy: concurrent orphan-GC reservations. Arena-only and never logged — a crash clears them, which is the correct restart state |

## Identifier widths

Loam mints no identifier space of its own: object ids are opaque
byte strings bounded by `MAX_OBJECT_ID`, bodies are addressed by
their 32-byte SHA-256 digest, and correlation ids come from
fluxor's channel vocabulary. The one width worth recording is the
digest, because several wires assume it:

| Id | Width | Symbol | Source | Notes |
|---|---|---|---|---|
| Content digest | 32 bytes | `DIGEST_LEN` | eight sites: `mechanics/loam_{body,object,ec,extent,admin,manifest}_wire.rs`, `mechanics/object_pic_state.rs`, `replicated/loam_placement.rs` | SHA-256. Restated per wire rather than shared, so each stays independently includable; const-equal, and a mismatch would be caught at the first cross-wire round trip |

## Known gaps

Ceilings this register records honestly as unresolved, rather than
implying they are settled:

- **`MAX_BODY`, `MAX_STREAM_TOTAL` and `MAX_FLEET` are not
  profiled.** The in-flight tables and the arenas take the profile
  axis; these three do not, so they are single numbers serving both
  a microcontroller and a server. Each is a value decision rather
  than a mechanism one — the axis is there to take — but no such
  decision has been made, and a number nobody has chosen per profile
  is recorded here rather than presented as a considered one.
- **The pack step does not pass or declare a profile.** `fluxor
  modules build` compiles with no `--cfg loam_profile`, so a
  bare-metal image always takes the `embedded` fallback — the right
  default, but `minimal` and `server` are reachable only in cargo
  builds, through `RUSTFLAGS`. The same step declares no
  `--check-cfg` for `loam_profile` either, so its strict build sees
  the selector as an unknown name; `loam_limits.rs` fences that one
  ladder with a scoped `allow`. A way for a project to pass and
  declare its own cfg is an upstream ask on fluxor, not something
  loam can settle in this tree.
- **`DIGEST_LEN` is declared in eight places.** Const-equal, and a
  mismatch would surface at the first cross-wire round trip, but the
  width has no single home.
- **A snapshot is profile-specific.** `REC_SIZE` derives from
  `MAX_PATH`, so a file written by one profile fails the
  `size == SNAP_HDR + count * REC_SIZE` validity check on the other
  and is treated as the invalid generation — the same path a torn
  write takes. Deliberate: silently reinterpreting another profile's
  records would mispair keys with revisions.
