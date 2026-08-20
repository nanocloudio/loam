# Loam Architecture

Loam is fluxor-native. Every line of production storage logic runs
in a fluxor PIC module under [`modules/`](../modules/); the host
crate under [`src/`](../src/) is a vocabulary library that consumers
(the loam CLI, the daemon, the fluxor build tool) all speak.

## Layout

```text
loam/
├── modules/                  # fluxor PIC modules — all runtime logic
│   ├── app/                  # one directory per module: mod.rs + manifest.toml
│   │   ├── namespace_router/     # storage.namespace (BIND / RENAME / UNBIND / LOOKUP)
│   │   ├── object_index/         # storage.object metadata (PUT / UPDATE / REMOVE / GET)
│   │   ├── block_allocator/      # storage.block surface
│   │   ├── raft_metadata_client/ # proposes through a replica group
│   │   ├── clustor_bridge/       # decision records across the group's envelope
│   │   ├── body_store/           # content-addressed body blobs
│   │   ├── admin_router/         # front-door admin ops
│   │   ├── block_log/            # channel-fronted append-only log
│   │   ├── placement_router/     # fleet table + FleetEpoch broadcast
│   │   ├── body_fanout_router/   # replicated bodies: fan-out, fallback, read repair
│   │   ├── ec_body_router/       # erasure-coded bodies: k+m shards, reconstructing GET
│   │   ├── loam_load_gen/        # offers Propose records at a controlled rate
│   │   ├── loam_throughput_counter/  # counts resolved records per window
│   │   ├── metadata_e2e_probe/   # single-shot metadata round trip
│   │   ├── body_e2e_probe/       # single-shot body round trip
│   │   ├── cache_manager/        # reserved name, stub body
│   │   ├── io_scheduler/         # reserved name, stub body
│   │   └── telemetry_agg/        # reserved name, stub body
│   └── common/               # shared no_std source, split by storage tier
│       ├── mechanics/        #   single-node fence classes; fluxor-only
│       └── replicated/       #   quorum fence classes; may reach clustor
├── src/                      # vocabulary only — no runtime
│   ├── lib.rs
│   ├── core/                 # Config, Error, RuntimePlan
│   ├── namespace.rs          # PathKey, NamespaceKind
│   ├── object.rs             # ObjectId, ObjectDescriptor, ObjectPlacement
│   ├── block.rs              # BlockClass, BlockVolume
│   ├── fluxor.rs             # FluxorTarget, FluxorGraphProfile
│   ├── placement.rs          # NodeClass, StorageRole, PlacementPlan
│   ├── raft.rs               # ClustorBinding descriptor
│   ├── module_bindings.rs    # module → surface visibility table
│   ├── storage/              # WritePlan, SurfaceDescriptor, AchievableFence
│   ├── control/              # Tenant, RoutingEpoch
│   └── ops/                  # HealthReport
├── config/loam.toml          # the config `loam validate` / `loam plan` parse
├── tools/loam-cli/           # host crate: the loam CLI + loam-server daemon
├── tools/loam-client/        # host crate: client library for the admin surface
├── docs/
└── target/fluxor/            # staged by `fluxor sync`: every declared
                              #   dependency's modules + source artefacts
```

## Vocabulary, not runtime

`src/` holds types only. Anything that mutates state lives in a
PIC. The vocabulary covers:

- **Identity** (`ObjectId`, `PathKey`, `BlockVolume`, `BlockClass`)
- **Descriptor records** (`ObjectDescriptor`, `ObjectPlacement`,
  `NamespaceBinding`, `NamespaceEntry`)
- **Surface metadata** (`StorageSurface`, `AchievableFence`,
  `WritePlan`, `SurfaceDescriptor`, `ModuleBinding`,
  `MODULE_BINDINGS`)
- **Target/profile enums** (`FluxorTarget`, `FluxorGraphProfile`,
  `NodeClass`, `StorageRole`, `PlacementPlan`, `ClustorBinding`,
  `ConsistencyMode`)
- **Configuration + project errors** (`Config`, `RuntimePlan`,
  `Error`, `Result`)
- **Surface-agnostic records** (`Tenant`, `RoutingEpoch`,
  `HealthReport`)

Fence + storage-handle types come from `fluxor-contracts` and are
re-exported through the `prelude`.

## PIC durability

Each public-surface PIC (`namespace_router`, `object_index`,
`block_allocator`) and `raft_metadata_client` writes every applied
event to a WAL via the fluxor `fs` contract before mutating its
in-arena state, then replays the WAL on open. `body_store` writes
each content-addressed blob to `<root_dir>/<hex_digest>` and
persists slot metadata in arena. Files are created on first boot via
`FS_OPEN_CREATE` — no pre-touch required. Shared primitives:
[`modules/common/mechanics/wal_io.rs`](../modules/common/mechanics/wal_io.rs).

`admin_router` fronts the public PICs. External admin clients speak
[`loam_admin_wire.rs`](../modules/common/mechanics/loam_admin_wire.rs)
— the whole file lifecycle (`BIND`, `PUT_FILE`, `GET_FILE`,
`DELETE_FILE`, `LIST_FILES`, `STAT_FILE`, with revision-gated
overwrite), the streaming form for anything past the 60 KiB
single-shot cap (`PUT_FILE_OPEN` / `_CHUNK` / `_COMMIT` and
`READ_FILE_RANGE`), and the raw body ops (`PUT_BODY`, `GET_BODY`,
`PUT_BODY_KEYED`, `DELETE_BODY`). The router demuxes each to the
right downstream PIC, runs a 3-stage state machine for the composed
`PUT_FILE`, and hosts the orphan-body GC loop.

For multi-client production deployments the `loam-server` binary in
[`tools/loam-cli/`](../tools/loam-cli/) hosts the full graph and
exposes it through three surfaces: the unix admin socket
(`--socket`), an S3-compatible HTTP gateway (`--s3-listen` —
PUT/GET/HEAD/DELETE per object, buckets are namespace roots), and
the loam network contract. The contract
([`modules/common/mechanics/loam_net_wire.rs`](../modules/common/mechanics/loam_net_wire.rs))
is framed channel bridging over TCP — one channel message per frame,
per-tag FIFO order preserved — so a channel pair can span machines
and the PICs on either end can't tell. It carries the body plane:
`--serve-body` turns a node into a body_store host, and a
`tcp:ADDR` member in the admin node's `--fleet` list points the body
channels at it.

On the gateway, a bucket is a namespace root and an ETag is the
content digest. `--s3-credentials FILE` turns on AWS SigV4
verification with per-access-key bucket scopes, which is what makes
the bucket a tenancy boundary; without it the gateway is anonymous.
Verification is loam's
([`tools/loam-cli/src/sigv4.rs`](../tools/loam-cli/src/sigv4.rs));
signing belongs to wave, which owns the S3 protocol.

## block_log: channel-fronted durability

The `block_log` PIC ([`modules/app/block_log/`](../modules/app/block_log/),
body in
[`modules/common/mechanics/block_log_body.rs`](../modules/common/mechanics/block_log_body.rs))
exposes an append-only log via two channels: `log_requests` takes
`AppendReq` / `ReplayReq` frames, `log_responses` emits
`AppendResp` / `ReplayRecord` / `ReplayEnd` frames. Wire format in
[`modules/common/mechanics/loam_log_wire.rs`](../modules/common/mechanics/loam_log_wire.rs).

It gives a consumer PIC durability as a channel rather than as a
syscall, so swapping the backing storage (fs syscalls for direct
block-device channels on bare metal) is one body file swap that
leaves the consumer unchanged. The WAL-using PICs take the syscall
route instead, including `wal_io.rs` directly: fluxor's `fs`
provider dispatches the whole write path and offers write and fsync
in the shape a bounded step needs, so the indirection buys nothing
they need.

## Two-plane model

Loam has two independent planes with independent fault domains:

**Metadata plane** (Raft-guarded, small, replicated by clustor in
production):

- Namespace bindings: `(namespace_root, path) → ObjectId`
- Object descriptors: `ObjectId → { content_hash, size, placement }`
- Block volume metadata
- Placement claims

The PIC wire formats (`loam_wire.rs`, `loam_object_wire.rs`,
`loam_block_wire.rs`, `loam_decision_wire.rs`) carry these as
fixed-size binary records bounded under 4 KiB each.

**Body plane** (out of Raft, addressed by content hash):

- Object bytes
- Block-volume extents
- Cache, page-backing, working sets

Bodies live in `body_store`; metadata references them only by
`content_hash`, so no body byte ever enters a Raft log.

Above `body_store` sit two interchangeable routers, both stateless
because placement and addressing are pure functions of (digest,
fleet): `body_fanout_router` replicates whole bodies across a ranked
replica set, `ec_body_router` splits each body into k data + m
parity shards. `placement_router` owns the fleet table and
broadcasts a FleetEpoch snapshot; the routers cache it and compute
targets locally by rendezvous hashing, so no PUT costs a round trip
into the router.

A block volume rides the same plane rather than getting one of its
own: the volume descriptor is an ordinary content-addressed blob
bound at a namespace path, and its extents are mutable keyed blobs
under derived keys. Volume metadata therefore inherits binding,
replication and GC unchanged.

## Scale past one arena

An arena holds every record applied to its PIC instance, so
per-instance capacity is a ceiling. The namespace passes it: bindings
live in a sorted, binary-searchable snapshot file with alternating
generations, an incremental compactor merges old-snapshot × arena
into the next generation and rotates the WAL, and the arena becomes a
hot cache with eviction and tombstones. `object_index` and
`block_allocator` hold whole-set arenas, so their capacity is the
arena. Details, including the compaction hysteresis and the
cursor-paged `OP_REFERENCED` the orphan GC asks, are in
[`modules/README.md`](../modules/README.md).

## Topology invariance

Single-device, micro-DC, and hyperscale all run the same PIC
binaries with different graph profiles wiring different numbers of
PIC instances. What changes:

- Number of partitions.
- Body provider variants (single disk → replicated → erasure-coded).
- Placement policy.

What never changes:

- The wire formats (`modules/common/{mechanics,replicated}/loam_*_wire.rs`).
- The `Fence` vocabulary (`fluxor-contracts`).
- The PIC ABI shape (channels + step bodies).
