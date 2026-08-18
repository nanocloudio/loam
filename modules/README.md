# Loam Fluxor Modules

This directory holds Loam's Fluxor PIC module roles. All modules are
Transformer modules and target the pi5 board (bare-metal bcm2712) first.

Layout follows the fluxor CLI convention: module shims live at
`modules/app/<name>/mod.rs` (+ `manifest.toml`), shared step bodies
and wire formats under `modules/common/mechanics/` and
`modules/common/replicated/`, split by fence class and enforced by
`tools/ci/tier_guard.sh`. `fluxor modules build`
discovers `modules/app/*/mod.rs`,
handles staleness, and emits to `target/fluxor/<silicon>/modules/`.

## Roles

### Public storage surfaces (advertise on the mesh)

Slot counts below are the bare-metal profile; see
[Arena sizing](#arena-sizing) for the host figures.

| Module | Surface | What it does |
|---|---|---|
| `namespace_router` | `storage.namespace` | Arena (256 binding slots) over a compacted snapshot file + WAL-backed durability via the fluxor `fs` contract. Registers as a provider: exports `module_provides_contract` + `module_provider_dispatch` |
| `object_index` | `storage.object` | Whole-set arena (256 object slots) + WAL-backed durability |
| `block_allocator` | `storage.block` | Whole-set arena (64 volume slots) + WAL-backed durability |

### Internal (no public surface)

| Module | What it does |
|---|---|
| `raft_metadata_client` | [`common/replicated/raft_proposer_body.rs`](common/replicated/raft_proposer_body.rs); proposes through a replica group, carries a WAL, addresses results by the producer's correlation id |
| `clustor_bridge` | Carries loam's decision records across the replica group's channel envelope via the consumer facade |
| `admin_router` | The admin op surface: bind, file and body ops, plus orphan-body GC |
| `body_store` | Content-addressed blob store with streamed writes and keyed extents |
| `block_log` | Append/replay log body — durability as a channel rather than as a syscall |
| `ec_body_router` | Erasure-coded fan-out, reconstructing reads, scrub with re-placement |
| `placement_router` | Owns fleet membership + broadcasts a FleetEpoch snapshot on every change; consumers cache and compute placement locally via [`common/replicated/loam_placement.rs`](common/replicated/loam_placement.rs) |
| `body_fanout_router` | Sits between `admin_router` and the `body_store` fleet; all-must-succeed PUT, ranked GET/HEAD fallback with read repair, full-set DELETE, background scrub |
| `cache_manager`, `io_scheduler`, `telemetry_agg` | Reserved names carrying `stub_body.rs`'s ping/noop/ticks protocol — they hold their place in a graph and do nothing else |

### Replication topology

Placement follows the "channels as state-surfaces" discipline:
`placement_router` owns the authoritative fleet table and
broadcasts `[op:u8=0x60][epoch:u64][count:u8][members:count u8]`
on its `fleet_epoch` output whenever membership changes.
Consumers subscribe, cache the latest snapshot,
and compute per-object targets locally via
`loam_placement::pick_targets` — rendezvous hashing over the
object key. No per-PUT RPC into the router; placement is a pure
function of the cached snapshot + content digest.

`body_fanout_router` semantics: all-must-succeed PUT (any
replica NAK fails the upstream PUT). GET/HEAD try the rendezvous
primary first and fall back serially through the ranked replica
set; only when every ranked replica has failed is a NAK forwarded
upstream. A fallback GET success triggers READ REPAIR: the
returned body is re-PUT (best-effort, one-shot, never surfaced
upstream) to every earlier-ranked replica that NAKed NOT_FOUND.
DELETE fans out to the full ranked replica set — existed is the
OR of the replica flags, and only all-replicas-failed NAKs
upstream.

Background scrub (active when the router's `scrub_interval` is
nonzero): each interval the router SCANs one page of one
target's digest inventory (`OP_SCAN`, cursor-paged over
body_store's slot table), HEAD-probes each digest's ranked
replica set, and for a digest present on some ranked replicas
but NOT_FOUND on others GETs the body from a holder and re-PUTs
it to the missers. Targets are walked round-robin over all wired
channel slots, so bodies stranded on a member that left the
fleet are probed and healed onto the current fleet. Scrub
traffic is internal — nothing is ever written upstream.

Bodies past the 60 KiB single-shot cap STREAM: the writer
declares the content digest up front (`OP_WOPEN(digest, total)`),
appends bounded chunks (`OP_WAPPEND`), and `OP_WCOMMIT` publishes
only if every declared byte arrived AND incrementally hashes to
the declared digest — body_store streams to a temp file and
copies to the content path at commit. Digest-first is what keeps rendezvous
placement working for streams: the fanout router ranks the
replica set at WOPEN and fans every chunk all-must-succeed, with
per-member session-id tracking and cross-member abort on any
failure. Reads of large bodies use stateless `OP_RANGE`
(offset/length, ≤ 60 KiB per response), which walks the ranked
replica set with the same fallback as GET. Sessions abandoned
mid-stream are reaped and their temp files unlinked.

A cursor-0 `OP_SCAN` makes body_store sweep its root dir
(FS_OPENDIR + FS_READDIR) and rehydrate slot-table entries for
every on-disk body it doesn't know about (size via FS_OPEN +
FS_STAT — no body reads), so scan is authoritative for the disk
inventory even right after a whole-fleet restart.

`ec_body_router` is the erasure-coding sibling: a body with
digest D is split into k data + m parity shards (systematic
Cauchy Reed-Solomon over GF(256), `common/mechanics/loam_ec.rs` — the MDS
property is brute-force-verified in tests over every loss
pattern). Shard i lives on ranked target i under the derived key
`sha256("loam-ec-shard" || D || i)` via body_store's `PUT_KEYED`
— placement and addressing are pure functions of (D, fleet), so
the router keeps no durable state. The shard blob
(`common/mechanics/loam_ec_wire.rs`) is self-describing, which is how
body_store verifies a keyed blob on disk-fallback reads and how
a GET reassembles: any k of the k+m shards reconstruct the body,
and a reconstructed body must sha256 back to D before it is
served. One reassembly is in flight at a time (the shard buffer
is the arena's big allocation) — a client GET and a scrub fetch
share it, whichever comes second retries.

EC scrub (active when the router's `scrub_interval` is nonzero)
heals shard-level damage without client traffic: SCAN one page
of one member's key inventory per interval (round-robin), GET
each discovered blob from that member (its header identifies
body digest, geometry, and shard index), HEAD-probe every
shard's ranked home, then heal. Three outcomes: only the
discovered shard's own home is missing → direct-copy the blob
there (the re-placement case — rendezvous ranking moved after a
fleet change); other shards missing and ≥ k sources reachable →
fetch, reconstruct, verify against the body digest, re-encode
and PUT_KEYED each missing shard to its home; every home
verified present → delete the stray from the scanned member. A
stray is only deleted in a round where nothing needed repair, so
cleanup can never race the copy it depends on; unrecoverable
bodies (< k sources) are counted and retried on later rounds.

### Diagnostic

| Module | Purpose |
|---|---|
| `loam_load_gen` | Offers Propose records at a controlled rate (`inject_period`, `batch_per_step`, `total`, `warmup_ticks`) and reports offered against emitted, so a shortfall downstream is attributable |
| `loam_throughput_counter` | Counts resolved operations per window and since boot, split committed from refused. Reads either the plane's decision records or a surface's one-byte acks (`stream`) |
| `metadata_e2e_probe` / `body_e2e_probe` | Single-shot runtime probes; success is their PASS log |

Driven by [`tools/e2e/metadata_load.sh`](../tools/e2e/metadata_load.sh)
(bounded, gates on conservation) and
[`tools/e2e/metadata_soak.sh`](../tools/e2e/metadata_soak.sh)
(sustained, samples throughout).

## WAL plumbing (public surfaces)

Each public-surface PIC accepts a WAL file path via its `params`
byte slice on `module_new`. When set:

1. `module_new_with_wal_impl` opens the path via the fluxor `fs`
   contract — `wal_open_or_create`, i.e.
   `provider_call(-1, FS_OPEN_CREATE, ...)`, so first boot needs no
   pre-touch — and replays every record into the arena.
2. `module_step_impl` does **log-then-arena** on each successful
   apply: pre-validate opcode → `wal_append` (write + fsync via
   the `fs` contract) → mutate the arena → ack.
3. Empty `params` keeps the channel-only mode (no durability).

The WAL format is `[len: u32 LE][crc32: u32 LE][payload]` per
record, where the payload is the binary wire format the PIC already
speaks on its `requests` channel. CRC + length-prefix make replay
torn-tail tolerant: a partial trailing record is dropped on open.

Shared primitives live in
[`common/mechanics/wal_io.rs`](common/mechanics/wal_io.rs); each
public PIC has a `common/mechanics/<surface>_pic_body.rs` step body
that wires the WAL into the arena.

### Durability on the embedded profile

The `fat32` provider dispatches the whole write path —
`OPEN_CREATE`, `WRITE`, `FSYNC`, `UNLINK`, `PREALLOCATE` — and
advertises it through `fs::CAPS`. It also offers the write and fsync
submit/poll pair, which is the shape a bounded step needs: a module
submits and polls across steps instead of blocking inside one.

So the WAL path has a durable backing on both profiles. The host
profile is covered by
[`tests/pic_entry_points.rs`](../tests/pic_entry_points.rs),
[`tests/pic_object.rs`](../tests/pic_object.rs) and
[`tests/pic_block.rs`](../tests/pic_block.rs); the embedded profile
is covered by the `fluxor rig test` scenarios in
[`tests/hardware/`](../tests/hardware/).

`FS_OPEN` does not create a file; `FS_OPEN_CREATE` does, on both
profiles, so a PIC lands its WAL on first boot without the graph
profile pre-touching anything.

## Arena sizing

The arenas are **not caches** — they hold every record ever applied
to that PIC instance. WAL replay reconstructs the full state on
open. Sizing is therefore the per-instance live-record budget;
multi-PIC deployments shard further by partition (see
[`src/placement.rs`](../src/placement.rs)).

Caps are per capacity profile, selected by the build target:
bare-metal PIC builds (`target_os = "none"`) keep the bounded
embedded arena, host-runtime builds (the `loam-server` standalone
service, host tests) get service-class capacity. The build target is
the only selector — there is no per-silicon knob at the pack step —
so a module loaded on the host profile carries the host caps.

| Arena | Bare metal | Host |
|---|---|---|
| namespace bindings | 256 | 8192 |
| object descriptors | 256 | 8192 |
| block volumes | 64 | 1024 |
| body slots | 64 | 8192 |

Adjust per-PIC by changing `ARENA_CAPACITY` in the corresponding
`common/mechanics/<surface>_pic_body.rs`. The PIC `ModuleState` struct is
heap-allocated by the fluxor kernel via `heap_alloc`, so bumping
the cap raises the per-module memory budget linearly.

### Namespace scale: arena as hot cache

The namespace arena is a hot cache, not the whole set. A sorted,
binary-searchable snapshot file (`common/mechanics/loam_snapshot.rs`,
`<wal>.snapA`/`.snapB` alternating generations — an unfinished
generation carries an invalid header and can never outrank the
durable one) holds every binding; the incremental compactor
(bounded records per step) merges old-snapshot × arena into the
next generation, rotates the WAL afterward (boot replays only
the short tail), and re-triggers on dirty-entry hysteresis — a
naive occupancy trigger livelocks: compaction runs continuously
and starves eviction. Lookup misses binary-search the snapshot;
full arenas evict snapshot-covered slots (safe mid-merge: a
pre-cursor evictee's record flows in from the old snapshot, and
emit-tags are per-slot generation bytes so reused slots can't be
mismarked); deletes TOMBSTONE (masking the on-disk record until
compaction drops both, at the binding's revision so re-binds win
normally); listings walk arena then snapshot without
duplicates. Proven by a test pushing 8704 bindings through an
8192 arena with live compaction, then restarting onto snapshot +
tail.

OP_REFERENCED — the orphan GC's question — is CURSOR-PAGED so it
stays bounded per step at snapshot scale: page 0 checks the
arena, every page scans a bounded window (128 records) of the
snapshot. flag=1 → referenced (definitive); flag=0 +
next_cursor=0 → definitively unreferenced; otherwise the caller
(admin_router's GC loop) re-asks from next_cursor before
deciding delete. Conservative direction survives at every edge:
hash-only records, read failures, and snapshot records masked by
an arena tombstone all answer "referenced" (the tombstoned blob
is collected after compaction drops the record).

## Block volumes: mutable keyed extents

A block volume is an ordinary content-addressed DESCRIPTOR file
(`common/mechanics/loam_extent_wire.rs`: `LVOL` magic, volume_id, size,
extent size — bound at the volume's path, so volume metadata
rides bind/replication/GC unchanged) plus N fixed-size extents in
the body plane under derived keys
`sha256("loam-vol-extent" ‖ volume_id ‖ index)`. Extent blobs are
self-describing (`LVEX` header echoes the key, which is how
disk-fallback reads verify them) and MUTABLE: `PUT_KEYED`
overwrites, last write wins (body_store unlinks before create —
FS_OPEN_CREATE doesn't truncate, and a shorter overwrite must not
leave a stale tail for the restart-time fallback read). The
fanout router fans PUT_KEYED all-must-succeed to the key's ranked
replica set, so extents replicate exactly like bodies.

Ownership: body_store slots and SCAN entries carry a KEYED flag
(restored after restart by a 4-byte magic sniff in the disk
sweep). The orphan GC skips keyed entries — extents and EC shards
are never orphan-collectable; their lifecycle belongs to their
writers (volume delete / EC scrub). Sub-extent writes
read-modify-write in `loam-client` (sound under the one-publisher
discipline a block volume's consumer enforces). Admin surface:
`PUT_BODY_KEYED` / `DELETE_BODY`; client surface:
create/open/volume_read/volume_write/delete_volume.

Known trade: the replication scrub skips keyed entries, because a
heal re-put would store them under a content hash rather than their
key. HEAD takes the same disk fallback GET does (slot miss →
FS_STAT + magic sniff), so STAT and GET answer correctly right after
a whole-fleet restart.
