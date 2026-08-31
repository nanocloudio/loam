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
| `namespace_router` | `storage.namespace` | Arena (256 binding slots) over a compacted snapshot file + WAL-backed durability via the fluxor `fs` contract. The graph's one registered provider: exports `module_provides_contract` + `module_provider_dispatch`, answering `LOOKUP`, `STAT`, `CLOSE`, `BIND`, `RENAME`, `DELETE`, `CAPS` and the change pair `SUBSCRIBE` / `CHANGES` that level-triggered consumers reconcile against. `LIST` alone is channel-only — a listing is cursor-paged and a `provider_call` returns one buffer |

`object_index` (whole-set arena, 256 object slots) and
`block_allocator` (64 volume slots) are WAL-backed and reachable by
their ports, but declare NO canonical surface. Neither could honour
one: `storage.object` is whole-blob byte access and descriptors are
not object bytes; `storage.block` is raw block I/O and volume
accounting is not a block device. Each `manifest.toml` records that
in place, next to the claim it declines to make.

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
| `telemetry_agg` | An 11-line shim over `stub_body.rs`'s ping/noop/ticks protocol, and the one reserved name in the roster. It is held rather than dropped because the job behind it — metrics, health and readiness — is one a sustained soak cannot run without, so the name will be filled rather than retired. No other placeholder is kept: a reserved name is a cost paid by every reader, the roster, the docs and the tier guard |

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

The invariant a load run holds the plane to is conservation: every
record the plane accepts is committed or refused, never dropped.

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

So the WAL path has a durable backing on both profiles.

`FS_OPEN` does not create a file; `FS_OPEN_CREATE` does, on both
profiles, so a PIC lands its WAL on first boot without the graph
profile pre-touching anything.

## Arena sizing

An arena is the per-instance live-record budget: a flat, fixed-size
array of slots, allocated with the PIC's `ModuleState` by the fluxor
kernel via `heap_alloc`. Raising a cap raises that module's memory
budget linearly.

What an arena MEANS differs by surface, and the difference decides
whether its cap is a ceiling:

- **Namespace** — a HOT CACHE over the durable snapshot, where the
  snapshot tier is compiled in. The snapshot file and the WAL hold
  the whole set, so a bind into a full arena retries once behind an
  eviction of a snapshot-covered slot (never a locked one, whose
  lock the snapshot record does not carry);
  `ns_scales_past_arena_capacity_via_snapshot` drives 512 bindings
  past capacity with live compaction and a restart. With no active
  snapshot
  to evict against — and on `minimal`, where the tier is compiled
  out — the arena IS the set and a bind past it is refused, which is
  the behaviour the composed-node e2e exercises under overload.
- **Object descriptors and block volumes** — WHOLE-SET arenas. Every
  live record is resident, so the cap is a true ceiling and a record
  past it is refused.
- **Body slots** — an index over the on-disk inventory, rehydrated
  from the root directory by a cursor-0 `OP_SCAN`. It bounds
  working-set lookup, not bodies held.

Caps are per capacity profile, selected by an explicit
`--cfg loam_profile="…"` with the build target as the fallback
(`target_os = "none"` → `embedded`, otherwise `node`):

| Arena | `minimal` | `embedded` | `node` | `server` |
|---|---|---|---|---|
| namespace bindings | 64 | 256 | 8192 | 8192 |
| object descriptors | 64 | 256 | 8192 | 8192 |
| block volumes | 8 | 64 | 1024 | 1024 |
| body slots | 16 | 64 | 8192 | 8192 |

Every profiled constant lives in
[`common/mechanics/loam_limits.rs`](common/mechanics/loam_limits.rs)
and nowhere else — a PIC body takes its `ARENA_CAPACITY` from that
file rather than declaring a number. `tools/ci/limit_guard.sh` fails
the build on a `cfg(target_os)` capacity constant anywhere outside
it, and on a ceiling with no row in
[`docs/limit_register.md`](../docs/limit_register.md), which carries
the reasoning behind each figure.

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
duplicates. Proven by `ns_scales_past_arena_capacity_via_snapshot`,
which pushes 512 bindings past the arena capacity with live
compaction interleaved, then restarts onto snapshot + tail. It is a
no-op on `minimal`, where the tier is compiled out and a full arena
is an honest refusal.

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
