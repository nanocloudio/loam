# Loam Architecture

Loam is fluxor-native. Every line of storage logic runs in a fluxor
PIC module under [`modules/`](../modules/), composed into graphs that
`fluxor run` runs; the operator's applet is a PIC module too, run by
`fluxor exec`. Nothing on the shipping path is a host binary.

## Layout

```text
loam/
├── modules/                  # fluxor PIC modules — all runtime logic
│   ├── app/                  # one directory per module: mod.rs + manifest.toml
│   │   ├── namespace_router/     # storage.namespace (BIND / RENAME / UNBIND / LOOKUP)
│   │   ├── object_provider/      # storage.object: objects as files, per-caller capabilities
│   │   ├── object_index/         # object descriptors (PUT / UPDATE / REMOVE / GET)
│   │   ├── block_allocator/      # block volume metadata
│   │   ├── loam_volume/          # storage.block: one volume as a block device
│   │   ├── raft_metadata_client/ # proposes through a replica group
│   │   ├── clustor_bridge/       # decision records across the group's envelope
│   │   ├── body_store/           # content-addressed body blobs
│   │   ├── admin_gate/           # the admin plane's sessions and authority
│   │   ├── admin_router/         # the admin op surface
│   │   ├── block_log/            # channel-fronted append-only log
│   │   ├── placement_router/     # fleet table + FleetEpoch broadcast
│   │   ├── body_fanout_router/   # replicated bodies: fan-out, fallback, read repair
│   │   ├── ec_body_router/       # erasure-coded bodies: k+m shards, reconstructing GET
│   │   ├── loam_cli/             # the operator applet (`fluxor exec loam`)
│   │   ├── loam_load_gen/        # offers Propose records at a controlled rate
│   │   ├── loam_throughput_counter/  # counts resolved records per window
│   │   ├── metadata_e2e_probe/   # single-shot metadata round trip
│   │   ├── body_e2e_probe/       # single-shot body round trip
│   │   └── telemetry_agg/        # reserved name, stub body
│   └── common/               # shared no_std source, split by storage tier
│       ├── mechanics/        #   single-node fence classes; fluxor-only
│       └── replicated/       #   quorum fence classes; may reach clustor
├── packaging/                # service bundles and templates, the applet's bundle
├── examples/                 # reference graphs
├── tests/harness/            # the module harness: every unit test
├── tools/                    # CI, graph and service gates; diagnostics
├── docs/
└── target/fluxor/            # staged by `fluxor sync`: every declared
                              #   dependency's modules + source artefacts
```

## Graphs are the configuration

A deployment is a graph: which modules run, how their ports are
wired, and the parameters each takes — WAL paths, a body root, a
listening port, the mesh roots a gate trusts, a capacity profile
(`variant:`). `fluxor build` validates a graph against the modules'
manifests, so a misnamed port or parameter is refused before
anything runs. A module's surface is what its `manifest.toml`
declares and its fence is what its dispatch returns; nothing else
restates either. A service bundle (`packaging/service/`) is a graph
plus the modules it pins plus a declared parameter schema, run with
`fluxor run <bundle> --param …`.

Fence + storage-handle types come from `fluxor-contracts`.

## PIC durability

Each public-surface PIC (`namespace_router`, `object_index`,
`block_allocator`) and `raft_metadata_client` writes every applied
event to a WAL via the fluxor `fs` contract before mutating its
in-arena state, then replays the WAL on open. That WAL is the
module's recovery authority; the metadata plane above it is
authoritative for acceptance, not for replay. An append is a state
machine rather than a call, so a device that has accepted work but
not finished it costs a later step instead of an operation refusal.
`body_store` writes each content-addressed blob to
`<root_dir>/<hex_digest>` and persists slot metadata in arena, and
publishes it with the strongest recipe the storage provider offers —
refusing rather than acknowledging a blob it cannot publish durably.
Files are created on first boot via `FS_OPEN_CREATE` — no pre-touch
required. Shared primitives:
[`modules/common/mechanics/wal_io.rs`](../modules/common/mechanics/wal_io.rs);
the contracts are in [`durability.md`](durability.md).

What a PIC then ADVERTISES is decided by the proof it holds, not by
how it was wired. In replicated mode each `Committed` record carries
its own proof — the log's `source`, the Raft `term` and `index`, the
`quorum`, and a witness over the committed bytes — and a provider
reports `ReplicatedDurable` only for an applied commit whose proof
shows a real quorum and a real witness. One voter, or no witness,
reports `LocalDurable`.

The witness is what makes that fence checkable. `Fence::dominates`
orders two fences from the same log by commit index, and at the same
index it compares witnesses: two replicas of one log commit identical
bytes and so agree, while two logs that diverged at that position do
not. A witness that were a counter, or zero, would report a fork as
agreement — which is why a proof missing one is refused a replicated
claim rather than being padded into the shape of one.

`admin_router` fronts the public PICs. External admin clients speak
[`loam_admin_wire.rs`](../modules/common/mechanics/loam_admin_wire.rs)
— the whole file lifecycle (`BIND`, `PUT_FILE`, `GET_FILE`,
`DELETE_FILE`, `LIST_FILES`, `STAT_FILE`, with revision-gated
overwrite), the streaming form for anything past the 60 KiB
single-shot cap (`PUT_FILE_OPEN` / `_CHUNK` / `_COMMIT` and
`READ_FILE_RANGE`), `LOOKUP` (a path's object id, revision and kind
without its body), the raw body ops (`PUT_BODY`, `GET_BODY`,
`PUT_BODY_KEYED`, `DELETE_BODY`), and the volume ops (`LEASE`,
`VOLUME`). `admin_gate` admits each request under the capabilities
its session presented before the router sees it
([Sessions and authority](#sessions-and-authority)).
The router demuxes each to the right downstream PIC, runs a 3-stage state machine for the composed
`PUT_FILE`, and hosts the lifecycle sweep that reclaims orphaned body
blobs and unbound object descriptors. A write's ack — `BIND`,
`PUT_FILE`, `DELETE_FILE` — ends with the fence the namespace achieved
for its bind, carried up from the namespace's own write ack, so a
storage provider reports durability it was told rather than one it
assumed. The composed write's crash
model — idempotent retry, unreachable intermediate state, and
conservative reclamation, with the fault matrix behind it — is in
[`durability.md`](durability.md).

`LEASE` gives a volume one writer at a time: acquire, renew or
release a TTL lease keyed by (root, path), answered with a fence
token that grows whenever the holder changes and is never reissued.
The router stamps each request with its own wall clock — strictly
increasing, and refused outright when there is no clock — and the
namespace decides it in log order like any mutating record, so
every replica and every replay reaches the same verdict. The lease
table lives in the namespace WAL and is carried across a rotation
by seeding the new log with it; a record stamped no later than the
last one applied to its volume is a redelivered duplicate and
changes nothing.

`VOLUME` moves a volume's committed root forward. `BEGIN` opens a
flush, `COMMIT` binds the volume's path to a new map root at
`expected + 1`, `ABORT` closes a flush without binding, and `DELETE`
unbinds the path under the same lease and revision check. It is the
only way to change a volume binding: a plain `BIND`, `RENAME` or
`UNBIND` — on the channel wire or the provider surface — that would
create, replace, move or remove one is refused (`NAK_FENCED` 0xFC on
the channel, `EPERM` on the surface), so no change to a volume
escapes the fence. A commit
is admitted only when the current revision is exactly `expected`
(`CONFLICT` otherwise), the writer holds the live lease under the
fence it names (`LEASE_LOST` otherwise), and it opened a flush first.
The router stamps the record like a lease request and the namespace
decides it in log order, so the bind is the one atomic point every
replica agrees on. While any flush is open the namespace answers
every `REFERENCED` question "referenced", and a `BEGIN` is refused
while a GC reservation stands: together they keep the orphan GC off
the bodies of a flush whose commit is not yet decided. A reservation
carries the sweep's server time, and deciding one ends every open
flush whose writer's lease has expired by then — that writer's commit
is refused anyway — so a crashed writer holds the GC off only until
its lease lapses.

Loam's public surfaces are graphs around that core. The loam-s3
service puts wave's `http` and `s3_serve` in front of
`object_provider`, which answers fluxor's `storage.object` contract
with objects named `bucket/key` as files under namespace root
`bucket`: buckets are namespace roots and ETags are content digests.
SigV4 is verified by `s3_serve`, which owns the S3 protocol, and each
access key acts under the capability its credentials line carries.
The loam-admin service exposes the admin wire itself over mutual
TLS, for the operator's applet and for a volume's `loam_volume` on
another node.

The body plane spans machines through fluxor's `remote_channel`. A
body channel carries `[len:u32][cid:u32][record]` frames whether its
peer is in the graph or not, so a `body_fanout_router` member port is
wired either to a local `body_store` or to a `remote_channel` that
dials a loam-body node through a client-mode `tls`; the node is a
`body_store` behind a server `tls` and a listening `remote_channel`
that takes only a session whose peer certificate verified. The
correlation id is what lets the router put a deadline on each answer
and drop one that arrives after it: a member across a network can
lose the requests in flight when its session ends.

## Sessions and authority

mTLS authenticates a connection; a capability authorises what is
done on it. `admin_gate` holds the admin plane's sessions: one per
connection on the clear side of a server `tls` — bound to the peer
certificate `tls` verified, by connection id and generation — and one
per in-graph link (`[session:u32][frame]` records), for a module in
the same graph such as `object_provider` or `loam_volume`.

A session presents capability chains with `MSG_CAP_PRESENT` before
its first request. Each is verified against the `mesh_roots` the gate
is configured with and the trusted clock, and recorded against the
session (at most `MAX_SESSION_GRANTS`); it dies with the session.

**Every request is admitted where it is framed, in the gate, before
it reaches `admin_router`.** The gate frames each request out of the
session's byte stream (`loam_admin_wire::request_len`) and names what
it touches with the wire's own decoders (`request_scope`): a key
under a namespace root, the content-addressed body plane, or a
stream. A key is admitted by a grant whose object is
`grant::scope_object` of a `/`-terminated prefix of `root/path` —
the storage contract's scope rule, so a grant minted with
`--scope photos/` reaches the same keys here as through
`storage.object` — and the body plane by a grant on its own object.
Reads need `ReadState`, writes and leases `SendCommand`, the keyed
body plane (`PUT_BODY_KEYED`, `DELETE_BODY`) `Admin`; a lease may not
reach past the grant that admitted it. A refusal is
`STATUS_FORBIDDEN`, distinct from `STATUS_NAK` because the remedy is
a capability, not a retry, and it is encoded in the op's own ack
shape so a client decodes it with the decoder it was already waiting
on. A byte that names no request is answered `FORBIDDEN` under the cid
it carries, and closes the session: nothing after it can be framed.

Ops that name no key are judged by where their effect lands. A
content-addressed `PUT_BODY` or `GET_BODY` cannot change bytes anyone
else reads (one digest is one set of bytes), and what it stores stays
an unreferenced orphan until a bind or a volume commit on a granted
key names it. A streamed write's chunks and commit name only a
stream id, so they are admitted only on the session that opened the
stream.

**Lease holders are bound to identity.** The gate rewrites the holder
in every `LEASE` and `VOLUME` request to a hash of the session's
identity and the holder the caller chose. A session cannot acquire,
renew, release or commit under another identity's holder, even by
sending its bytes, and one identity's writers still exclude each
other.

**Replies go only to the session that asked.** The gate forwards each
request under a correlation id it assigns and maps the reply back to
the session's own; a reply that arrives after its session closed is
discarded, never delivered to another.

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
- Block-volume extents and extent-map pages
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
own. Every extent version is an ordinary content-addressed body, and
so is every page of the copy-on-write map from extent index to digest
([`loam_volume_map_wire.rs`](../modules/common/mechanics/loam_volume_map_wire.rs)):
a root page holding the volume's geometry and up to 1024 child
digests, and at depth 2 leaf pages of 1024 extent digests each. The
volume's committed state is its path bound to the root's digest at a
revision, as a `VOLUME` binding. A flush writes the changed extents,
the leaves on the changed paths and a new root, then commits the
bind; before it every reader resolves the old root, after it the new
one, and a crash between leaves orphans rather than a mixed volume.
A snapshot of a volume is a binding of its root digest, which pins
exactly the extent versions that root reaches.

The orphan GC follows the maps. A body no binding names may still be
a page or an extent of a bound volume root, so before deleting one
the body sweep walks every root the namespace lists as a `VOLUME`
binding (`OP_VOLUME_ROOTS`, cursor-paged), reading one page per
downstream round trip and keeping the body at the first page that
names it, or at any page it cannot read.

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
