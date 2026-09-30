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

│   │   └── telemetry_agg/        # reserved name, stub body
│   └── common/               # shared no_std source, split by storage tier
│       ├── mechanics/        #   single-node fence classes; fluxor-only
│       └── replicated/       #   quorum fence classes; may reach clustor
├── src/                      # config vocabulary only — no runtime
│   ├── lib.rs
│   ├── core/                 # Config, Error
│   ├── fluxor.rs             # FluxorTarget, FluxorGraphProfile
│   └── storage/              # AchievableFence
├── config/loam.toml          # the config `loam validate` / `loam plan` parse
├── tools/loam-cli/           # host crate: the loam CLI + loam-server daemon
├── tools/loam-client/        # host crate: client library for the admin surface
├── docs/
└── target/fluxor/            # staged by `fluxor sync`: every declared
                              #   dependency's modules + source artefacts
```

## Config vocabulary, not runtime

`src/` holds the types `config/loam.toml` is written in, and
nothing else. Anything that mutates state lives in a PIC:

- **Configuration + project errors** (`Config`, `Error`, `Result`)
- **Target/profile enums** (`FluxorTarget`, `FluxorGraphProfile`)
- **Declared fence intent** (`AchievableFence`)

There is deliberately no module→surface table here. A module's
surface is what its `manifest.toml` declares and its fence is what
its dispatch returns, so a table in `src/` would be a second copy
of both, free to drift from the thing it describes while still
compiling. `loam surfaces --modules modules` reads the manifests
instead.

Fence + storage-handle types come from `fluxor-contracts` and are
re-exported through the `prelude`.

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
`VOLUME`), preceded where required by `AUTH`. `loam-server` checks
each request against the caller's grant before the router sees it
([Transport security and authorisation](#transport-security-and-authorisation)).
The router demuxes each to the right downstream PIC, runs a 3-stage state machine for the composed
`PUT_FILE`, and hosts the lifecycle sweep that reclaims orphaned body
blobs and unbound object descriptors. The composed write's crash
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

## Transport security and authorisation

Two ways in, one per kind of caller:

- **The unix socket** is the local operator's: full authority,
  reachable only by the host's own users, and optionally gated by
  `AUTH` with the `--admin-token` secret. `AUTH` is
  connection-scoped: the boundary is who is on the far end of the
  socket, established once rather than re-argued per op. The token is
  the one field an unauthenticated peer can make the server hold,
  which is why `MAX_TOKEN` is bounded low.
- **`--admin-listen`** is TLS 1.3 only (rustls, ring provider, no TLS
  1.2 compiled in), and REFUSED at startup without a server
  certificate, a client CA and a grant table. A client must present a
  certificate chaining to the CA; its URI SAN, else DNS SAN, else
  CommonName is its identity. Resumption is off, so each connection
  is judged on the certificate it presents.

**Every request is checked where it is framed: in `loam-server`, before
it reaches `admin_router`.** The router is a PIC that sees channel
frames and cannot know which certificate a request came under; the
host terminates TLS, holds the identity for the connection's life,
and already has to frame each request out of the byte stream
(`loam_admin_wire::request_len`). The check decodes the opcode and
the namespace root with the wire's own decoders and applies the grant
table — identity → roots and classes (`read`, `write`, `lease`,
`admin`). Default deny throughout: no grant, no access; an opcode the
table does not name is refused and the connection closed. A refusal
is `STATUS_FORBIDDEN`, distinct from `STATUS_NAK` because the remedy
is a grant, not a retry, and it is encoded in the op's own ack shape
so a client decodes it with the decoder it was already waiting on.
The class of every op, and the file format, are in
[running.md](running.md#remote-admin).

Ops that name no root are judged by where their effect lands. A
content-addressed `PUT_BODY` or `GET_BODY` needs its class on some
root: a put cannot change bytes anyone else reads (one digest is one
set of bytes), and what it stores stays an unreferenced orphan until
a bind or a volume commit on a granted root names it. The keyed
body plane (`PUT_BODY_KEYED`, `DELETE_BODY`) overwrites and deletes
across every root and is `admin`. A streamed write's chunks and commit
name only a stream id, so they are accepted only on the connection
that opened the stream.

**Lease holders are bound to identity.** For a TLS caller the server
rewrites the holder in every `LEASE` and `VOLUME` request to a hash of
the identity and the holder the caller chose. An identity cannot
acquire, renew, release or commit under another's holder, even by
sending its bytes, and one identity's writers still exclude each
other. The local operator's holders pass through: it has authority
over a stuck writer's lease.

**Replies go only to the connection that asked.** The loop serves
every open admin connection — a control plane holds one for its
creates and deletes while each attached volume's node holds its own —
and forwards each request under a server-assigned correlation id
that names the connection, mapping the reply back to the client's.
A reply that arrives after its connection closed is discarded, never
delivered to another connection.

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
