# Loam

Loam is a fluxor-native distributed storage foundation: a namespace
of path bindings, an object index, and a content-addressed body
plane, replicated through clustor when composed with it. Every line
of production storage logic runs as a [fluxor](../fluxor/)
position-independent (PIC) module under [`modules/`](modules/); the
`loam` crate under [`src/`](src/) is a vocabulary library of shared
types that the CLI, the PIC bodies, and the fluxor build tool all
consume.

## Quick start

```sh
make build                     # workspace crates + PIC module artefacts

# body-plane smoke: a probe writes a blob to a content-addressed
# store and reads it back
mkdir -p data/bodies-0
fluxor run - <<'EOF'
target: linux
tick_us: 1000
scheduler:
  accept_cycles: true
modules:
  - name: body_a
    type: body_store
    params:
      root_dir: "data/bodies-0"
  - name: probe
    type: body_e2e_probe
wiring:
  - from: probe.req_out
    to: body_a.body_requests
  - from: body_a.body_responses
    to: probe.resp_in
EOF
```

Success is `[body_e2e] PASS` in the log and a content-addressed file
under `data/bodies-0/`. Stop the graph with Ctrl-C.
[`docs/running.md`](docs/running.md) continues from here: the CLI, the
`loam-server` daemon with its S3 gateway, and the replicated
deployment shapes.

## Setup

Loam consumes fluxor through the local OCI store. One-time setup on
a development machine:

```sh
git clone git@github.com:nanocloudio/fluxor.git ../fluxor
make -C ../fluxor install    # put the fluxor CLI launcher on PATH
make -C ../fluxor publish    # publish SDK, module palette, runtime into the store

# in loam's checkout
make build
```

`fluxor.toml [dependencies]` declares fluxor, clustor, and wave;
each dependency publishes its artefacts into the same store with
`make publish` from its own checkout. `fluxor sync` stages every
pinned artefact under `target/fluxor/` — nothing reaches into a
sibling checkout at build time. To pick up newly published
dependency versions, run `fluxor update` and commit the lockfile.

## Repository layout

| Path | Contents |
|---|---|
| `modules/app/` | One directory per PIC module: `mod.rs` + `manifest.toml`. All runtime logic. |
| `modules/common/` | Shared `no_std` source, split by storage tier: `mechanics/` (single-node) and `replicated/` (quorum; may reach clustor). |
| `src/` | The `loam` vocabulary crate — types only, no runtime. |
| `config/` | `loam.toml`, the config `loam validate` and `loam plan` parse. |
| `tools/loam-cli/` | Host crate: the `loam` CLI and the `loam-server` daemon. |
| `tools/loam-client/` | Host crate: client library for the daemon's admin surface. |
| `docs/` | Reference documentation, indexed by [`docs/overview.md`](docs/overview.md). |
| `fluxor.toml` | Project manifest for the `fluxor` CLI: identity, dependencies, policy. |
| `Makefile` | Thin alias layer over the `fluxor` CLI; `make help` lists the targets. |

[`modules/README.md`](modules/README.md) documents the wire formats,
arena sizing, snapshots, erasure coding, and keyed extents.
[`tools/README.md`](tools/README.md) says what each script and crate
is for.

## The modules

| Module | Surface | What it does |
|---|---|---|
| `namespace_router` | `storage.namespace` | Path bindings — BIND / RENAME / UNBIND / LOOKUP / LIST, WAL-backed over a compacted snapshot file. The graph's one registered provider: it answers the canonical surface by dispatch, including `SUBSCRIBE` / `CHANGES`, which is what a level-triggered consumer reconciles against. `LIST` is served on the channel wire rather than by dispatch, being cursor-paged |
| `object_index` | — (internal) | Object descriptors — OBJ_PUT / UPDATE / REMOVE / GET, WAL-backed. Declares no surface: descriptors are not object bytes |
| `block_allocator` | — (internal) | Block volume metadata, WAL-backed. Declares no surface: volume accounting is not a block device, and `storage.block` is fluxor's `sd`/`nvme` |
| `raft_metadata_client` | — (internal) | Proposes metadata decisions through a replica group; single and replicated modes |
| `clustor_bridge` | — (internal) | Carries loam decision records across the replica group's channel envelope |
| `body_store` | — (internal) | Content-addressed blobs on disk, with streamed writes and keyed extents |
| `placement_router` | — (internal) | Fleet membership; broadcasts a FleetEpoch snapshot on every change |
| `body_fanout_router` | — (internal) | Replicated bodies: all-must-succeed PUT, ranked GET/HEAD fallback with read repair, full-set DELETE, background scrub |
| `ec_body_router` | — (internal) | Erasure-coded bodies: k+m Reed-Solomon shards, reconstructing GET, scrub with re-placement and repair |
| `admin_router` | — (internal) | Front-door admin RPC; demuxes the file and body lifecycle and runs the orphan-body GC |
| `block_log` | — (internal) | Channel-fronted append-only log over an fs or block backend |
| `loam_load_gen` | — (probe) | Offers Propose records at a controlled rate, reporting offered against emitted |
| `loam_throughput_counter` | — (probe) | Counts resolved operations per window, committed split from refused |
| `metadata_e2e_probe` | — (probe) | Single-shot metadata round trip |
| `body_e2e_probe` | — (probe) | Single-shot body round trip |

`telemetry_agg` is a reserved name carrying the stub step body — it
holds its place in a graph and does nothing else, pending the
metrics and readiness surface. `cache_manager` and `io_scheduler`
were the same and were deleted: a name reserved for a year is a cost
paid by every reader.

## CLI — two modes

**In-process** (`loam` binary): each subcommand spins up the PICs it
needs, sends one request through the appropriate wire format, drives
the step bodies until the response lands, and prints JSON. `make
build` leaves the binaries under `target/debug/`.

```sh
loam validate --config config/loam.toml
loam plan     --config config/loam.toml
loam surfaces --modules modules   # reads modules/app/*/manifest.toml
loam bind        --wal data/ns.wal acme /users/alice sha256:cafe
loam read        --wal data/ns.wal acme /users/alice
loam put-body    --body-root data/bodies - <my-file.bin
loam put-object  --wal data/obj.wal --id sha256:... --namespace acme --key /k --size 12
loam resolve     --ns-wal data/ns.wal --obj-wal data/obj.wal acme /file.txt
loam put-file    --wal data/ns.wal --body-root data/bodies acme /file.txt - <content
```

**Daemon + remote client** (`loam-server`, with `loam admin-bind` as
the one-shot CLI client and [`tools/loam-client/`](tools/loam-client/)
as the library one): the daemon hosts a long-running graph
(admin_router + namespace_router + body_store + object_index) and
exposes it through up to three surfaces — a unix admin socket, an
S3-compatible HTTP gateway, and the loam_net_wire TCP bridge that
lets the body plane live on another machine.

```sh
# single node: admin socket + S3 gateway, one local body store
loam-server --socket /tmp/loam.sock --s3-listen 127.0.0.1:9000 \
            --ns-wal data/ns.wal --obj-wal data/obj.wal \
            --fleet dir:data/bodies
loam admin-bind --socket /tmp/loam.sock acme /users/alice sha256:cafe
curl -T report.pdf http://127.0.0.1:9000/docs/report.pdf
curl http://127.0.0.1:9000/docs/report.pdf
```

For the replicated shape (gateway and metadata on one node, bodies
on others, background scrub healing under-replication), see
[`docs/running.md`](docs/running.md). The PIC graph is the kernel;
sockets, HTTP, and the net bridge are public surfaces onto its
channels.

### The S3 gateway

`--s3-listen` fronts the graph with PUT/GET/HEAD/DELETE per object
and `GET /bucket?prefix=&delimiter=/` ListBucketResult listings with
CommonPrefixes. Buckets are namespace roots, ETags are content
digests, and concurrency is thread-per-connection over the
single-threaded PIC graph.

Objects past the 60 KiB single-shot cap stream end to end: the
gateway spools (disk past 1 MiB), declares the digest up front, and
drives chunked digest-verified writes and ranged reads through the
admin surface and body plane, to 1 GiB per object.

`--s3-credentials FILE` turns on AWS SigV4 verification with
per-access-key bucket scopes, which is what makes the bucket a
tenancy boundary; without it the gateway is anonymous.
`--gc-interval N` runs the orphan-body GC: blobs no binding
references are swept via body SCAN + namespace OP_REFERENCED +
DELETE, guarded against in-flight composed writes.

## Replication

The metadata plane binds through clustor: `raft_metadata_client` in
replicated mode proposes through `clustor_bridge` into a replica
group, behind a plane-level read gate. The body plane replicates
outside Raft, through `placement_router` and `body_fanout_router`;
the network contract
([`modules/common/mechanics/loam_net_wire.rs`](modules/common/mechanics/loam_net_wire.rs))
bridges channel pairs between nodes over TCP so the body plane can
live on a separate machine. [`docs/running.md`](docs/running.md)
describes the deployment shapes.

## Project family

- **fluxor** provides the kernel, graph runtime, PIC ABI, storage
  contracts, and the `fs` provider loam's modules consume.
- **clustor** is the Raft substrate; `raft_metadata_client` talks to
  it over channels.
- **wave** owns the S3 protocol: the signing side of the requests
  loam's gateway verifies.
- **lattice** is the Raft-backed KV sibling.
- **quantum** is the multi-protocol messaging sibling.
- **truffle** is the media sibling; uses loam as its storage
  foundation.

## Documentation

- [`docs/overview.md`](docs/overview.md) — index of the doc set
- [`docs/running.md`](docs/running.md) — validated bring-up: graphs,
  CLI, daemon, replicated shapes
- [`docs/architecture.md`](docs/architecture.md) — layout, the
  two-plane model, durability, scaling
- [`docs/native_fluxor.md`](docs/native_fluxor.md) — how loam sits on
  fluxor: surfaces, fences, the step contract
- [`docs/specification.md`](docs/specification.md) — the invariants
  loam holds itself to
