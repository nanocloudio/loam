# Loam

Loam is a fluxor-native distributed storage foundation: a namespace
of path bindings, an object index, and a content-addressed body
plane, replicated through clustor when composed with it. Everything
loam ships is a [fluxor](../fluxor/) position-independent (PIC)
module under [`modules/`](modules/), composed into graphs that
`fluxor run` runs, and an operator applet that `fluxor exec` runs.
There is no host binary and no cargo crate on the shipping path.

## Quick start

```sh
make build                     # the PIC module artefacts

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
[`docs/running.md`](docs/running.md) continues from here: the
services, the operator applet, and the replicated shapes.

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

## Services

Loam runs as service bundles: a graph, the modules it pins, and a
declared parameter schema. Each is run with its parameters, from
the store once published or from its manifest in this checkout:

```sh
fluxor run packaging/service/loam-s3/workload.toml \
  --param port=9000 --param credentials=/etc/loam/s3.credentials \
  --param mesh_roots=$(cat /etc/loam/mesh_root) \
  --param ns_wal=/var/lib/loam/ns.wal --param obj_wal=/var/lib/loam/obj.wal \
  --param body_dir=/var/lib/loam/bodies --param spool_dir=/var/lib/loam/spool
```

| Service | What it is |
|---|---|
| [`loam-s3`](packaging/service/loam-s3/) | An S3 endpoint: wave's `http` and `s3_serve` in front of loam's `storage.object` provider, the admin plane and one body store. Every request is SigV4-signed; the credentials file maps an access key to its secret, its bucket scope and the capability it acts under |
| [`loam-admin`](packaging/mtls/loam-admin/) | A node's admin plane over mutual TLS: the session layer (`admin_gate`) in front of `admin_router`, the namespace, the object index and a body store. Clients present capabilities before anything else; the mesh root they chain to is configuration |
| [`loam-nbd`](packaging/mtls/loam-nbd/) | A loam volume as an NBD block device: `nbd_serve` over `loam_volume`, which reaches its node over mutual TLS and holds the volume's writer lease |
| [`loam-body`](packaging/mtls/loam-body/) | A body store behind one mutually authenticated `remote_channel` session: a node of another graph's body fleet |
| [`loam-crypt-nbd`](packaging/mtls/loam-crypt-nbd/) | loam-nbd with fluxor's `crypt_block` between the export and the volume: the node holding the volume stores only ciphertext |

The mutual-TLS services are templates under `packaging/mtls/`
rendered with their values (`tools/e2e/render_service.py`): their
CA, certificate and key are files the build reads, which a bundle
cannot yet take as run-time parameters.

## The operator applet

`loam` is a PIC module run by `fluxor exec`, speaking the admin wire
to a node over mutual TLS. Its client certificate and key are read
from `~/.config/loam/` (`client.der`, `client.key.der`) when it is
installed; the node's certificate is checked against the host's
trusted CAs, or the bundle `FLUXOR_CA_BUNDLE` names.

```sh
fluxor install packaging/cli/workload.toml
fluxor exec loam -- --admin node:7443 --capability ops.cap put tenant /docs/r.pdf r.pdf
fluxor exec loam -- --admin node:7443 --capability ops.cap ls tenant /docs/
fluxor exec loam -- --admin node:7443 --capability ops.cap volume create tenant /vols/db0 1073741824 32768
fluxor exec loam -- --admin node:7443 --capability ops.cap snapshot create tenant snap snap.manifest
fluxor exec loam -- --admin node:7443 --capability ops.cap export snap.manifest tenant \
  --to node2:7443 --to-capability ops2.cap
```

`fluxor exec loam -- help` lists every command. A capability file
holds one `fxcap1.` chain per line (`fluxor modules cap mint`).

## Repository layout

| Path | Contents |
|---|---|
| `modules/app/` | One directory per PIC module: `mod.rs` + `manifest.toml`. |
| `modules/common/` | Shared `no_std` source, split by storage tier: `mechanics/` (single-node) and `replicated/` (quorum; may reach clustor). |
| `packaging/` | The service bundles and templates, and the applet's bundle. |
| `examples/` | Reference graphs: the metadata plane, composed nodes, the body plane smoke. |
| `tests/harness/` | The module harness: every unit test, over the same sources the modules build. |
| `tools/` | CI gates, graph and service gates, diagnostics — see [`tools/README.md`](tools/README.md). |
| `docs/` | Reference documentation, indexed by [`docs/overview.md`](docs/overview.md). |
| `fluxor.toml` | Project manifest for the `fluxor` CLI: identity, dependencies, policy. |
| `Makefile` | Thin alias layer over the `fluxor` CLI; `make help` lists the targets. |

[`modules/README.md`](modules/README.md) documents the wire formats,
arena sizing, snapshots, erasure coding, and block volumes.

## The modules

| Module | Surface | What it does |
|---|---|---|
| `namespace_router` | `storage.namespace` | Path bindings — BIND / RENAME / UNBIND / LOOKUP / LIST, WAL-backed over a compacted snapshot file. It answers the canonical surface by provider dispatch, including `SUBSCRIBE` / `CHANGES`, which is what a level-triggered consumer reconciles against. `LIST` is served on the channel wire rather than by dispatch, being cursor-paged |
| `object_provider` | `storage.object` | Objects named `bucket/key` as files under namespace root `bucket`, each caller acting under the capability it presented. wave's `s3_serve` speaks S3 in front of it |
| `loam_volume` | `storage.block` | One Loam volume as a block device: reads through the committed extent map, stages writes, and completes a flush after the fenced commit. Holds the volume's writer lease, so one instance writes a volume at a time |
| `admin_gate` | — (internal) | The admin plane's session layer: TLS and in-graph sessions, capabilities presented and verified against the mesh roots, every request admitted by scope and permission |
| `admin_router` | — (internal) | The admin op surface; demuxes the file and body lifecycle and runs the orphan-body GC |
| `object_index` | — (internal) | Object descriptors — OBJ_PUT / UPDATE / REMOVE / GET, WAL-backed. Declares no surface: descriptors are not object bytes |
| `block_allocator` | — (internal) | Block volume metadata, WAL-backed. Declares no surface: volume accounting is not a block device; a volume's bytes are `loam_volume`'s |
| `raft_metadata_client` | — (internal) | Proposes metadata decisions through a replica group; single and replicated modes |
| `clustor_bridge` | — (internal) | Carries loam decision records across the replica group's channel envelope |
| `body_store` | — (internal) | Content-addressed blobs on disk, with streamed writes and keyed EC shards |
| `placement_router` | — (internal) | Fleet membership; broadcasts a FleetEpoch snapshot on every change |
| `body_fanout_router` | — (internal) | Replicated bodies, local or on other nodes: all-must-succeed PUT, ranked GET/HEAD fallback with read repair, full-set DELETE, background scrub |
| `ec_body_router` | — (internal) | Erasure-coded bodies: k+m Reed-Solomon shards, reconstructing GET, scrub with re-placement and repair |
| `block_log` | — (internal) | Channel-fronted append-only log over the fluxor `fs` contract |
| `loam_cli` | — (applet) | The operator applet `fluxor exec loam` runs |
| `loam_load_gen` | — (probe) | Offers Propose records at a controlled rate, reporting offered against emitted |
| `loam_throughput_counter` | — (probe) | Counts resolved operations per window, committed split from refused |
| `metadata_e2e_probe` | — (probe) | Single-shot metadata round trip |
| `body_e2e_probe` | — (probe) | Single-shot body round trip |

`telemetry_agg` is a reserved name carrying the stub step body — it
holds its place in a graph and does nothing else, pending the
metrics and readiness surface.

## Authority

mTLS authenticates a connection; a capability authorises what is
done on it. A client presents chains minted from the mesh root
(`MSG_CAP_PRESENT`) before its first request, and each request is
admitted by what it touches: a key under a namespace root by a grant
on a `/`-terminated prefix of `root/path` — the storage contract's
scope rule, so `--scope photos/` reaches the same keys through S3 and
through the admin plane — and the body plane by a grant on its own
object. Reads need `ReadState`; writes and leases `SendCommand`; the
raw keyed body plane `Admin`. A refusal is answered `FORBIDDEN` in
the request's own shape.

## Replication

The metadata plane binds through clustor: `raft_metadata_client` in
replicated mode proposes through `clustor_bridge` into a replica
group, behind a plane-level read gate. The body plane replicates
outside Raft, through `placement_router` and `body_fanout_router`.
A member on another node is a `loam-body` service, reached through
fluxor's `remote_channel` over mutual TLS: a body channel carries
`[len:u32][cid:u32][record]` frames whether its peer is local or
remote. [`docs/running.md`](docs/running.md) describes the
deployment shapes.

## Consuming loam

Siblings consume loam through the store, never through its checkout:
`fluxor publish` puts loam's modules and bundles into the store,
`fluxor store pin` records them in the consumer's `fluxor.lock`, and
`fluxor sync` materialises them. A consumer either runs a loam
service with its parameters or composes loam's modules into its own
graph.

## Project family

- **fluxor** provides the kernel, graph runtime, PIC ABI, storage
  contracts, `tls`, `remote_channel`, capabilities, and the `fs`
  provider loam's modules consume.
- **clustor** is the Raft substrate; `raft_metadata_client` talks to
  it over channels.
- **wave** owns HTTP and S3: `http` and `s3_serve` front loam's
  `storage.object` in the loam-s3 service.
- **lattice** is the Raft-backed KV sibling.
- **quantum** is the multi-protocol messaging sibling.
- **truffle** is the media sibling; uses loam as its storage
  foundation.

## Documentation

- [`docs/overview.md`](docs/overview.md) — index of the doc set
- [`docs/running.md`](docs/running.md) — bring-up: graphs, services,
  the applet, replicated shapes
- [`docs/architecture.md`](docs/architecture.md) — layout, the
  two-plane model, durability, scaling
- [`docs/native_fluxor.md`](docs/native_fluxor.md) — how loam sits on
  fluxor: surfaces, fences, the step contract
- [`docs/specification.md`](docs/specification.md) — the invariants
  loam holds itself to
- [`docs/limit_register.md`](docs/limit_register.md) — every ceiling,
  per profile
