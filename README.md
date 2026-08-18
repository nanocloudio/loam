# Loam

Fluxor-native distributed storage foundation. Every line of
production logic runs in a [Fluxor](https://github.com/nanocloudio/fluxor)
PIC module under [`modules/`](modules/); the `loam` crate under
[`src/`](src/) is a thin vocabulary library that PIC tests, the
CLI, and the fluxor build tool all consume. Clustor is the
replication substrate (see [../clustor](../clustor)).

## Project shape

```
modules/           # Fluxor PIC modules — all runtime logic
src/               # vocabulary types (no runtime)
config/            # loam.toml — the config `loam validate` parses
tools/ci/          # CI gates ([ci.test] scripts)
tools/e2e/         # e2e drivers (s3_driven, multi3_bringup, …)
tools/diag/        # diagnostics, run by hand after a failure
tools/loam-cli/    # fluxor-native dev CLI + loam-server daemon
tools/loam-client/ # client library for the daemon's admin surface
examples/          # graph profiles (shadow-tracked — see Tests)
tests/             # PIC harness tests (shadow-tracked)
docs/              # architecture + specification
.context/          # product brief, RFCs, stress tests
```

[`tools/README.md`](tools/README.md) says what each script and crate
is for.

Dependencies resolve from the store: `fluxor sync` stages every
declared project's published modules and source artefacts under
`target/fluxor/`. Nothing reaches into a sibling checkout.

See [`docs/architecture.md`](docs/architecture.md) for the
type-by-type tour.

## What's in `modules/`

| Module | Surface | What it does |
|---|---|---|
| `namespace_router` | `storage.namespace` | Path bindings — BIND / RENAME / UNBIND / LOOKUP / LIST, WAL-backed over a compacted snapshot file |
| `object_index` | `storage.object` | Object descriptors — OBJ_PUT / UPDATE / REMOVE / GET, WAL-backed |
| `block_allocator` | `storage.block` | Block volume metadata, WAL-backed |
| `raft_metadata_client` | — (internal) | Proposes metadata decisions through a replica group; single and replicated modes |
| `clustor_bridge` | — (internal) | Carries loam decision records across Clustor's channel envelope |
| `body_store` | — (internal) | Content-addressed blobs on disk, with streamed writes and keyed extents |
| `placement_router` | — (internal) | Fleet membership; broadcasts a FleetEpoch snapshot on every change |
| `body_fanout_router` | — (internal) | Replicated bodies: all-must-succeed PUT, ranked GET/HEAD fallback with read repair, full-set DELETE, background scrub |
| `ec_body_router` | — (internal) | Erasure-coded bodies: k+m Reed-Solomon shards, reconstructing GET, scrub with re-placement and repair |
| `admin_router` | — (internal) | Front-door admin RPC; demuxes the file and body lifecycle and runs the orphan-body GC |
| `block_log` | — (internal) | Channel-fronted append-only log over an fs or block backend |
| `loam_load_gen` | — (probe) | Offers Propose records at a controlled rate, reporting offered against emitted |
| `loam_throughput_counter` | — (probe) | Counts resolved operations per window, committed split from refused |
| `metadata_e2e_probe` | — (probe) | Single-shot metadata round trip; PASS is the result |
| `body_e2e_probe` | — (probe) | Single-shot body round trip |

`cache_manager`, `io_scheduler` and `telemetry_agg` are reserved
names carrying the stub step body — they hold their place in a graph
and do nothing else.

See [`modules/README.md`](modules/README.md) for wire formats, arena
sizing, snapshots, erasure coding, and keyed extents.

## Build and test

```bash
make build                    # fluxor build — workspace + PIC modules
make test                     # fluxor test — workspace suites + [ci.test] scripts
fluxor modules build --target bcm2712   # PIC .fmod artifacts (pi5 board, bcm2712 silicon)
```

### Tests

Per the team's test-tracking standard (`../standards/test-tracking.md`,
alongside this checkout), `tests/` and `examples/` are versioned in a
second, local-only Git repo rooted at `.git-shadow/`. It shares this
working tree and has no path to the GitHub remote, so deployment
topology and unpublished performance numbers stay off a public history
without losing version control over them.

For contributors holding that repo: shadow edits are invisible to
`git status` on the primary, so run `git shadow status` alongside it out
of habit (`git shadow log --oneline -20` for recent history).
`fluxor ci` hard-fails when the shadow checkout is missing rather than
reporting green having run nothing.

Staging **new** files needs `-f` — the primary `.gitignore` outranks the
shadow exclude — and MUST keep the exclude pathspec, or `-f` force-adds
every cargo build blob:

```sh
git shadow add -Af tests examples ':(exclude)*target/*'
```

Two of the gates hold the running system to conservation rather than
to a rate, so they stay meaningful on any machine. The load gate
drives the metadata plane under offered load: every record the plane
accepts is either committed or refused, never dropped. The
composed-node gate puts a public surface on that plane and adds the
claim only a composition can make — every request that entered the
surface received exactly one answer.

## CLI — two modes

**In-process** (`loam` binary): each subcommand spins up the PICs
it needs, sends one request through the appropriate wire format,
drives the step bodies until the response lands, and prints JSON.

```bash
loam validate --config config/loam.toml
loam plan     --config config/loam.toml
loam surfaces
loam bind        --wal /tmp/ns.wal acme /users/alice sha256:cafe
loam read        --wal /tmp/ns.wal acme /users/alice
loam put-body    --body-root /tmp/bodies <my-file.bin
loam put-object  --wal /tmp/obj.wal --id sha256:... --namespace acme --key /k --size 12
loam resolve     --ns-wal /tmp/ns.wal --obj-wal /tmp/obj.wal acme /file.txt
loam put-file    --wal /tmp/ns.wal --body-root /tmp/bodies acme /file.txt <content
```

**Daemon + remote client** (`loam-server`, with `loam admin-bind`
as the one-shot CLI client and
[`tools/loam-client/`](tools/loam-client/) as the library one):
the daemon hosts a long-running graph (admin_router +
namespace_router + body_store + object_index) and exposes it
through up to three surfaces — a unix admin socket, an
S3-compatible HTTP gateway, and the loam_net_wire TCP bridge
that lets the body plane live on another machine.

```bash
# single node: admin socket + S3 gateway, one local body store
loam-server --socket /tmp/loam.sock --s3-listen 127.0.0.1:9000 \
            --ns-wal /tmp/ns.wal --obj-wal /tmp/obj.wal \
            --fleet dir:/tmp/bodies
loam admin-bind --socket /tmp/loam.sock acme /users/alice sha256:cafe
curl -T report.pdf http://127.0.0.1:9000/docs/report.pdf
curl http://127.0.0.1:9000/docs/report.pdf

# replicated: gateway + metadata on A, bodies on B and C. Every
# object lands on 2 nodes (all-must-succeed PUT); reads fall back
# to the surviving replica when a body node dies; --scrub-interval
# heals under-replication in the background.
loam-server --serve-body 0.0.0.0:7100 --body-root /var/lib/loam/bodies   # nodes B, C
loam-server --s3-listen 0.0.0.0:9000 --ns-wal ... --obj-wal ... \
            --fleet tcp:nodeB:7100,tcp:nodeC:7100 \
            --replica-count 2 --scrub-interval 5000                       # node A
```

This is the architecturally cleanest fluxor-native model: the
PIC graph is the kernel; sockets, HTTP, and the net bridge are
public surfaces onto its channels.

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

The metadata plane binds through Clustor: `raft_metadata_client` in
replicated mode proposes through `clustor_bridge` into a replica
group, behind a plane-level read gate.
[`tools/e2e/multi3_bringup.sh`](tools/e2e/multi3_bringup.sh) runs
three fluxor processes — full loam plus clustor replica graphs, from
[`examples/linux/clustor_multi3.yaml`](examples/linux/clustor_multi3.yaml)
— commits a loam bind through a 2-of-3 quorum, and checks that the
three per-node WAL segments are byte-identical. See
[`docs/clustor-bring-up.md`](docs/clustor-bring-up.md).

The body plane replicates outside Raft, through `placement_router`
and `body_fanout_router`, and the network contract
([`modules/common/mechanics/loam_net_wire.rs`](modules/common/mechanics/loam_net_wire.rs))
bridges channel pairs between nodes over TCP so the body plane can
live on a separate machine.

## Project family

- **Fluxor** provides the kernel, graph runtime, PIC ABI,
  storage contracts, and the `fs` provider. Loam's PIC
  modules consume fluxor's `fs` contract and (in production)
  block-device channels.
- **Clustor** is the Raft substrate. The `raft_metadata_client`
  PIC talks to a Clustor PIC over channels.
- **Wave** owns the S3 protocol: the `s3` connector module the
  graphs in [`examples/s3/`](examples/s3/) run, and the
  `wave-common` `s3_core` SigV4 signer + `s3_wire` records it
  signs and frames with. Loam's gateway is the verifying side;
  `tools/e2e/s3_driven.sh` gates that the two agree.
- **Lattice** is the Raft-backed KV sibling.
- **Quantum** is the multi-protocol messaging sibling.
- **Truffle** is the media sibling; uses Loam as its storage
  foundation.

The working plan lives in
[`.context/rfcs/`](.context/rfcs/), not here.
