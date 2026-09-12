# Running Loam

This guide brings loam up on one Linux machine, from a single smoke
graph to a multi-node body plane, and finishes with the replicated
metadata shape. Every command was run as written; the graphs are
embedded and pipe straight into `fluxor run`, so there is nothing
else to fetch.

## Prerequisites

Loam runs on the [fluxor](../../fluxor/) runtime. One-time setup on
a development machine:

```sh
git clone git@github.com:nanocloudio/fluxor.git ../fluxor
make -C ../fluxor install    # put the fluxor CLI launcher on PATH
make -C ../fluxor publish    # publish SDK, runtime, and foundation modules

# in this repository
make build                   # workspace crates + PIC module artefacts
```

`make build` compiles the host crates (the `loam` CLI and the
`loam-server` daemon land under `target/debug/`) and packs each PIC
module into a `.fmod` artefact. Dependencies materialise from the
local OCI store per `fluxor.lock`; if the store has moved on since
the lockfile was written, `fluxor sync` re-resolves and restages.

The examples below call the binaries bare; put them on PATH first:

```sh
export PATH=$PWD/target/debug:$PATH
```

## Body-plane smoke graph

The smallest live graph: a probe writes a blob into a
content-addressed store and reads it back. `root_dir` must exist
before the graph starts — `body_store` does not create it.

```sh
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

Smoke checks:

- the log prints `[body_e2e] PASS`;
- `ls data/bodies-0` shows one file named by the hex content digest.

`scheduler: accept_cycles: true` is required because the probe and
the store form a request/response cycle. Stop the graph with Ctrl-C.

## The CLI, in process

Each `loam` subcommand spins up the PIC bodies it needs in process,
drives one request through the wire format, and prints JSON. State
lives wherever the `--wal` and `--body-root` arguments point, so a
scratch directory is enough:

```sh
mkdir -p data/quickstart
loam validate --config config/loam.toml
loam surfaces --modules modules   # reads modules/app/*/manifest.toml
echo "hello loam" | loam put-file --wal data/quickstart/ns.wal \
    --body-root data/quickstart/bodies acme /notes/hello.txt -
loam read --wal data/quickstart/ns.wal acme /notes/hello.txt
```

`put-file` answers with the content digest and the fences achieved
(`"fence_body": "ContentHashed"`, `"fence_binding": "LocalDurable"`);
`read` returns the binding — object id, revision, kind. The `-`
argument reads content from stdin.

## Single-node daemon

`loam-server` hosts the long-running graph (admin_router +
namespace_router + body_store + object_index) and exposes it through
a unix admin socket and an S3-compatible HTTP gateway:

```sh
mkdir -p data/srv
loam-server --socket /tmp/loam.sock --s3-listen 127.0.0.1:9000 \
            --ns-wal data/srv/ns.wal --obj-wal data/srv/obj.wal \
            --fleet dir:data/srv/bodies
```

Smoke checks, from another shell:

```sh
loam admin-bind --socket /tmp/loam.sock acme /users/alice sha256:cafe
echo "report body" > report.txt
curl -T report.txt http://127.0.0.1:9000/docs/report.txt
curl http://127.0.0.1:9000/docs/report.txt
curl "http://127.0.0.1:9000/docs?prefix=&delimiter=/"
```

`admin-bind` answers `"status": "ok"` over the socket; the second
curl returns the uploaded bytes; the third returns a
ListBucketResult XML document listing `report.txt`. Buckets are
namespace roots and ETags are content digests. Stop the daemon with
Ctrl-C (or `kill`); state is in the WALs and the body root, so a
restart replays to the same contents.

`--s3-credentials FILE` turns on SigV4 verification with
per-access-key bucket scopes; without it the gateway is anonymous.
`--gc-interval N` sweeps orphaned body blobs and unbound object
descriptors every N ticks — see [durability.md](durability.md).

## Remote admin

The admin surface can also be reached over TCP, for a consumer that
runs somewhere other than the storage node — a volume backend, a CSI
plugin. It carries no per-op authorization: a connection that
authenticates can bind, read and delete anything in any namespace,
so `--admin-listen` is REFUSED without `--admin-token` rather than
quietly serving an anonymous surface off-box.

```sh
head -c 32 /dev/urandom | xxd -p -c 64 > /etc/loam.token
loam-server --socket /tmp/loam.sock --admin-listen 0.0.0.0:7788 \
            --admin-token /etc/loam.token \
            --ns-wal data/srv/ns.wal --obj-wal data/srv/obj.wal \
            --fleet dir:data/srv/bodies
```

Authentication is connection-scoped, not per-request: a client
presents the token once, and the boundary that matters is who is on
the far end of the socket. `loam-client`'s `connect_tcp` pairs with
`authenticate` for exactly that reason.

## Block volumes over NBD

A volume is N fixed-size extents in the body plane, replicated like
any other body. `loam-nbd` exports one as an NBD device, so a kernel
(`nbd-client`) or a hypervisor (qemu's `nbd:` driver) can mount what
loam already stores:

```sh
loam-nbd --socket /tmp/loam.sock --volume vol:/disks/data \
         --listen 127.0.0.1:10809
```

Against a remote node, which is the shape a volume backend runs in:

```sh
loam-nbd --admin tcp://storage-node:7788 --token-file /etc/loam.token \
         --volume vol:/disks/data --listen 127.0.0.1:10809
```

## Snapshots, clones and export

A snapshot is a manifest — a `(key, digest)` listing — and nothing
more. It pins its bodies by BINDING them under a root the caller
names, so they are protected by the same reachability answer the
orphan GC already computes for ordinary bindings: no per-body
refcount appears, and the collector needs no snapshot-shaped query.
The manifest itself is returned to the caller as bytes, to store
wherever it belongs.

`loam-client` carries the operations: `snapshot_create` writes the
manifest, `snapshot_restore` binds its entries under a new root (a
clone — bodies are shared, not copied), and `snapshot_delete` drops
it, after which the GC reclaims whatever nothing else references.

Export between two clusters is a function over two clients rather
than a protocol. `export_snapshot` asks the destination which
digests it lacks (`manifest_missing_here`), sends only those, then
binds the manifest's entries — so deduplication is free and the
transfer is ordinary reads and writes. The manifest is
encryption-agnostic and its digests are over plaintext, so it means
the same thing on both sides whatever keys each cluster holds.

## Replicated body plane

The loam network contract bridges channel pairs between processes
over TCP, so the body plane can live on other machines.
`--serve-body` turns a node into a body host; `--fleet` gives the
admin node its member list, in the order that defines rendezvous
identity. All three processes below can also run on separate hosts;
only the addresses change.

```sh
# body nodes
mkdir -p data/2node/bodies-b data/2node/bodies-c
loam-server --serve-body 127.0.0.1:7101 --body-root data/2node/bodies-b &
loam-server --serve-body 127.0.0.1:7102 --body-root data/2node/bodies-c &

# admin node: gateway + metadata, bodies on the two hosts above
loam-server --s3-listen 127.0.0.1:9011 \
            --ns-wal data/2node/ns.wal --obj-wal data/2node/obj.wal \
            --fleet tcp:127.0.0.1:7101,tcp:127.0.0.1:7102 \
            --replica-count 2 --scrub-interval 5000 &
```

Smoke checks:

```sh
echo "two node body" > tn.txt
curl -T tn.txt http://127.0.0.1:9011/docs/tn.txt
curl http://127.0.0.1:9011/docs/tn.txt
ls data/2node/bodies-b data/2node/bodies-c   # same digest on both
```

With `--replica-count 2` every PUT lands on both nodes before it is
acknowledged — desired replicas and required synchronous replicas are
one number, for the reasons in [durability.md](durability.md). Kill
one body node and the GET still answers from the survivor;
`--scrub-interval` heals under-replication in the background once the
fleet is whole again. Stop everything with `kill` on the three
processes.

## Replicated metadata

The metadata plane replicates through clustor. In that shape,
`raft_metadata_client` runs in replicated mode and proposes each
metadata decision through `clustor_bridge` into a replica group; the
decision commits through a durability quorum before the client sees
`Committed`, and a plane-level read gate holds reads until replay has
drained. Bodies stay outside the Raft log throughout — only the
fixed-size decision records of
[`loam_decision_wire.rs`](../modules/common/mechanics/loam_decision_wire.rs)
are replicated.

Composing that graph needs clustor's published module palette in the
store alongside loam's (declared in `fluxor.toml`, staged by
`fluxor sync`). The composed deployment profiles are part of the
replication work in flight and are not yet published as a
self-contained public recipe; the single-node shapes above are the
supported bring-up today.
