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
loam surfaces
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
[`loam_decision_wire.rs`](../modules/common/replicated/loam_decision_wire.rs)
are replicated.

Composing that graph needs clustor's published module palette in the
store alongside loam's (declared in `fluxor.toml`, staged by
`fluxor sync`). The composed deployment profiles are part of the
replication work in flight and are not yet published as a
self-contained public recipe; the single-node shapes above are the
supported bring-up today.
