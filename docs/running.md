# Running Loam

This guide brings loam up on one Linux machine, from a single smoke
graph to a body plane spread across nodes, and finishes with the
replicated metadata shape. Everything runs under the fluxor runtime:
graphs with `fluxor run`, the operator applet with `fluxor exec`. The
service gates under `tools/e2e/` run each shape below as written.

## Prerequisites

Loam runs on the [fluxor](../../fluxor/) runtime. One-time setup on
a development machine:

```sh
git clone git@github.com:nanocloudio/fluxor.git ../fluxor
make -C ../fluxor install    # put the fluxor CLI launcher on PATH
make -C ../fluxor publish    # publish SDK, runtime, and foundation modules

# in this repository
make build                   # the PIC module artefacts
```

`make build` packs each PIC module into a `.fmod` artefact under
`target/fluxor/`. Dependencies materialise from the local OCI store
per `fluxor.lock`; if the store has moved on since the lockfile was
written, `fluxor sync` re-resolves and restages.

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

## Identities and capabilities

Two things stand between a client and loam's state. mTLS
authenticates the connection: the services that take connections
from other machines verify the peer's certificate against a CA they
are given. A capability authorises what is done on it: a chain
minted from the mesh root, presented before the first request, whose
scope and permissions admit each request.

```sh
mkdir -p /etc/loam
head -c 32 /dev/urandom > /etc/loam/root.seed
fluxor modules keygen --key /etc/loam/root.seed | tail -1 > /etc/loam/mesh_root

now=$(date +%s)
mint() { fluxor modules cap mint --key /etc/loam/root.seed "$@" \
           --not-before $((now - 60)) --not-after $((now + 86400 * 30)) | tail -1; }
{
  mint --scope tenant/ --perms read_state,send_command
  # the body plane's object: SHA-256("loam.body-plane\0"), first 16 bytes
  mint --object "$(printf 'loam.body-plane\0' | sha256sum | cut -c1-32)" \
       --perms read_state,send_command
} > /etc/loam/ops.cap
```

A grant's scope is a `/`-terminated prefix of `root/path`: the chain
above reaches every key under root `tenant`, and `--scope tenant/docs/`
would reach only those under `/docs/`. The same rule decides an S3
key under bucket `tenant`. Reads need `read_state`; writes and leases
`send_command`; the keyed body plane (`PUT_BODY_KEYED`, `DELETE_BODY`)
`admin`. A request no presented chain admits is answered `FORBIDDEN`
in its own ack shape, and the session stays open: the remedy is a
capability, not a retry. A byte that names no request closes it.

A lease or volume request's holder is replaced, on the way in, with
one bound to the session's identity, so no client can name another's
writer, while one identity's writers still tell each other apart by
the holders they choose.

## An S3 endpoint

The loam-s3 service is wave's `http` and `s3_serve` in front of
loam's `storage.object` provider, the admin plane and one body store:

```sh
mkdir -p /var/lib/loam/bodies /var/lib/loam/spool
echo "AKTENANT000000000001 tenant-secret tenant/ $(mint --scope tenant/ --perms read_state,send_command)" \
  > /etc/loam/s3.credentials
fluxor run packaging/service/loam-s3/workload.toml \
  --param port=9000 --param credentials=/etc/loam/s3.credentials \
  --param mesh_roots=$(cat /etc/loam/mesh_root) \
  --param ns_wal=/var/lib/loam/ns.wal --param obj_wal=/var/lib/loam/obj.wal \
  --param body_dir=/var/lib/loam/bodies --param spool_dir=/var/lib/loam/spool
```

Each credentials line is an access key, its secret, the bucket scope
it may sign for, and the capability it acts under. Every request is
SigV4-signed; an unsigned one is refused. Smoke checks:

```sh
S="--aws-sigv4 aws:amz:us-east-1:s3 --user AKTENANT000000000001:tenant-secret"
echo "report body" > report.txt
curl $S -T report.txt http://127.0.0.1:9000/tenant/docs/report.txt
curl $S http://127.0.0.1:9000/tenant/docs/report.txt
curl $S "http://127.0.0.1:9000/tenant?list-type=2&prefix=docs/"
```

Buckets are namespace roots and ETags are content digests. A body
larger than one record streams: `object_provider` spools it under
`spool_dir` and writes it as one `PUT_FILE` stream, and reads come
back in ranges pinned to the object they started on. State is in the
WALs and the body directory, so a restart replays to the same
contents. `gc_interval` (ticks; 0 is off) sweeps orphaned bodies and
unbound object descriptors — see [durability.md](durability.md).

## The admin plane and the applet

The loam-admin service is a node's admin plane over mutual TLS. Its
CA, certificate and key are read when the graph is built, so it is a
template under `packaging/mtls/` rendered with its values:

```sh
python3 tools/e2e/render_service.py packaging/mtls/loam-admin/linux.yaml node.yaml \
  port=7443 mesh_roots=$(cat /etc/loam/mesh_root) gc_interval=0 \
  ns_wal=/var/lib/loam/ns.wal obj_wal=/var/lib/loam/obj.wal body_dir=/var/lib/loam/bodies \
  ca=/etc/loam/ca.pem cert=/etc/loam/server.der key=/etc/loam/server.key.der
fluxor run node.yaml
```

A client certificate must chain to `ca`. The operator applet is the
client: installed once, with its certificate and key under
`~/.config/loam/` (`client.der`, `client.key.der`, DER), and run with
the node's address and a capability file:

```sh
fluxor install packaging/cli/workload.toml
L="fluxor exec loam -- --admin storage-node:7443 --capability /etc/loam/ops.cap"
$L put tenant /docs/report.txt report.txt --type text/plain
$L ls tenant /docs/
$L get tenant /docs/report.txt back.txt
$L put tenant /docs/report.txt report.txt --if-absent     # refused: bound
$L rm tenant /docs/report.txt
```

The node's certificate is checked against the host's trusted CAs, or
those in the bundle `FLUXOR_CA_BUNDLE` names, and must name the host
dialled.

## Block volumes over NBD

A volume is a copy-on-write map of fixed-size extents, each an
ordinary body replicated like any other, committed by binding the
volume's path to the map's root. Its extents are a power of two of
at most 32 KiB.

```sh
$L volume create tenant /vols/db0 1073741824 32768
python3 tools/e2e/render_service.py packaging/mtls/loam-nbd/linux.yaml nbd.yaml \
  port=10809 admin=storage-node:7443 capability=/etc/loam/ops.cap \
  root=tenant path=/vols/db0 block_size=4096 lease_ttl_ms=30000 \
  cert=/etc/loam/client.der key=/etc/loam/client.key.der
fluxor run nbd.yaml
nbd-client 127.0.0.1 10809 /dev/nbd0
```

`loam_volume` takes the volume's writer lease when it starts and
renews it every half TTL; a second device on the same volume is
refused (`the volume has another writer`) while the lease is held.
Writes are staged: `FLUSH`, and a write carrying `FUA`, is answered
only once the commit has landed, and until then a crash loses the
staged writes without tearing anything committed. Drained, the
device commits what is staged and releases the lease; a device
stopped without draining, or killed, holds the volume until its
lease lapses. `$L volume read tenant /vols/db0 <offset> <length> <file>`
reads what is committed, from any client.

The loam-crypt-nbd template
([`packaging/mtls/loam-crypt-nbd/`](../packaging/mtls/loam-crypt-nbd/))
puts fluxor's `crypt_block` between the device and the volume, so the
node holding the volume stores only ciphertext; it takes loam-nbd's
values and `crypt_key`, the key vault entry it encrypts under.

## Snapshots, clones and export

A snapshot is a manifest — a `(key, digest, kind, size, content
type)` listing — and nothing more. It pins its bodies by BINDING them
under a root the caller names, so they are protected by the same
reachability answer the orphan GC already computes for ordinary
bindings: no per-body refcount appears, and the collector needs no
snapshot-shaped query. The manifest itself is written to a file, to
store wherever it belongs.

```sh
$L snapshot create tenant snap-1 snap-1.manifest
$L snapshot restore snap-1.manifest tenant-clone     # bodies shared, not copied
$L snapshot delete snap-1                            # the GC reclaims the rest
$L export snap-1.manifest tenant --to node2:7443 --to-capability /etc/loam/node2.cap
```

Each manifest entry carries its binding's kind, so a volume restores
as a volume — the GC walks the maps of volume bindings only.

Export is two sessions rather than a protocol: the applet asks the
destination which digests it lacks — every entry's, and for a volume
every page and extent its root reaches — sends only those, then
binds the manifest's entries, so deduplication is free and a second
export of the same manifest sends nothing. Each body moves whole,
in one admin answer. The manifest is encryption-agnostic and its
digests are over plaintext, so it means the same thing on both sides
whatever keys each cluster holds.

## Body plane across nodes

A body node is a `body_store` behind one mutually authenticated
`remote_channel` session — the loam-body template:

```sh
python3 tools/e2e/render_service.py packaging/mtls/loam-body/linux.yaml body-b.yaml \
  port=7101 body_dir=/var/lib/loam/bodies-b \
  ca=/etc/loam/ca.pem cert=/etc/loam/server.der key=/etc/loam/server.key.der
fluxor run body-b.yaml
```

The node at the front runs `body_fanout_router`, each member port
wired to a `remote_channel` that dials one body node through a
client-mode `tls`. [`tools/e2e/graphs/fleet_s3.yaml`](../tools/e2e/graphs/fleet_s3.yaml)
is that graph: the loam-s3 shape with two remote members and
`replicas: 2`. Every record on a body channel is
`[len:u32][cid:u32][record]`, so a member is wired the same way
whether its store is in the graph or on another node; `remote_channel`
carries the frames record for record, and refuses a session whose
peer states a different channel table.

With `replicas: 2` every PUT lands on both nodes before it is
acknowledged — desired replicas and required synchronous replicas are
one number, for the reasons in [durability.md](durability.md). Lose
one body node and reads are answered by the survivor; a member that
misses an answer's deadline (`MEMBER_DEADLINE_MS`) is asked last
until it answers again, so a read waits out at most one deadline.
Writes are refused while a replica is missing, and land on both once
its member has redialled. `scrub_interval` heals under-replication in
the background once the fleet is whole.

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
`fluxor sync`). [`examples/linux/clustor_multi3.yaml`](../examples/linux/clustor_multi3.yaml)
is the three-node shape and `tools/e2e/multi3_bringup.sh` brings it
up; the composed deployment profiles are not yet published as
self-contained service bundles.
