# Loam ⇄ Clustor: replicated metadata bring-up

Composing loam's metadata plane with a real Clustor replica group —
single node first, then three. The map of how the pieces fit, and
the traps that cost time.

## Single node — `examples/linux/clustor_e2e.yaml`

The smallest composition that exercises the whole path:

```
metadata_e2e_probe ─Propose→ raft_metadata_client (MODE_REPLICATED, WAL)
    └─→ clustor_bridge ─MSG_CLIENT_PROPOSAL→ consensus.proposals
            … WAL append → durability quorum → commit → apply …
    ┌─← clustor_bridge ←MSG_COMMITTED_ENTRY─ consensus.committed_entries
raft_metadata_client ─Committed(witness_epoch = commit index)→ probe ⇒ PASS
```

A single replica reaches quorum the moment its local fsync
completes, so this proves the wire and the lifecycle without the peer
mesh.

### Pieces

- **[`modules/app/clustor_bridge/`](../modules/app/clustor_bridge/)**
  translates loam_decision_wire ⇄ clustor envelopes. It mounts
  `clustor-common`'s `replica_facade.rs` for the envelope, the frame
  splitter and the committed-entry decode, so it mirrors no Clustor
  constant of its own. The loam Propose record travels VERBATIM as
  Clustor's opaque command body, so the committed entry hands back
  plane + correlation_id + inner, and the bridge synthesizes the loam
  Committed with witness_epoch = the Raft commit index. The
  `witness_quorum` param is the voter count (1 here).
- **`loam_decision_wire` Propose carries a `correlation_id`**
  (`[op][plane][corr u32][len u16][inner]`) — without it,
  replicated-mode commits could never be matched to pending
  proposals. `corr = 0` at the `metadata_ops` hop means "unassigned";
  the proposer assigns on forward, node-scoped with `self_id` in the
  high byte.
- **`raft_metadata_client`** wires its optional Clustor channels via
  `dev_channel_port` (out[1] = clustor_requests, in[1] =
  clustor_commits) and runs `mode: 1` (MODE_REPLICATED) from params.
- **The Clustor half** is `clustor/configs/single-minimal.yaml` with
  loam's plane standing in for `example_consumer` — the same
  composites (`peer_router`, `gateway`, `consensus`, `durability`,
  `control_plane`, `admission`, `operations`), wired the same way.
  When Clustor's composition changes, this file follows it rather
  than growing a variant. The bridge is the sole writer to
  `consensus.proposals`.

### Bring-up

```sh
# 1. Publish clustor to the local registry (loam's fluxor.toml
#    declares clustor = "0.0.1") and stage every dependency's
#    published modules under target/fluxor/.
(cd ../clustor && make publish)
fluxor update && fluxor sync

# 2. Build this project's own modules. Nothing is copied out of a
#    sibling checkout — `fluxor sync` stages the dependencies.
fluxor modules build --target bcm2712

# 3. Runtime prerequisite: the fs contract has no MKDIR, so the
#    directory must exist. The proposer creates its own WAL via
#    FS_OPEN_CREATE.
mkdir -p wal                       # replica log segments (cwd-relative!)

# 4. Run
fluxor run examples/linux/clustor_e2e.yaml
# success: "[meta_e2e] PASS" and wal] hb entries > 0
```

### Traps

- **`wal/` is cwd-relative** and the fs contract can't mkdir: a
  missing dir means every WAL open fails silently, so entries stay 0
  forever. Create it.
- **One writer per input port.** Fluxor fan-in to a port clobbers, so
  the bridge must be the SOLE writer to `consensus.proposals`.
- **`dev_log` values must be ASCII** — NULs are stripped by the log
  pipeline.

## Three replicas — `examples/linux/clustor_multi3.yaml`

The per-node template: the same loam plane composed with clustor's
`multi-3node.yaml` shape (peer mesh over `linux_net`, replicator WAL
catch-up, `voter_count: 3`). One command runs the whole thing:

```sh
tools/e2e/multi3_bringup.sh          # renders, spawns 3 nodes, checks, cleans up
```

Acceptance is two claims:

- **Exactly one node logs `[meta_e2e] PASS`** — the leader's.
  `consensus` drains its proposals port only while it holds
  leadership, so a follower's proposals wait on the proposer's retry
  sweep and its probe logs `[meta_e2e] FAIL timeout`. Because
  correlation ids are node-scoped, only the leader's proposer can
  match the committed bind it proposed, which is what makes the
  commit node-attributed rather than merely observed.
- **The three per-node WAL segments are byte-identical** — the
  replicated log converged on every replica, so the bind committed
  through a real 2-of-3 quorum and the committed entry reached every
  node's apply pipeline.

### Additional traps

- **Every node needs its own working directory.** Clustor's WAL
  writes `wal/p0000_seg_*` cwd-relative; three replicas sharing one
  segment file is silent corruption. The script gives each node a
  sandbox of symlinks plus a real `wal/`.
- **NetProto edges default to the `audio` rate class.** Edges into
  ports capped at `rate_class_max = "transaction"` need an explicit
  `rate: transaction`.
- **ABI drift is three-sided**: the fluxor CLI, the staged
  `target/fluxor/fluxor-abi` SDK snapshot, and the pinned
  `fluxor-linux` runtime must all agree. The canonical registry is
  immutable — bump fluxor's version and `make publish`, then
  `fluxor update && fluxor sync` in BOTH clustor and loam.
- **The probe must skip `OP_REPLAY_DRAINED`** on `metadata_results`:
  the plane-level read-gate marker precedes the Committed.
