# Loam on Fluxor

How loam sits on [fluxor](../../fluxor/): which modules advertise a
surface, what every step body owes the kernel, and how the
durability path works. The module roster and layout are in
[`architecture.md`](architecture.md); wire formats, arena sizing and
the replication topology are in
[`../modules/README.md`](../modules/README.md). This file does not
repeat either.

## Surface visibility

Each loam PIC is either **public** — it implements a fluxor storage
surface and returns a real `Fence` — or **internal**, sitting behind
a public module. The declaration is the module's own
`manifest.toml`: a `provides` key makes it public, its absence makes
it internal. `loam surfaces --modules modules` reads those manifests
and prints the result, so there is no second table to drift.

Three modules declare a surface, and each is the one that can answer it:

| Module | Fluxor surface | Ops | Fence it returns |
| --- | --- | --- | --- |
| `namespace_router` | `storage.namespace` | `LOOKUP` `STAT` `LIST` `CLOSE` `BIND` `RENAME` `DELETE` `SUBSCRIBE` `CHANGES` `CAPS`, by provider dispatch | `ReplicatedDurable` on the quorum path, `LocalDurable` WAL-only, `Volatile` with no WAL |
| `object_provider` | `storage.object` | `PRESENT` `PUT` `GET` `HEAD` `RANGE_GET` `DELETE` `LIST` `PUT_STREAMED_*`, by provider dispatch, each under the capability its caller presented | For a write, the namespace's fence for its bind, as the admin plane's answer carries it; `Volatile` for a read |
| `loam_volume` | `storage.block` | `CAPS` `EXEC` `SUBMIT` `REAP` on its `blocks` channel; `READ`, `WRITE`, `FLUSH`, with `FUA` and `PREFLUSH`. `DISCARD` is not advertised and is refused | `Volatile` for a staged write; `RevisionMonotone` at the volume's committed revision for a flush, a `FUA` write or a `PREFLUSH` |

`LIST` (0x1302) answers one page of names under a prefix, in key
order after a cursor, through the dispatch; the channel wire's
`loam_wire::OP_LIST` serves the same name-ordered walk, with each
binding, to a consumer wired to the module's ports.

`CAPS` advertises the optional ops this provider implements — BIND,
RENAME, DELETE, SUBSCRIBE, CHANGES. The mandatory read ops carry no
bit, so a consumer reads the bits for what is optional and assumes
the rest.

Every other module is internal by omission.

Two nearby modules deliberately claim NOTHING. `object_index`
holds descriptors, so it cannot answer `storage.object`, which is
whole-blob byte access — it has no bytes to return.
`block_allocator` does volume accounting, so it cannot answer
`storage.block`, which is raw block I/O — in loam that is
`loam_volume`, which serves a volume's bytes. Either claim would be one nothing could
honour, and by-contract resolution is precisely the mechanism that
would route a real consumer to it. The `storage.object` surface is a
composition — descriptors here, bytes from the body plane — which
`admin_router` performs, and `object_provider` exports the dispatch
that claims it.

The fence column is what the dispatch actually returns, not a
ceiling: `achieved_fence` reports `Volatile` when there is no WAL,
because the whole point of the fence axis is that a consumer can
tell the three apart.

Public modules return real `Fence` values, claimed from the PROOF in
hand rather than from the mode configured. Being wired for
replication says where records arrive from; it says nothing about
whether any of them reached a quorum, so it cannot be what licenses a
`ReplicatedDurable` claim.

What licenses it is an applied commit whose record carries a real
quorum and a real witness. Each `Committed` record on
[`loam_decision_wire.rs`](../modules/common/mechanics/loam_decision_wire.rs)
carries its own proof — the log's `source`, the Raft `term` and
`index`, the `quorum`, and a witness over the committed bytes — and
`CommitProof::is_replicated` is the single place that decides whether
those add up to replication. A commit backed by one voter, or
carrying no witness, reports `LocalDurable`: durable, which it is,
rather than replicated, which it is not.

The body plane and the admin front door are internal throughout —
`body_store`, `body_fanout_router`, `ec_body_router`,
`clustor_bridge`, `admin_router`, `block_log` and the probes
advertise nothing. Of the three public modules, `namespace_router`
is the one fluxor's loader registers as a provider: it exports
`module_provides_contract` and `module_provider_dispatch`, so a
sibling reaches it by contract rather than by port name.

## Execution principle

Every module honours the fluxor step contract:

- no blocking
- bounded work per step
- explicit backpressure
- no hidden threads
- no unbounded allocation

## PIC durability

The three public-surface PICs and `raft_metadata_client` durably log
every apply through the fluxor `fs` contract. On `module_new`, when
`params` carries a WAL file path, the PIC opens it with
`wal_open_or_create` (`FS_OPEN_CREATE`, so first boot needs no
pre-touch), replays every prior record into the arena, and from then
on durable-appends each successful apply before mutating the arena —
log-then-arena ordering.

Shared primitives:
[`modules/common/mechanics/wal_io.rs`](../modules/common/mechanics/wal_io.rs).
Per-PIC bodies: `modules/common/mechanics/<surface>_pic_body.rs`.

The object and block arenas hold every committed record, and WAL
replay restores full state on open. Caps come from the capacity
profile: a bcm2712 module image is `embedded` — 256 bindings / 256
objects / 64 volumes / 64 body slots — and a host build is `node`,
at service-class 8192 / 8192 / 1024 / 8192. The namespace arena is
the exception: past its cap it becomes a hot cache over a compacted
snapshot file ([`modules/README.md`](../modules/README.md),
"Namespace scale").
Multi-PIC deployments shard further by partition.

## Both profiles, one write path

Fluxor's `fs` contract dispatches the whole WAL write path —
open-create, write, fsync, unlink — on the embedded profile as well
as on the host, so a bounded step drives the same durable backing in
both places and a PIC lands its WAL on first boot without the graph
profile pre-touching anything.

## Operational rules from silicon

Two rules the bare-metal profile imposes, both worth knowing before
composing a graph for hardware:

- **A graph with the net debug overlay needs
  `scheduler: { accept_cycles: true }`.** The platform debug overlay
  (`debug.to: net`) injects a bidirectional `ip ↔ log_net` pair,
  which the scheduler treats as a cycle; without the flag the graph
  is rejected before the scheduler starts. The host runtime rejects
  the same graph with a visible cycle error, so reproducing on the
  host first is the cheap move.
- **Port order is load-bearing.** The PIC ABI hands a module only
  its slot-0 output as `out_chan`, so a module that writes acks to
  `out_chan` must declare that port first. `namespace_router`'s
  manifest says so at the declaration site.
