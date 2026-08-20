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
a public module. The decision table is
[`src/module_bindings.rs`](../src/module_bindings.rs), which is what
`loam surfaces` prints:

| Module | Fluxor surface | Visibility | Achievable fence |
| --- | --- | --- | --- |
| `namespace_router` | `storage.namespace` | Public | `ReplicatedDurable` |
| `object_index` | `storage.object` | Public | `ReplicatedDurable` |
| `block_allocator` | `storage.block` | Public | `LocalDurable` |
| `raft_metadata_client` | — | Internal | consumes clustor's public API |
| `cache_manager` | — | Internal | page-backing is not a public surface |
| `io_scheduler` | — | Internal | admission/flush plumbing |
| `placement_router` | — | Internal | placement is internal to loam |
| `telemetry_agg` | — | Internal | readiness/telemetry, not a surface |

Public modules return real `Fence` values: `ReplicatedDurable` with
a non-empty `ClustorFenceWitness` when backed by clustor, or
`LocalDurable` when acting purely against a local device.

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

The arena is not a cache: it holds every committed record, and WAL
replay restores full state on open. Caps come from the capacity
profile the build target selects — bare-metal builds
(`target_os = "none"`) get 256 bindings / 256 objects / 64 volumes /
64 body slots, host-runtime builds get service-class 8192 / 8192 /
1024 / 8192. The namespace arena is the exception: past its cap it
becomes a hot cache over a compacted snapshot file
([`modules/README.md`](../modules/README.md), "Namespace scale").
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
