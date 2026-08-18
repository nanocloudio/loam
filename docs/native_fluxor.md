# Loam Fluxor Architecture

How Loam sits on Fluxor: which modules advertise a surface, what
every step body owes the kernel, and how the durability path works.
The module roster and layout are in
[`architecture.md`](architecture.md); wire formats, arena sizing and
the replication topology are in
[`../modules/README.md`](../modules/README.md). This file does not
repeat either.

## Surface visibility

Each Loam PIC is either **public** — it implements a Fluxor storage
surface and returns a real `Fence` — or **internal**, sitting behind
a public module. The decision table is
[`src/module_bindings.rs`](../src/module_bindings.rs), which is what
`loam surfaces` prints:

| Module | Fluxor surface | Visibility | Achievable fence |
| --- | --- | --- | --- |
| `namespace_router` | `storage.namespace` | Public | `ReplicatedDurable` |
| `object_index` | `storage.object` | Public | `ReplicatedDurable` |
| `block_allocator` | `storage.block` | Public | `LocalDurable` |
| `raft_metadata_client` | — | Internal | consumes Clustor's public API |
| `cache_manager` | — | Internal | page-backing is not a public surface |
| `io_scheduler` | — | Internal | admission/flush plumbing |
| `placement_router` | — | Internal | placement is internal to Loam |
| `telemetry_agg` | — | Internal | readiness/telemetry, not a surface |

Public modules MUST return real `Fence` values: `ReplicatedDurable`
with a non-empty `ClustorFenceWitness` when backed by Clustor, or
`LocalDurable` when acting purely against a local device.

The body plane and the admin front door are internal throughout —
`body_store`, `body_fanout_router`, `ec_body_router`,
`clustor_bridge`, `admin_router`, `block_log` and the probes
advertise nothing. Of the three public modules, `namespace_router`
is the one fluxor's loader registers as a provider: it exports
`module_provides_contract` and `module_provider_dispatch`, so a
sibling reaches it by contract rather than by port name.

## Execution principle

Every module honors the Fluxor step contract:

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
Per-PIC bodies: `modules/common/mechanics/<surface>_pic_body.rs`. The
host PIC test harness drives the same code paths through real `fs`
syscalls backed by `std::fs` — see
[`tests/common/pic_harness.rs`](../tests/common/pic_harness.rs).

The arena is not a cache: it holds every committed record, and WAL
replay restores full state on open. Caps come from the capacity
profile the build target selects — bare-metal builds
(`target_os = "none"`) get 256 bindings / 256 objects / 64 volumes /
64 body slots, host-runtime builds get service-class 8192 / 8192 /
1024 / 8192. The namespace arena is the exception: past its cap it
becomes a hot cache over a compacted snapshot file
(`modules/README.md`, "Namespace scale"). Multi-PIC deployments shard
further by partition.

## Both profiles, one write path

Fluxor's `fat32` dispatches the whole write path — `OPEN_CREATE`,
`WRITE`, `FSYNC`, `UNLINK`, `PREALLOCATE` — and offers write and
fsync submit/poll, so a bounded step submits and polls across steps
instead of blocking inside one. The WAL therefore has the same
durable backing on the embedded profile as on the host, and a PIC
lands its WAL on first boot without the graph profile pre-touching
anything.

## What the hardware teaches

Two findings worth not rediscovering, both from bringing the
metadata plane up on pi5:

- **A missing `scheduler: { accept_cycles: true }` halts pi5
  silently.** The platform debug overlay (`debug.to: net`) injects a
  bidirectional `ip ↔ log_net` pair, which the scheduler treats as a
  cycle. Without `accept_cycles`, `prepare_graph` returns `-22` and
  the kernel halts before the scheduler starts — no UDP, no UART,
  because the panic path needs `UART_READY` and init bails before
  that. The host runtime rejects the same graph visibly (`[graph] N
  module(s) involved in cycles — graph rejected.`). Reproducing on
  the host first is the cheap move.
- **Port order is load-bearing.** The PIC ABI hands a module only
  its slot-0 output as `out_chan`, so a module that writes acks to
  `out_chan` must declare that port first. `namespace_router`'s
  manifest says so at the declaration site.

## Measured behaviour

The metadata plane is measured by
[`tools/e2e/metadata_load.sh`](../tools/e2e/metadata_load.sh)
(bounded) and
[`tools/e2e/metadata_soak.sh`](../tools/e2e/metadata_soak.sh)
(sustained), both reading `[loam-lg]` offered/emitted against
`[loam-tp]` committed/aborted.
[`tools/e2e/composed_node.sh`](../tools/e2e/composed_node.sh) adds the
composed case: load enters at a public surface that proposes through
the plane rather than applying, so the surface's answers and the
plane's decisions are both accounted for.

On the host profile at `tick_us: 1000`, a single replica commits
~250 records/s — the replica's durable-write rate, not a loam
ceiling. Below that rate the plane is lossless (1000 offered → 1000
committed, 0 refused); above it the excess is refused rather than
dropped, and the total is conserved either way. That conservation,
not the rate, is what the gates assert, so they stay meaningful on
any machine.

On silicon, [`tests/hardware/`](../tests/hardware/) holds the
`fluxor rig test` scenarios.
