# Loam documentation

Loam is a distributed storage foundation built as a graph of
cooperative [fluxor](../../fluxor/) PIC modules. A namespace of path
bindings, an object index, and a content-addressed body plane run as
wired modules; metadata replicates through clustor, bodies replicate
outside Raft through their own routers. The same module binaries run
single-node or composed into a replicated deployment; only the graph
changes.

## Start here

- [running.md](running.md) — validated bring-up: the body-plane
  smoke graph, the CLI, the `loam-server` daemon, and the replicated
  shapes
- [architecture.md](architecture.md) — layout, the two-plane model,
  durability, and how the design scales

## Architecture reference

- [architecture.md](architecture.md) — repository layout, the
  vocabulary crate, PIC durability, the two-plane model, arena
  scaling, topology invariance
- [native_fluxor.md](native_fluxor.md) — how loam sits on fluxor:
  surface visibility, the step contract, the WAL write path, and the
  operational rules bare-metal bring-up imposes
- [specification.md](specification.md) — the invariants loam holds
  itself to, stated against the vocabulary in the tree

## Guides

- [running.md](running.md) — bring-up, smoke checks, daemon surfaces,
  replicated deployment shapes
