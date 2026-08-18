# Tools

A file is named for what it is, its directory for whose it is — the
convention `wave/tools/`, `spectra/tools/` and `quantum/tools/` share.

| Directory | Role |
| --- | --- |
| `ci/` | Gates, run by `fluxor ci` as `[ci.test]` scripts |
| `e2e/` | End-to-end drivers that boot a graph and drive it from outside |
| `diag/` | Diagnostics — run by hand when something has already gone wrong |
| `loam-cli/`, `loam-client/` | Host Cargo crates (see below) |

## `ci/`

| Script | Gate |
| --- | --- |
| `shadow_guard.sh` | Hard-fails when `tests/` or `examples/` is not materialised, so CI cannot run zero tests and report green (`../../standards/test-tracking.md` §7) |
| `tier_guard.sh` | Holds the storage tier boundary: mechanics and replicated rosters stay disjoint, no upward reach into `common/`, no clustor from the mechanics tier |

## `e2e/`

| Script | Proves |
| --- | --- |
| `s3_driven.sh` | The S3 connector is *usable*, not just signed: runtime-chosen PUT/GET driven through the `s3_client` graph against loam's own `--s3-listen` gateway, then read back with curl independently of the connector. Wired as a `[ci.test]` script. Builds `loam-server` itself — nothing else in CI builds it, so requiring it as a prerequisite would make the gate turn on whether someone had built it by hand. Runs against the runtime `fluxor` provisions into this project's target dir — the same binary `fluxor run` executes — rather than a sibling source tree's cargo output, which exists only if someone built fluxor from source and which fluxor's own tooling removes |
| `multi3_bringup.sh` | 3-node replicated metadata bring-up: renders `examples/linux/clustor_multi3.yaml` per node, spawns three graphs, asserts exactly one leader PASS and byte-identical WAL segments across replicas |
| `metadata_load.sh` | The replicated metadata plane under offered load, gated on conservation — every record the plane accepts is committed or refused, never dropped. Asserts no rate, so it stays meaningful on any machine. Wired as a `[ci.test]` script |
| `metadata_soak.sh` | The same plane held at rate for a sustained run, for what only time surfaces: drift, leaks, and a settling in-flight count |
| `composed_node.sh` | A public surface sitting on that plane, gating both conservation claims at once — every proposal resolved, and every request answered. Also runs a module the way a module is actually run, loaded at an address it was not linked for, which no host test does. Wired as a `[ci.test]` script |

## `diag/`

| Script | What it shows |
| --- | --- |
| `pic_abs_addr.py` | Absolute code addresses stored in a module's data. A module is linked at zero and loaded elsewhere, so such an address is wrong at runtime — and it is a baked-in value rather than a relocation, so nothing corrects it and nothing reports it. Most modules carry an expected, inert set (the SDK's `_KEEP_*` anchors, which nothing dereferences), which is why this reports rather than gates: resolve the addresses against `readelf -sW` before concluding. Reach for it when a module faults but its host tests pass |

## Host crates

| Crate | What it does |
| --- | --- |
| `loam-cli` | Fluxor-native dev CLI (`loam`) — each subcommand spins up the PIC bodies it needs in-process — plus the `loam-server` daemon (unix-socket admin, `--s3-listen` gateway, TCP body-plane bridge) |
| `loam-client` | Client library for `loam-server --socket`'s admin surface: one struct, blocking calls, no dependencies — links the same `loam_admin_wire.rs` the PIC modules compile |

Both are members of the root workspace and are covered by the root
`cargo test`.
