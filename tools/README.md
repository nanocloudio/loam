# Tools

A file is named for what it is, its directory for whose it is — a
convention shared with wave, spectra and quantum.

| Directory | Role |
| --- | --- |
| `diag/` | Diagnostics — run by hand when something has already gone wrong |
| `loam-cli/`, `loam-client/` | Host Cargo crates (see below) |

## `diag/`

| Script | What it shows |
| --- | --- |
| `pic_abs_addr.py` | Absolute code addresses stored in a module's data. A module is linked at zero and loaded elsewhere, so such an address is wrong at runtime — and it is a baked-in value rather than a relocation, so nothing corrects it and nothing reports it. Most modules carry an expected, inert set (the SDK's `_KEEP_*` anchors, which nothing dereferences), which is why this reports rather than gates: resolve the addresses against `readelf -sW` before concluding. Reach for it when a module faults on the device but behaves correctly on the host |

## Host crates

| Crate | What it does |
| --- | --- |
| `loam-cli` | Fluxor-native dev CLI (`loam`) — each subcommand spins up the PIC bodies it needs in-process — plus the `loam-server` daemon (unix-socket admin, `--s3-listen` gateway, TCP body-plane bridge) |
| `loam-client` | Client library for `loam-server --socket`'s admin surface: one struct, blocking calls, no dependencies — links the same `loam_admin_wire.rs` the PIC modules compile |

Both are members of the root workspace.
