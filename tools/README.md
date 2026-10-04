# Tools

A file is named for what it is, its directory for whose it is — a
convention shared with wave, spectra and quantum.

| Directory | Role |
| --- | --- |
| `ci/` | Structural gates — what the tree must be; run by `fluxor ci` |
| `e2e/` | Graph and service gates — built modules run by the fluxor-linux runtime and driven from outside; run by `fluxor ci` |
| `diag/` | Diagnostics — run by hand when something has already gone wrong |

## `ci/`

| Script | What it gates |
| --- | --- |
| `shadow_guard.sh` | The shadow-tracked `tests/` and `examples/` are materialised, so nothing passes vacuously |
| `shipping_surface.sh` | The shipping surface carries no cargo dependency: no crate but the test harness, no binary, modules mount only `modules/common` and the fluxor SDK, the bundles' modules are built |
| `tier_guard.sh` | The storage tier boundary: mechanics vs replicated rosters, no upward reach, no clustor from mechanics |
| `limit_guard.sh` | The limit register against the capacity profiles |
| `profile_matrix.sh` | The harness under the minimal, embedded and server profiles (`fluxor ci` runs the default) |

## `e2e/`

| Script | What it gates |
| --- | --- |
| `s3_service.sh` | The loam-s3 bundle: an object's life under curl, refusals, wave's S3 traffic driver, restart durability |
| `admin_tls.sh` | The admin plane over mutual TLS, driven by the `loam` applet: files, volumes, snapshots, export, and the refusals |
| `nbd.sh` | A volume as an NBD device: flush durability across kill -9, FUA, the writer lease, an ungranted device |
| `fleet.sh` | Bodies on two loam-body nodes over remote_channel: replication, a node lost and regained |
| `metadata_load.sh`, `metadata_soak.sh` | The replicated metadata plane under offered load: every record committed or refused |
| `composed_node.sh` | A public surface on that plane in one graph: every proposal resolved, every request answered |
| `body_publication.sh` | The fence the body store negotiates from a live filesystem provider |
| `multi3_bringup.sh` | Three metadata nodes brought up by hand, for rig work |

`service_lib.sh` holds the service gates' shared setup (a work
directory, a CA and identities, a mesh root and capabilities, graphs
stopped by their own process tree); `graph_run.sh` the graph gates'.
`render_service.py` fills a template's `${param:…}` values for the
mTLS templates under `packaging/mtls/`; `nbd_client.py` is the NBD
client the `nbd` gate drives the device with.

## `diag/`

| Script | What it shows |
| --- | --- |
| `pic_abs_addr.py` | Absolute code addresses stored in a module's data. A module is linked at zero and loaded elsewhere, so such an address is wrong at runtime — and it is a baked-in value rather than a relocation, so nothing corrects it and nothing reports it. Most modules carry an expected, inert set (the SDK's `_KEEP_*` anchors, which nothing dereferences), which is why this reports rather than gates: resolve the addresses against `readelf -sW` before concluding. Reach for it when a module faults on the device but behaves correctly on the host |
