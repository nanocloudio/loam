# Loam Specification

The invariants loam holds itself to, stated against the vocabulary
in the tree. They are normative: implemented behaviour conforms to
them today, and anything new must conform to land. One of them
(PARTITION-SHARD's multi-partition case) is a design target, marked
where it is stated.

## Invariants

- **FENCE-TRUE:** Every loam operation returns a `Fence` — fluxor's
  enum, re-exported as `loam::fluxor_contracts::Fence` from the
  `fluxor-contracts` source artefact `fluxor sync` stages — that
  accurately reflects what the underlying graph achieved. No
  operation may advertise a stronger fence than it actually
  produced. Concretely:
  - A purely in-memory store advertises `Volatile` for local ops.
  - A WAL-backed store advertises `LocalDurable` only after the WAL
    append has been fsync'd.
  - `ReplicatedDurable` requires a non-empty `ClustorFenceWitness`;
    the store refuses to construct one without proof of quorum.
  - Stores refuse caller-asserted fences they cannot honour: a
    memory-only namespace store will not accept a caller's
    `LocalDurable`.
- **RAFT-META:** Namespace and replicated metadata effects derive
  from clustor log entries or snapshots.
- **BODY-SEPARATE:** Object/file body durability is tracked
  separately from metadata durability.
- **PATH-SAFE:** Namespace paths are absolute, normalised by the
  caller, and cannot contain parent traversal. A path is a *mutable*
  `(namespace_root, segments)` binding to a *stable* `ObjectId`.
  Rename preserves `ObjectId` — it is an atomic re-binding in the
  replicated log, not a directory entry move. The path may change;
  the underlying object identity does not.
- **GRAPH-NATIVE:** Loam storage engines are fluxor graph modules,
  not hidden side threads.
- **BODY-OUT-OF-RAFT:** Object bodies, EC shards, cache contents,
  and page-backing state never enter any Raft log. Raft replicates
  only the `Propose` records of
  [`loam_decision_wire.rs`](../modules/common/replicated/loam_decision_wire.rs)
  — small, identity-bearing metadata (path bindings, object
  descriptors with `content_hash`, block volume metadata, placement
  claims), capped at `MAX_INNER` = 4 KiB per record. Body durability
  is proved independently: by content hash
  (`Fence::ContentHashed`), by local fsync (`Fence::LocalDurable`),
  and/or by a body-provider quorum whose witness is issued by the
  body provider, not by `ClustorFenceWitness`. The two witnesses
  prove different things and have independent fault domains.
- **TOPOLOGY-INVARIANT:** A `Propose` record's shape is identical on
  a 1-node "cluster," a micro-DC, and a hyperscale fleet. Cluster
  topology decides how many Raft groups and which group routes a
  decision — never what a decision looks like.
- **PARTITION-SHARD:** Each partition is a pure shard — its own PIC
  instances (its own bindings, object index, block volumes) and its
  own Raft replica group. Partitions share no state, never
  coordinate, and never see each other's decisions. The routing
  function `(decision identity) -> partition_id` is stable across
  runs and locality-respecting: all decisions about a single path,
  ObjectId, or volume_id route to the same partition. Horizontal
  scale is achieved by raising the partition count; the
  per-partition code is unchanged. A single-partition graph is the
  degenerate case of this rule, not an exception to it. Status:
  deployments today are single-partition; the multi-partition graph
  is a design target, not wired.
- **TENANT-ISOLATED:** A tenant is identified by the `ns` field
  every namespace record on
  [`loam_wire.rs`](../modules/common/mechanics/loam_wire.rs)
  carries. Tenants share no namespace state: a bind/rename/unbind
  under tenant A is structurally invisible to tenant B's reads,
  lists, and reverse lookups. Two tenants may legitimately hold the
  same path string bound to different objects; the path is qualified
  by its namespace root, so collisions across tenants are
  impossible. On the S3 gateway the bucket is the namespace root,
  which is what makes a SigV4 credential's per-bucket scope a
  tenancy boundary.

## Storage Surfaces

Fluxor (not loam) defines the surface vocabulary and the `Fence`
enum that operations return. The family is four; loam declares three
of them.

| Surface | Declared by | Reached by |
| --- | --- | --- |
| `storage.namespace` | `namespace_router` | contract — it exports `module_provides_contract` and `module_provider_dispatch`, so fluxor's loader registers it |
| `storage.object` | `object_index` | its ports, named in graph YAML |
| `storage.block` | `block_allocator` | its ports, named in graph YAML |
| `file.data` | — | file bytes reach the body plane through `admin_router`'s composed PutFile |

A surface name binds to the module that can serve it. Descriptors
are not object bytes and volume accounting is not a block device, so
`storage.object` and `storage.block` name modules whose shape does
not fit them, and the port-named route is the honest one until the
surface moves to a module that does fit.

Everything else is internal and advertises nothing on the mesh —
`body_store`, `body_fanout_router`, `ec_body_router`,
`placement_router`, `raft_metadata_client`, `clustor_bridge`,
`admin_router`, `block_log`, `object_index`, `block_allocator` and
`telemetry_agg`. Fluxor's surface vocabulary deliberately gives
append-log behaviour and page-backing no surface names of their
own, so loam does not invent any. Nor does it carry modules that
exist only to reserve a name: page-backing and I/O admission have
no module here, because neither has a consumer or a surface to
answer.

## Clustor Binding

Clustor is the only Raft substrate. Loam binds namespace, object
metadata, and block maps to clustor replica groups through explicit
descriptors carried on the decision wire
([`modules/common/replicated/loam_decision_wire.rs`](../modules/common/replicated/loam_decision_wire.rs)).
Loam consumes clustor's public API only; it does not depend on
clustor internals.

## Fluxor Binding

Fluxor validates target capability, runs native modules, and
publishes the storage surface contracts and `Fence` enum loam
implements. Loam graph profiles are target-specific but share the
same fluxor-owned surface vocabulary.

## Sibling Boundary

Loam and lattice are siblings on clustor, not layers. Loam's
`path -> ObjectId` binding store is its own; it is not backed by
lattice.
