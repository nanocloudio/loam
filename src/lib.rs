//! Loam — Fluxor-native distributed storage foundation.
//!
//! This crate is the **vocabulary** the Loam PIC modules and any
//! external consumer (tests, the loam-cli tool) speak. All runtime
//! logic lives under [`modules/`](../modules/). The host-side
//! storage stack (`LoamInstance`, `body_provider`, `wal`,
//! per-surface stores, Clustor in-process proxy, host-side
//! `raft_metadata_client`) has been removed in favour of the PIC
//! implementations:
//!
//! - [`modules/app/namespace_router/`](../modules/app/namespace_router/)
//! - [`modules/app/object_index/`](../modules/app/object_index/)
//! - [`modules/app/block_allocator/`](../modules/app/block_allocator/)
//! - [`modules/app/raft_metadata_client/`](../modules/app/raft_metadata_client/)
//! - [`modules/app/body_store/`](../modules/app/body_store/)
//! - [`modules/app/admin_router/`](../modules/app/admin_router/)
//!
//! What stays in `src/` is the type vocabulary every consumer
//! agrees on: surface identifiers, fence shapes (re-exported from
//! `fluxor_contracts`), descriptors, target/profile enums,
//! partition-assignment, raft-decision unions, the
//! module-to-surface visibility table, configuration types, and
//! the project-level `Error`/`Result`.

// The mounted contracts source is `#![no_std]` and uses `alloc::` paths;
// its submodules resolve `alloc` through the crate root, so bind it here.
extern crate alloc;

/// Fluxor's public contracts, consumed as staged **source** rather than a
/// cargo dependency (zero fluxor cargo edges). The mounted file's
/// `#[cfg(feature = "serde")]` gates evaluate against *this* crate's
/// features, so loam declares a default-on `serde` feature (Cargo.toml)
/// and the derives resolve against loam's own `serde` dependency.
// Staged by `fluxor sync` from the digest-pinned store artefact
// (standards/dependencies.md). Run `fluxor sync` after a fresh clone
// or an `update`; a missing path here means the sync has not run.
#[allow(
    unused_attributes,
    reason = "mounted file carries a crate-level #![no_std]"
)]
#[path = "../target/fluxor/fluxor-contracts/src/lib.rs"]
pub mod fluxor_contracts;

pub mod block;
pub mod control;
pub mod core;
pub mod fluxor;
pub mod module_bindings;
pub mod namespace;
pub mod object;
pub mod ops;
pub mod placement;
pub mod raft;
pub mod storage;

pub mod prelude {
    pub use crate::block::{BlockClass, BlockVolume};
    pub use crate::core::config::Config;
    pub use crate::core::error::{Error, Result};
    pub use crate::fluxor::{FluxorGraphProfile, FluxorTarget};
    pub use crate::fluxor_contracts::{
        ClustorFenceWitness, Fence, HashAlgo, StorageHandle, StorageSurface,
    };
    pub use crate::module_bindings::{
        public_modules, ModuleBinding, ModuleVisibility, MODULE_BINDINGS,
    };
    pub use crate::namespace::{
        NamespaceBinding, NamespaceEntry, NamespaceKind, NamespaceMutation, NamespaceOpen, PathKey,
    };
    pub use crate::object::{
        DataClass, ErasureProfile, ObjectDescriptor, ObjectId, ObjectPlacement, ObjectWrite,
    };
    pub use crate::placement::{NodeClass, PlacementPlan, StorageRole};
    pub use crate::raft::{ClustorBinding, ConsistencyMode};
    pub use crate::storage::{AchievableFence, CommitStep, SurfaceDescriptor, WritePlan};
}

pub const PROJECT_NAME: &str = "loam";
pub const SPECIFICATION_PATH: &str = "docs/specification.md";
