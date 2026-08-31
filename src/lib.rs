//! Loam — Fluxor-native distributed storage foundation.
//!
//! This crate is the **vocabulary** the Loam PIC modules and any
//! external consumer (tests, the loam-cli tool) speak. All runtime
//! logic lives under [`modules/`](../modules/). There is no
//! host-side storage stack here — no instance type, no body
//! provider, no per-surface stores, no in-process Clustor proxy.
//! The PIC modules are the implementation:
//!
//! - [`modules/app/namespace_router/`](../modules/app/namespace_router/)
//! - [`modules/app/object_index/`](../modules/app/object_index/)
//! - [`modules/app/block_allocator/`](../modules/app/block_allocator/)
//! - [`modules/app/raft_metadata_client/`](../modules/app/raft_metadata_client/)
//! - [`modules/app/body_store/`](../modules/app/body_store/)
//! - [`modules/app/admin_router/`](../modules/app/admin_router/)
//!
//! What stays in `src/` is the CONFIGURATION vocabulary and
//! nothing else: the types `config/loam.toml` is written in, the
//! project-level `Error`/`Result`, and fluxor's contracts mounted
//! as source for consumers that want them.
//!
//! In particular there is no module-to-surface visibility table
//! here, and no descriptor, placement or tenancy vocabulary. A
//! module's surface is what its `manifest.toml` declares; a table in
//! `src/` would be a second copy of that, free to drift from the
//! manifests while still compiling. `loam surfaces` reads the
//! manifests directly, so there is nothing to keep in step.

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

pub mod core;
pub mod fluxor;
pub mod storage;

pub mod prelude {
    pub use crate::core::config::Config;
    pub use crate::core::error::{Error, Result};
    pub use crate::fluxor::{FluxorGraphProfile, FluxorTarget};
    pub use crate::fluxor_contracts::{
        ClustorFenceWitness, Fence, HashAlgo, StorageHandle, StorageSurface,
    };
    pub use crate::storage::AchievableFence;
}

pub const PROJECT_NAME: &str = "loam";
pub const SPECIFICATION_PATH: &str = "docs/specification.md";
