//! Loam-side implementations of Fluxor's storage surface contracts and
//! the Loam-internal types needed to produce honest fence values.
//!
//! The surface and fence vocabulary lives in the `fluxor_contracts`
//! module (fluxor contracts source mounted at the crate root). Loam owns *how* its modules produce real, accurate `Fence`
//! values out the other side. The Fluxor types are re-exported here for
//! the convenience of `storage::*` glob imports; new code is welcome to
//! use `crate::fluxor_contracts` directly.

use crate::core::error::{Error, Result};
use serde::{Deserialize, Serialize};

pub use crate::fluxor_contracts::{
    content_type, ClustorFenceWitness, Fence, HashAlgo, StorageHandle, StorageSurface,
};

/// Loam-internal description of a write's intended fence shape, used by
/// modules to plan an operation before they have a real `Fence` to
/// return. Distinct from `Fence` itself: this is intent, not proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WritePlan {
    pub target_surface: StorageSurface,
    pub want_replicated: bool,
    pub commit_step: CommitStep,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommitStep {
    BodyDurable,
    MetadataCommitted,
    QuorumCommitted,
}

impl WritePlan {
    pub fn object_put_replicated() -> Self {
        Self {
            target_surface: StorageSurface::Object,
            want_replicated: true,
            commit_step: CommitStep::MetadataCommitted,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.commit_step == CommitStep::QuorumCommitted && !self.want_replicated {
            return Err(Error::invalid_fence(
                "quorum commit requires want_replicated = true",
            ));
        }
        Ok(())
    }
}

/// Descriptor recorded by a surface implementation when it exposes
/// itself to the mesh. Carries the canonical Fluxor content type and
/// the fence shape the implementation is able to honestly produce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurfaceDescriptor {
    pub name: String,
    pub surface: StorageSurface,
    pub achievable_fence: AchievableFence,
}

/// The strongest fence shape a given implementation can produce. Used
/// to keep FENCE-TRUE honest at module advertise time.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AchievableFence {
    Volatile,
    LocalDurable,
    ReplicatedDurable,
    ContentHashed,
    RevisionMonotone,
    ViewConsistent,
}
