//! The fence vocabulary `Config` is written in.
//!
//! Everything else that once lived here — `WritePlan`, `CommitStep`,
//! `SurfaceDescriptor` — described a host-side storage stack that no
//! longer exists, and had no consumer anywhere in the tree. The
//! surface and fence vocabulary proper is fluxor's
//! (`fluxor_contracts`, and `modules/sdk/fence.rs` for the runtime
//! type); a module's honest per-op fence is what its dispatch
//! returns, not what a table here asserts.

use serde::{Deserialize, Serialize};

/// The strongest fence shape an implementation can produce, as
/// declared in `config/loam.toml`. This is configuration intent —
/// what an operator asks the deployment to hold itself to — not
/// proof, which only a returned `Fence` can be.
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
