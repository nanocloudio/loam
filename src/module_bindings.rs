//! Module-to-surface wiring per docs/native_fluxor.md.
//!
//! Each Loam PIC module is either:
//!   - **Public**: it implements a Fluxor surface contract and advertises
//!     itself on the mesh under the canonical content type. Operations
//!     it returns must carry a real `Fence`.
//!   - **Internal**: it sits behind a public module, consuming Clustor's
//!     public API or another internal port. It is NOT advertised as a
//!     public surface (notably, `cache_manager` and `page_backing` stay
//!     internal in this round).

use crate::fluxor_contracts::StorageSurface;
use crate::storage::AchievableFence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleVisibility {
    /// Advertises a Fluxor surface on the mesh.
    PublicSurface {
        surface: StorageSurface,
        achievable: AchievableFence,
    },
    /// Internal-only module. Consumes Clustor or another module; never
    /// surfaces on the public mesh.
    Internal { rationale: &'static str },
}

#[derive(Debug, Clone, Copy)]
pub struct ModuleBinding {
    pub module: &'static str,
    pub visibility: ModuleVisibility,
}

/// Frozen table of module -> visibility decisions. Anything not in this
/// table is not a wired module.
pub const MODULE_BINDINGS: &[ModuleBinding] = &[
    ModuleBinding {
        module: "namespace_router",
        visibility: ModuleVisibility::PublicSurface {
            surface: StorageSurface::Namespace,
            achievable: AchievableFence::ReplicatedDurable,
        },
    },
    ModuleBinding {
        module: "object_index",
        visibility: ModuleVisibility::PublicSurface {
            surface: StorageSurface::Object,
            achievable: AchievableFence::ReplicatedDurable,
        },
    },
    ModuleBinding {
        module: "block_allocator",
        visibility: ModuleVisibility::PublicSurface {
            surface: StorageSurface::Block,
            achievable: AchievableFence::LocalDurable,
        },
    },
    ModuleBinding {
        module: "raft_metadata_client",
        visibility: ModuleVisibility::Internal {
            rationale: "consumes Clustor's public API; not a surface itself",
        },
    },
    ModuleBinding {
        module: "cache_manager",
        visibility: ModuleVisibility::Internal {
            rationale: "page-backing is not a public Loam surface in this round",
        },
    },
    ModuleBinding {
        module: "io_scheduler",
        visibility: ModuleVisibility::Internal {
            rationale: "admission/flush plumbing behind public surfaces",
        },
    },
    ModuleBinding {
        module: "placement_router",
        visibility: ModuleVisibility::Internal {
            rationale: "placement decisions are internal to Loam",
        },
    },
    ModuleBinding {
        module: "telemetry_agg",
        visibility: ModuleVisibility::Internal {
            rationale: "readiness/telemetry reporter, not a storage surface",
        },
    },
];

impl ModuleBinding {
    pub fn is_public(&self) -> bool {
        matches!(self.visibility, ModuleVisibility::PublicSurface { .. })
    }

    pub fn surface(&self) -> Option<StorageSurface> {
        match self.visibility {
            ModuleVisibility::PublicSurface { surface, .. } => Some(surface),
            ModuleVisibility::Internal { .. } => None,
        }
    }
}

pub fn public_modules() -> impl Iterator<Item = &'static ModuleBinding> {
    MODULE_BINDINGS.iter().filter(|b| b.is_public())
}

pub fn lookup(module: &str) -> Option<&'static ModuleBinding> {
    MODULE_BINDINGS.iter().find(|b| b.module == module)
}
