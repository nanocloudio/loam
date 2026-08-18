use crate::core::error::{Error, Result};
use crate::fluxor_contracts::{ClustorFenceWitness, Fence, StorageHandle, StorageSurface};
use crate::object::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathKey(String);

impl PathKey {
    pub fn new(path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        validate_path(&path)?;
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A path binding: the mutable side of (namespace_root, segments) ->
/// stable ObjectId. Renames preserve `object_id` — only the binding
/// changes (atomically re-bound through Clustor).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceBinding {
    pub namespace_root: String,
    pub path: PathKey,
    pub object_id: ObjectId,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceEntry {
    pub path: PathKey,
    pub object_id: ObjectId,
    pub revision: u64,
    pub kind: NamespaceKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceKind {
    File,
    Directory,
    Object,
    Volume,
    Symlink,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceMutation {
    /// Bind a path to an ObjectId (or rebind to a new ObjectId).
    Put(NamespaceEntry),
    /// Remove the binding; ObjectId lifetime is unaffected.
    Remove { path: PathKey, base_revision: u64 },
    /// Atomic re-binding from `from` to `to`. Preserves ObjectId — this
    /// is NOT a directory-entry move; the underlying object identity
    /// doesn't change.
    Rename {
        from: PathKey,
        to: PathKey,
        base_revision: u64,
    },
}

/// Returned by `namespace_router` when a caller opens a namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceOpen {
    pub handle: StorageHandle,
    pub fence: Fence,
}

impl NamespaceOpen {
    /// Open a namespace under a replicated Clustor binding. The fence
    /// MUST carry a non-empty witness — Loam will not advertise
    /// `ReplicatedDurable` without one.
    pub fn replicated(
        mesh_handle_id: u64,
        lease_epoch: u64,
        witness: ClustorFenceWitness,
    ) -> Result<Self> {
        if witness.is_empty() {
            return Err(Error::invalid_fence(
                "ReplicatedDurable open requires a non-empty Clustor witness",
            ));
        }
        let fence_epoch = witness.fence_epoch;
        let quorum = witness.quorum;
        Ok(Self {
            handle: StorageHandle {
                surface: StorageSurface::Namespace,
                content_type: StorageSurface::Namespace.content_type(),
                mesh_handle_id,
                lease_epoch,
            },
            fence: Fence::ReplicatedDurable {
                quorum,
                epoch: fence_epoch,
                witness,
            },
        })
    }

    /// Open a namespace backed only by a local durable device (e.g.
    /// FAT32). Honest downgrade for small/local providers.
    pub fn local(mesh_handle_id: u64, lease_epoch: u64) -> Self {
        Self {
            handle: StorageHandle {
                surface: StorageSurface::Namespace,
                content_type: StorageSurface::Namespace.content_type(),
                mesh_handle_id,
                lease_epoch,
            },
            fence: Fence::LocalDurable,
        }
    }
}

pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::invalid_path("path must not be empty"));
    }
    if !path.starts_with('/') {
        return Err(Error::invalid_path("path must be absolute"));
    }
    if path.contains('\0') {
        return Err(Error::invalid_path("path must not contain NUL"));
    }
    if path.split('/').any(|part| part == "..") {
        return Err(Error::invalid_path(
            "path must not contain parent traversal",
        ));
    }
    Ok(())
}
