use crate::core::error::{Error, Result};
use crate::fluxor_contracts::{ClustorFenceWitness, Fence, StorageHandle, StorageSurface};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ObjectId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectDescriptor {
    pub id: ObjectId,
    pub namespace: String,
    pub key: String,
    pub size_bytes: u64,
    pub content_hash: String,
    pub placement: ObjectPlacement,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectPlacement {
    pub data_class: DataClass,
    pub replica_count: u8,
    pub erasure: Option<ErasureProfile>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Local,
    Replicated,
    ErasureCoded,
    RemoteCached,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErasureProfile {
    pub data_shards: u8,
    pub parity_shards: u8,
}

impl ObjectPlacement {
    pub fn replicated(replica_count: u8) -> Self {
        Self {
            data_class: DataClass::Replicated,
            replica_count,
            erasure: None,
        }
    }
}

/// Returned by `object_index` when a caller writes (puts) an object.
/// The `fence` reflects what the underlying graph actually achieved —
/// never a stronger guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectWrite {
    pub handle: StorageHandle,
    pub object_id: ObjectId,
    pub fence: Fence,
}

impl ObjectWrite {
    pub fn replicated(
        object_id: ObjectId,
        mesh_handle_id: u64,
        lease_epoch: u64,
        witness: ClustorFenceWitness,
    ) -> Result<Self> {
        if witness.is_empty() {
            return Err(Error::invalid_fence(
                "ReplicatedDurable object write requires a non-empty Clustor witness",
            ));
        }
        let fence_epoch = witness.fence_epoch;
        let quorum = witness.quorum;
        Ok(Self {
            handle: StorageHandle {
                surface: StorageSurface::Object,
                content_type: StorageSurface::Object.content_type(),
                mesh_handle_id,
                lease_epoch,
            },
            object_id,
            fence: Fence::ReplicatedDurable {
                quorum,
                epoch: fence_epoch,
                witness,
            },
        })
    }

    pub fn local(object_id: ObjectId, mesh_handle_id: u64, lease_epoch: u64) -> Self {
        Self {
            handle: StorageHandle {
                surface: StorageSurface::Object,
                content_type: StorageSurface::Object.content_type(),
                mesh_handle_id,
                lease_epoch,
            },
            object_id,
            fence: Fence::LocalDurable,
        }
    }
}
