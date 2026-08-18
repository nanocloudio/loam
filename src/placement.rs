use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeClass {
    Rp,
    Pi5,
    Host,
    Rack,
    Hyperscale,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageRole {
    Namespace,
    ObjectData,
    BlockData,
    Cache,
    Control,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlacementPlan {
    pub node_class: NodeClass,
    pub roles: Vec<StorageRole>,
    pub colocate_metadata_and_data: bool,
}

impl PlacementPlan {
    pub fn single_node(node_class: NodeClass, role: StorageRole) -> Self {
        Self {
            node_class,
            roles: vec![role],
            colocate_metadata_and_data: true,
        }
    }

    pub fn micro_datacenter() -> Self {
        Self {
            node_class: NodeClass::Pi5,
            roles: vec![
                StorageRole::Namespace,
                StorageRole::ObjectData,
                StorageRole::BlockData,
                StorageRole::Cache,
            ],
            colocate_metadata_and_data: false,
        }
    }
}
