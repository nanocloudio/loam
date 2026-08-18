use crate::core::config::Config;
use crate::placement::{NodeClass, PlacementPlan, StorageRole};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePlan {
    pub node_id: String,
    pub placement: PlacementPlan,
}

impl RuntimePlan {
    pub fn from_config(config: &Config) -> Self {
        Self {
            node_id: config.storage.node_id.clone(),
            placement: PlacementPlan::single_node(NodeClass::Host, StorageRole::All),
        }
    }
}
