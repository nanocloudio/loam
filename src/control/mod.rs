use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tenant {
    pub tenant_id: String,
    pub namespace_prefix: String,
    pub max_objects: u64,
    pub max_volume_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingEpoch {
    pub epoch: u64,
    pub source: String,
}

impl RoutingEpoch {
    pub fn initial(source: impl Into<String>) -> Self {
        Self {
            epoch: 1,
            source: source.into(),
        }
    }
}
