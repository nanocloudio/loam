use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClustorBinding {
    pub replica_group: String,
    pub partition: u64,
    pub consistency: ConsistencyMode,
    pub durability_ledger: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyMode {
    LeaderLease,
    ReadIndex,
    QuorumCommit,
}

impl ClustorBinding {
    pub fn namespace(replica_group: impl Into<String>, partition: u64) -> Self {
        Self {
            replica_group: replica_group.into(),
            partition,
            consistency: ConsistencyMode::ReadIndex,
            durability_ledger: "namespace".to_string(),
        }
    }
}
