use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockVolume {
    pub volume_id: String,
    pub class: BlockClass,
    pub logical_bytes: u64,
    pub block_size: u32,
    pub thin_provisioned: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockClass {
    Local,
    ThinProvisioned,
    Replicated,
    ChainReplicated,
    Snapshot,
}

impl BlockVolume {
    pub fn logical_block_count(&self) -> u64 {
        self.logical_bytes / u64::from(self.block_size)
    }
}
