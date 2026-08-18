#![allow(dead_code, reason = "shared #[path]-included surface; each includer uses a subset")]

pub type NamespaceRevision = u64;
pub type ObjectRevision = u64;
pub type VolumeRevision = u64;
pub type TenantId = u32;
pub type ShardId = u32;
pub type RoutingEpoch = u64;

pub const SURFACE_NAMESPACE: u8 = 1;
pub const SURFACE_OBJECT: u8 = 2;
pub const SURFACE_BLOCK: u8 = 3;
pub const SURFACE_CACHE: u8 = 4;

pub const FENCE_ACCEPTED: u8 = 0;
pub const FENCE_WRITEBACK: u8 = 1;
pub const FENCE_LOCAL_DURABLE: u8 = 2;
pub const FENCE_REPLICATED_DURABLE: u8 = 3;

