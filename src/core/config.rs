use crate::core::error::{Error, Result};
use crate::fluxor::{FluxorGraphProfile, FluxorTarget};
use crate::storage::AchievableFence;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub control_plane: ControlPlaneConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub paths: PathConfig,
    pub fluxor: FluxorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneConfig {
    #[serde(default = "default_cp_mode")]
    pub mode: String,
    #[serde(default = "default_http_bind")]
    pub embedded_http_bind: String,
    #[serde(default = "default_raft_bind")]
    pub embedded_raft_bind: String,
    #[serde(default = "default_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageConfig {
    pub node_id: String,
    pub default_fence: AchievableFence,
    pub namespace_shards: u32,
    pub object_shards: u32,
    pub block_volume_count: u32,
    pub max_object_bytes: u64,
    pub max_volume_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FluxorConfig {
    pub target: FluxorTarget,
    pub module_profile: FluxorGraphProfile,
    #[serde(default = "default_true")]
    pub validate_graphs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathConfig {
    pub data_dir: PathBuf,
    pub wal_dir: PathBuf,
    pub object_dir: PathBuf,
    pub block_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("data"),
            wal_dir: PathBuf::from("data/wal"),
            object_dir: PathBuf::from("data/objects"),
            block_dir: PathBuf::from("data/blocks"),
            cache_dir: PathBuf::from("data/cache"),
        }
    }
}

impl Config {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path).map_err(|err| {
            Error::invalid_config(format!("failed to read {}: {err}", path.display()))
        })?;
        let config = toml::from_str::<Self>(&data).map_err(|err| {
            Error::invalid_config(format!("failed to parse {}: {err}", path.display()))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.control_plane.mode != "embedded" && self.control_plane.mode != "external" {
            return Err(Error::invalid_config(
                "control_plane.mode must be embedded or external",
            ));
        }
        if self.storage.node_id.trim().is_empty() {
            return Err(Error::invalid_config("storage.node_id must not be empty"));
        }
        if self.storage.namespace_shards == 0 {
            return Err(Error::invalid_config(
                "storage.namespace_shards must be greater than zero",
            ));
        }
        if self.storage.object_shards == 0 {
            return Err(Error::invalid_config(
                "storage.object_shards must be greater than zero",
            ));
        }
        if self.storage.block_volume_count == 0 {
            return Err(Error::invalid_config(
                "storage.block_volume_count must be greater than zero",
            ));
        }
        if self.storage.max_object_bytes == 0 {
            return Err(Error::invalid_config(
                "storage.max_object_bytes must be greater than zero",
            ));
        }
        if self.storage.max_volume_bytes == 0 {
            return Err(Error::invalid_config(
                "storage.max_volume_bytes must be greater than zero",
            ));
        }
        if self.fluxor.validate_graphs
            && !self
                .fluxor
                .target
                .supports_profile(&self.fluxor.module_profile)
        {
            return Err(Error::UnsupportedTarget(format!(
                "target {} does not support module profile {}",
                self.fluxor.target.as_str(),
                self.fluxor.module_profile.as_str()
            )));
        }
        Ok(())
    }
}

fn default_cp_mode() -> String {
    "embedded".to_string()
}

fn default_http_bind() -> String {
    "127.0.0.1:19100".to_string()
}

fn default_raft_bind() -> String {
    "127.0.0.1:19101".to_string()
}

fn default_cache_ttl_seconds() -> u64 {
    5
}

fn default_true() -> bool {
    true
}
