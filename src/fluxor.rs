use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FluxorTarget {
    Linux,
    Wasm,
    Pi5,
    Bcm2712,
    Rp2350,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FluxorGraphProfile {
    LoamLinuxMinimal,
    LoamPi5Storage,
    LoamRackStorage,
    LoamBrowserCache,
}

impl FluxorTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Wasm => "wasm",
            Self::Pi5 => "pi5",
            Self::Bcm2712 => "bcm2712",
            Self::Rp2350 => "rp2350",
        }
    }

    pub fn supports_profile(&self, profile: &FluxorGraphProfile) -> bool {
        match (self, profile) {
            (Self::Linux, FluxorGraphProfile::LoamLinuxMinimal) => true,
            (Self::Linux, FluxorGraphProfile::LoamRackStorage) => true,
            (Self::Pi5, FluxorGraphProfile::LoamPi5Storage) => true,
            (Self::Bcm2712, FluxorGraphProfile::LoamPi5Storage) => true,
            (Self::Wasm, FluxorGraphProfile::LoamBrowserCache) => true,
            (Self::Rp2350, FluxorGraphProfile::LoamBrowserCache) => false,
            _ => false,
        }
    }
}

impl FluxorGraphProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LoamLinuxMinimal => "loam-linux-minimal",
            Self::LoamPi5Storage => "loam-pi5-storage",
            Self::LoamRackStorage => "loam-rack-storage",
            Self::LoamBrowserCache => "loam-browser-cache",
        }
    }
}
