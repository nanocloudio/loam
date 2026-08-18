use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid namespace path: {0}")]
    InvalidPath(String),
    #[error("invalid storage fence: {0}")]
    InvalidFence(String),
    #[error("unsupported target capability: {0}")]
    UnsupportedTarget(String),
}

impl Error {
    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::InvalidConfig(message.into())
    }

    pub fn invalid_path(message: impl Into<String>) -> Self {
        Self::InvalidPath(message.into())
    }

    pub fn invalid_fence(message: impl Into<String>) -> Self {
        Self::InvalidFence(message.into())
    }
}
