use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthReport {
    pub ready: bool,
    pub node_id: String,
    pub reasons: Vec<String>,
}

impl HealthReport {
    pub fn ready(node_id: impl Into<String>) -> Self {
        Self {
            ready: true,
            node_id: node_id.into(),
            reasons: Vec::new(),
        }
    }

    pub fn blocked(node_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            ready: false,
            node_id: node_id.into(),
            reasons: vec![reason.into()],
        }
    }
}
