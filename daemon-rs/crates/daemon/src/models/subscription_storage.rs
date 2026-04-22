use serde::{Deserialize, Serialize};

/// Mirror of `pb::Subscription` for JSON persistence.
// Storage-facing subscription record model used by the optional subscriptions runtime.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct SubscriptionRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub interval_seconds: u32,
    #[serde(default)]
    pub timeout_seconds: u32,
    #[serde(default)]
    pub max_bytes: u64,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub last_updated: String,
    #[serde(default)]
    pub last_error: String,
    #[serde(default)]
    pub etag: String,
    #[serde(default)]
    pub last_modified: String,
    #[serde(default)]
    pub next_refresh_after: i64,
    #[serde(default)]
    pub consecutive_failures: u32,
}

// Storage-facing subscription document model used by the optional subscriptions runtime.
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct SubscriptionStorageDocument {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub subscriptions: Vec<SubscriptionRecord>,
}
