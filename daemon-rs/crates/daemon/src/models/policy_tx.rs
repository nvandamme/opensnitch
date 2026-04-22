use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PolicyOwner {
    LocalUid(u32),
    UnixAbstractName(String),
    NetworkIdentity(String),
    IpFallback(String),
    System,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TxPhase {
    Planned,
    IntentPersisted,
    Committed,
    RolledBack,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyChangeSet {
    pub tx_id: String,
    pub idempotency_key: String,
    pub owner: PolicyOwner,
    pub expected_revision: Option<u64>,
    pub base_revision: u64,
    pub committed_revision: Option<u64>,
    pub created_at_unix_nano: i64,
    pub phase: TxPhase,
    pub operations: Vec<String>,
    pub outcome: Option<String>,
}
