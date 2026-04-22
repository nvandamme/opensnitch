use std::{
    path::PathBuf,
    sync::Arc,
};

use dashmap::DashMap;

use opensnitch_proto::pb;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};

use super::defaults::{DEFAULT_ROOT_DIR, DEFAULT_STORE_FILE};
use super::reply::base_reply;
use crate::services::subscription::storage::SubscriptionStorage;

/// Orchestrates subscription list management: list, apply, delete, refresh, deploy.
///
/// - `list`    — return current subscriptions from storage.
/// - `apply`   — upsert subscriptions into storage and sync the rule-list layout.
/// - `delete`  — remove subscriptions from storage and sync the rule-list layout.
/// - `refresh` — download or validate list content for each subscription, persisting
///               HTTP cache validators and retry schedule metadata.
/// - `deploy`  — sync the current rule-list layout without downloading.
#[derive(Clone)]
pub struct SubscriptionService {
    pub(super) storage: Arc<SubscriptionStorage>,
    pub(super) root_dir: PathBuf,
    pub(super) http: reqwest::Client,
    /// Per-subscription async mutex prevents two concurrent refreshes of the same entry.
    pub(super) locks: Arc<DashMap<String, Arc<AsyncMutex<()>>>>,
}

impl SubscriptionService {
    pub fn new(storage: Arc<SubscriptionStorage>, root_dir: impl Into<PathBuf>) -> Self {
        let http = reqwest::Client::builder()
            .http1_only()
            .no_proxy()
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            storage,
            root_dir: root_dir.into(),
            http,
            locks: Arc::new(DashMap::new()),
        }
    }

    /// Create a service backed by the canonical system paths.
    /// Falls back to an in-memory store when the store file cannot be loaded.
    pub fn with_system_defaults() -> Self {
        let storage = SubscriptionStorage::new(DEFAULT_STORE_FILE).unwrap_or_else(|err| {
            warn!("subscription storage unavailable at {DEFAULT_STORE_FILE}: {err}; using in-memory store");
            SubscriptionStorage::in_memory()
        });
        debug!(
            root_dir = DEFAULT_ROOT_DIR,
            store = DEFAULT_STORE_FILE,
            "subscription service initialized"
        );
        Self::new(storage, DEFAULT_ROOT_DIR)
    }

    /// Dispatch a proto `SubscriptionRequest` and return the appropriate reply.
    pub async fn handle_request(&self, req: pb::SubscriptionRequest) -> pb::SubscriptionReply {
        let op = pb::SubscriptionOperation::try_from(req.operation)
            .unwrap_or(pb::SubscriptionOperation::Unspecified);
        match op {
            pb::SubscriptionOperation::List => self.handle_list(),
            pb::SubscriptionOperation::Apply => self.handle_apply(req.subscriptions).await,
            pb::SubscriptionOperation::Delete => self.handle_delete(req.subscriptions).await,
            pb::SubscriptionOperation::Refresh => {
                self.handle_refresh(req.subscriptions, req.targets, req.force)
                    .await
            }
            pb::SubscriptionOperation::Deploy => self.handle_deploy().await,
            pb::SubscriptionOperation::Unspecified => {
                base_reply(pb::SubscriptionOperation::Unspecified, "unspecified operation", false)
            }
        }
    }

    pub(super) async fn sync_layout_error(&self) -> Option<String> {
        self.sync_layout().await.err().map(|err| err.to_string())
    }

    pub(super) async fn flush_storage_best_effort(&self) {
        let _ = self.storage.clone().flush_async().await;
    }

    /// Returns `(total, ready, errored)` subscription counts for stats telemetry.
    pub fn counts(&self) -> (u64, u64, u64) {
        self.storage.counts()
    }
}


