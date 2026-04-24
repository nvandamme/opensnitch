use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use dashmap::DashMap;

use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};
use transport_wire_core::{
    WireRuleSubscriptionEntry, WireSubscription, WireSubscriptionAction, WireSubscriptionEvent,
    WireSubscriptionStatistics,
};

use super::defaults::{DEFAULT_ROOT_DIR, DEFAULT_STORE_FILE};
use crate::models::subscription_storage::SubscriptionRecord;
use crate::services::subscription::storage::SubscriptionStorage;
use crate::utils::http_client::{HttpClient, build_http_client};
use crate::utils::time_nonce::unix_epoch_nanos;

/// Maximum entries kept in the subscription event ring.
const SUB_EVENT_RING_CAPACITY: usize = 64;

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
    pub(super) http: HttpClient,
    /// Per-subscription async mutex prevents two concurrent refreshes of the same entry.
    pub(super) locks: Arc<DashMap<String, Arc<AsyncMutex<()>>>>,
    /// Cumulative successful refresh downloads since daemon start.
    pub(super) refresh_count: Arc<AtomicU64>,
    /// Cumulative refresh errors since daemon start.
    pub(super) refresh_errors: Arc<AtomicU64>,
    /// Most recent subscription lifecycle events (newest-first ring, capacity SUB_EVENT_RING_CAPACITY).
    pub(super) events: Arc<Mutex<Vec<WireSubscriptionEvent>>>,
}

impl SubscriptionService {
    pub fn new(storage: Arc<SubscriptionStorage>, root_dir: impl Into<PathBuf>) -> Self {
        let http = build_http_client();
        Self {
            storage,
            root_dir: root_dir.into(),
            http,
            locks: Arc::new(DashMap::new()),
            refresh_count: Arc::new(AtomicU64::new(0)),
            refresh_errors: Arc::new(AtomicU64::new(0)),
            events: Arc::new(Mutex::new(Vec::with_capacity(SUB_EVENT_RING_CAPACITY))),
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

    pub(super) async fn sync_layout_error(&self) -> Option<String> {
        self.sync_layout().await.err().map(|err| err.to_string())
    }

    pub(super) async fn flush_storage_best_effort(&self) {
        let _ = self.storage.clone().flush_async().await;
    }

    pub(super) fn push_event(&self, sub: WireSubscription, action: WireSubscriptionAction) {
        let unixnano = i64::try_from(unix_epoch_nanos()).unwrap_or(i64::MAX);
        let time = crate::services::stats::StatsService::format_event_time(unixnano);
        let event = WireSubscriptionEvent {
            time,
            subscription: Some(sub),
            action: action as i32,
            unixnano,
        };
        let mut ring = self
            .events
            .lock()
            .expect("subscription events lock poisoned");
        if ring.len() >= SUB_EVENT_RING_CAPACITY {
            let last = ring.len() - 1;
            ring.remove(last);
        }
        ring.insert(0, event);
    }

    /// Returns a wire subscription statistics snapshot for metrics export.
    pub fn subscription_stats(&self) -> WireSubscriptionStatistics {
        let events = self
            .events
            .lock()
            .expect("subscription events lock poisoned")
            .clone();
        self.storage.subscription_stats(
            self.refresh_count.load(Ordering::Relaxed),
            self.refresh_errors.load(Ordering::Relaxed),
            events,
        )
    }

    /// Returns a wire subscription statistics snapshot enriched with the static
    /// `rule_subscriptions` list derived by cross-referencing the supplied list of
    /// (rule_name, operator_data_path) pairs against the subscription-managed
    /// `rules.list.d/` directory tree.
    ///
    /// The relationship is N:N: a rule with multiple `lists.*` operators can reference
    /// different groups, and each group can be populated by multiple subscriptions.
    ///
    /// `list_rule_paths` should come from `RuleService::list_rule_data_paths()`.
    pub fn subscription_stats_with_rules(
        &self,
        list_rule_paths: &[(std::sync::Arc<str>, std::path::PathBuf)],
    ) -> WireSubscriptionStatistics {
        let mut stats = self.subscription_stats();
        stats.rule_subscriptions = self.build_rule_subscription_entries(list_rule_paths);
        stats
    }

    /// Builds a sorted `Vec<WireRuleSubscriptionEntry>` mapping each rule that carries
    /// `lists.*` operators to the subscription(s) whose files those operators reference.
    ///
    /// The mapping is N:N:
    /// - A rule can have multiple list operators pointing to different group directories.
    /// - A group directory can contain symlinks from multiple subscriptions.
    ///
    /// Each group directory is populated (via `layout.rs`) by every enabled subscription
    /// that lists that group name, plus every subscription contributes to `all` and
    /// to its own `sanitize(filename)` group.
    pub fn build_rule_subscription_entries(
        &self,
        list_rule_paths: &[(std::sync::Arc<str>, std::path::PathBuf)],
    ) -> Vec<WireRuleSubscriptionEntry> {
        use crate::utils::name_parsing::sanitize_ascii_name;
        use std::collections::{HashMap, HashSet};

        let rules_list_dir = self.root_dir.join("rules.list.d");

        // Build group_dir_name → Vec<subscription_display_name>.
        // Mirrors the group membership assigned by layout.rs sync_rule_links():
        //   each enabled sub contributes to sanitize(filename), "all", and each explicit group.
        let records = self.storage.list_records();
        let mut group_to_subs: HashMap<String, Vec<String>> = HashMap::new();
        for rec in records.iter().filter(|r| r.enabled) {
            let display = if rec.name.is_empty() {
                rec.filename.clone()
            } else {
                rec.name.clone()
            };
            group_to_subs
                .entry(sanitize_ascii_name(&rec.filename))
                .or_default()
                .push(display.clone());
            group_to_subs
                .entry("all".to_string())
                .or_default()
                .push(display.clone());
            for grp in &rec.groups {
                group_to_subs
                    .entry(sanitize_ascii_name(grp))
                    .or_default()
                    .push(display.clone());
            }
        }

        // Collect the set of subscription names from all list operator paths per rule.
        let mut rule_subs: HashMap<String, HashSet<String>> = HashMap::new();
        for (rule_name, path) in list_rule_paths {
            let Ok(rel) = path.strip_prefix(&rules_list_dir) else {
                continue;
            };
            let group = rel.to_string_lossy();
            if let Some(subs) = group_to_subs.get(group.as_ref()) {
                for s in subs {
                    rule_subs
                        .entry(rule_name.to_string())
                        .or_default()
                        .insert(s.clone());
                }
            }
        }

        // Convert to wire entries sorted by rule name for determinism.
        let mut entries: Vec<WireRuleSubscriptionEntry> = rule_subs
            .into_iter()
            .map(|(rule, subs)| {
                let mut subscriptions: Vec<String> = subs.into_iter().collect();
                subscriptions.sort();
                WireRuleSubscriptionEntry {
                    rule,
                    subscriptions,
                }
            })
            .collect();
        entries.sort_by(|a, b| a.rule.cmp(&b.rule));
        entries
    }

    /// Returns the current subscription records as canonical domain models.
    pub fn list_records(&self) -> Vec<SubscriptionRecord> {
        self.storage.list_records()
    }
}
