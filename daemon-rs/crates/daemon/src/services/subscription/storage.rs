use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use transport_wire_core::{WireSubscription, WireSubscriptionEvent, WireSubscriptionStatistics};

use super::{SubscriptionRecord, record_from_wire, record_to_wire};
use crate::models::subscription_storage::SubscriptionStorageDocument;
use crate::services::storage::StorageService;
use crate::utils::sort_key::sort_by_string_key;

struct StoreInner {
    items: HashMap<String, SubscriptionRecord>,
    dirty: bool,
}

pub(crate) struct SubscriptionStorage {
    path: PathBuf,
    inner: Mutex<StoreInner>,
}

impl SubscriptionStorage {
    /// Load or create a file-backed store at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Result<Arc<Self>> {
        let path = path.into();
        let storage = StorageService::global();
        let inner = if storage.path_exists_sync("subscription", &path)? {
            let data = storage
                .read_to_string_sync_and_notify("subscription", &path)
                .with_context(|| format!("reading subscription store: {}", path.display()))?;
            let doc: SubscriptionStorageDocument =
                StorageService::parse_with_storage_format_for_path(&path, &data)
                    .unwrap_or_default();
            let items = doc
                .subscriptions
                .into_iter()
                .filter(|r| !r.id.is_empty())
                .map(|r| (r.id.clone(), r))
                .collect();
            StoreInner {
                items,
                dirty: false,
            }
        } else {
            StoreInner {
                items: HashMap::new(),
                dirty: false,
            }
        };
        Ok(Arc::new(Self {
            path,
            inner: Mutex::new(inner),
        }))
    }

    /// Create a fresh in-memory store (tests or fallback when disk is unavailable).
    pub fn in_memory() -> Arc<Self> {
        Arc::new(Self {
            path: PathBuf::new(),
            inner: Mutex::new(StoreInner {
                items: HashMap::new(),
                dirty: false,
            }),
        })
    }
    // Public wire-oriented helpers retained for subscription RPC surfaces.
    #[allow(dead_code)]
    pub fn list(&self) -> Vec<WireSubscription> {
        let inner = self.inner.lock().expect("subscription storage poisoned");
        let mut out: Vec<_> = inner.items.values().cloned().map(record_to_wire).collect();
        sort_by_string_key(&mut out, |item| item.id.as_str());
        out
    }
    // Public wire-oriented helpers retained for subscription RPC surfaces.
    #[allow(dead_code)]
    pub fn apply(&self, items: Vec<WireSubscription>) -> Vec<WireSubscription> {
        let records = items.into_iter().map(record_from_wire).collect();
        self.apply_records(records)
            .into_iter()
            .map(record_to_wire)
            .collect()
    }

    pub(crate) fn apply_records(&self, items: Vec<SubscriptionRecord>) -> Vec<SubscriptionRecord> {
        let mut inner = self.inner.lock().expect("subscription storage poisoned");
        for mut record in items {
            if let Some(existing) = inner.items.get(&record.id)
                && existing.url == record.url
            {
                record.etag = existing.etag.clone();
                record.last_modified = existing.last_modified.clone();
                record.next_refresh_after = existing.next_refresh_after;
                record.consecutive_failures = existing.consecutive_failures;
            }
            inner.items.insert(record.id.clone(), record);
        }
        inner.dirty = true;
        let mut out: Vec<_> = inner.items.values().cloned().collect();
        sort_by_string_key(&mut out, |item| item.id.as_str());
        out
    }

    pub(crate) fn list_records(&self) -> Vec<SubscriptionRecord> {
        let inner = self.inner.lock().expect("subscription storage poisoned");
        let mut out: Vec<_> = inner.items.values().cloned().collect();
        sort_by_string_key(&mut out, |item| item.id.as_str());
        out
    }

    pub(crate) fn put_record(&self, record: SubscriptionRecord) -> SubscriptionRecord {
        let mut inner = self.inner.lock().expect("subscription storage poisoned");
        let out = record.clone();
        inner.items.insert(record.id.clone(), record);
        inner.dirty = true;
        out
    }

    pub fn delete(&self, ids: &[String]) {
        let mut inner = self.inner.lock().expect("subscription storage poisoned");
        for id in ids {
            inner.items.remove(id);
        }
        inner.dirty = true;
    }

    /// Persist dirty state to disk atomically.
    ///
    /// Write sequence:
    ///   1. Serialise state to JSON.
    ///   2. Write + flush + fsync to a sibling temp file (`<path>.tmp`).
    ///   3. `rename` the temp file over the target path (atomic on POSIX).
    ///   4. fsync the parent directory to make the rename durable.
    ///
    /// The temp file is removed on serialisation or I/O error before any
    /// rename attempt, so the existing store file is never truncated.
    pub fn flush(&self) -> Result<()> {
        let mut inner = self.inner.lock().expect("subscription storage poisoned");
        if !inner.dirty || self.path.as_os_str().is_empty() {
            return Ok(());
        }

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                StorageService::global()
                    .create_dir_all_sync_and_notify("subscription", parent)
                    .with_context(|| format!("creating store dir: {}", parent.display()))?;
            }
        }

        let subscriptions: Vec<SubscriptionRecord> = inner.items.values().cloned().collect();
        let doc = SubscriptionStorageDocument {
            version: 1,
            subscriptions,
        };
        StorageService::global().convert_and_write_with_storage_format_to_path_sync_and_notify(
            "subscription",
            &self.path,
            &doc,
            true,
        )?;

        inner.dirty = false;
        Ok(())
    }

    pub async fn flush_async(self: Arc<Self>) -> Result<()> {
        tokio::task::spawn_blocking(move || self.flush())
            .await
            .context("joining subscription storage flush task")?
    }

    /// Returns a wire subscription statistics snapshot for metrics export.
    ///
    /// Computes scalars (total/ready/error) and breakdown maps (by_status,
    /// by_group, by_node) from the current storage state in a single lock pass.
    /// The event log and cumulative counters (refresh_count, refresh_errors)
    /// are supplied by the caller and merged in before returning.
    pub fn subscription_stats(
        &self,
        refresh_count: u64,
        refresh_errors: u64,
        events: Vec<WireSubscriptionEvent>,
    ) -> WireSubscriptionStatistics {
        let inner = self.inner.lock().expect("subscription storage poisoned");
        let mut total = 0u64;
        let mut ready = 0u64;
        let mut error = 0u64;
        let mut by_status: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        let mut by_group: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        let mut by_node: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for record in inner.items.values() {
            total += 1;
            match record.status.as_str() {
                "ready" => ready += 1,
                "error" => error += 1,
                _ => {}
            }
            *by_status.entry(record.status.clone()).or_default() += 1;
            for group in &record.groups {
                *by_group.entry(group.clone()).or_default() += 1;
            }
            if !record.node.is_empty() {
                *by_node.entry(record.node.clone()).or_default() += 1;
            }
        }
        WireSubscriptionStatistics {
            total,
            ready,
            error,
            refresh_count,
            refresh_errors,
            by_status,
            by_group,
            by_node,
            events,
            rule_subscriptions: vec![],
        }
    }
}
