use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use opensnitch_proto::pb;

use super::{SubscriptionRecord, proto_to_record, record_to_proto};
use crate::models::subscription_storage::SubscriptionStorageDocument;
use crate::services::storage::StorageService;
use crate::utils::atomic_write::sibling_temp_path_with_suffix;
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
            let doc: SubscriptionStorageDocument = serde_json::from_str(&data).unwrap_or_default();
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

    pub fn list(&self) -> Vec<pb::Subscription> {
        let inner = self.inner.lock().expect("subscription storage poisoned");
        let mut out: Vec<_> = inner.items.values().map(record_to_proto).collect();
        sort_by_string_key(&mut out, |item| item.id.as_str());
        out
    }

    pub fn apply(&self, items: Vec<pb::Subscription>) -> Vec<pb::Subscription> {
        let mut inner = self.inner.lock().expect("subscription storage poisoned");
        for item in &items {
            let mut record = proto_to_record(item);
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
        let mut out: Vec<_> = inner.items.values().map(record_to_proto).collect();
        sort_by_string_key(&mut out, |item| item.id.as_str());
        out
    }

    pub(crate) fn list_records(&self) -> Vec<SubscriptionRecord> {
        let inner = self.inner.lock().expect("subscription storage poisoned");
        let mut out: Vec<_> = inner.items.values().cloned().collect();
        sort_by_string_key(&mut out, |item| item.id.as_str());
        out
    }

    pub(crate) fn put_record(&self, record: SubscriptionRecord) -> pb::Subscription {
        let mut inner = self.inner.lock().expect("subscription storage poisoned");
        let proto = record_to_proto(&record);
        inner.items.insert(record.id.clone(), record);
        inner.dirty = true;
        proto
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
        let data = serde_json::to_string_pretty(&doc).context("serializing subscription store")?;

        let temp_path = sibling_temp_path_with_suffix(&self.path, ".tmp");

        StorageService::global().write_bytes_atomic_sync_and_notify(
            "subscription",
            &temp_path,
            &self.path,
            data.as_bytes(),
        )?;

        inner.dirty = false;
        Ok(())
    }

    pub async fn flush_async(self: Arc<Self>) -> Result<()> {
        tokio::task::spawn_blocking(move || self.flush())
            .await
            .context("joining subscription storage flush task")?
    }

    /// Returns `(total, ready, errored)` subscription counts.
    pub fn counts(&self) -> (u64, u64, u64) {
        let inner = self.inner.lock().expect("subscription storage poisoned");
        let mut total = 0u64;
        let mut ready = 0u64;
        let mut errored = 0u64;
        for record in inner.items.values() {
            total += 1;
            match record.status.as_str() {
                "ready" => ready += 1,
                "error" => errored += 1,
                _ => {}
            }
        }
        (total, ready, errored)
    }
}
