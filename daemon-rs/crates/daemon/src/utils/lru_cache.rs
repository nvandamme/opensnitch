use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::atomic::{AtomicU64, Ordering},
    sync::mpsc::{self as std_mpsc, Receiver as StdReceiver, SyncSender as StdSyncSender},
    num::NonZeroUsize,
    sync::{Arc, Mutex, OnceLock, RwLock},
    thread,
    time::Instant,
};

use tokio::sync::{RwLock as AsyncRwLock, mpsc};

const TOUCH_QUEUE_CAPACITY: usize = 4096;
const TOUCH_BATCH_MAX: usize = 256;
const INSERT_MANY_INCREMENTAL_MAX: usize = 64;

#[derive(Default)]
struct DualLayerMetrics {
    touch_enqueued: AtomicU64,
    touch_dropped: AtomicU64,
    touch_reconciled_batches: AtomicU64,
    touch_reconciled_keys: AtomicU64,
    publish_full: AtomicU64,
    publish_incremental: AtomicU64,
    publish_reconcile_scans: AtomicU64,
    publish_reconcile_removed: AtomicU64,
    publish_total_ns: AtomicU64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct DualLayerMetricsSnapshot {
    pub(crate) touch_enqueued: u64,
    pub(crate) touch_dropped: u64,
    pub(crate) touch_reconciled_batches: u64,
    pub(crate) touch_reconciled_keys: u64,
    pub(crate) publish_full: u64,
    pub(crate) publish_incremental: u64,
    pub(crate) publish_reconcile_scans: u64,
    pub(crate) publish_reconcile_removed: u64,
    pub(crate) publish_total_ns: u64,
}

impl DualLayerMetrics {
    fn global() -> &'static DualLayerMetrics {
        static GLOBAL_METRICS: OnceLock<DualLayerMetrics> = OnceLock::new();
        GLOBAL_METRICS.get_or_init(DualLayerMetrics::default)
    }

    fn snapshot(&self) -> DualLayerMetricsSnapshot {
        DualLayerMetricsSnapshot {
            touch_enqueued: self.touch_enqueued.load(Ordering::Relaxed),
            touch_dropped: self.touch_dropped.load(Ordering::Relaxed),
            touch_reconciled_batches: self.touch_reconciled_batches.load(Ordering::Relaxed),
            touch_reconciled_keys: self.touch_reconciled_keys.load(Ordering::Relaxed),
            publish_full: self.publish_full.load(Ordering::Relaxed),
            publish_incremental: self.publish_incremental.load(Ordering::Relaxed),
            publish_reconcile_scans: self.publish_reconcile_scans.load(Ordering::Relaxed),
            publish_reconcile_removed: self.publish_reconcile_removed.load(Ordering::Relaxed),
            publish_total_ns: self.publish_total_ns.load(Ordering::Relaxed),
        }
    }
}

pub(crate) fn global_dual_layer_metrics_snapshot() -> DualLayerMetricsSnapshot {
    DualLayerMetrics::global().snapshot()
}

impl DualLayerMetricsSnapshot {
    pub(crate) fn saturating_delta(self, previous: Self) -> Self {
        Self {
            touch_enqueued: self.touch_enqueued.saturating_sub(previous.touch_enqueued),
            touch_dropped: self.touch_dropped.saturating_sub(previous.touch_dropped),
            touch_reconciled_batches: self
                .touch_reconciled_batches
                .saturating_sub(previous.touch_reconciled_batches),
            touch_reconciled_keys: self
                .touch_reconciled_keys
                .saturating_sub(previous.touch_reconciled_keys),
            publish_full: self.publish_full.saturating_sub(previous.publish_full),
            publish_incremental: self
                .publish_incremental
                .saturating_sub(previous.publish_incremental),
            publish_reconcile_scans: self
                .publish_reconcile_scans
                .saturating_sub(previous.publish_reconcile_scans),
            publish_reconcile_removed: self
                .publish_reconcile_removed
                .saturating_sub(previous.publish_reconcile_removed),
            publish_total_ns: self.publish_total_ns.saturating_sub(previous.publish_total_ns),
        }
    }

    pub(crate) fn total(&self) -> u64 {
        self.publish_full
            + self.publish_incremental
            + self.touch_enqueued
            + self.touch_dropped
            + self.touch_reconciled_keys
    }
}

fn elapsed_ns(start: Instant) -> u64 {
    let nanos = start.elapsed().as_nanos();
    nanos.min(u128::from(u64::MAX)) as u64
}

pub(crate) struct LruCache<K, V>
where
    K: Eq + Hash + Clone,
{
    entries: lru::LruCache<K, V>,
}

impl<K, V> LruCache<K, V>
where
    K: Eq + Hash + Clone,
{
    pub(crate) fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("non-zero capacity");
        Self {
            entries: lru::LruCache::new(cap),
        }
    }

    pub(crate) fn insert(&mut self, key: K, value: V) {
        self.entries.put(key, value);
    }

    pub(crate) fn set_capacity(&mut self, capacity: usize) {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("non-zero capacity");
        self.entries.resize(cap);
    }

    pub(crate) fn remove_by<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.entries.pop(key)
    }

    pub(crate) fn get_by<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.entries.get(key)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn peek_by<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.entries.peek(key)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    fn capacity(&self) -> usize {
        self.entries.cap().get()
    }

    pub(crate) fn snapshot_entries(&self) -> Vec<(K, V)>
    where
        V: Clone,
    {
        self.entries
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
}

pub(crate) struct DualLayerLruMap<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    mutable: Arc<AsyncRwLock<LruCache<K, V>>>,
    snapshot: Arc<RwLock<Arc<HashMap<K, V>>>>,
    touch_tx: mpsc::Sender<K>,
    touch_rx: Arc<RwLock<Option<mpsc::Receiver<K>>>>,
    touch_reconciler_started: Arc<RwLock<bool>>,
    metrics: Arc<DualLayerMetrics>,
}

impl<K, V> DualLayerLruMap<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub(crate) fn new(capacity: usize) -> Self {
        let (touch_tx, touch_rx) = mpsc::channel(TOUCH_QUEUE_CAPACITY);
        Self {
            mutable: Arc::new(AsyncRwLock::new(LruCache::new(capacity))),
            snapshot: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
            touch_tx,
            touch_rx: Arc::new(RwLock::new(Some(touch_rx))),
            touch_reconciler_started: Arc::new(RwLock::new(false)),
            metrics: Arc::new(DualLayerMetrics::default()),
        }
    }

    fn try_start_touch_reconciler(&self) {
        let mut started_guard = self
            .touch_reconciler_started
            .write()
            .expect("touch reconciler state lock poisoned");
        if *started_guard {
            return;
        }

        let Ok(_runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };

        let mut rx_guard = self
            .touch_rx
            .write()
            .expect("touch receiver state lock poisoned");
        let Some(mut rx) = rx_guard.take() else {
            return;
        };

        *started_guard = true;
        drop(started_guard);
        drop(rx_guard);

        let mutable = Arc::clone(&self.mutable);
        let metrics = Arc::clone(&self.metrics);
        tokio::spawn(async move {
            while let Some(first_key) = rx.recv().await {
                let mut batch = HashSet::new();
                batch.insert(first_key);
                while batch.len() < TOUCH_BATCH_MAX {
                    match rx.try_recv() {
                        Ok(key) => {
                            batch.insert(key);
                        }
                        Err(_) => break,
                    }
                }

                metrics
                    .touch_reconciled_batches
                    .fetch_add(1, Ordering::Relaxed);
                DualLayerMetrics::global()
                    .touch_reconciled_batches
                    .fetch_add(1, Ordering::Relaxed);
                metrics
                    .touch_reconciled_keys
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                DualLayerMetrics::global()
                    .touch_reconciled_keys
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);

                let mut cache = mutable.write().await;
                for key in batch {
                    let _ = cache.get_by(&key);
                }
            }
        });
    }

    fn publish_incremental_update<F>(&self, updater: F)
    where
        F: FnOnce(&mut HashMap<K, V>),
    {
        let start = Instant::now();
        let mut snapshot_guard = self
            .snapshot
            .write()
            .expect("dual-layer snapshot write lock poisoned");
        let mut next_snapshot = Arc::clone(&snapshot_guard);
        updater(Arc::make_mut(&mut next_snapshot));
        *snapshot_guard = next_snapshot;
        self.metrics
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
    }

    async fn publish_incremental_insert(&self, key: K, value: V, reconcile_with_mutable: bool) {
        let start = Instant::now();
        let mutable_guard = if reconcile_with_mutable {
            Some(self.mutable.read().await)
        } else {
            None
        };

        let mut snapshot_guard = self
            .snapshot
            .write()
            .expect("dual-layer snapshot write lock poisoned");
        let mut next_snapshot = Arc::clone(&snapshot_guard);
        let map = Arc::make_mut(&mut next_snapshot);
        map.insert(key, value);

        if let Some(cache) = mutable_guard.as_ref() {
            self.metrics
                .publish_reconcile_scans
                .fetch_add(1, Ordering::Relaxed);
            DualLayerMetrics::global()
                .publish_reconcile_scans
                .fetch_add(1, Ordering::Relaxed);
            let before = map.len();
            map.retain(|snapshot_key, _| cache.peek_by(snapshot_key).is_some());
            let removed = before.saturating_sub(map.len()) as u64;
            self.metrics
                .publish_reconcile_removed
                .fetch_add(removed, Ordering::Relaxed);
            DualLayerMetrics::global()
                .publish_reconcile_removed
                .fetch_add(removed, Ordering::Relaxed);
        }

        *snapshot_guard = next_snapshot;
        self.metrics
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
    }

    async fn publish_incremental_insert_many(
        &self,
        entries: Vec<(K, V)>,
        reconcile_with_mutable: bool,
    ) {
        let start = Instant::now();
        let mutable_guard = if reconcile_with_mutable {
            Some(self.mutable.read().await)
        } else {
            None
        };

        let mut snapshot_guard = self
            .snapshot
            .write()
            .expect("dual-layer snapshot write lock poisoned");
        let mut next_snapshot = Arc::clone(&snapshot_guard);
        let map = Arc::make_mut(&mut next_snapshot);
        for (key, value) in entries {
            map.insert(key, value);
        }

        if let Some(cache) = mutable_guard.as_ref() {
            self.metrics
                .publish_reconcile_scans
                .fetch_add(1, Ordering::Relaxed);
            DualLayerMetrics::global()
                .publish_reconcile_scans
                .fetch_add(1, Ordering::Relaxed);
            let before = map.len();
            map.retain(|snapshot_key, _| cache.peek_by(snapshot_key).is_some());
            let removed = before.saturating_sub(map.len()) as u64;
            self.metrics
                .publish_reconcile_removed
                .fetch_add(removed, Ordering::Relaxed);
            DualLayerMetrics::global()
                .publish_reconcile_removed
                .fetch_add(removed, Ordering::Relaxed);
        }

        *snapshot_guard = next_snapshot;
        self.metrics
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
    }

    async fn publish_from_mutable(&self) {
        let start = Instant::now();
        let next_snapshot = {
            let cache = self.mutable.read().await;
            Arc::new(HashMap::<K, V>::from_iter(cache.snapshot_entries()))
        };

        let mut snapshot_guard = self
            .snapshot
            .write()
            .expect("dual-layer snapshot write lock poisoned");
        *snapshot_guard = next_snapshot;
        self.metrics.publish_full.fetch_add(1, Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_full
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
    }

    pub(crate) async fn insert(&self, key: K, value: V) {
        let (inserted_key, inserted_value, reconcile_with_mutable) = {
            let mut cache = self.mutable.write().await;
            let len_before = cache.len();
            let capacity = cache.capacity();
            let existed_before = cache.peek_by(&key).is_some();
            cache.insert(key.clone(), value.clone());
            (
                key,
                value,
                !existed_before && len_before >= capacity,
            )
        };

        self.publish_incremental_insert(inserted_key, inserted_value, reconcile_with_mutable)
            .await;
    }

    pub(crate) async fn insert_many<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (K, V)>,
    {
        let entries: Vec<(K, V)> = entries.into_iter().collect();
        if entries.is_empty() {
            return;
        }

        if entries.len() > INSERT_MANY_INCREMENTAL_MAX {
            let mut cache = self.mutable.write().await;
            for (key, value) in entries {
                cache.insert(key, value);
            }
            drop(cache);
            self.publish_from_mutable().await;
            return;
        }

        let (reconcile_with_mutable, snapshot_entries) = {
            let mut cache = self.mutable.write().await;
            let len_before = cache.len();
            let capacity = cache.capacity();
            let unique_keys: HashSet<K> = entries.iter().map(|(key, _)| key.clone()).collect();
            let existing_count = unique_keys
                .iter()
                .filter(|key| cache.peek_by(*key).is_some())
                .count();
            for (key, value) in entries {
                cache.insert(key.clone(), value.clone());
            }

            let new_unique = unique_keys.len().saturating_sub(existing_count);
            let reconcile_with_mutable = len_before.saturating_add(new_unique) > capacity;
            let snapshot_entries: Vec<(K, V)> = cache
                .snapshot_entries()
                .into_iter()
                .filter(|(key, _)| unique_keys.contains(key))
                .collect();
            (reconcile_with_mutable, snapshot_entries)
        };

        self.publish_incremental_insert_many(snapshot_entries, reconcile_with_mutable)
            .await;
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn set_capacity(&self, capacity: usize) {
        {
            let mut cache = self.mutable.write().await;
            cache.set_capacity(capacity);
        }
        self.publish_from_mutable().await;
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn remove_by<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let removed = {
            let mut cache = self.mutable.write().await;
            cache.remove_by(key)
        };
        if removed.is_some() {
            self.publish_incremental_update(|snapshot| {
                let _ = snapshot.remove(key);
            });
        }
        removed
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn clear(&self) {
        {
            let mut cache = self.mutable.write().await;
            cache.clear();
        }
        self.publish_incremental_update(|snapshot| snapshot.clear());
    }

    pub(crate) fn get_snapshot(&self) -> Arc<HashMap<K, V>> {
        let guard = self
            .snapshot
            .read()
            .expect("dual-layer snapshot read lock poisoned");
        Arc::clone(&guard)
    }

    pub(crate) fn get(&self, key: &K) -> Option<V> {
        let value = self.get_snapshot().get(key).cloned();
        if value.is_some() {
            self.try_start_touch_reconciler();
            match self.touch_tx.try_send(key.clone()) {
                Ok(_) => {
                    self.metrics.touch_enqueued.fetch_add(1, Ordering::Relaxed);
                    DualLayerMetrics::global()
                        .touch_enqueued
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    self.metrics.touch_dropped.fetch_add(1, Ordering::Relaxed);
                    DualLayerMetrics::global()
                        .touch_dropped
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        value
    }

    pub(crate) fn peek(&self, key: &K) -> Option<V> {
        self.get_snapshot().get(key).cloned()
    }

    pub(crate) fn len(&self) -> usize {
        self.get_snapshot().len()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn len_mutable(&self) -> usize {
        self.mutable.read().await.len()
    }

    #[allow(dead_code)]
    pub(crate) fn metrics_snapshot(&self) -> DualLayerMetricsSnapshot {
        self.metrics.snapshot()
    }
}

pub(crate) struct SyncDualLayerLruMap<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    mutable: Arc<RwLock<LruCache<K, V>>>,
    snapshot: Arc<RwLock<Arc<HashMap<K, V>>>>,
    touch_tx: StdSyncSender<K>,
    touch_rx: Arc<Mutex<Option<StdReceiver<K>>>>,
    touch_reconciler_started: Arc<RwLock<bool>>,
    metrics: Arc<DualLayerMetrics>,
}

impl<K, V> SyncDualLayerLruMap<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub(crate) fn new(capacity: usize) -> Self {
        let (touch_tx, touch_rx) = std_mpsc::sync_channel(TOUCH_QUEUE_CAPACITY);
        Self {
            mutable: Arc::new(RwLock::new(LruCache::new(capacity))),
            snapshot: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
            touch_tx,
            touch_rx: Arc::new(Mutex::new(Some(touch_rx))),
            touch_reconciler_started: Arc::new(RwLock::new(false)),
            metrics: Arc::new(DualLayerMetrics::default()),
        }
    }

    fn try_start_touch_reconciler(&self) {
        let mut started_guard = self
            .touch_reconciler_started
            .write()
            .expect("touch reconciler state lock poisoned");
        if *started_guard {
            return;
        }

        let mut rx_guard = self
            .touch_rx
            .lock()
            .expect("touch receiver state lock poisoned");
        let Some(rx) = rx_guard.take() else {
            return;
        };

        *started_guard = true;
        drop(started_guard);
        drop(rx_guard);

        let mutable = Arc::clone(&self.mutable);
        let metrics = Arc::clone(&self.metrics);
        thread::spawn(move || {
            while let Ok(first_key) = rx.recv() {
                let mut batch = HashSet::new();
                batch.insert(first_key);
                while batch.len() < TOUCH_BATCH_MAX {
                    match rx.try_recv() {
                        Ok(key) => {
                            batch.insert(key);
                        }
                        Err(_) => break,
                    }
                }

                metrics
                    .touch_reconciled_batches
                    .fetch_add(1, Ordering::Relaxed);
                DualLayerMetrics::global()
                    .touch_reconciled_batches
                    .fetch_add(1, Ordering::Relaxed);
                metrics
                    .touch_reconciled_keys
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                DualLayerMetrics::global()
                    .touch_reconciled_keys
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);

                let mut cache = mutable.write().expect("dual-layer mutable write lock poisoned");
                for key in batch {
                    let _ = cache.get_by(&key);
                }
            }
        });
    }

    fn publish_incremental_update<F>(&self, updater: F)
    where
        F: FnOnce(&mut HashMap<K, V>),
    {
        let start = Instant::now();
        let mut snapshot_guard = self
            .snapshot
            .write()
            .expect("dual-layer snapshot write lock poisoned");
        let mut next_snapshot = Arc::clone(&snapshot_guard);
        updater(Arc::make_mut(&mut next_snapshot));
        *snapshot_guard = next_snapshot;
        self.metrics
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
    }

    fn publish_incremental_insert(&self, key: K, value: V, reconcile_with_mutable: bool) {
        let start = Instant::now();
        let mutable_guard = if reconcile_with_mutable {
            Some(
                self.mutable
                    .read()
                    .expect("dual-layer mutable read lock poisoned"),
            )
        } else {
            None
        };

        let mut snapshot_guard = self
            .snapshot
            .write()
            .expect("dual-layer snapshot write lock poisoned");
        let mut next_snapshot = Arc::clone(&snapshot_guard);
        let map = Arc::make_mut(&mut next_snapshot);
        map.insert(key, value);

        if let Some(cache) = mutable_guard.as_ref() {
            self.metrics
                .publish_reconcile_scans
                .fetch_add(1, Ordering::Relaxed);
            DualLayerMetrics::global()
                .publish_reconcile_scans
                .fetch_add(1, Ordering::Relaxed);
            let before = map.len();
            map.retain(|snapshot_key, _| cache.peek_by(snapshot_key).is_some());
            let removed = before.saturating_sub(map.len()) as u64;
            self.metrics
                .publish_reconcile_removed
                .fetch_add(removed, Ordering::Relaxed);
            DualLayerMetrics::global()
                .publish_reconcile_removed
                .fetch_add(removed, Ordering::Relaxed);
        }

        *snapshot_guard = next_snapshot;
        self.metrics
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
    }

    fn publish_incremental_insert_many(&self, entries: Vec<(K, V)>, reconcile_with_mutable: bool) {
        let start = Instant::now();
        let mutable_guard = if reconcile_with_mutable {
            Some(
                self.mutable
                    .read()
                    .expect("dual-layer mutable read lock poisoned"),
            )
        } else {
            None
        };

        let mut snapshot_guard = self
            .snapshot
            .write()
            .expect("dual-layer snapshot write lock poisoned");
        let mut next_snapshot = Arc::clone(&snapshot_guard);
        let map = Arc::make_mut(&mut next_snapshot);
        for (key, value) in entries {
            map.insert(key, value);
        }

        if let Some(cache) = mutable_guard.as_ref() {
            self.metrics
                .publish_reconcile_scans
                .fetch_add(1, Ordering::Relaxed);
            DualLayerMetrics::global()
                .publish_reconcile_scans
                .fetch_add(1, Ordering::Relaxed);
            let before = map.len();
            map.retain(|snapshot_key, _| cache.peek_by(snapshot_key).is_some());
            let removed = before.saturating_sub(map.len()) as u64;
            self.metrics
                .publish_reconcile_removed
                .fetch_add(removed, Ordering::Relaxed);
            DualLayerMetrics::global()
                .publish_reconcile_removed
                .fetch_add(removed, Ordering::Relaxed);
        }

        *snapshot_guard = next_snapshot;
        self.metrics
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_incremental
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
    }

    fn publish_from_mutable(&self) {
        let start = Instant::now();
        let next_snapshot = {
            let cache = self
                .mutable
                .read()
                .expect("dual-layer mutable read lock poisoned");
            Arc::new(HashMap::<K, V>::from_iter(cache.snapshot_entries()))
        };

        let mut snapshot_guard = self
            .snapshot
            .write()
            .expect("dual-layer snapshot write lock poisoned");
        *snapshot_guard = next_snapshot;
        self.metrics.publish_full.fetch_add(1, Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_full
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
        DualLayerMetrics::global()
            .publish_total_ns
            .fetch_add(elapsed_ns(start), Ordering::Relaxed);
    }

    pub(crate) fn insert(&self, key: K, value: V) {
        let (inserted_key, inserted_value, reconcile_with_mutable) = {
            let mut cache = self
                .mutable
                .write()
                .expect("dual-layer mutable write lock poisoned");
            let len_before = cache.len();
            let capacity = cache.capacity();
            let existed_before = cache.peek_by(&key).is_some();
            cache.insert(key.clone(), value.clone());
            (
                key,
                value,
                !existed_before && len_before >= capacity,
            )
        };
        self.publish_incremental_insert(inserted_key, inserted_value, reconcile_with_mutable);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn insert_many<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (K, V)>,
    {
        let entries: Vec<(K, V)> = entries.into_iter().collect();
        if entries.is_empty() {
            return;
        }

        if entries.len() > INSERT_MANY_INCREMENTAL_MAX {
            let mut cache = self
                .mutable
                .write()
                .expect("dual-layer mutable write lock poisoned");
            for (key, value) in entries {
                cache.insert(key, value);
            }
            drop(cache);
            self.publish_from_mutable();
            return;
        }

        let (reconcile_with_mutable, snapshot_entries) = {
            let mut cache = self
                .mutable
                .write()
                .expect("dual-layer mutable write lock poisoned");
            let len_before = cache.len();
            let capacity = cache.capacity();
            let unique_keys: HashSet<K> = entries.iter().map(|(key, _)| key.clone()).collect();
            let existing_count = unique_keys
                .iter()
                .filter(|key| cache.peek_by(*key).is_some())
                .count();
            for (key, value) in entries {
                cache.insert(key.clone(), value.clone());
            }

            let new_unique = unique_keys.len().saturating_sub(existing_count);
            let reconcile_with_mutable = len_before.saturating_add(new_unique) > capacity;
            let snapshot_entries: Vec<(K, V)> = cache
                .snapshot_entries()
                .into_iter()
                .filter(|(key, _)| unique_keys.contains(key))
                .collect();
            (reconcile_with_mutable, snapshot_entries)
        };

        self.publish_incremental_insert_many(snapshot_entries, reconcile_with_mutable);
    }

    pub(crate) fn set_capacity(&self, capacity: usize) {
        {
            let mut cache = self
                .mutable
                .write()
                .expect("dual-layer mutable write lock poisoned");
            cache.set_capacity(capacity);
        }
        self.publish_from_mutable();
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn remove_by<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let removed = {
            let mut cache = self
                .mutable
                .write()
                .expect("dual-layer mutable write lock poisoned");
            cache.remove_by(key)
        };
        if removed.is_some() {
            self.publish_incremental_update(|snapshot| {
                let _ = snapshot.remove(key);
            });
        }
        removed
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn clear(&self) {
        {
            let mut cache = self
                .mutable
                .write()
                .expect("dual-layer mutable write lock poisoned");
            cache.clear();
        }
        self.publish_incremental_update(|snapshot| snapshot.clear());
    }

    pub(crate) fn get_snapshot(&self) -> Arc<HashMap<K, V>> {
        let guard = self
            .snapshot
            .read()
            .expect("dual-layer snapshot read lock poisoned");
        Arc::clone(&guard)
    }

    pub(crate) fn get(&self, key: &K) -> Option<V> {
        let value = self.get_snapshot().get(key).cloned();
        if value.is_some() {
            self.try_start_touch_reconciler();
            match self.touch_tx.try_send(key.clone()) {
                Ok(_) => {
                    self.metrics.touch_enqueued.fetch_add(1, Ordering::Relaxed);
                    DualLayerMetrics::global()
                        .touch_enqueued
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    self.metrics.touch_dropped.fetch_add(1, Ordering::Relaxed);
                    DualLayerMetrics::global()
                        .touch_dropped
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        value
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn peek(&self, key: &K) -> Option<V> {
        self.get_snapshot().get(key).cloned()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn len(&self) -> usize {
        self.get_snapshot().len()
    }

    #[allow(dead_code)]
    pub(crate) fn metrics_snapshot(&self) -> DualLayerMetricsSnapshot {
        self.metrics.snapshot()
    }
}
