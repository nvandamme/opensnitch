use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::mpsc::{self as std_mpsc, Receiver as StdReceiver, SyncSender as StdSyncSender},
    num::NonZeroUsize,
    sync::{Arc, Mutex, RwLock},
    thread,
};

use tokio::sync::{RwLock as AsyncRwLock, mpsc};

const TOUCH_QUEUE_CAPACITY: usize = 4096;
const TOUCH_BATCH_MAX: usize = 256;

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

                let mut cache = mutable.write().await;
                for key in batch {
                    let _ = cache.get_by(&key);
                }
            }
        });
    }

    async fn publish_from_mutable(&self) {
        let next_snapshot = {
            let cache = self.mutable.read().await;
            Arc::new(HashMap::<K, V>::from_iter(cache.snapshot_entries()))
        };

        let mut snapshot_guard = self
            .snapshot
            .write()
            .expect("dual-layer snapshot write lock poisoned");
        *snapshot_guard = next_snapshot;
    }

    pub(crate) async fn insert(&self, key: K, value: V) {
        {
            let mut cache = self.mutable.write().await;
            cache.insert(key, value);
        }
        self.publish_from_mutable().await;
    }

    pub(crate) async fn insert_many<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (K, V)>,
    {
        {
            let mut cache = self.mutable.write().await;
            for (key, value) in entries {
                cache.insert(key, value);
            }
        }
        self.publish_from_mutable().await;
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
            self.publish_from_mutable().await;
        }
        removed
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn clear(&self) {
        {
            let mut cache = self.mutable.write().await;
            cache.clear();
        }
        self.publish_from_mutable().await;
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
            let _ = self.touch_tx.try_send(key.clone());
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

                let mut cache = mutable.write().expect("dual-layer mutable write lock poisoned");
                for key in batch {
                    let _ = cache.get_by(&key);
                }
            }
        });
    }

    fn publish_from_mutable(&self) {
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
    }

    pub(crate) fn insert(&self, key: K, value: V) {
        {
            let mut cache = self
                .mutable
                .write()
                .expect("dual-layer mutable write lock poisoned");
            cache.insert(key, value);
        }
        self.publish_from_mutable();
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn insert_many<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (K, V)>,
    {
        {
            let mut cache = self
                .mutable
                .write()
                .expect("dual-layer mutable write lock poisoned");
            for (key, value) in entries {
                cache.insert(key, value);
            }
        }
        self.publish_from_mutable();
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
            self.publish_from_mutable();
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
        self.publish_from_mutable();
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
            let _ = self.touch_tx.try_send(key.clone());
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
}
