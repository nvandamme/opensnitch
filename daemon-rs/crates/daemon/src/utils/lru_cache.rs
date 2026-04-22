//! Thread-safe LRU-approximate cache backed by [`quick_cache::sync::Cache`].
//!
//! # Design
//!
//! The previous dual-layer design existed to work around `lru::LruCache` being
//! single-threaded.  `quick_cache::sync::Cache` is natively thread-safe (sharded
//! internally), so the dual-layer (mutable + snapshot) and the touch-reconciler
//! background task are no longer needed.
//!
//! # Eviction policy
//!
//! `quick_cache` v0.6 uses a **hot/cold frequency-aware** eviction algorithm.
//! Items enter the Hot queue when the hot budget allows, otherwise the Cold queue.
//! Cold items that have been accessed (referenced > 0) are promoted to Hot on the
//! next eviction scan; unreferenced Cold items are evicted.  Hit rates are
//! typically equal to or better than strict LRU in production workloads.
//!
//! **Note**: exact LRU eviction order is not guaranteed.  In particular, items
//! inserted early (while the Hot queue is filling) tend to persist even under
//! sustained insert pressure, because Hot-list eviction only runs when the Cold
//! list is empty.  Write-only workloads may not evict the first-inserted items.
//!
//! # Strategy extension points
//!
//! [`quick_cache`] exposes two optional extension traits for finer-grained
//! eviction control:
//!
//! - [`quick_cache::Weighter`]: assign per-entry weights so the cache budgets
//!   by bytes (or another domain unit) rather than item count.  **Currently
//!   used** for the process-info cache via `ProcessInfoWeighter`: process
//!   entries carry variable-length `env_map` and `args` allocations, and
//!   unit-weighted capacity would allow a small number of large processes to
//!   exhaust the memory budget.  DNS and connection caches use the default
//!   [`UnitWeighter`] because their value types have bounded, uniform sizes.
//!
//! - [`quick_cache::Lifecycle`]: hook `on_evict` / `before_evict` / `is_pinned`
//!   for TTL enforcement, side-effect callbacks on eviction, or pinning hot
//!   entries that must not be displaced.  Use `before_evict` to zero the weight
//!   and retain an item (effectively moving it to the zero-weight free list).

use std::{
    borrow::Borrow,
    hash::Hash,
    sync::{Arc, OnceLock},
    sync::atomic::{AtomicU64, Ordering},
};

use quick_cache::{
    DefaultHashBuilder, OptionsBuilder, UnitWeighter, Weighter,
    sync::{Cache, DefaultLifecycle},
};

// ---------------------------------------------------------------------------
// Global hit / miss metrics
// ---------------------------------------------------------------------------

#[derive(Default)]
struct GlobalLruMetrics {
    hits: AtomicU64,
    misses: AtomicU64,
}

impl GlobalLruMetrics {
    fn global() -> &'static GlobalLruMetrics {
        static GLOBAL: OnceLock<GlobalLruMetrics> = OnceLock::new();
        GLOBAL.get_or_init(GlobalLruMetrics::default)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DualLayerMetricsSnapshot {
    pub(crate) hits: u64,
    pub(crate) misses: u64,
}

impl DualLayerMetricsSnapshot {
    pub(crate) fn saturating_delta(self, previous: Self) -> Self {
        Self {
            hits: self.hits.saturating_sub(previous.hits),
            misses: self.misses.saturating_sub(previous.misses),
        }
    }

    pub(crate) fn total(&self) -> u64 {
        self.hits + self.misses
    }
}

pub(crate) fn global_dual_layer_metrics_snapshot() -> DualLayerMetricsSnapshot {
    let m = GlobalLruMetrics::global();
    DualLayerMetricsSnapshot {
        hits: m.hits.load(Ordering::Relaxed),
        misses: m.misses.load(Ordering::Relaxed),
    }
}

// ---------------------------------------------------------------------------
// ConcurrentLruCache
// ---------------------------------------------------------------------------

/// Thread-safe concurrent cache.
///
/// Wraps [`quick_cache::sync::Cache`] behind an `Arc` so instances can be
/// cheaply cloned and shared across threads.
///
/// The default weighter is [`UnitWeighter`] (each entry has weight 1, so
/// `capacity` is an item count).  Pass a custom [`Weighter`] with
/// [`ConcurrentLruCache::with_weighter`] to budget by bytes or other domain
/// units instead.
pub(crate) struct ConcurrentLruCache<K, V, W = UnitWeighter>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    W: Weighter<K, V> + Clone + Send + Sync + 'static,
{
    inner: Arc<Cache<K, V, W, DefaultHashBuilder, DefaultLifecycle<K, V>>>,
}

impl<K, V, W> Clone for ConcurrentLruCache<K, V, W>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    W: Weighter<K, V> + Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Constructor for the default unit-weighted variant (`capacity` = item count).
impl<K, V> ConcurrentLruCache<K, V, UnitWeighter>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Cache::new(capacity.max(1))),
        }
    }
}

/// Operations and constructors available for any [`Weighter`].
impl<K, V, W> ConcurrentLruCache<K, V, W>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    W: Weighter<K, V> + Clone + Send + Sync + 'static,
{
    /// Create a cache capped by a total **weight budget** (e.g. bytes) rather
    /// than item count.
    ///
    /// - `weight_capacity`: maximum sum of all entry weights before eviction.
    /// - `estimated_items`: expected number of entries (sizes the internal
    ///   ghost-key tracker — an order-of-magnitude estimate is sufficient).
    /// - `weighter`: a [`Weighter`] implementation that returns a `u64` weight
    ///   for each `(key, value)` pair.  Weight must not change after insertion;
    ///   returning `0` keeps the entry in a non-evictable free list.
    pub(crate) fn with_weighter(weight_capacity: u64, estimated_items: usize, weighter: W) -> Self {
        let opts = OptionsBuilder::new()
            .weight_capacity(weight_capacity)
            .estimated_items_capacity(estimated_items)
            .build()
            .expect("valid OptionsBuilder configuration");
        Self {
            inner: Arc::new(Cache::with_options(
                opts,
                weighter,
                DefaultHashBuilder::default(),
                DefaultLifecycle::default(),
            )),
        }
    }

    /// Fetch an entry, updating its recency. Increments global hit / miss counter.
    pub(crate) fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let v = self.inner.get(key);
        let m = GlobalLruMetrics::global();
        if v.is_some() {
            m.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            m.misses.fetch_add(1, Ordering::Relaxed);
        }
        v
    }

    /// Fetch an entry without affecting its recency.
    pub(crate) fn peek<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.peek(key)
    }

    pub(crate) fn insert(&self, key: K, value: V) {
        self.inner.insert(key, value);
    }

    pub(crate) fn insert_many<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (K, V)>,
    {
        for (k, v) in entries {
            self.inner.insert(k, v);
        }
    }

    pub(crate) fn remove_by<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.remove(key).map(|(_, v)| v)
    }

    pub(crate) fn clear(&self) {
        self.inner.clear();
    }

    /// Resize the cache. If the new capacity is smaller than the current
    /// weight, items are evicted immediately to fit.
    pub(crate) fn set_capacity(&self, capacity: usize) {
        self.inner.set_capacity(capacity.max(1) as u64);
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }
}

// ---------------------------------------------------------------------------
// Type aliases for call-site compatibility
// ---------------------------------------------------------------------------

/// Async-flavoured cache alias (previously a separate type; now identical to
/// [`SyncDualLayerLruMap`] since all operations are lock-free).
pub(crate) type DualLayerLruMap<K, V> = ConcurrentLruCache<K, V>;

/// Sync-flavoured cache alias.
pub(crate) type SyncDualLayerLruMap<K, V> = ConcurrentLruCache<K, V>;


