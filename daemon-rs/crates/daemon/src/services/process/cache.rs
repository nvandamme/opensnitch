use std::{
    collections::HashMap,
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use quick_cache::Weighter;

use crate::models::process_state::ProcessInfo;
use crate::utils::lru_cache::ConcurrentLruCache;

use super::hash_cache::PersistentHashCache;
use super::ProcessService;

pub(super) struct ProcessCache {
    pub(super) entries: Arc<ConcurrentLruCache<u32, CachedProcessEntry, ProcessInfoWeighter>>,
    pub(super) exit_deadlines: tokio::sync::Mutex<HashMap<u32, Instant>>,
    pub(super) hash_cache: Arc<PersistentHashCache>,
}

impl Default for ProcessCache {
    fn default() -> Self {
        Self::with_hash_cache_path(Self::default_hash_cache_path())
    }
}

impl ProcessCache {
    /// Resolve the default on-disk hash-cache path.
    ///
    /// Placed in `/var/cache/opensnitchd/` for production installs, falling back
    /// to a temp directory when that path is not writable (e.g. dev/test).
    fn default_hash_cache_path() -> std::path::PathBuf {
        use super::hash_cache::HASH_CACHE_FILENAME;
        let prod = std::path::PathBuf::from("/var/cache/opensnitchd");
        if prod.exists() || std::fs::create_dir_all(&prod).is_ok() {
            prod.join(HASH_CACHE_FILENAME)
        } else {
            std::env::temp_dir()
                .join("opensnitchd")
                .join(HASH_CACHE_FILENAME)
        }
    }

    pub(super) fn with_hash_cache_path(path: std::path::PathBuf) -> Self {
        let capacity = PROCESS_INFO_CACHE_CAPACITY.load(Ordering::Relaxed).max(1);
        let weight_capacity = capacity as u64 * ProcessInfoWeighter::ESTIMATED_BYTES_PER_ENTRY;
        Self {
            entries: Arc::new(ConcurrentLruCache::with_weighter(
                weight_capacity,
                capacity,
                ProcessInfoWeighter,
            )),
            exit_deadlines: tokio::sync::Mutex::new(HashMap::new()),
            hash_cache: Arc::new(PersistentHashCache::load_or_new(path)),
        }
    }
}

#[derive(Clone)]
pub(super) struct CachedProcessEntry {
    pub(super) info: ProcessInfo,
    pub(super) starttime: Option<u64>,
}

/// Assigns a byte-approximate weight to each [`CachedProcessEntry`].
///
/// `ProcessInfo` contains variable-length heap allocations (env map, args,
/// parent chain) whose sizes vary by several orders of magnitude across
/// process types.  Using unit weighting would let a few processes with large
/// environment maps fill the entire memory budget.  This weighter uses O(1)
/// `.len()` calls (no iteration) to estimate the heap footprint:
///
/// - `env_map.len() * 64` — approx. 32 B key + 32 B value per env var
/// - `args.len() * 48`    — approx. 48 B per argument string
/// - `parent_chain.len() * 64` — approx. 64 B per parent node
/// - `path.len()`         — exact byte count for the executable path
/// - `+ 512`              — fixed base for struct overhead and misc fields
///
/// The result is an order-of-magnitude byte estimate — sufficient to prevent
/// memory budget blow-up without requiring expensive heap introspection.
#[derive(Clone, Copy, Default)]
pub(super) struct ProcessInfoWeighter;

impl ProcessInfoWeighter {
    /// Multiplier used to convert the item-count `PROCESS_INFO_CACHE_CAPACITY`
    /// into a byte budget for [`ConcurrentLruCache::with_weighter`].
    pub(super) const ESTIMATED_BYTES_PER_ENTRY: u64 = 4_096;
}

impl Weighter<u32, CachedProcessEntry> for ProcessInfoWeighter {
    fn weight(&self, _key: &u32, val: &CachedProcessEntry) -> u64 {
        let info = &val.info;
        let base: u64 = 512;
        let env_weight: u64 = info.env_map.len() as u64 * 64;
        let args_weight: u64 = info.args.len() as u64 * 48;
        let chain_weight: u64 = info.parent_chain.len() as u64 * 64;
        // Minimum weight of 1 — zero-weight entries skip eviction entirely.
        (base + info.path.len() as u64 + args_weight + env_weight + chain_weight).max(1)
    }
}

pub(super) const EXIT_CACHE_TTL: Duration = Duration::from_secs(2);
pub(super) const EXIT_CACHE_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const fn default_process_info_cache_capacity() -> usize {
    if cfg!(test) {
        8_192
    } else {
        131_072
    }
}

const DEFAULT_PROCESS_INFO_CACHE_CAPACITY: usize = default_process_info_cache_capacity();
pub(super) static PROCESS_INFO_CACHE_CAPACITY: AtomicUsize =
    AtomicUsize::new(DEFAULT_PROCESS_INFO_CACHE_CAPACITY);

impl ProcessService {
    pub(crate) fn configure_cache_capacity(capacity: usize) {
        PROCESS_INFO_CACHE_CAPACITY.store(capacity.max(1), Ordering::Relaxed);
    }

    pub async fn cleanup_expired(&self) {
        self.cache.cleanup_expired().await;
    }

    pub fn spawn_cleanup_task(&self, shutdown: CancellationToken) -> JoinHandle<()> {
        self.spawn_cleanup_task_with_interval(shutdown, EXIT_CACHE_CLEANUP_INTERVAL)
    }

    /// Spawn the background task that periodically flushes the persistent hash
    /// cache to disk and garbage-collects stale entries.
    pub fn spawn_hash_cache_flush_task(&self, shutdown: CancellationToken) -> JoinHandle<()> {
        use super::hash_cache::{HASH_CACHE_FLUSH_INTERVAL, HASH_CACHE_GC_INTERVAL};
        self.cache.hash_cache.spawn_flush_task(
            shutdown,
            HASH_CACHE_FLUSH_INTERVAL,
            HASH_CACHE_GC_INTERVAL,
        )
    }

    pub(crate) fn spawn_cleanup_task_with_interval(
        &self,
        shutdown: CancellationToken,
        interval: Duration,
    ) -> JoinHandle<()> {
        let service = self.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = ticker.tick() => service.cleanup_expired().await,
                }
            }
        })
    }
}

impl ProcessCache {
    pub(super) async fn cleanup_expired(&self) {
        tracing::debug!(
            "[cache] deleting old events, total byPID: {}",
            self.entries.len()
        );
        let now = Instant::now();
        let expired = {
            let mut deadlines = self.exit_deadlines.lock().await;
            let expired = deadlines
                .iter()
                .filter_map(|(pid, deadline)| (*deadline <= now).then_some(*pid))
                .collect::<Vec<_>>();
            for pid in &expired {
                deadlines.remove(pid);
            }
            expired
        };

        let entries = Arc::clone(&self.entries);
        for pid in expired {
            let _ = entries.remove_by(&pid);
        }
    }

    pub(super) async fn mark_exit_deadline(&self, pid: u32, deadline: Instant) {
        self.exit_deadlines.lock().await.insert(pid, deadline);
    }

    pub(super) async fn clear_exit_deadline(&self, pid: u32) {
        self.exit_deadlines.lock().await.remove(&pid);
    }

    pub(super) async fn exit_deadline(&self, pid: u32) -> Option<Instant> {
        self.exit_deadlines.lock().await.get(&pid).copied()
    }
}
