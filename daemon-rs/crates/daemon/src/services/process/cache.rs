use std::{
    collections::HashMap,
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::models::process_state::ProcessInfo;
use crate::utils::lru_cache::DualLayerLruMap;

use super::ProcessService;

pub(super) struct ProcessCache {
    pub(super) entries: Arc<DualLayerLruMap<u32, CachedProcessEntry>>,
    pub(super) exit_deadlines: tokio::sync::Mutex<HashMap<u32, Instant>>,
}

impl Default for ProcessCache {
    fn default() -> Self {
        let capacity = PROCESS_INFO_CACHE_CAPACITY.load(Ordering::Relaxed).max(1);
        Self {
            entries: Arc::new(DualLayerLruMap::new(capacity)),
            exit_deadlines: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
}

#[derive(Clone)]
pub(super) struct CachedProcessEntry {
    pub(super) info: ProcessInfo,
    pub(super) starttime: Option<u64>,
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
            let _ = entries.remove_by(&pid).await;
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
