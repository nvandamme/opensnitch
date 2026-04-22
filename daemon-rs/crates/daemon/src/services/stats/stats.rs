use std::sync::{Arc, Mutex, atomic::Ordering};

use opensnitch_proto::pb;

use super::internal::{CacheAlignedAtomicU64, StatsCounters, StatsInner};
use crate::config::StatsConfig;
use crate::models::connection_state::ConnectionAttempt;
pub(crate) use crate::models::storage_event_counters::StorageEventCounters;
use crate::utils::time_nonce::unix_epoch_nanos;

#[derive(Clone)]
pub struct StatsService {
    pub(super) inner: Arc<Mutex<StatsInner>>,
    pub(super) counters: Arc<StatsCounters>,
    pub(super) fast_allow: Arc<CacheAlignedAtomicU64>,
    pub(super) fast_deny: Arc<CacheAlignedAtomicU64>,
    pub(super) sub_total: Arc<CacheAlignedAtomicU64>,
    pub(super) sub_ready: Arc<CacheAlignedAtomicU64>,
    pub(super) sub_error: Arc<CacheAlignedAtomicU64>,
}

impl Default for StatsService {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StatsInner::default())),
            counters: Arc::new(StatsCounters::default()),
            fast_allow: Arc::new(CacheAlignedAtomicU64::default()),
            fast_deny: Arc::new(CacheAlignedAtomicU64::default()),
            sub_total: Arc::new(CacheAlignedAtomicU64::default()),
            sub_ready: Arc::new(CacheAlignedAtomicU64::default()),
            sub_error: Arc::new(CacheAlignedAtomicU64::default()),
        }
    }
}

impl StatsService {
    /// Store current subscription counts; reflected in the next snapshot.
    pub fn update_subscription_counts(&self, total: u64, ready: u64, error: u64) {
        self.sub_total.0.store(total, Ordering::Relaxed);
        self.sub_ready.0.store(ready, Ordering::Relaxed);
        self.sub_error.0.store(error, Ordering::Relaxed);
    }

    pub fn apply_config(&self, config: StatsConfig) {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        if config.max_events > 0 {
            inner.max_events = config.max_events;
        }
        if config.max_stats > 0 {
            inner.max_stats = config.max_stats;
        }
        if config.workers > 0 {
            inner.workers = config.workers;
        }
        let max_stats = inner.max_stats;

        while inner.events.len() > inner.max_events {
            inner.events.pop_front();
        }

        inner.by_proto.trim_to_limit(max_stats);
        inner.by_address.trim_to_limit(max_stats);
        inner.by_host.trim_to_limit(max_stats);
        inner.by_port.trim_to_limit(max_stats);
        inner.by_uid.trim_to_limit(max_stats);
        inner.by_executable.trim_to_limit(max_stats);
    }

    pub fn on_connect_attempt(&self, attempt: &ConnectionAttempt) {
        self.counters.connections.fetch_add(1, Ordering::Relaxed);
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        let max_stats = inner.max_stats;

        inner.by_proto.bump(Self::protocol_name(attempt), max_stats);
        inner.by_address.bump(attempt.dst_addr, max_stats);
        inner.by_port.bump(attempt.dst_port, max_stats);
        inner.by_uid.bump(attempt.uid, max_stats);
    }

    pub fn on_connection_metadata(&self, executable: &str, dst_host: Option<&str>) {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        let max_stats = inner.max_stats;
        inner.by_executable.bump(executable, max_stats);
        if let Some(host) = dst_host
            && !host.is_empty()
        {
            inner.by_host.bump(host, max_stats);
        }
    }

    pub fn on_event(&self, connection: pb::Connection, rule: Option<pb::Rule>) {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        if inner.events.len() >= inner.max_events {
            inner.events.pop_front();
        }

        let unix_nano = i64::try_from(unix_epoch_nanos()).unwrap_or(i64::MAX);
        inner.events.push_back(pb::Event {
            time: Self::format_event_time(unix_nano),
            connection: Some(connection),
            rule,
            unixnano: unix_nano,
        });
    }

    pub fn snapshot(&self, rules_count: u64) -> pb::Statistics {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        self.build_snapshot(&mut inner, rules_count)
    }

    pub fn snapshot_if_pending(&self, rules_count: u64) -> Option<pb::Statistics> {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        if inner.events.is_empty() {
            return None;
        }

        Some(self.build_snapshot(&mut inner, rules_count))
    }
}
