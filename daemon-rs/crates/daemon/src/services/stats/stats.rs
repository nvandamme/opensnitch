use std::sync::{Arc, Mutex, atomic::Ordering};

use transport_wire_core::{WireConnection, WireRule, WireSubscriptionStatistics};

use super::internal::{
    BreakdownCounters, CacheAlignedAtomicU64, EventsState, STATS_EVENT_RING_CAPACITY,
    StatsCounters, StatsEvent,
};
use crate::config::StatsConfig;
use crate::models::connection::state::ConnectionAttempt;
use crate::models::metrics::snapshot::MetricsSnapshot;
pub(crate) use crate::models::storage::event_counters::StorageEventCounters;
use crate::utils::time_nonce::unix_epoch_nanos;

#[derive(Clone)]
pub struct StatsService {
    pub(super) breakdown: Arc<Mutex<BreakdownCounters>>,
    pub(super) events_state: Arc<Mutex<EventsState>>,
    pub(super) counters: Arc<StatsCounters>,
    pub(super) fast_allow: Arc<CacheAlignedAtomicU64>,
    pub(super) fast_deny: Arc<CacheAlignedAtomicU64>,
    pub(super) sub_stats: Arc<Mutex<Option<WireSubscriptionStatistics>>>,
}

impl Default for StatsService {
    fn default() -> Self {
        Self {
            breakdown: Arc::new(Mutex::new(BreakdownCounters::default())),
            events_state: Arc::new(Mutex::new(EventsState::default())),
            counters: Arc::new(StatsCounters::default()),
            fast_allow: Arc::new(CacheAlignedAtomicU64::default()),
            fast_deny: Arc::new(CacheAlignedAtomicU64::default()),
            sub_stats: Arc::new(Mutex::new(None)),
        }
    }
}

impl StatsService {
    pub(crate) fn configure_event_ring_capacity(capacity: usize) {
        STATS_EVENT_RING_CAPACITY.store(capacity.max(1), Ordering::Relaxed);
    }

    /// Replace the subscription statistics block; reflected in the next metrics export.
    pub fn update_subscription_stats(&self, stats: WireSubscriptionStatistics) {
        *self
            .sub_stats
            .lock()
            .expect("subscription stats mutex poisoned") = Some(stats);
    }

    pub fn apply_config(&self, config: StatsConfig) {
        // Lock ordering: events_state before breakdown (matches snapshot).
        let mut ev = self
            .events_state
            .lock()
            .expect("stats events mutex poisoned");
        let mut bd = self
            .breakdown
            .lock()
            .expect("stats breakdown mutex poisoned");
        if config.max_events > 0 {
            let cap = STATS_EVENT_RING_CAPACITY.load(Ordering::Relaxed).max(1);
            let max_events = config.max_events.min(cap).max(1);
            ev.max_events = max_events;
            ev.events.set_capacity(max_events);
        }
        if config.workers > 0 {
            ev.workers = config.workers;
        }
        if config.max_stats > 0 {
            bd.max_stats = config.max_stats;
        }
        let max_stats = bd.max_stats;
        ev.events.trim_to_capacity();
        bd.by_proto.trim_to_limit(max_stats);
        bd.by_address.trim_to_limit(max_stats);
        bd.by_host.trim_to_limit(max_stats);
        bd.by_port.trim_to_limit(max_stats);
        bd.by_uid.trim_to_limit(max_stats);
        bd.by_executable.trim_to_limit(max_stats);
        bd.by_rule.trim_to_limit(max_stats);
    }

    pub fn on_connect_attempt(&self, attempt: &ConnectionAttempt) {
        self.counters.connections.fetch_add(1, Ordering::Relaxed);
        let mut bd = self
            .breakdown
            .lock()
            .expect("stats breakdown mutex poisoned");
        let max_stats = bd.max_stats;
        bd.by_proto.bump(Self::protocol_name(attempt), max_stats);
        bd.by_address.bump(attempt.dst_addr, max_stats);
        bd.by_port.bump(attempt.dst_port, max_stats);
        bd.by_uid.bump(attempt.uid, max_stats);
    }

    pub fn on_connection_metadata(&self, executable: &str, dst_host: Option<&str>) {
        let mut bd = self
            .breakdown
            .lock()
            .expect("stats breakdown mutex poisoned");
        let max_stats = bd.max_stats;
        bd.by_executable.bump(executable, max_stats);
        if let Some(host) = dst_host
            && !host.is_empty()
        {
            bd.by_host.bump(host, max_stats);
        }
    }

    pub fn on_event(&self, connection: Arc<WireConnection>, rule: Option<Arc<WireRule>>) {
        let unix_nano = i64::try_from(unix_epoch_nanos()).unwrap_or(i64::MAX);
        let event = StatsEvent {
            time: Self::format_event_time(unix_nano),
            connection: Some(connection),
            rule,
            unixnano: unix_nano,
        };
        let mut ev = match self.events_state.try_lock() {
            Ok(ev) => ev,
            Err(std::sync::TryLockError::WouldBlock) => {
                self.counters
                    .dropped_events_contention
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.counters
                    .dropped_events_contention
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        ev.events.push_overwrite(event);
    }
    // Retained for optional diagnostics surfaces that expose stats queue contention.
    #[allow(dead_code)]
    pub fn dropped_events_contention_count(&self) -> u64 {
        self.counters
            .dropped_events_contention
            .load(Ordering::Relaxed)
    }

    pub fn snapshot(&self, rules_count: u64) -> MetricsSnapshot {
        // Lock ordering: events_state before breakdown.
        let mut ev = self
            .events_state
            .lock()
            .expect("stats events mutex poisoned");
        let mut bd = self
            .breakdown
            .lock()
            .expect("stats breakdown mutex poisoned");
        self.build_snapshot(&mut bd, &mut ev, rules_count)
    }

    pub fn snapshot_if_pending(&self, rules_count: u64) -> Option<MetricsSnapshot> {
        // Lock ordering: events_state before breakdown.
        let mut ev = self
            .events_state
            .lock()
            .expect("stats events mutex poisoned");
        if ev.events.is_empty() {
            return None;
        }
        let mut bd = self
            .breakdown
            .lock()
            .expect("stats breakdown mutex poisoned");
        Some(self.build_snapshot(&mut bd, &mut ev, rules_count))
    }
}
