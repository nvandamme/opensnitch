use std::{
    collections::{HashMap, VecDeque},
    env,
    hash::Hash,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use opensnitch_proto::pb;
use time::macros::format_description;

use crate::config::StatsConfig;
use crate::models::connection_state::ConnectionAttempt;

const GO_BACKEND_COMPAT_VERSION: &str = "1.9.0";
static DAEMON_VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
const EVENT_TIME_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

#[repr(align(64))]
struct CacheAlignedAtomicU64(AtomicU64);

impl Default for CacheAlignedAtomicU64 {
    fn default() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl CacheAlignedAtomicU64 {
    fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    fn fetch_add(&self, value: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(value, ordering)
    }
}

#[derive(Clone)]
pub struct StatsService {
    inner: Arc<Mutex<StatsInner>>,
    counters: Arc<StatsCounters>,
    fast_allow: Arc<CacheAlignedAtomicU64>,
    fast_deny: Arc<CacheAlignedAtomicU64>,
}

#[derive(Default)]
struct StatsCounters {
    dns_responses: CacheAlignedAtomicU64,
    connections: CacheAlignedAtomicU64,
    ignored: CacheAlignedAtomicU64,
    accepted: CacheAlignedAtomicU64,
    dropped: CacheAlignedAtomicU64,
    rule_hits: CacheAlignedAtomicU64,
    rule_misses: CacheAlignedAtomicU64,
}

impl Default for StatsService {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StatsInner::default())),
            counters: Arc::new(StatsCounters::default()),
            fast_allow: Arc::new(CacheAlignedAtomicU64::default()),
            fast_deny: Arc::new(CacheAlignedAtomicU64::default()),
        }
    }
}

struct StatsInner {
    started_at: Option<Instant>,
    by_proto: LimitedCountersString,
    by_address: LimitedCountersCopy<IpAddr>,
    by_host: LimitedCountersString,
    by_port: LimitedCountersCopy<u16>,
    by_uid: LimitedCountersCopy<u32>,
    by_executable: LimitedCountersString,
    events: VecDeque<pb::Event>,
    max_events: usize,
    max_stats: usize,
    workers: usize,
}

impl Default for StatsInner {
    fn default() -> Self {
        Self {
            started_at: Some(Instant::now()),
            by_proto: LimitedCountersString::default(),
            by_address: LimitedCountersCopy::default(),
            by_host: LimitedCountersString::default(),
            by_port: LimitedCountersCopy::default(),
            by_uid: LimitedCountersCopy::default(),
            by_executable: LimitedCountersString::default(),
            events: VecDeque::new(),
            max_events: 150,
            max_stats: 25,
            workers: 6,
        }
    }
}

impl StatsService {
    fn daemon_version_string() -> &'static str {
        DAEMON_VERSION
            .get_or_init(|| {
                env::var("OPENSNITCH_DAEMON_VERSION")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| GO_BACKEND_COMPAT_VERSION.to_string())
            })
            .as_str()
    }

    #[cfg(test)]
    pub(crate) fn probe_bump_limited_counter(
        map: &mut HashMap<String, u64>,
        key: String,
        max_stats: usize,
    ) {
        let mut counters = LimitedCountersString {
            map: std::mem::take(map),
            min_key: None,
            min_dirty: true,
        };
        counters.bump(&key, max_stats);
        *map = counters.map;
    }

    fn format_event_time(unix_nano: i64) -> String {
        let secs = unix_nano.div_euclid(1_000_000_000);
        let nanos = unix_nano.rem_euclid(1_000_000_000) as u32;
        let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(secs) else {
            return "1970-01-01 00:00:00".to_string();
        };
        let dt = dt.replace_nanosecond(nanos).unwrap_or(dt);

        dt.format(EVENT_TIME_FORMAT)
            .unwrap_or_else(|_| "1970-01-01 00:00:00".to_string())
    }

    fn protocol_name(attempt: &ConnectionAttempt) -> &'static str {
        match attempt.protocol {
            crate::models::connection_state::TransportProtocol::Tcp => "tcp",
            crate::models::connection_state::TransportProtocol::Udp => "udp",
            crate::models::connection_state::TransportProtocol::UdpLite => "udplite",
            crate::models::connection_state::TransportProtocol::Sctp => "sctp",
            crate::models::connection_state::TransportProtocol::Icmp => "icmp",
        }
    }

    fn build_snapshot(&self, inner: &mut StatsInner, rules_count: u64) -> pb::Statistics {
        let events = std::mem::take(&mut inner.events).into_iter().collect();

        pb::Statistics {
            daemon_version: Self::daemon_version_string().to_string(),
            rules: rules_count,
            uptime: inner
                .started_at
                .map(|started| started.elapsed().as_secs())
                .unwrap_or(0),
            dns_responses: self.counters.dns_responses.load(Ordering::Relaxed),
            connections: self.counters.connections.load(Ordering::Relaxed),
            ignored: self.counters.ignored.load(Ordering::Relaxed),
            accepted: self.counters.accepted.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            rule_hits: self.counters.rule_hits.load(Ordering::Relaxed),
            rule_misses: self.counters.rule_misses.load(Ordering::Relaxed),
            by_proto: inner.by_proto.map.clone(),
            by_address: inner
                .by_address
                .map
                .iter()
                .map(|(addr, count)| (addr.to_string(), *count))
                .collect(),
            by_host: inner.by_host.map.clone(),
            by_port: inner
                .by_port
                .map
                .iter()
                .map(|(port, count)| (port.to_string(), *count))
                .collect(),
            by_uid: inner
                .by_uid
                .map
                .iter()
                .map(|(uid, count)| (uid.to_string(), *count))
                .collect(),
            by_executable: inner.by_executable.map.clone(),
            events,
        }
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

    pub fn on_fast_allow(&self) {
        self.fast_allow.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fast_allow_count(&self) -> u64 {
        self.fast_allow.load(Ordering::Relaxed)
    }

    pub fn on_fast_deny(&self) {
        self.fast_deny.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fast_deny_count(&self) -> u64 {
        self.fast_deny.load(Ordering::Relaxed)
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

    pub fn on_dns_resolved(&self) {
        self.counters.dns_responses.fetch_add(1, Ordering::Relaxed);
        self.counters.accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_verdict(&self, allow: bool) {
        if allow {
            self.counters.accepted.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn on_rule_hit(&self) {
        self.counters.rule_hits.fetch_add(1, Ordering::Relaxed);
    }

    // Go parity: when no rule matches and default action is applied, statistics
    // count it as a miss and a dropped connection, regardless of verdict action.
    pub fn on_missed_default_action(&self) {
        self.counters.rule_misses.fetch_add(1, Ordering::Relaxed);
        self.counters.dropped.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub fn on_ignored(&self) {
        self.counters.ignored.fetch_add(1, Ordering::Relaxed);
        self.counters.accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_event(&self, connection: pb::Connection, rule: Option<pb::Rule>) {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        if inner.events.len() >= inner.max_events {
            inner.events.pop_front();
        }

        let unix_nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|now| now.as_nanos().try_into().ok())
            .unwrap_or(i64::MAX);
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

#[derive(Default)]
struct LimitedCountersString {
    map: HashMap<String, u64>,
    min_key: Option<String>,
    min_dirty: bool,
}

impl LimitedCountersString {
    fn bump(&mut self, key: &str, max_stats: usize) {
        if max_stats == 0 {
            return;
        }

        if let Some(value) = self.map.get_mut(key) {
            *value += 1;
            if self.min_key.as_deref() == Some(key) {
                self.min_dirty = true;
            }
            return;
        }

        if self.map.len() >= max_stats {
            self.evict_min();
        }

        let owned = key.to_string();
        self.map.insert(owned.clone(), 1);
        self.min_key = Some(owned);
        self.min_dirty = false;
    }

    fn trim_to_limit(&mut self, max_stats: usize) {
        while self.map.len() > max_stats {
            self.evict_min();
        }
        if self.map.is_empty() {
            self.min_key = None;
            self.min_dirty = false;
        } else {
            self.recompute_min();
        }
    }

    fn evict_min(&mut self) {
        if self.map.is_empty() {
            self.min_key = None;
            self.min_dirty = false;
            return;
        }

        if self
            .min_key
            .as_ref()
            .is_none_or(|key| !self.map.contains_key(key))
            || self.min_dirty
        {
            self.recompute_min();
        }

        if let Some(min_key) = self.min_key.take() {
            self.map.remove(&min_key);
        }
        self.min_dirty = true;
    }

    fn recompute_min(&mut self) {
        if let Some((key, _count)) = self.map.iter().min_by_key(|(_, count)| *count) {
            self.min_key = Some(key.clone());
            self.min_dirty = false;
        } else {
            self.min_key = None;
            self.min_dirty = false;
        }
    }
}

struct LimitedCountersCopy<K> {
    map: HashMap<K, u64>,
    min_key: Option<K>,
    min_dirty: bool,
}

impl<K> Default for LimitedCountersCopy<K> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            min_key: None,
            min_dirty: false,
        }
    }
}

impl<K> LimitedCountersCopy<K>
where
    K: Copy + Eq + Hash,
{
    fn bump(&mut self, key: K, max_stats: usize) {
        if max_stats == 0 {
            return;
        }

        if let Some(value) = self.map.get_mut(&key) {
            *value += 1;
            if self.min_key == Some(key) {
                self.min_dirty = true;
            }
            return;
        }

        if self.map.len() >= max_stats {
            self.evict_min();
        }

        self.map.insert(key, 1);
        self.min_key = Some(key);
        self.min_dirty = false;
    }

    fn trim_to_limit(&mut self, max_stats: usize) {
        while self.map.len() > max_stats {
            self.evict_min();
        }
        if self.map.is_empty() {
            self.min_key = None;
            self.min_dirty = false;
        } else {
            self.recompute_min();
        }
    }

    fn evict_min(&mut self) {
        if self.map.is_empty() {
            self.min_key = None;
            self.min_dirty = false;
            return;
        }

        if self.min_key.is_none_or(|key| !self.map.contains_key(&key)) || self.min_dirty {
            self.recompute_min();
        }

        if let Some(min_key) = self.min_key.take() {
            self.map.remove(&min_key);
        }
        self.min_dirty = true;
    }

    fn recompute_min(&mut self) {
        if let Some((key, _count)) = self.map.iter().min_by_key(|(_, count)| *count) {
            self.min_key = Some(*key);
            self.min_dirty = false;
        } else {
            self.min_key = None;
            self.min_dirty = false;
        }
    }
}
