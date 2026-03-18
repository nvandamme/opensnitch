use std::{
    collections::HashMap,
    env,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use opensnitch_proto::pb;

use crate::config::StatsConfig;
use crate::models::connection_state::ConnectionAttempt;

const GO_BACKEND_COMPAT_VERSION: &str = "1.9.0";
static DAEMON_VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();

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

#[derive(Clone)]
pub struct StatsService {
    inner: Arc<Mutex<StatsInner>>,
    counters: Arc<StatsCounters>,
    fast_allow: Arc<AtomicU64>,
    fast_deny: Arc<AtomicU64>,
}

#[derive(Default)]
struct StatsCounters {
    dns_responses: AtomicU64,
    connections: AtomicU64,
    ignored: AtomicU64,
    accepted: AtomicU64,
    dropped: AtomicU64,
    rule_hits: AtomicU64,
    rule_misses: AtomicU64,
}

impl Default for StatsService {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StatsInner::default())),
            counters: Arc::new(StatsCounters::default()),
            fast_allow: Arc::new(AtomicU64::new(0)),
            fast_deny: Arc::new(AtomicU64::new(0)),
        }
    }
}

struct StatsInner {
    started_at: Option<Instant>,
    by_proto: HashMap<String, u64>,
    by_address: HashMap<String, u64>,
    by_host: HashMap<String, u64>,
    by_port: HashMap<String, u64>,
    by_uid: HashMap<String, u64>,
    by_executable: HashMap<String, u64>,
    events: Vec<pb::Event>,
    max_events: usize,
    max_stats: usize,
    workers: usize,
}

pub(crate) trait StatsCounterMapExt {
    fn bump_limited_counter(&mut self, key: String, max_stats: usize);
    fn trim_to_limit(&mut self, max_stats: usize);
}

impl StatsCounterMapExt for HashMap<String, u64> {
    fn bump_limited_counter(&mut self, key: String, max_stats: usize) {
        if let Some(value) = self.get_mut(&key) {
            *value += 1;
            return;
        }

        if self.len() >= max_stats
            && let Some(min_key) = self
                .iter()
                .min_by_key(|(_, count)| *count)
                .map(|(existing_key, _)| existing_key.clone())
        {
            self.remove(&min_key);
        }

        self.insert(key, 1);
    }

    fn trim_to_limit(&mut self, max_stats: usize) {
        while self.len() > max_stats {
            let Some(min_key) = self
                .iter()
                .min_by_key(|(_, count)| *count)
                .map(|(existing_key, _)| existing_key.clone())
            else {
                break;
            };
            self.remove(&min_key);
        }
    }
}

trait EventTimeExt {
    fn format_event_time(self) -> String;
}

impl EventTimeExt for i64 {
    fn format_event_time(self) -> String {
        let secs = self.div_euclid(1_000_000_000);
        let nanos = self.rem_euclid(1_000_000_000) as u32;
        let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(secs) else {
            return "1970-01-01 00:00:00".to_string();
        };
        let dt = dt.replace_nanosecond(nanos).unwrap_or(dt);

        let Ok(format) =
            time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second]")
        else {
            return "1970-01-01 00:00:00".to_string();
        };

        dt.format(&format)
            .unwrap_or_else(|_| "1970-01-01 00:00:00".to_string())
    }
}

trait ConnectionAttemptStatsExt {
    fn protocol_name(&self) -> &'static str;
}

impl ConnectionAttemptStatsExt for ConnectionAttempt {
    fn protocol_name(&self) -> &'static str {
        match self.protocol {
            crate::models::connection_state::TransportProtocol::Tcp => "tcp",
            crate::models::connection_state::TransportProtocol::Udp => "udp",
            crate::models::connection_state::TransportProtocol::UdpLite => "udplite",
            crate::models::connection_state::TransportProtocol::Sctp => "sctp",
            crate::models::connection_state::TransportProtocol::Icmp => "icmp",
        }
    }
}

impl Default for StatsInner {
    fn default() -> Self {
        Self {
            started_at: Some(Instant::now()),
            by_proto: HashMap::new(),
            by_address: HashMap::new(),
            by_host: HashMap::new(),
            by_port: HashMap::new(),
            by_uid: HashMap::new(),
            by_executable: HashMap::new(),
            events: Vec::new(),
            max_events: 150,
            max_stats: 25,
            workers: 6,
        }
    }
}

impl StatsService {
    fn build_snapshot(&self, inner: &mut StatsInner, rules_count: u64) -> pb::Statistics {
        let events = std::mem::take(&mut inner.events);

        pb::Statistics {
            daemon_version: daemon_version_string().to_string(),
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
            by_proto: inner.by_proto.clone(),
            by_address: inner.by_address.clone(),
            by_host: inner.by_host.clone(),
            by_port: inner.by_port.clone(),
            by_uid: inner.by_uid.clone(),
            by_executable: inner.by_executable.clone(),
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
            inner.events.remove(0);
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

        inner
            .by_proto
            .bump_limited_counter(attempt.protocol_name().to_string(), max_stats);
        inner
            .by_address
            .bump_limited_counter(attempt.dst_ip.clone(), max_stats);
        inner
            .by_port
            .bump_limited_counter(attempt.dst_port.to_string(), max_stats);
        inner
            .by_uid
            .bump_limited_counter(attempt.uid.to_string(), max_stats);
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
        inner
            .by_executable
            .bump_limited_counter(executable.to_string(), max_stats);
        if let Some(host) = dst_host
            && !host.is_empty()
        {
            inner
                .by_host
                .bump_limited_counter(host.to_string(), max_stats);
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
            inner.events.remove(0);
        }

        let unix_nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|now| now.as_nanos().try_into().ok())
            .unwrap_or(i64::MAX);
        inner.events.push(pb::Event {
            time: unix_nano.format_event_time(),
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
