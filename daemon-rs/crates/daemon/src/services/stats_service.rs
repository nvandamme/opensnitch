use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use opensnitch_proto::pb;

use crate::config::StatsConfig;
use crate::models::connection_state::ConnectionAttempt;

#[derive(Clone)]
pub struct StatsService {
    inner: Arc<Mutex<StatsInner>>,
    daemon_owned_fast_allow: Arc<AtomicU64>,
}

impl Default for StatsService {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StatsInner::default())),
            daemon_owned_fast_allow: Arc::new(AtomicU64::new(0)),
        }
    }
}

struct StatsInner {
    started_at: Option<Instant>,
    dns_responses: u64,
    connections: u64,
    ignored: u64,
    accepted: u64,
    dropped: u64,
    rule_hits: u64,
    rule_misses: u64,
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

trait StatsCounterMapExt {
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
            started_at: None,
            dns_responses: 0,
            connections: 0,
            ignored: 0,
            accepted: 0,
            dropped: 0,
            rule_hits: 0,
            rule_misses: 0,
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
    fn build_snapshot(inner: &mut StatsInner, rules_count: u64) -> pb::Statistics {
        let events = std::mem::take(&mut inner.events);

        pb::Statistics {
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            rules: rules_count,
            uptime: inner
                .started_at
                .map(|started| started.elapsed().as_secs())
                .unwrap_or(0),
            dns_responses: inner.dns_responses,
            connections: inner.connections,
            ignored: inner.ignored,
            accepted: inner.accepted,
            dropped: inner.dropped,
            rule_hits: inner.rule_hits,
            rule_misses: inner.rule_misses,
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
        inner.max_events = config.max_events.max(1);
        inner.max_stats = config.max_stats.max(1);
        inner.workers = config.workers.max(1);
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
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        let max_stats = inner.max_stats;
        if inner.started_at.is_none() {
            inner.started_at = Some(Instant::now());
        }

        inner.connections += 1;
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

    pub fn on_daemon_owned_fast_allow(&self) {
        self.daemon_owned_fast_allow.fetch_add(1, Ordering::Relaxed);
    }

    pub fn daemon_owned_fast_allow_count(&self) -> u64 {
        self.daemon_owned_fast_allow.load(Ordering::Relaxed)
    }

    pub fn on_connection_metadata(&self, executable: &str, dst_host: Option<&str>) {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        let max_stats = inner.max_stats;
        if !executable.is_empty() {
            inner
                .by_executable
                .bump_limited_counter(executable.to_string(), max_stats);
        }
        if let Some(host) = dst_host
            && !host.is_empty()
        {
            inner
                .by_host
                .bump_limited_counter(host.to_string(), max_stats);
        }
    }

    pub fn on_dns_resolved(&self) {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        if inner.started_at.is_none() {
            inner.started_at = Some(Instant::now());
        }
        inner.dns_responses += 1;
        inner.accepted += 1;
    }

    pub fn on_verdict(&self, allow: bool) {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        if allow {
            inner.accepted += 1;
        } else {
            inner.dropped += 1;
        }
    }

    pub fn on_rule_hit(&self) {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        inner.rule_hits += 1;
    }

    pub fn on_rule_miss(&self) {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        inner.rule_misses += 1;
    }

    pub fn on_ignored(&self) {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        inner.ignored += 1;
        inner.accepted += 1;
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
        Self::build_snapshot(&mut inner, rules_count)
    }

    pub fn snapshot_if_pending(&self, rules_count: u64) -> Option<pb::Statistics> {
        let mut inner = self.inner.lock().expect("stats mutex poisoned");
        if inner.events.is_empty() {
            return None;
        }

        Some(Self::build_snapshot(&mut inner, rules_count))
    }
}

#[cfg(test)]
mod tests {
    use super::{StatsCounterMapExt, StatsService};
    use crate::config::StatsConfig;
    use opensnitch_proto::pb;

    #[test]
    fn bump_limited_counter_evicts_lowest_entry_at_capacity() {
        let mut map =
            std::collections::HashMap::from([("alpha".to_string(), 3), ("beta".to_string(), 1)]);

        map.bump_limited_counter("gamma".to_string(), 2);

        assert_eq!(map.len(), 2);
        assert!(map.contains_key("alpha"));
        assert!(map.contains_key("gamma"));
        assert!(!map.contains_key("beta"));
    }

    #[test]
    fn apply_config_trims_existing_event_backlog() {
        let stats = StatsService::default();
        for index in 0..3 {
            stats.on_event(
                pb::Connection {
                    protocol: "tcp".to_string(),
                    dst_ip: format!("10.0.0.{index}"),
                    ..Default::default()
                },
                None,
            );
        }

        stats.apply_config(StatsConfig {
            max_events: 2,
            max_stats: 5,
            workers: 1,
        });

        let snapshot = stats.snapshot(0);
        assert_eq!(snapshot.events.len(), 2);
    }

    #[test]
    fn dns_and_ignored_traffic_increment_accepted() {
        let stats = StatsService::default();

        stats.on_dns_resolved();
        stats.on_ignored();

        let snapshot = stats.snapshot(0);
        assert_eq!(snapshot.dns_responses, 1);
        assert_eq!(snapshot.ignored, 1);
        assert_eq!(snapshot.accepted, 2);
    }

    #[test]
    fn daemon_owned_fast_allow_counter_is_tracked_separately() {
        let stats = StatsService::default();

        stats.on_daemon_owned_fast_allow();
        stats.on_daemon_owned_fast_allow();

        assert_eq!(stats.daemon_owned_fast_allow_count(), 2);
        let snapshot = stats.snapshot(0);
        assert_eq!(snapshot.connections, 0);
        assert_eq!(snapshot.accepted, 0);
    }

    #[test]
    fn snapshot_if_pending_returns_none_without_events_and_drains_when_present() {
        let stats = StatsService::default();
        assert!(stats.snapshot_if_pending(0).is_none());

        stats.on_event(pb::Connection::default(), None);
        let snapshot = stats.snapshot_if_pending(0).expect("pending snapshot");
        assert_eq!(snapshot.events.len(), 1);
        assert!(stats.snapshot_if_pending(0).is_none());
    }
}
