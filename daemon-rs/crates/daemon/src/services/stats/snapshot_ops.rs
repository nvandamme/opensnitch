use std::sync::atomic::Ordering;
use transport_wire_core::WireStatistics;

use crate::models::connection_state::ConnectionAttempt;
use crate::models::metrics_snapshot::MetricsSnapshot;
use crate::services::storage::StorageService;

use super::{
    internal::{BreakdownCounters, EventsState},
    stats::StatsService,
};

const DIAG_STATS_DROPPED_EVENTS_CONTENTION: &str = "diag.stats.dropped_events_contention";
const DIAG_STORAGE_EVENT_BUS_DROPPED_INGRESS: &str = "diag.storage.event_bus.dropped_ingress";

impl StatsService {
    /// Format `unix_nano` as `"yyyy-mm-dd hh:mm:ss"` without allocating an
    /// intermediate `fmt::write` buffer.  Writes directly into a 19-byte stack
    /// array, then converts to `String` with a single exact-sized allocation
    /// — avoids the `time::format_description` dispatch overhead of the
    /// previous `dt.format(EVENT_TIME_FORMAT)` call.
    pub(crate) fn format_event_time(unix_nano: i64) -> String {
        use std::io::Write;
        let secs = unix_nano.div_euclid(1_000_000_000);
        let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(secs) else {
            return "1970-01-01 00:00:00".to_string();
        };
        let dt = dt
            .replace_nanosecond(unix_nano.rem_euclid(1_000_000_000) as u32)
            .unwrap_or(dt);
        let mut buf = [0u8; 19];
        let _ = write!(
            &mut buf[..],
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
        );
        // SAFETY: buf contains only ASCII digits, hyphens, colons, and spaces.
        unsafe { String::from_utf8_unchecked(buf.to_vec()) }
    }

    pub(super) fn protocol_name(attempt: &ConnectionAttempt) -> &'static str {
        match attempt.protocol {
            crate::models::connection_state::TransportProtocol::Tcp => "tcp",
            crate::models::connection_state::TransportProtocol::Udp => "udp",
            crate::models::connection_state::TransportProtocol::UdpLite => "udplite",
            crate::models::connection_state::TransportProtocol::Sctp => "sctp",
            crate::models::connection_state::TransportProtocol::Icmp => "icmp",
        }
    }

    pub(super) fn build_snapshot(
        &self,
        bd: &mut BreakdownCounters,
        ev: &mut EventsState,
        rules_count: u64,
    ) -> MetricsSnapshot {
        let events = ev
            .events
            .drain_all()
            .into_iter()
            .map(|event| event.into_wire_event())
            .collect();

        let stats = WireStatistics {
            daemon_version: Self::daemon_version_string(),
            rules: rules_count,
            uptime: ev
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
            by_proto: bd.by_proto.map.clone(),
            by_address: bd
                .by_address
                .map
                .iter()
                .map(|(addr, count)| (addr.to_string(), *count))
                .collect(),
            by_host: bd.by_host.map.clone(),
            by_port: bd
                .by_port
                .map
                .iter()
                .map(|(port, count)| (port.to_string(), *count))
                .collect(),
            by_uid: bd
                .by_uid
                .map
                .iter()
                .map(|(uid, count)| (uid.to_string(), *count))
                .collect(),
            by_executable: bd.by_executable.map.clone(),
            events,
        };

        let mut by_rule = bd.by_rule.map.clone();
        by_rule.insert(
            DIAG_STATS_DROPPED_EVENTS_CONTENTION.to_string(),
            self.counters
                .dropped_events_contention
                .load(Ordering::Relaxed),
        );
        by_rule.insert(
            DIAG_STORAGE_EVENT_BUS_DROPPED_INGRESS.to_string(),
            StorageService::global().dropped_ingress_events_count(),
        );

        MetricsSnapshot::new(
            stats,
            self.sub_stats
                .lock()
                .expect("subscription stats mutex poisoned")
                .clone(),
            by_rule,
        )
    }
}
