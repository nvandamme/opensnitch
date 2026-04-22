use std::sync::atomic::Ordering;

use opensnitch_proto::pb;
use time::macros::format_description;

use crate::models::connection_state::ConnectionAttempt;

use super::{internal::StatsInner, stats::StatsService};
const EVENT_TIME_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

impl StatsService {
    pub(super) fn format_event_time(unix_nano: i64) -> String {
        let secs = unix_nano.div_euclid(1_000_000_000);
        let nanos = unix_nano.rem_euclid(1_000_000_000) as u32;
        let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(secs) else {
            return "1970-01-01 00:00:00".to_string();
        };
        let dt = dt.replace_nanosecond(nanos).unwrap_or(dt);

        dt.format(EVENT_TIME_FORMAT)
            .unwrap_or_else(|_| "1970-01-01 00:00:00".to_string())
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
        inner: &mut StatsInner,
        rules_count: u64,
    ) -> pb::Statistics {
        let events = inner.events.drain_all();

        pb::Statistics {
            daemon_version: Self::daemon_version_string(),
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
            subscription_total: self.sub_total.0.load(Ordering::Relaxed),
            subscription_ready: self.sub_ready.0.load(Ordering::Relaxed),
            subscription_error: self.sub_error.0.load(Ordering::Relaxed),
        }
    }
}
