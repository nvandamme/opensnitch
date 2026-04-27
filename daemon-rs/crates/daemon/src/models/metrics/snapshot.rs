//! Extended statistics snapshot for metrics export.
//!
//! Contains the standard transport stats payload plus daemon-rs-only
//! fields such as per-rule hit counts and the subscription statistics block
//! that are not part of the upstream `ui.proto` wire format.
//!
//! The gRPC path sends the transport stats payload as-is; the metrics export path
//! receives this richer struct.
//!
//! Boundary note:
//! - `Wire*` stats types come from `transport_wire_core` and represent
//!   the transport/wire boundary contract consumed by metrics exporters.
//! - Prometheus protobuf output (`io.prometheus.client.MetricFamily`) is a
//!   separate protocol model and lives under `models/prometheus_wire.rs`.

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};
use transport_wire_core::{WireStatistics, WireSubscriptionStatistics};

/// Snapshot sent to [`crate::platform::stats::exporter_port::StatsExporterPort`].
///
/// Bundles the standard transport stats payload with daemon-rs-only fields:
/// - `subscription_stats`: mirrored-shape block (scalars + breakdowns + event log),
///   not in `ui.proto` but consumed by the metrics exporters.
/// - `by_rule`: per-rule hit counts, not in `ui.proto`.
#[cfg(any(
    feature = "metrics-http-serve-text",
    feature = "metrics-http-serve-openmetrics",
    feature = "metrics-http-serve-protobuf",
    feature = "metrics-http-push-text",
    feature = "metrics-http-push-openmetrics",
    feature = "metrics-http-push-protobuf",
    feature = "metrics-http-push-influxdb",
    feature = "metrics-syslog"
))]
pub struct MetricsSnapshot {
    pub stats: WireStatistics,
    /// `None` when the subscriptions feature is disabled or no data is available yet.
    pub subscription_stats: Option<WireSubscriptionStatistics>,
    pub by_rule: HashMap<String, u64>,
    export_snapshot: Arc<OnceLock<Arc<MetricsExportSnapshot>>>,
}

#[cfg(any(
    feature = "metrics-http-serve-text",
    feature = "metrics-http-serve-openmetrics",
    feature = "metrics-http-serve-protobuf",
    feature = "metrics-http-push-text",
    feature = "metrics-http-push-openmetrics",
    feature = "metrics-http-push-protobuf",
    feature = "metrics-http-push-influxdb",
    feature = "metrics-syslog"
))]
impl Clone for MetricsSnapshot {
    fn clone(&self) -> Self {
        Self {
            stats: self.stats.clone(),
            subscription_stats: self.subscription_stats.clone(),
            by_rule: self.by_rule.clone(),
            export_snapshot: Arc::clone(&self.export_snapshot),
        }
    }
}

#[cfg(any(
    feature = "metrics-http-serve-text",
    feature = "metrics-http-serve-openmetrics",
    feature = "metrics-http-serve-protobuf",
    feature = "metrics-http-push-text",
    feature = "metrics-http-push-openmetrics",
    feature = "metrics-http-push-protobuf",
    feature = "metrics-http-push-influxdb",
    feature = "metrics-syslog"
))]
impl MetricsSnapshot {
    pub fn new(
        stats: WireStatistics,
        subscription_stats: Option<WireSubscriptionStatistics>,
        by_rule: HashMap<String, u64>,
    ) -> Self {
        Self {
            stats,
            subscription_stats,
            by_rule,
            export_snapshot: Arc::new(OnceLock::new()),
        }
    }

    pub(crate) fn export_view(&self) -> Arc<MetricsExportSnapshot> {
        Arc::clone(
            self.export_snapshot
                .get_or_init(|| Arc::new(MetricsExportSnapshot::from(self))),
        )
    }
}

#[cfg(any(
    feature = "metrics-http-serve-text",
    feature = "metrics-http-serve-openmetrics",
    feature = "metrics-http-serve-protobuf",
    feature = "metrics-http-push-text",
    feature = "metrics-http-push-openmetrics",
    feature = "metrics-http-push-protobuf",
    feature = "metrics-http-push-influxdb",
    feature = "metrics-syslog"
))]
pub(crate) struct MetricsExportSnapshot {
    pub(crate) rules: u64,
    pub(crate) daemon_version: String,
    pub(crate) uptime: u64,
    pub(crate) dns_responses: u64,
    pub(crate) connections: u64,
    pub(crate) ignored: u64,
    pub(crate) accepted: u64,
    pub(crate) dropped: u64,
    pub(crate) rule_hits: u64,
    pub(crate) rule_misses: u64,
    pub(crate) subscription_stats: Option<WireSubscriptionStatistics>,
    pub(crate) by_subscription_status: Vec<(String, u64)>,
    pub(crate) by_subscription_group: Vec<(String, u64)>,
    pub(crate) by_subscription_node: Vec<(String, u64)>,
    pub(crate) by_proto: Vec<(String, u64)>,
    pub(crate) by_address: Vec<(String, u64)>,
    pub(crate) by_host: Vec<(String, u64)>,
    pub(crate) by_port: Vec<(String, u64)>,
    pub(crate) by_uid: Vec<(String, u64)>,
    pub(crate) by_executable: Vec<(String, u64)>,
    pub(crate) by_rule: Vec<(String, u64)>,
}

#[cfg(any(
    feature = "metrics-http-serve-text",
    feature = "metrics-http-serve-openmetrics",
    feature = "metrics-http-serve-protobuf",
    feature = "metrics-http-push-text",
    feature = "metrics-http-push-openmetrics",
    feature = "metrics-http-push-protobuf",
    feature = "metrics-http-push-influxdb",
    feature = "metrics-syslog"
))]
impl From<&MetricsSnapshot> for MetricsExportSnapshot {
    fn from(snapshot: &MetricsSnapshot) -> Self {
        let stats = &snapshot.stats;
        let (by_subscription_status, by_subscription_group, by_subscription_node) =
            match snapshot.subscription_stats.as_ref() {
                Some(sub_stats) => (
                    sorted_pairs(&sub_stats.by_status),
                    sorted_pairs(&sub_stats.by_group),
                    sorted_pairs(&sub_stats.by_node),
                ),
                None => (Vec::new(), Vec::new(), Vec::new()),
            };

        Self {
            rules: stats.rules,
            daemon_version: stats.daemon_version.clone(),
            uptime: stats.uptime,
            dns_responses: stats.dns_responses,
            connections: stats.connections,
            ignored: stats.ignored,
            accepted: stats.accepted,
            dropped: stats.dropped,
            rule_hits: stats.rule_hits,
            rule_misses: stats.rule_misses,
            subscription_stats: snapshot.subscription_stats.clone(),
            by_subscription_status,
            by_subscription_group,
            by_subscription_node,
            by_proto: sorted_pairs(&stats.by_proto),
            by_address: sorted_pairs(&stats.by_address),
            by_host: sorted_pairs(&stats.by_host),
            by_port: sorted_pairs(&stats.by_port),
            by_uid: sorted_pairs(&stats.by_uid),
            by_executable: sorted_pairs(&stats.by_executable),
            by_rule: sorted_pairs(&snapshot.by_rule),
        }
    }
}

#[cfg(any(
    feature = "metrics-http-serve-text",
    feature = "metrics-http-serve-openmetrics",
    feature = "metrics-http-serve-protobuf",
    feature = "metrics-http-push-text",
    feature = "metrics-http-push-openmetrics",
    feature = "metrics-http-push-protobuf",
    feature = "metrics-http-push-influxdb",
    feature = "metrics-syslog"
))]
fn sorted_pairs(map: &HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut pairs: Vec<_> = map
        .iter()
        .map(|(key, value)| (key.clone(), *value))
        .collect();
    pairs.sort_by(|left, right| right.1.cmp(&left.1));
    pairs
}
