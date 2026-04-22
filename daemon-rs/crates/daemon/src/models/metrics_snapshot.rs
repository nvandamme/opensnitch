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

use std::collections::HashMap;
use transport_wire_core::{WireStatistics, WireSubscriptionStatistics};

/// Snapshot sent to [`crate::platform::ports::stats_exporter_port::StatsExporterPort`].
///
/// Bundles the standard transport stats payload with daemon-rs-only fields:
/// - `subscription_stats`: mirrored-shape block (scalars + breakdowns + event log),
///   not in `ui.proto` but consumed by the metrics exporters.
/// - `by_rule`: per-rule hit counts, not in `ui.proto`.
#[cfg_attr(not(feature = "metrics-export"), allow(dead_code))]
pub struct MetricsSnapshot {
    pub stats: WireStatistics,
    /// `None` when the subscriptions feature is disabled or no data is available yet.
    pub subscription_stats: Option<WireSubscriptionStatistics>,
    pub by_rule: HashMap<String, u64>,
}
