//! Extended statistics snapshot for metrics export.
//!
//! Contains the standard `pb::Statistics` proto payload plus daemon-rs-only
//! fields such as per-rule hit counts and the subscription statistics block
//! that are not part of the upstream `ui.proto` wire format.
//!
//! The gRPC path sends `pb::Statistics` as-is; the metrics export path
//! receives this richer struct.

use std::collections::HashMap;

use opensnitch_proto::pb;

/// Snapshot sent to [`crate::platform::ports::stats_exporter_port::StatsExporterPort`].
///
/// Bundles the standard proto `Statistics` with daemon-rs-only fields:
/// - `subscription_stats`: mirrored-shape block (scalars + breakdowns + event log),
///   not in `ui.proto` but consumed by the metrics exporters.
/// - `by_rule`: per-rule hit counts, not in `ui.proto`.
#[cfg_attr(not(feature = "metrics-export"), allow(dead_code))]
pub struct MetricsSnapshot {
    pub stats: pb::Statistics,
    /// `None` when the subscriptions feature is disabled or no data is available yet.
    pub subscription_stats: Option<pb::SubscriptionStatistics>,
    pub by_rule: HashMap<String, u64>,
}
