use crate::models::metrics_snapshot::MetricsSnapshot;

/// Trait for pluggable stats snapshot exporters.
///
/// Implementors receive a [`MetricsSnapshot`] each time the
/// `StatsFlow` emission cycle fires (1s cadence when events are pending).
///
/// The snapshot contains the standard transport stats payload plus
/// daemon-rs-only fields (subscription counts, per-rule hit breakdown) that
/// are not part of the upstream `ui.proto` wire format.
///
/// Intended adapter targets:
/// - Prometheus: convert counters/gauges to text-format and serve via HTTP
///   `/metrics` endpoint (prometheus-client or axum-based scrape server).
/// - Grafana Mimir / InfluxDB: batch-push the snapshot counters on each tick.
/// - Any other pull/push metrics backend.
///
/// Go equivalent: the `daemon/statistics/stats.go` `Serialize()` path feeds
/// the gRPC ping; no Prometheus scrape endpoint exists in the Go daemon, but
/// the stats payload carries all counter fields needed for one.
pub trait StatsExporterPort: Send + Sync {
    /// Called once per emission cycle with the drained statistics snapshot.
    ///
    /// Implementations must be non-blocking; offload I/O to an internal async
    /// channel or background task to avoid stalling the `StatsFlow` loop.
    fn export_snapshot(&self, snapshot: &MetricsSnapshot);
}
