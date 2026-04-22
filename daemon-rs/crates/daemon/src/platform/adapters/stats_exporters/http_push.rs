//! Push-style stats exporter — Prometheus push-gateway (text / protobuf).
//!
//! Feature-gated behind any of:
//! - `metrics-http-push-text`
//! - `metrics-http-push-openmetrics`
//! - `metrics-http-push-protobuf`
//!
//! All enabled push format features are sent on every tick — one POST request
//! per active format.
//! Sends a metrics snapshot payload to a
//! remote HTTP endpoint on every `StatsFlow` emission tick (1 s cadence when events
//! are pending).  I/O is off-loaded to a bounded background channel so
//! `export_snapshot` never blocks the `StatsFlow` loop.
//!
//! # Activation
//!
//! Set `OPENSNITCH_PUSH_URL` to the push endpoint.  Without this variable the
//! adapter is a no-op and the push background task is never started.
//!
//! Optional tuning variables:
//! - `OPENSNITCH_PUSH_JOB`     — job label for push-gateway (default: `opensnitchd`)
//! - `OPENSNITCH_PUSH_TOKEN`   — bearer / API token for authentication (optional)
//! - `OPENSNITCH_PUSH_GZIP`    — `1` / `true` / `yes` to gzip-compress push bodies (default: off)
//!
//! Protocol boundary note:
//! - The input snapshot shape comes from daemon metrics aliases
//!   (`models/metrics_snapshot.rs`).
//! - `pushgateway-proto` emits Prometheus `io.prometheus.client.MetricFamily`
//!   protobuf frames, not OpenSnitch transport `proto::pb::*` messages.
//!
//! ## Push-gateway / Mimir remote-write
//!
//! Set `OPENSNITCH_PUSH_URL` to the push-gateway base URL, e.g.:
//!   `http://pushgateway:9091`
//!   `https://mimir.example.com/api/v1/push`
//!   `https://prometheus-blocks-prod-us-central1.grafana.net/api/prom/push`
//!
//! The adapter POSTs Prometheus text format 0.0.4 to `{url}/metrics/job/{job}`.
//! For Mimir / Grafana Cloud remote-write, set `OPENSNITCH_PUSH_URL` to the full
//! push endpoint path and `OPENSNITCH_PUSH_JOB` is appended as usual.
//!
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::models::metrics_snapshot::MetricsSnapshot;
use crate::platform::ports::stats_exporter_port::StatsExporterPort;
use transport_wire_core::WireSubscriptionStatistics;

// ---------------------------------------------------------------------------
// Environment variable keys
// ---------------------------------------------------------------------------
//
// DESIGN_RULES §7 — Configuration Surface Precedence Rule:
// CLI switches (--metrics-push-*) have highest precedence, then
// env vars (typically used in testing/CI), then JSON config (metrics.json).
//   OPENSNITCH_PUSH_URL     ↔ metrics.push.url
//   OPENSNITCH_PUSH_FORMAT  ↔ metrics.push.format
//   OPENSNITCH_PUSH_JOB     ↔ metrics.push.job
//   OPENSNITCH_PUSH_TOKEN   ↔ metrics.push.token
//   OPENSNITCH_PUSH_GZIP    ↔ metrics.push.gzip
//   OPENSNITCH_PUSH_BUCKET  ↔ metrics.push.bucket
//   OPENSNITCH_PUSH_ORG     ↔ metrics.push.org
// ---------------------------------------------------------------------------

pub const PUSH_URL_ENV: &str = "OPENSNITCH_PUSH_URL";
pub(crate) const PUSH_FORMAT_ENV: &str = "OPENSNITCH_PUSH_FORMAT";
pub(crate) const PUSH_JOB_ENV: &str = "OPENSNITCH_PUSH_JOB";
pub(crate) const PUSH_TOKEN_ENV: &str = "OPENSNITCH_PUSH_TOKEN";
pub(crate) const PUSH_GZIP_ENV: &str = "OPENSNITCH_PUSH_GZIP";

const CHANNEL_CAPACITY: usize = 4;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushFormat {
    /// Prometheus text format 0.0.4 POSTed to `{url}/metrics/job/{job}`.
    /// Compatible with Prometheus push-gateway, Grafana Mimir, and Grafana Cloud.
    Pushgateway,
    /// Prometheus protobuf (`io.prometheus.client.MetricFamily`, delimited) POSTed
    /// to `{url}/metrics/job/{job}`.  Preferred by Prometheus-native backends.
    PushgatewayProto,
    /// Legacy config value preserved for compatibility.
    InfluxDb,
}

#[derive(Debug, Clone)]
pub struct PushConfig {
    pub url: String,
    pub format: PushFormat,
    pub job: String,
    pub token: Option<String>,
    /// Gzip-compress the push body (`Content-Encoding: gzip`).
    /// Activated by `OPENSNITCH_PUSH_GZIP=1/true/yes`.
    pub gzip: bool,
}

pub(crate) struct CompactSnapshot {
    pub(crate) rules: u64,
    pub(crate) uptime: u64,
    pub(crate) dns_responses: u64,
    pub(crate) connections: u64,
    pub(crate) ignored: u64,
    pub(crate) accepted: u64,
    pub(crate) dropped: u64,
    pub(crate) rule_hits: u64,
    pub(crate) rule_misses: u64,
    pub(crate) subscription_stats: Option<WireSubscriptionStatistics>,
    pub(crate) by_proto: Vec<(String, u64)>,
    pub(crate) by_address: Vec<(String, u64)>,
    pub(crate) by_host: Vec<(String, u64)>,
    pub(crate) by_port: Vec<(String, u64)>,
    pub(crate) by_uid: Vec<(String, u64)>,
    pub(crate) by_executable: Vec<(String, u64)>,
    pub(crate) by_rule: Vec<(String, u64)>,
}

impl From<&MetricsSnapshot> for CompactSnapshot {
    fn from(m: &MetricsSnapshot) -> Self {
        let s = &m.stats;
        Self {
            rules: s.rules,
            uptime: s.uptime,
            dns_responses: s.dns_responses,
            connections: s.connections,
            ignored: s.ignored,
            accepted: s.accepted,
            dropped: s.dropped,
            rule_hits: s.rule_hits,
            rule_misses: s.rule_misses,
            subscription_stats: m.subscription_stats.clone(),
            by_proto: sorted_pairs(&s.by_proto),
            by_address: sorted_pairs(&s.by_address),
            by_host: sorted_pairs(&s.by_host),
            by_port: sorted_pairs(&s.by_port),
            by_uid: sorted_pairs(&s.by_uid),
            by_executable: sorted_pairs(&s.by_executable),
            by_rule: sorted_pairs(&m.by_rule),
        }
    }
}

fn sorted_pairs(map: &std::collections::HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut pairs: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1));
    pairs
}

// ---------------------------------------------------------------------------
// Compact snapshot (no repeated Events slice — avoids per-tick clone overhead)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Push adapter
// ---------------------------------------------------------------------------

/// Push-style stats exporter.
///
/// Construct with [`PushStatsExporter::new`], passing a resolved [`PushConfig`]
/// and the daemon shutdown token.  The background push task starts immediately.
pub struct PushStatsExporter {
    tx: mpsc::Sender<CompactSnapshot>,
}

impl PushStatsExporter {
    pub fn new(config: PushConfig, shutdown: CancellationToken) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let exporter = Arc::new(Self { tx });
        tokio::spawn(push_worker(rx, config, shutdown));
        exporter
    }
}

impl StatsExporterPort for PushStatsExporter {
    /// Non-blocking: enqueue the snapshot for the background push task.
    /// Drops the snapshot if the channel is full (fail-open).
    fn export_snapshot(&self, snapshot: &MetricsSnapshot) {
        let compact = CompactSnapshot::from(snapshot);
        if self.tx.try_send(compact).is_err() {
            debug!("push stats exporter: channel full — snapshot dropped");
        }
    }
}

// ---------------------------------------------------------------------------
// Background worker
// ---------------------------------------------------------------------------

async fn push_worker(
    mut rx: mpsc::Receiver<CompactSnapshot>,
    config: PushConfig,
    shutdown: CancellationToken,
) {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let endpoint = build_endpoint(&config);
    info!(
        format = ?config.format,
        endpoint = %endpoint,
        "push stats exporter started"
    );

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            maybe = rx.recv() => {
                let Some(snapshot) = maybe else { break };
                    post_snapshot(&client, &config, &endpoint, &snapshot).await;
            }
        }
    }

    info!("push stats exporter stopped");
}

/// Pre-compute the endpoint URL so we don't rebuild it on every tick.
fn build_endpoint(config: &PushConfig) -> String {
    format!(
        "{}/metrics/job/{}",
        config.url.trim_end_matches('/'),
        config.job
    )
}

async fn post_snapshot(
    client: &reqwest::Client,
    config: &PushConfig,
    endpoint: &str,
    snapshot: &CompactSnapshot,
) {
    // Push every compiled-in push format independently.
    // One POST per active format feature; errors are logged per-format and do
    // not prevent the remaining formats from being sent.

    #[cfg(feature = "metrics-http-push-text")]
    {
        let body = encode_as_prometheus_text(snapshot);
        if let Err(e) = post_one_format(
            client,
            config,
            endpoint,
            body,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .await
        {
            debug!(endpoint, format = "prom-text", "push failed: {e}");
        }
    }

    #[cfg(feature = "metrics-http-push-openmetrics")]
    {
        let body = encode_as_openmetrics_text(snapshot);
        if let Err(e) = post_one_format(
            client,
            config,
            endpoint,
            body,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .await
        {
            debug!(endpoint, format = "openmetrics", "push failed: {e}");
        }
    }

    #[cfg(feature = "metrics-http-push-protobuf")]
    {
        let body = encode_as_prometheus_proto(snapshot);
        if let Err(e) = post_one_format(
                client,
                config,
                endpoint,
                body,
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited",
            )
            .await
            {
                debug!(endpoint, format = "prom-proto", "push failed: {e}");
            }
    }
}

/// Issue a single POST for one wire format body.
async fn post_one_format(
    client: &reqwest::Client,
    config: &PushConfig,
    endpoint: &str,
    body_bytes: Vec<u8>,
    content_type: &'static str,
) -> Result<(), reqwest::Error> {
    let (final_body, gzip_encoded) = if config.gzip {
        match gzip_compress(&body_bytes) {
            Some(c) => (c, true),
            None => (body_bytes, false),
        }
    } else {
        (body_bytes, false)
    };

    let mut req = client
        .post(endpoint)
        .header("Content-Type", content_type)
        .body(final_body);

    if gzip_encoded {
        req = req.header("Content-Encoding", "gzip");
    }

    if let Some(ref token) = config.token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        debug!(
            status = resp.status().as_u16(),
            endpoint, content_type, "push stats exporter: non-2xx response"
        );
    }
    Ok(())
}

/// Encode snapshot as OpenMetrics text 1.0.0.
/// Returns empty bytes when `metrics-http-push-openmetrics` is not active.
#[allow(unreachable_code, unused_variables)]
fn encode_as_openmetrics_text(_snapshot: &CompactSnapshot) -> Vec<u8> {
    #[cfg(feature = "metrics-http-push-openmetrics")]
    {
        use super::encoder_prometheus_openmetrics::{OpenMetricsSnapshot, render_openmetrics_text};
        return render_openmetrics_text(&OpenMetricsSnapshot {
            rules: _snapshot.rules,
            uptime: _snapshot.uptime,
            dns_responses: _snapshot.dns_responses,
            connections: _snapshot.connections,
            ignored: _snapshot.ignored,
            accepted: _snapshot.accepted,
            dropped: _snapshot.dropped,
            rule_hits: _snapshot.rule_hits,
            rule_misses: _snapshot.rule_misses,
            subscription_stats: _snapshot.subscription_stats.clone(),
            by_proto: _snapshot.by_proto.clone(),
            by_address: _snapshot.by_address.clone(),
            by_host: _snapshot.by_host.clone(),
            by_port: _snapshot.by_port.clone(),
            by_uid: _snapshot.by_uid.clone(),
            by_executable: _snapshot.by_executable.clone(),
            by_rule: _snapshot.by_rule.clone(),
        })
        .into_bytes();
    }
    Vec::new()
}

/// Encode snapshot as Prometheus text 0.0.4.
/// Returns empty bytes when `metrics-http-push-text` is not active.
#[allow(unreachable_code, unused_variables)]
fn encode_as_prometheus_text(snapshot: &CompactSnapshot) -> Vec<u8> {
    #[cfg(feature = "metrics-http-push-text")]
    {
        use super::encoder_prometheus_text::{PrometheusTextSnapshot, render_prometheus_text};
        return render_prometheus_text(&PrometheusTextSnapshot {
            rules: snapshot.rules,
            uptime: snapshot.uptime,
            dns_responses: snapshot.dns_responses,
            connections: snapshot.connections,
            ignored: snapshot.ignored,
            accepted: snapshot.accepted,
            dropped: snapshot.dropped,
            rule_hits: snapshot.rule_hits,
            rule_misses: snapshot.rule_misses,
            subscription_stats: snapshot.subscription_stats.clone(),
            by_proto: snapshot.by_proto.clone(),
            by_address: snapshot.by_address.clone(),
            by_host: snapshot.by_host.clone(),
            by_port: snapshot.by_port.clone(),
            by_uid: snapshot.by_uid.clone(),
            by_executable: snapshot.by_executable.clone(),
            by_rule: snapshot.by_rule.clone(),
        })
        .into_bytes();
    }
    Vec::new()
}

/// Encode snapshot as Prometheus protobuf (length-delimited MetricFamily).
/// Returns empty bytes when `metrics-http-push-protobuf` is not active.
#[allow(unreachable_code, unused_variables)]
fn encode_as_prometheus_proto(snapshot: &CompactSnapshot) -> Vec<u8> {
    #[cfg(feature = "metrics-http-push-protobuf")]
    {
        use super::encoder_prometheus_protobuf::{ProtoSnapshot, render_prometheus_proto};
        return render_prometheus_proto(&ProtoSnapshot {
            rules: snapshot.rules,
            uptime: snapshot.uptime,
            dns_responses: snapshot.dns_responses,
            connections: snapshot.connections,
            ignored: snapshot.ignored,
            accepted: snapshot.accepted,
            dropped: snapshot.dropped,
            rule_hits: snapshot.rule_hits,
            rule_misses: snapshot.rule_misses,
            subscription_stats: snapshot.subscription_stats.clone(),
            by_proto: snapshot.by_proto.clone(),
            by_address: snapshot.by_address.clone(),
            by_host: snapshot.by_host.clone(),
            by_port: snapshot.by_port.clone(),
            by_uid: snapshot.by_uid.clone(),
            by_executable: snapshot.by_executable.clone(),
            by_rule: snapshot.by_rule.clone(),
        });
    }
    Vec::new()
}

fn gzip_compress(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;

    let mut enc = GzEncoder::new(
        Vec::with_capacity(data.len() / 2 + 20),
        Compression::default(),
    );
    enc.write_all(data).ok()?;
    enc.finish().ok()
}

#[cfg(test)]
#[path = "../../../tests/metrics/stats_exporter_push.rs"]
mod push_exporter_tests;
