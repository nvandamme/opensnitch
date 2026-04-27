//! Push-style stats exporter — Prometheus push-gateway (text / OpenMetrics / protobuf).
//!
//! Feature-gated behind any of:
//! - `metrics-http-push-text`
//! - `metrics-http-push-openmetrics`
//! - `metrics-http-push-protobuf`
//!
//! Sends the configured push format on every tick.
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
//! The adapter POSTs the configured Prometheus/OpenMetrics push payload to
//! `{url}/metrics/job/{job}`.
//! For Mimir / Grafana Cloud remote-write, set `OPENSNITCH_PUSH_URL` to the full
//! push endpoint path and `OPENSNITCH_PUSH_JOB` is appended as usual.
//!
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hyper::Method;
use hyper::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, HeaderName};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::models::metrics::snapshot::{MetricsExportSnapshot, MetricsSnapshot};
use crate::platform::stats::exporter_port::StatsExporterPort;
use crate::utils::http_client::{HttpClient, build_http_client, build_request, send_request};

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
    /// OpenMetrics text 1.0.0 POSTed to `{url}/metrics/job/{job}`.
    /// Useful when the receiving endpoint expects OpenMetrics semantics/EOF.
    PushgatewayOpenMetrics,
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
    pub bucket: String,
    pub org: String,
}

pub(crate) type CompactSnapshot = MetricsExportSnapshot;

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
    tx: mpsc::Sender<Arc<CompactSnapshot>>,
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
        if self.tx.try_send(snapshot.export_view()).is_err() {
            debug!("push stats exporter: channel full — snapshot dropped");
        }
    }
}

// ---------------------------------------------------------------------------
// Background worker
// ---------------------------------------------------------------------------

async fn push_worker(
    mut rx: mpsc::Receiver<Arc<CompactSnapshot>>,
    config: PushConfig,
    shutdown: CancellationToken,
) {
    let client = build_http_client();

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
                if let Err(err) = post_snapshot(&client, &config, &endpoint, &snapshot).await {
                    debug!(error = %err, "push stats exporter: push failed");
                }
            }
        }
    }

    info!("push stats exporter stopped");
}

/// Pre-compute the endpoint URL so we don't rebuild it on every tick.
fn build_endpoint(config: &PushConfig) -> String {
    if config.format == PushFormat::InfluxDb {
        let url = config.url.trim_end_matches('/');
        if url.contains("precision=") {
            return url.to_string();
        }
        if url.contains('?') {
            if url.contains("bucket=") {
                return format!("{url}&precision=s");
            }
            return format!("{url}&bucket={}&precision=s", config.bucket);
        }

        let mut qs = format!("?bucket={}&precision=s", config.bucket);
        if !config.org.is_empty() {
            qs.push_str("&org=");
            qs.push_str(&config.org);
        }
        return format!("{url}{qs}");
    }

    format!(
        "{}/metrics/job/{}",
        config.url.trim_end_matches('/'),
        config.job
    )
}

async fn post_snapshot(
    client: &HttpClient,
    config: &PushConfig,
    endpoint: &str,
    snapshot: &CompactSnapshot,
) -> Result<()> {
    match config.format {
        PushFormat::Pushgateway => {
            #[cfg(feature = "metrics-http-push-text")]
            {
                let body = encode_as_prometheus_text(snapshot);
                post_one_format(
                    client,
                    config,
                    endpoint,
                    body,
                    "text/plain; version=0.0.4; charset=utf-8",
                )
                .await?;
            }
        }
        PushFormat::PushgatewayOpenMetrics => {
            #[cfg(feature = "metrics-http-push-openmetrics")]
            {
                let body = encode_as_prometheus_openmetrics(snapshot);
                post_one_format(
                    client,
                    config,
                    endpoint,
                    body,
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                )
                .await?;
            }
        }
        PushFormat::PushgatewayProto => {
            #[cfg(feature = "metrics-http-push-protobuf")]
            {
                let body = encode_as_prometheus_proto(snapshot);
                post_one_format(
                    client,
                    config,
                    endpoint,
                    body,
                    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited",
                )
                .await?;
            }
        }
        PushFormat::InfluxDb => {
            #[cfg(feature = "metrics-http-push-influxdb")]
            {
                let body = render_influxdb_line_protocol(snapshot).into_bytes();
                post_one_format(client, config, endpoint, body, "text/plain; charset=utf-8")
                    .await?;
            }
        }
    }

    Ok(())
}

/// Issue a single POST for one wire format body.
async fn post_one_format(
    client: &HttpClient,
    config: &PushConfig,
    endpoint: &str,
    body_bytes: Vec<u8>,
    content_type: &'static str,
) -> Result<()> {
    let (final_body, gzip_encoded) = if config.gzip {
        match gzip_compress(&body_bytes) {
            Some(c) => (c, true),
            None => (body_bytes, false),
        }
    } else {
        (body_bytes, false)
    };

    let mut headers: Vec<(HeaderName, String)> = vec![(CONTENT_TYPE, content_type.to_string())];

    if gzip_encoded {
        headers.push((CONTENT_ENCODING, "gzip".to_string()));
    }

    if let Some(ref token) = config.token {
        headers.push((AUTHORIZATION, format!("Bearer {token}")));
    }

    let request = build_request(Method::POST, endpoint, &headers, final_body)?;
    let response = send_request(client, request, HTTP_TIMEOUT, None).await?;

    if !response.status.is_success() {
        debug!(
            status = response.status.as_u16(),
            endpoint, content_type, "push stats exporter: non-2xx response"
        );
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn render_prometheus_text(snapshot: &CompactSnapshot) -> String {
    String::from_utf8(encode_as_prometheus_text(snapshot)).unwrap_or_default()
}

#[allow(dead_code)]
pub(crate) fn render_prometheus_proto_push(snapshot: &CompactSnapshot) -> Vec<u8> {
    encode_as_prometheus_proto(snapshot)
}

#[allow(dead_code)]
pub(crate) fn render_influxdb_line_protocol(snapshot: &CompactSnapshot) -> String {
    super::encoder_influxdb::render_line_protocol(snapshot)
}

/// Encode snapshot as Prometheus text 0.0.4.
/// Returns empty bytes when `metrics-http-push-text` is not active.
#[allow(unreachable_code, unused_variables)]
fn encode_as_prometheus_text(snapshot: &CompactSnapshot) -> Vec<u8> {
    #[cfg(feature = "metrics-http-push-text")]
    {
        return super::encoder_prometheus_text::render_prometheus_text(snapshot).into_bytes();
    }
    Vec::new()
}

/// Encode snapshot as OpenMetrics text 1.0.0.
/// Returns empty bytes when `metrics-http-push-openmetrics` is not active.
#[allow(unreachable_code, unused_variables)]
fn encode_as_prometheus_openmetrics(snapshot: &CompactSnapshot) -> Vec<u8> {
    #[cfg(feature = "metrics-http-push-openmetrics")]
    {
        return super::encoder_prometheus_openmetrics::render_openmetrics_text(snapshot)
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
        return super::encoder_prometheus_protobuf::render_prometheus_proto(snapshot);
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
