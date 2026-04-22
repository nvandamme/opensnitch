//! Prometheus scrape adapter for [`StatsExporterPort`].
//!
//! Feature-gated behind `metrics-export`.  When enabled, creates a minimal
//! HTTP server that serves a single `/metrics` endpoint with full Prometheus
//! content negotiation per <https://prometheus.io/docs/instrumenting/content_negotiation/>.
//!
//! # Supported formats
//!
//! - `text/plain; version=0.0.4` — Prometheus text 0.0.4 (default fallback)
//! - `text/plain; version=1.0.0; charset=utf-8; escaping=allow-utf-8` — Prometheus text 1.0.0
//! - `application/openmetrics-text; version=1.0.0; charset=utf-8` — OpenMetrics 1.0.0
//! - `application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily;
//!   encoding=delimited` — binary protobuf (preferred when Prometheus requests it)
//!
//! Format selection follows q-value negotiation; richest supported format wins on ties
//! (OpenMetrics > Text1.0.0 > Text0.0.4 > Proto).
//!
//! # Compression
//!
//! When the scraper sends `Accept-Encoding: gzip`, the response body is gzip-compressed
//! and `Content-Encoding: gzip` is set.  Falls back to plain body on compression failure.
//!
//! # Activation
//!
//! Set `OPENSNITCH_PROMETHEUS_ADDR` (e.g. `127.0.0.1:9100`) before starting
//! the daemon.  The server is only started when the env-var is present.
//!
//! # Prometheus metric names
//!
//! All metrics are prefixed with `opensnitch_`.  Counters carry the `_total`
//! suffix per Prometheus conventions.  Breakdown maps (by_proto, by_host,
//! etc.) are exposed as gauges with a single label key.
use std::convert::Infallible;
use std::fmt::Write as FmtWrite;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use opensnitch_proto::pb;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::platform::ports::stats_exporter_port::StatsExporterPort;

// ---------------------------------------------------------------------------
// Compact snapshot (no Events slice — reduces per-tick allocation)
// ---------------------------------------------------------------------------

struct CompactStats {
    rules: u64,
    uptime: u64,
    dns_responses: u64,
    connections: u64,
    ignored: u64,
    accepted: u64,
    dropped: u64,
    rule_hits: u64,
    rule_misses: u64,
    subscription_total: u64,
    subscription_ready: u64,
    subscription_error: u64,
    by_proto: Vec<(String, u64)>,
    by_address: Vec<(String, u64)>,
    by_host: Vec<(String, u64)>,
    by_port: Vec<(String, u64)>,
    by_uid: Vec<(String, u64)>,
    by_executable: Vec<(String, u64)>,
}

impl From<&pb::Statistics> for CompactStats {
    fn from(s: &pb::Statistics) -> Self {
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
            subscription_total: s.subscription_total,
            subscription_ready: s.subscription_ready,
            subscription_error: s.subscription_error,
            by_proto: sorted_pairs(&s.by_proto),
            by_address: sorted_pairs(&s.by_address),
            by_host: sorted_pairs(&s.by_host),
            by_port: sorted_pairs(&s.by_port),
            by_uid: sorted_pairs(&s.by_uid),
            by_executable: sorted_pairs(&s.by_executable),
        }
    }
}

fn sorted_pairs(map: &std::collections::HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut pairs: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1));
    pairs
}

// ---------------------------------------------------------------------------
// Prometheus client model protobuf types  (io.prometheus.client)
//
// Types live in `crate::models::prometheus_wire` per DESIGN_RULES §3
// (data-contract ownership).  Re-aliased here for ergonomic use within this
// module and as a visible path for the sibling push adapter.
// ---------------------------------------------------------------------------

/// Re-export of [`crate::models::prometheus_wire`] under the conventional
/// `prom_proto` alias used within this crate.
///
/// Shared with [`super::stats_exporter_push`] for protobuf push format.
pub(crate) use crate::models::prometheus_wire as prom_proto;

// ---------------------------------------------------------------------------
// Response format selection (Prometheus content negotiation)
// ---------------------------------------------------------------------------

enum ResponseFormat {
    /// `text/plain; version=0.0.4` — default, always supported.
    Text,
    /// `text/plain; version=1.0.0; charset=utf-8; escaping=allow-utf-8` — UTF-8 safe variant.
    Text100,
    /// `application/openmetrics-text; version=1.0.0; charset=utf-8` — OpenMetrics 1.0.0.
    OpenMetrics,
    /// `application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily;
    /// encoding=delimited` — preferred when Prometheus requests it.
    Proto,
}

/// Negotiate the response format from the `Accept` header.
///
/// Follows the Prometheus content negotiation spec: parses q-values and picks
/// the supported format with the highest weight.  Defaults to
/// [`ResponseFormat::Text`] (PrometheusText0.0.4) when:
/// - the `Accept` header is absent,
/// - no recognised MIME type appears in the header, or
/// - multiple formats have equal weight (richest wins: OpenMetrics > Text1.0.0 > Text0.0.4 > Proto).
fn negotiate_format(accept: Option<&str>) -> ResponseFormat {
    let Some(accept) = accept else {
        return ResponseFormat::Text;
    };

    let mut best_proto_q: f32 = -1.0;
    let mut best_text_q: f32 = -1.0;
    let mut best_text100_q: f32 = -1.0;
    let mut best_openmetrics_q: f32 = -1.0;

    for entry in accept.split(',') {
        let entry = entry.trim();
        let mut parts = entry.splitn(2, ';');
        let mime = parts.next().unwrap_or("").trim();
        let params_str = parts.next().unwrap_or("");

        let mut q_val: f32 = 1.0;
        let mut has_prom_proto = false;
        let mut has_encoding_delimited = false;
        let mut has_version_100 = false;

        for param in params_str.split(';') {
            let param = param.trim();
            if let Some(q) = param.strip_prefix("q=") {
                q_val = q.parse::<f32>().unwrap_or(0.0).clamp(0.0, 1.0);
            } else if param == "proto=io.prometheus.client.MetricFamily" {
                has_prom_proto = true;
            } else if param == "encoding=delimited" {
                has_encoding_delimited = true;
            } else if param.eq_ignore_ascii_case("version=1.0.0") {
                has_version_100 = true;
            }
        }

        if mime.eq_ignore_ascii_case("application/vnd.google.protobuf")
            && has_prom_proto
            && has_encoding_delimited
        {
            best_proto_q = best_proto_q.max(q_val);
        } else if mime.eq_ignore_ascii_case("application/openmetrics-text") {
            // Accept any openmetrics-text entry; we always respond with 1.0.0.
            best_openmetrics_q = best_openmetrics_q.max(q_val);
        } else if mime.eq_ignore_ascii_case("text/plain") && has_version_100 {
            best_text100_q = best_text100_q.max(q_val);
        } else if mime.eq_ignore_ascii_case("text/plain") || mime == "*/*" {
            best_text_q = best_text_q.max(q_val);
        }
    }

    // Find the highest q across all recognised formats.
    let max_q = best_openmetrics_q
        .max(best_text100_q)
        .max(best_text_q)
        .max(best_proto_q);

    if max_q < 0.0 {
        // No recognised MIME type found — fall back to PrometheusText0.0.4.
        return ResponseFormat::Text;
    }

    // Among formats at max_q prefer the richest:
    //   OpenMetrics > Text1.0.0 > Text0.0.4 > Proto
    // (Proto requires strictly higher q than text, per existing convention.)
    if best_openmetrics_q >= max_q {
        ResponseFormat::OpenMetrics
    } else if best_text100_q >= max_q {
        ResponseFormat::Text100
    } else if best_proto_q > best_text_q {
        ResponseFormat::Proto
    } else {
        ResponseFormat::Text
    }
}

/// Returns `true` when the `Accept-Encoding` header includes `gzip` or `*`.
fn client_accepts_gzip(accept_encoding: Option<&str>) -> bool {
    let Some(enc) = accept_encoding else {
        return false;
    };
    enc.split(',').any(|part| {
        let token = part.trim().split(';').next().unwrap_or("").trim();
        token.eq_ignore_ascii_case("gzip") || token == "*"
    })
}

/// Gzip-compress `data`.  Returns `None` on allocation / I/O failure so the
/// caller can fall back to uncompressed output.
pub(crate) fn gzip_compress(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write as _;
    let mut enc = GzEncoder::new(Vec::with_capacity(data.len() / 2 + 20), Compression::default());
    enc.write_all(data).ok()?;
    enc.finish().ok()
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// Prometheus scrape adapter.
///
/// Construct with [`PrometheusStatsExporter::new`], then call
/// [`spawn_metrics_server`] to start the HTTP listener before attaching to
/// [`crate::flows::stats::StatsFlow::with_stats_exporter`].
pub struct PrometheusStatsExporter {
    latest: Arc<ArcSwap<Option<CompactStats>>>,
}

impl PrometheusStatsExporter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            latest: Arc::new(ArcSwap::from_pointee(None)),
        })
    }

    /// Spawn the `/metrics` HTTP server task.
    ///
    /// The task shuts down when `shutdown` is cancelled.  If the bind fails,
    /// a warning is logged and the task exits immediately (fail-open: the
    /// daemon continues without the metrics endpoint).
    pub fn spawn_metrics_server(
        self: Arc<Self>,
        addr: SocketAddr,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(err) => {
                    warn!(
                        addr = %addr,
                        "prometheus /metrics server: bind failed: {err} \
                         (metrics endpoint disabled)"
                    );
                    return;
                }
            };
            info!(addr = %addr, "prometheus /metrics server listening");
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let latest = self.latest.clone();
                                tokio::spawn(async move {
                                    let io = TokioIo::new(stream);
                                    let _ = http1::Builder::new()
                                        .serve_connection(
                                            io,
                                            service_fn(move |req| {
                                                serve_metrics(req, latest.clone())
                                            }),
                                        )
                                        .await;
                                });
                            }
                            Err(err) => {
                                tracing::debug!(
                                    "prometheus /metrics server: accept error: {err}"
                                );
                            }
                        }
                    }
                }
            }
            info!(addr = %addr, "prometheus /metrics server stopped");
        })
    }
}

impl StatsExporterPort for PrometheusStatsExporter {
    /// Store the snapshot atomically.  Never blocks; no I/O performed here.
    fn export_snapshot(&self, snapshot: &pb::Statistics) {
        self.latest
            .store(Arc::new(Some(CompactStats::from(snapshot))));
    }
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

async fn serve_metrics(
    req: Request<Incoming>,
    latest: Arc<ArcSwap<Option<CompactStats>>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::GET || req.uri().path() != "/metrics" {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    let accept = req
        .headers()
        .get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok());
    let accept_encoding = req
        .headers()
        .get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok());

    let format = negotiate_format(accept);
    let want_gzip = client_accepts_gzip(accept_encoding);

    let guard = latest.load();
    let (body_bytes, content_type): (Vec<u8>, &'static str) = match guard.as_ref().as_ref() {
        Some(stats) => match format {
            ResponseFormat::Proto => (
                render_prometheus_proto(stats),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited",
            ),
            ResponseFormat::Text => (
                render_prometheus_text(stats).into_bytes(),
                "text/plain; version=0.0.4; charset=utf-8",
            ),
            ResponseFormat::Text100 => (
                // Output is identical to 0.0.4; label values already allow UTF-8.
                render_prometheus_text(stats).into_bytes(),
                "text/plain; version=1.0.0; charset=utf-8; escaping=allow-utf-8",
            ),
            ResponseFormat::OpenMetrics => (
                render_openmetrics_text(stats).into_bytes(),
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            ),
        },
        None => (Vec::new(), "text/plain; version=0.0.4; charset=utf-8"),
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type);

    let final_body = if want_gzip {
        match gzip_compress(&body_bytes) {
            Some(compressed) => {
                builder = builder.header("Content-Encoding", "gzip");
                compressed
            }
            // Compression failed — fall back to plain body silently.
            None => body_bytes,
        }
    } else {
        body_bytes
    };

    Ok(builder.body(Full::new(Bytes::from(final_body))).unwrap())
}

// ---------------------------------------------------------------------------
// Prometheus text format 0.0.4 renderer
// ---------------------------------------------------------------------------

fn render_prometheus_text(s: &CompactStats) -> String {
    let mut buf = String::with_capacity(4096);

    // Counters (cumulative, _total suffix)
    counter(&mut buf, "opensnitch_connections_total",
        "Total network connections intercepted", s.connections);
    counter(&mut buf, "opensnitch_accepted_total",
        "Total connections accepted (including DNS responses)", s.accepted);
    counter(&mut buf, "opensnitch_dropped_total",
        "Total connections dropped", s.dropped);
    counter(&mut buf, "opensnitch_dns_responses_total",
        "Total DNS responses tracked", s.dns_responses);
    counter(&mut buf, "opensnitch_ignored_total",
        "Total connections ignored", s.ignored);
    counter(&mut buf, "opensnitch_rule_hits_total",
        "Total rule matches", s.rule_hits);
    counter(&mut buf, "opensnitch_rule_misses_total",
        "Total rule misses (default action applied)", s.rule_misses);

    // Gauges
    gauge(&mut buf, "opensnitch_rules",
        "Current number of loaded rules", s.rules);
    gauge(&mut buf, "opensnitch_uptime_seconds",
        "Daemon uptime in seconds", s.uptime);
    gauge(&mut buf, "opensnitch_subscription_total",
        "Total subscription slots", s.subscription_total);
    gauge(&mut buf, "opensnitch_subscription_ready",
        "Ready subscription slots", s.subscription_ready);
    gauge(&mut buf, "opensnitch_subscription_error",
        "Errored subscription slots", s.subscription_error);

    // Breakdown maps as gauge with label
    labeled_gauge(&mut buf, "opensnitch_connections_by_proto",
        "Connections by transport protocol", "proto", &s.by_proto);
    labeled_gauge(&mut buf, "opensnitch_connections_by_address",
        "Connections by remote address", "address", &s.by_address);
    labeled_gauge(&mut buf, "opensnitch_connections_by_host",
        "Connections by remote host", "host", &s.by_host);
    labeled_gauge(&mut buf, "opensnitch_connections_by_port",
        "Connections by remote port", "port", &s.by_port);
    labeled_gauge(&mut buf, "opensnitch_connections_by_uid",
        "Connections by user UID", "uid", &s.by_uid);
    labeled_gauge(&mut buf, "opensnitch_connections_by_executable",
        "Connections by executable", "executable", &s.by_executable);

    buf
}

fn counter(buf: &mut String, name: &str, help: &str, value: u64) {
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} counter").ok();
    writeln!(buf, "{name} {value}").ok();
}

fn gauge(buf: &mut String, name: &str, help: &str, value: u64) {
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} gauge").ok();
    writeln!(buf, "{name} {value}").ok();
}

fn labeled_gauge(buf: &mut String, name: &str, help: &str, label: &str, pairs: &[(String, u64)]) {
    if pairs.is_empty() {
        return;
    }
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} gauge").ok();
    for (key, value) in pairs {
        let escaped = escape_label_value(key);
        writeln!(buf, "{name}{{{label}=\"{escaped}\"}} {value}").ok();
    }
}

/// Escapes a Prometheus label value per text format 0.0.4 spec.
fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// OpenMetrics text 1.0.0 renderer
// ---------------------------------------------------------------------------

/// Render `stats` as OpenMetrics text 1.0.0.
///
/// Differences from Prometheus text 0.0.4:
/// - Counter MetricFamily names use the base name (without `_total`);
///   samples are rendered as `<base>_total` + `<base>_created`.
/// - Gauges with a unit get a `# UNIT` line after `# TYPE`.
/// - The output is terminated with `# EOF\n`.
fn render_openmetrics_text(s: &CompactStats) -> String {
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    let mut buf = String::with_capacity(4096);

    // Counters (OpenMetrics: base name for HELP/TYPE, _total + _created samples)
    om_counter(&mut buf, "opensnitch_connections",
        "Total network connections intercepted", s.connections, created);
    om_counter(&mut buf, "opensnitch_accepted",
        "Total connections accepted (including DNS responses)", s.accepted, created);
    om_counter(&mut buf, "opensnitch_dropped",
        "Total connections dropped", s.dropped, created);
    om_counter(&mut buf, "opensnitch_dns_responses",
        "Total DNS responses tracked", s.dns_responses, created);
    om_counter(&mut buf, "opensnitch_ignored",
        "Total connections ignored", s.ignored, created);
    om_counter(&mut buf, "opensnitch_rule_hits",
        "Total rule matches", s.rule_hits, created);
    om_counter(&mut buf, "opensnitch_rule_misses",
        "Total rule misses (default action applied)", s.rule_misses, created);

    // Gauges (dimensionless — no UNIT line except for uptime)
    om_gauge(&mut buf, "opensnitch_rules",
        "Current number of loaded rules", "", s.rules);
    om_gauge(&mut buf, "opensnitch_uptime_seconds",
        "Daemon uptime in seconds", "seconds", s.uptime);
    om_gauge(&mut buf, "opensnitch_subscription_total",
        "Total subscription slots", "", s.subscription_total);
    om_gauge(&mut buf, "opensnitch_subscription_ready",
        "Ready subscription slots", "", s.subscription_ready);
    om_gauge(&mut buf, "opensnitch_subscription_error",
        "Errored subscription slots", "", s.subscription_error);

    // Breakdown maps as labeled gauges
    om_labeled_gauge(&mut buf, "opensnitch_connections_by_proto",
        "Connections by transport protocol", "proto", &s.by_proto);
    om_labeled_gauge(&mut buf, "opensnitch_connections_by_address",
        "Connections by remote address", "address", &s.by_address);
    om_labeled_gauge(&mut buf, "opensnitch_connections_by_host",
        "Connections by remote host", "host", &s.by_host);
    om_labeled_gauge(&mut buf, "opensnitch_connections_by_port",
        "Connections by remote port", "port", &s.by_port);
    om_labeled_gauge(&mut buf, "opensnitch_connections_by_uid",
        "Connections by user UID", "uid", &s.by_uid);
    om_labeled_gauge(&mut buf, "opensnitch_connections_by_executable",
        "Connections by executable", "executable", &s.by_executable);

    buf.push_str("# EOF\n");
    buf
}

fn om_counter(buf: &mut String, base_name: &str, help: &str, value: u64, created: f64) {
    writeln!(buf, "# HELP {base_name} {help}").ok();
    writeln!(buf, "# TYPE {base_name} counter").ok();
    writeln!(buf, "{base_name}_total {value}").ok();
    writeln!(buf, "{base_name}_created {created}").ok();
}

fn om_gauge(buf: &mut String, name: &str, help: &str, unit: &str, value: u64) {
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} gauge").ok();
    if !unit.is_empty() {
        writeln!(buf, "# UNIT {name} {unit}").ok();
    }
    writeln!(buf, "{name} {value}").ok();
}

fn om_labeled_gauge(
    buf: &mut String,
    name: &str,
    help: &str,
    label: &str,
    pairs: &[(String, u64)],
) {
    if pairs.is_empty() {
        return;
    }
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} gauge").ok();
    for (key, value) in pairs {
        let escaped = escape_label_value(key);
        writeln!(buf, "{name}{{{label}=\"{escaped}\"}} {value}").ok();
    }
}

// ---------------------------------------------------------------------------
// Prometheus protobuf renderer (io.prometheus.client.MetricFamily, delimited)
// ---------------------------------------------------------------------------

/// Encode `stats` as a length-delimited stream of `MetricFamily` protobuf
/// messages (Prometheus binary protobuf format, `encoding=delimited`).
fn render_prometheus_proto(s: &CompactStats) -> Vec<u8> {
    use prost::Message as _;
    let families = build_proto_families(s);
    let mut buf = Vec::with_capacity(4096);
    for f in &families {
        // "delimited" encoding: each message is prefixed with its varint-encoded length.
        f.encode_length_delimited(&mut buf).ok();
    }
    buf
}

fn build_proto_families(s: &CompactStats) -> Vec<prom_proto::MetricFamily> {
    use prom_proto::*;
    let mut fams: Vec<MetricFamily> = Vec::with_capacity(20);

    macro_rules! counter_fam {
        ($name:expr, $help:expr, $val:expr) => {{
            MetricFamily {
                name: Some($name.to_string()),
                help: Some($help.to_string()),
                r#type: Some(MetricType::Counter as i32),
                metric: vec![Metric {
                    counter: Some(Counter { value: Some($val as f64) }),
                    ..Default::default()
                }],
            }
        }};
    }

    macro_rules! gauge_fam {
        ($name:expr, $help:expr, $val:expr) => {{
            MetricFamily {
                name: Some($name.to_string()),
                help: Some($help.to_string()),
                r#type: Some(MetricType::Gauge as i32),
                metric: vec![Metric {
                    gauge: Some(Gauge { value: Some($val as f64) }),
                    ..Default::default()
                }],
            }
        }};
    }

    fams.push(counter_fam!("opensnitch_connections_total",
        "Total network connections intercepted", s.connections));
    fams.push(counter_fam!("opensnitch_accepted_total",
        "Total connections accepted (including DNS responses)", s.accepted));
    fams.push(counter_fam!("opensnitch_dropped_total",
        "Total connections dropped", s.dropped));
    fams.push(counter_fam!("opensnitch_dns_responses_total",
        "Total DNS responses tracked", s.dns_responses));
    fams.push(counter_fam!("opensnitch_ignored_total",
        "Total connections ignored", s.ignored));
    fams.push(counter_fam!("opensnitch_rule_hits_total",
        "Total rule matches", s.rule_hits));
    fams.push(counter_fam!("opensnitch_rule_misses_total",
        "Total rule misses (default action applied)", s.rule_misses));

    fams.push(gauge_fam!("opensnitch_rules",
        "Current number of loaded rules", s.rules));
    fams.push(gauge_fam!("opensnitch_uptime_seconds",
        "Daemon uptime in seconds", s.uptime));
    fams.push(gauge_fam!("opensnitch_subscription_total",
        "Total subscription slots", s.subscription_total));
    fams.push(gauge_fam!("opensnitch_subscription_ready",
        "Ready subscription slots", s.subscription_ready));
    fams.push(gauge_fam!("opensnitch_subscription_error",
        "Errored subscription slots", s.subscription_error));

    // Breakdown gauges with a single label.
    for (metric_name, label_name, pairs) in [
        ("opensnitch_connections_by_proto",      "proto",       &s.by_proto),
        ("opensnitch_connections_by_address",    "address",     &s.by_address),
        ("opensnitch_connections_by_host",       "host",        &s.by_host),
        ("opensnitch_connections_by_port",       "port",        &s.by_port),
        ("opensnitch_connections_by_uid",        "uid",         &s.by_uid),
        ("opensnitch_connections_by_executable", "executable",  &s.by_executable),
    ] {
        if pairs.is_empty() {
            continue;
        }
        fams.push(MetricFamily {
            name: Some(metric_name.to_string()),
            help: Some(format!("Connections by {label_name}")),
            r#type: Some(MetricType::Gauge as i32),
            metric: pairs
                .iter()
                .map(|(k, v)| Metric {
                    label: vec![LabelPair {
                        name: Some(label_name.to_string()),
                        value: Some(k.clone()),
                    }],
                    gauge: Some(Gauge { value: Some(*v as f64) }),
                    ..Default::default()
                })
                .collect(),
        });
    }

    fams
}

// ---------------------------------------------------------------------------
// Entry point helper: resolve listen address from env
// ---------------------------------------------------------------------------

/// The environment variable used to opt-in to Prometheus metrics export.
///
/// Set to a `host:port` string, e.g. `"127.0.0.1:9100"`.  When absent or
/// empty, the metrics server is not started.
///
/// # Configuration surface precedence (DESIGN_RULES §7)
/// CLI switch `--metrics-prometheus-addr` has highest precedence, then
/// env var (typically used in testing/CI), then `metrics.json`
/// `prometheus.addr` field as the baseline.
pub const PROMETHEUS_ADDR_ENV: &str = "OPENSNITCH_PROMETHEUS_ADDR";


