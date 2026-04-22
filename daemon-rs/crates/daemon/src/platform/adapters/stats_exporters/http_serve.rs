//! Prometheus HTTP scrape adapter core for `StatsExporterPort`.
//!
//! This module owns HTTP server lifecycle and content negotiation only.
//! Rendering is delegated to format-specific encoder files:
//! - `encoder_prometheus_text`
//! - `encoder_prometheus_openmetrics`
//! - `encoder_prometheus_protobuf`
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::models::metrics_snapshot::MetricsSnapshot;
use crate::platform::ports::stats_exporter_port::StatsExporterPort;
use transport_wire_core::WireSubscriptionStatistics;

pub(crate) struct CompactStats {
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

impl From<&MetricsSnapshot> for CompactStats {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseFormat {
    Text,
    Text100,
    OpenMetrics,
    Proto,
}

#[allow(unused_mut)]
/// Negotiate the response format from the client's `Accept` header.
///
/// Returns:
/// - `Some(format)` — format to use (either the best match or the default
///   when no `Accept` header was sent).
/// - `None` — the client sent an `Accept` header that names formats not
///   enabled in this build; respond with **406 Not Acceptable**.
#[allow(unused_mut)]
fn negotiate_format(accept: Option<&str>) -> Option<ResponseFormat> {
    let Some(accept) = accept else {
        return Some(default_format());
    };

    let mut best_text_q: f32 = -1.0;
    let mut best_text100_q: f32 = -1.0;
    let mut best_openmetrics_q: f32 = -1.0;
    let mut best_proto_q: f32 = -1.0;

    for entry in accept.split(',') {
        let entry = entry.trim();
        let mut parts = entry.splitn(2, ';');
        let mime = parts.next().unwrap_or("").trim();
        let params_str = parts.next().unwrap_or("");

        let mut q_val: f32 = 1.0;
        let mut has_version_100 = false;
        let mut has_prom_proto = false;
        let mut has_encoding_delimited = false;

        for param in params_str.split(';') {
            let param = param.trim();
            if let Some(q) = param.strip_prefix("q=") {
                q_val = q.parse::<f32>().unwrap_or(0.0).clamp(0.0, 1.0);
            } else if param.eq_ignore_ascii_case("version=1.0.0") {
                has_version_100 = true;
            } else if param == "proto=io.prometheus.client.MetricFamily" {
                has_prom_proto = true;
            } else if param == "encoding=delimited" {
                has_encoding_delimited = true;
            }
        }

        if mime.eq_ignore_ascii_case("application/openmetrics-text") {
            #[cfg(feature = "metrics-http-serve-openmetrics")]
            {
                best_openmetrics_q = best_openmetrics_q.max(q_val);
            }
        } else if mime.eq_ignore_ascii_case("application/vnd.google.protobuf")
            && has_prom_proto
            && has_encoding_delimited
        {
            #[cfg(feature = "metrics-http-serve-protobuf")]
            {
                best_proto_q = best_proto_q.max(q_val);
            }
        } else if mime.eq_ignore_ascii_case("text/plain") && has_version_100 {
            #[cfg(feature = "metrics-http-serve-text")]
            {
                best_text100_q = best_text100_q.max(q_val);
            }
        } else if mime.eq_ignore_ascii_case("text/plain") || mime == "*/*" {
            #[cfg(feature = "metrics-http-serve-text")]
            {
                best_text_q = best_text_q.max(q_val);
            }
        }
    }

    let max_q = best_openmetrics_q
        .max(best_text100_q)
        .max(best_text_q)
        .max(best_proto_q);

    if max_q < 0.0 {
        // The client explicitly listed formats but none are compiled in.
        return None;
    }

    if best_openmetrics_q >= max_q {
        Some(ResponseFormat::OpenMetrics)
    } else if best_text100_q >= max_q {
        Some(ResponseFormat::Text100)
    } else if best_text_q >= max_q {
        Some(ResponseFormat::Text)
    } else {
        Some(ResponseFormat::Proto)
    }
}

#[allow(unreachable_code)]
fn default_format() -> ResponseFormat {
    #[cfg(feature = "metrics-http-serve-openmetrics")]
    {
        return ResponseFormat::OpenMetrics;
    }
    #[cfg(all(
        not(feature = "metrics-http-serve-openmetrics"),
        feature = "metrics-http-serve-text"
    ))]
    {
        return ResponseFormat::Text;
    }
    #[cfg(all(
        not(feature = "metrics-http-serve-openmetrics"),
        not(feature = "metrics-http-serve-text"),
        feature = "metrics-http-serve-protobuf"
    ))]
    {
        return ResponseFormat::Proto;
    }
    ResponseFormat::Text
}

fn client_accepts_gzip(accept_encoding: Option<&str>) -> bool {
    let Some(enc) = accept_encoding else {
        return false;
    };
    enc.split(',').any(|part| {
        let token = part.trim().split(';').next().unwrap_or("").trim();
        token.eq_ignore_ascii_case("gzip") || token == "*"
    })
}

pub struct PrometheusStatsExporter {
    latest: Arc<ArcSwap<Option<CompactStats>>>,
}

impl PrometheusStatsExporter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            latest: Arc::new(ArcSwap::from_pointee(None)),
        })
    }

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
                        "prometheus /metrics server: bind failed: {err} (metrics endpoint disabled)"
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
                                            service_fn(move |req| serve_metrics(req, latest.clone())),
                                        )
                                        .await;
                                });
                            }
                            Err(err) => tracing::debug!("prometheus /metrics server: accept error: {err}"),
                        }
                    }
                }
            }
            info!(addr = %addr, "prometheus /metrics server stopped");
        })
    }
}

impl StatsExporterPort for PrometheusStatsExporter {
    fn export_snapshot(&self, snapshot: &MetricsSnapshot) {
        self.latest
            .store(Arc::new(Some(CompactStats::from(snapshot))));
    }
}

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

    let format = match negotiate_format(accept) {
        Some(f) => f,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::NOT_ACCEPTABLE)
                .header("Content-Type", "text/plain; charset=utf-8")
                .body(Full::new(Bytes::from_static(
                    b"No metrics format matching your Accept header is enabled in this build",
                )))
                .unwrap());
        }
    };
    let want_gzip = client_accepts_gzip(accept_encoding);

    let guard = latest.load();
    let (body_bytes, content_type): (Vec<u8>, &'static str) = match guard.as_ref().as_ref() {
        Some(stats) => match format {
            ResponseFormat::Text => (
                render_prometheus_text(stats).into_bytes(),
                "text/plain; version=0.0.4; charset=utf-8",
            ),
            ResponseFormat::Text100 => (
                render_prometheus_text(stats).into_bytes(),
                "text/plain; version=1.0.0; charset=utf-8; escaping=allow-utf-8",
            ),
            ResponseFormat::OpenMetrics => (
                render_openmetrics_text(stats).into_bytes(),
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            ),
            ResponseFormat::Proto => (
                render_prometheus_proto(stats),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited",
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
            None => body_bytes,
        }
    } else {
        body_bytes
    };

    Ok(builder.body(Full::new(Bytes::from(final_body))).unwrap())
}

#[allow(unreachable_code)]
pub(crate) fn render_prometheus_text(s: &CompactStats) -> String {
    #[cfg(feature = "metrics-http-serve-text")]
    {
        use super::encoder_prometheus_text::{PrometheusTextSnapshot, render_prometheus_text};
        return render_prometheus_text(&PrometheusTextSnapshot {
            rules: s.rules,
            uptime: s.uptime,
            dns_responses: s.dns_responses,
            connections: s.connections,
            ignored: s.ignored,
            accepted: s.accepted,
            dropped: s.dropped,
            rule_hits: s.rule_hits,
            rule_misses: s.rule_misses,
            subscription_stats: s.subscription_stats.clone(),
            by_proto: s.by_proto.clone(),
            by_address: s.by_address.clone(),
            by_host: s.by_host.clone(),
            by_port: s.by_port.clone(),
            by_uid: s.by_uid.clone(),
            by_executable: s.by_executable.clone(),
            by_rule: s.by_rule.clone(),
        });
    }
    let _ = s;
    String::new()
}

#[allow(unreachable_code)]
pub(crate) fn render_openmetrics_text(s: &CompactStats) -> String {
    #[cfg(feature = "metrics-http-serve-openmetrics")]
    {
        use super::encoder_prometheus_openmetrics::{OpenMetricsSnapshot, render_openmetrics_text};
        return render_openmetrics_text(&OpenMetricsSnapshot {
            rules: s.rules,
            uptime: s.uptime,
            dns_responses: s.dns_responses,
            connections: s.connections,
            ignored: s.ignored,
            accepted: s.accepted,
            dropped: s.dropped,
            rule_hits: s.rule_hits,
            rule_misses: s.rule_misses,
            subscription_stats: s.subscription_stats.clone(),
            by_proto: s.by_proto.clone(),
            by_address: s.by_address.clone(),
            by_host: s.by_host.clone(),
            by_port: s.by_port.clone(),
            by_uid: s.by_uid.clone(),
            by_executable: s.by_executable.clone(),
            by_rule: s.by_rule.clone(),
        });
    }
    let _ = s;
    String::new()
}

#[allow(unreachable_code)]
pub(crate) fn render_prometheus_proto(s: &CompactStats) -> Vec<u8> {
    #[cfg(feature = "metrics-http-serve-protobuf")]
    {
        use super::encoder_prometheus_protobuf::{ProtoSnapshot, render_prometheus_proto};
        return render_prometheus_proto(&ProtoSnapshot {
            rules: s.rules,
            uptime: s.uptime,
            dns_responses: s.dns_responses,
            connections: s.connections,
            ignored: s.ignored,
            accepted: s.accepted,
            dropped: s.dropped,
            rule_hits: s.rule_hits,
            rule_misses: s.rule_misses,
            subscription_stats: s.subscription_stats.clone(),
            by_proto: s.by_proto.clone(),
            by_address: s.by_address.clone(),
            by_host: s.by_host.clone(),
            by_port: s.by_port.clone(),
            by_uid: s.by_uid.clone(),
            by_executable: s.by_executable.clone(),
            by_rule: s.by_rule.clone(),
        });
    }
    let _ = s;
    Vec::new()
}

pub const PROMETHEUS_ADDR_ENV: &str = "OPENSNITCH_PROMETHEUS_ADDR";

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
#[path = "../../../tests/metrics/stats_exporter_prometheus.rs"]
mod prometheus_exporter_tests;
