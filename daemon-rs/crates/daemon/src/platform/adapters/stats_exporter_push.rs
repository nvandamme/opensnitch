//! Push-style stats exporter — Prometheus push-gateway, Grafana Mimir, and InfluxDB.
//!
//! Feature-gated behind `metrics-export`.  Sends a `pb::Statistics` snapshot to a
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
//! - `OPENSNITCH_PUSH_FORMAT`  — `pushgateway` (default) | `pushgateway-proto` | `influxdb`
//! - `OPENSNITCH_PUSH_JOB`     — job label for push-gateway (default: `opensnitchd`)
//! - `OPENSNITCH_PUSH_TOKEN`   — bearer / API token for authentication (optional)
//! - `OPENSNITCH_PUSH_GZIP`    — `1` / `true` / `yes` to gzip-compress push bodies (default: off)
//! - `OPENSNITCH_PUSH_BUCKET`  — InfluxDB bucket (default: `opensnitch`)
//! - `OPENSNITCH_PUSH_ORG`     — InfluxDB organisation (default: empty)
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
//! ## InfluxDB (v2 / Cloud / v1)
//!
//! Set `OPENSNITCH_PUSH_FORMAT=influxdb` and `OPENSNITCH_PUSH_URL` to the write
//! endpoint, e.g.:
//!   - v2:    `http://influxdb:8086/api/v2/write?bucket=opensnitch&org=myorg`
//!   - v1:    `http://influxdb:8086/write?db=opensnitch`
//!   - Cloud: `https://us-east-1-1.aws.cloud2.influxdata.com/api/v2/write`
//!
//! The URL is used verbatim for InfluxDB (with `&precision=s` appended when not
//! already present).  `OPENSNITCH_PUSH_BUCKET` and `OPENSNITCH_PUSH_ORG` are only
//! appended as query params when using the default path suffix behaviour (i.e. when
//! no `bucket=` is already present in the URL).
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::models::metrics_snapshot::MetricsSnapshot;
use crate::platform::ports::stats_exporter_port::StatsExporterPort;

use opensnitch_proto::pb;

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
pub(crate) const PUSH_BUCKET_ENV: &str = "OPENSNITCH_PUSH_BUCKET";
pub(crate) const PUSH_ORG_ENV: &str = "OPENSNITCH_PUSH_ORG";

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
    /// InfluxDB line protocol POSTed to the URL verbatim (user provides full path).
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



// ---------------------------------------------------------------------------
// Compact snapshot (no repeated Events slice — avoids per-tick clone overhead)
// ---------------------------------------------------------------------------

struct CompactSnapshot {
    rules: u64,
    uptime: u64,
    dns_responses: u64,
    connections: u64,
    ignored: u64,
    accepted: u64,
    dropped: u64,
    rule_hits: u64,
    rule_misses: u64,
    subscription_stats: Option<pb::SubscriptionStatistics>,
    by_proto: Vec<(String, u64)>,
    by_address: Vec<(String, u64)>,
    by_host: Vec<(String, u64)>,
    by_port: Vec<(String, u64)>,
    by_uid: Vec<(String, u64)>,
    by_executable: Vec<(String, u64)>,
    by_rule: Vec<(String, u64)>,
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
                if let Err(err) = post_snapshot(&client, &config, &endpoint, &snapshot).await {
                    debug!("push stats exporter: push failed: {err}");
                }
            }
        }
    }

    info!("push stats exporter stopped");
}

/// Pre-compute the endpoint URL so we don't rebuild it on every tick.
fn build_endpoint(config: &PushConfig) -> String {
    match &config.format {
        PushFormat::Pushgateway | PushFormat::PushgatewayProto => {
            format!(
                "{}/metrics/job/{}",
                config.url.trim_end_matches('/'),
                config.job
            )
        }
        PushFormat::InfluxDb => {
            // Use the URL verbatim; append precision=s if no precision param present.
            let url = config.url.trim_end_matches('/');
            if url.contains("precision=") {
                url.to_string()
            } else if url.contains('?') {
                // URL already has query params — append ours.
                // Only auto-append bucket/org when there's no bucket= in the URL.
                if url.contains("bucket=") {
                    format!("{url}&precision=s")
                } else {
                    format!("{url}&bucket={}&precision=s", config.bucket)
                }
            } else {
                // No query string at all — build one.
                let mut qs = format!("?bucket={}&precision=s", config.bucket);
                if !config.org.is_empty() {
                    qs.push_str("&org=");
                    qs.push_str(&config.org);
                }
                format!("{url}{qs}")
            }
        }
    }
}

async fn post_snapshot(
    client: &reqwest::Client,
    config: &PushConfig,
    endpoint: &str,
    snapshot: &CompactSnapshot,
) -> Result<(), reqwest::Error> {
    let (body_bytes, content_type): (Vec<u8>, &'static str) = match &config.format {
        PushFormat::Pushgateway => (
            render_prometheus_text(snapshot).into_bytes(),
            "text/plain; version=0.0.4; charset=utf-8",
        ),
        PushFormat::PushgatewayProto => (
            render_prometheus_proto_push(snapshot),
            "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited",
        ),
        PushFormat::InfluxDb => (
            render_influxdb_line_protocol(snapshot).into_bytes(),
            "text/plain; charset=utf-8",
        ),
    };

    let (final_body, gzip_encoded) = if config.gzip {
        match super::stats_exporter_prometheus::gzip_compress(&body_bytes) {
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
        let auth_header = match &config.format {
            PushFormat::InfluxDb => format!("Token {token}"),
            PushFormat::Pushgateway | PushFormat::PushgatewayProto => format!("Bearer {token}"),
        };
        req = req.header("Authorization", auth_header);
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        debug!(
            status = resp.status().as_u16(),
            endpoint,
            "push stats exporter: non-2xx response"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Prometheus text format 0.0.4 (push-gateway body)
// ---------------------------------------------------------------------------

fn render_prometheus_text(s: &CompactSnapshot) -> String {
    let mut buf = String::with_capacity(4096);

    counter(&mut buf, "opensnitch_connections_total",
        "Total network connections intercepted", s.connections);
    counter(&mut buf, "opensnitch_accepted_total",
        "Total connections accepted", s.accepted);
    counter(&mut buf, "opensnitch_dropped_total",
        "Total connections dropped", s.dropped);
    counter(&mut buf, "opensnitch_dns_responses_total",
        "Total DNS responses tracked", s.dns_responses);
    counter(&mut buf, "opensnitch_ignored_total",
        "Total connections ignored", s.ignored);
    counter(&mut buf, "opensnitch_rule_hits_total",
        "Total rule matches", s.rule_hits);
    counter(&mut buf, "opensnitch_rule_misses_total",
        "Total rule misses", s.rule_misses);
    gauge(&mut buf, "opensnitch_rules",
        "Current number of loaded rules", s.rules);
    gauge(&mut buf, "opensnitch_uptime_seconds",
        "Daemon uptime in seconds", s.uptime);
    subscription_gauges_push(&mut buf, s.subscription_stats.as_ref());

    labeled_gauge(&mut buf, "opensnitch_connections_by_proto",
        "Connections by protocol", "proto", &s.by_proto);
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
    labeled_gauge(&mut buf, "opensnitch_rule_hits_by_rule",
        "Rule hits by rule name", "rule", &s.by_rule);

    buf
}

fn counter(buf: &mut String, name: &str, help: &str, value: u64) {
    use std::fmt::Write;
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} counter").ok();
    writeln!(buf, "{name} {value}").ok();
}

fn gauge(buf: &mut String, name: &str, help: &str, value: u64) {
    use std::fmt::Write;
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} gauge").ok();
    writeln!(buf, "{name} {value}").ok();
}

fn labeled_gauge(buf: &mut String, name: &str, help: &str, label: &str, pairs: &[(String, u64)]) {
    use std::fmt::Write;
    if pairs.is_empty() {
        return;
    }
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} gauge").ok();
    for (key, value) in pairs {
        let escaped = escape_prom_label_value(key);
        writeln!(buf, "{name}{{{label}=\"{escaped}\"}} {value}").ok();
    }
}

fn escape_prom_label_value(s: &str) -> String {
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

/// Render subscription scalars and breakdown maps into the push Prometheus text body.
fn subscription_gauges_push(buf: &mut String, sub: Option<&pb::SubscriptionStatistics>) {
    let Some(s) = sub else { return };
    gauge(buf, "opensnitch_subscription_total",          "Total configured subscriptions",          s.total);
    gauge(buf, "opensnitch_subscription_ready",          "Subscriptions in READY state",            s.ready);
    gauge(buf, "opensnitch_subscription_error",          "Subscriptions in ERROR state",            s.error);
    gauge(buf, "opensnitch_subscription_refresh_count",  "Cumulative successful refresh downloads", s.refresh_count);
    gauge(buf, "opensnitch_subscription_refresh_errors", "Cumulative refresh errors",              s.refresh_errors);
    let by_status: Vec<_> = s.by_status.iter().map(|(k, v)| (k.clone(), *v)).collect();
    let by_group:  Vec<_> = s.by_group.iter().map(|(k, v)| (k.clone(), *v)).collect();
    let by_node:   Vec<_> = s.by_node.iter().map(|(k, v)| (k.clone(), *v)).collect();
    labeled_gauge(buf, "opensnitch_subscription_by_status", "Subscription count by status", "status", &by_status);
    labeled_gauge(buf, "opensnitch_subscription_by_group",  "Subscription count by group",  "group",  &by_group);
    labeled_gauge(buf, "opensnitch_subscription_by_node",   "Subscription count by node",   "node",   &by_node);
    if !s.rule_subscriptions.is_empty() {
        use std::fmt::Write;
        writeln!(buf, "# HELP opensnitch_subscription_rule_info Rules backed by a subscription list operator (static N:N mapping)").ok();
        writeln!(buf, "# TYPE opensnitch_subscription_rule_info gauge").ok();
        for entry in &s.rule_subscriptions {
            let rule_esc = escape_prom_label_value(&entry.rule);
            for sub_name in &entry.subscriptions {
                let sub_esc = escape_prom_label_value(sub_name);
                writeln!(buf, "opensnitch_subscription_rule_info{{rule=\"{rule_esc}\",subscription=\"{sub_esc}\"}} 1").ok();
            }
        }
    }
}

/// Build Prometheus protobuf MetricFamily entries for subscription statistics (push).
fn subscription_proto_families_push(fams: &mut Vec<crate::models::prometheus_wire::MetricFamily>, sub: Option<&pb::SubscriptionStatistics>) {
    use crate::models::prometheus_wire::*;
    let Some(s) = sub else { return };
    macro_rules! sub_gauge_fam {
        ($name:expr, $help:expr, $val:expr) => {
            fams.push(MetricFamily {
                name: Some($name.to_string()),
                help: Some($help.to_string()),
                r#type: Some(MetricType::Gauge as i32),
                metric: vec![Metric { gauge: Some(Gauge { value: Some($val as f64) }), ..Default::default() }],
            });
        };
    }
    sub_gauge_fam!("opensnitch_subscription_total",           "Total configured subscriptions",          s.total);
    sub_gauge_fam!("opensnitch_subscription_ready",           "Subscriptions in READY state",            s.ready);
    sub_gauge_fam!("opensnitch_subscription_error",           "Subscriptions in ERROR state",            s.error);
    sub_gauge_fam!("opensnitch_subscription_refresh_count",   "Cumulative successful refresh downloads", s.refresh_count);
    sub_gauge_fam!("opensnitch_subscription_refresh_errors",  "Cumulative refresh errors",               s.refresh_errors);
    for (map_name, label_key, map) in [
        ("opensnitch_subscription_by_status", "status", &s.by_status),
        ("opensnitch_subscription_by_group",  "group",  &s.by_group),
        ("opensnitch_subscription_by_node",   "node",   &s.by_node),
    ] {
        if map.is_empty() { continue; }
        fams.push(MetricFamily {
            name: Some(map_name.to_string()),
            help: Some(format!("Subscription count by {label_key}")),
            r#type: Some(MetricType::Gauge as i32),
            metric: map.iter().map(|(k, v)| Metric {
                label: vec![LabelPair { name: Some(label_key.to_string()), value: Some(k.clone()) }],
                gauge: Some(Gauge { value: Some(*v as f64) }),
                ..Default::default()
            }).collect(),
        });
    }
    if !s.rule_subscriptions.is_empty() {
        fams.push(MetricFamily {
            name: Some("opensnitch_subscription_rule_info".to_string()),
            help: Some("Rules backed by a subscription list operator (static N:N mapping)".to_string()),
            r#type: Some(MetricType::Gauge as i32),
            metric: s.rule_subscriptions.iter().flat_map(|entry| {
                entry.subscriptions.iter().map(|sub_name| Metric {
                    label: vec![
                        LabelPair { name: Some("rule".to_string()), value: Some(entry.rule.clone()) },
                        LabelPair { name: Some("subscription".to_string()), value: Some(sub_name.clone()) },
                    ],
                    gauge: Some(Gauge { value: Some(1.0) }),
                    ..Default::default()
                })
            }).collect(),
        });
    }
}

// ---------------------------------------------------------------------------
// InfluxDB line protocol
// ---------------------------------------------------------------------------

fn render_influxdb_line_protocol(s: &CompactSnapshot) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut buf = String::with_capacity(4096);

    // Scalar counters + gauges as a single measurement line.
    buf.push_str("opensnitch_stats ");
    buf.push_str(&format!(
        "rules={rules}i,uptime={uptime}i,connections={connections}i,accepted={accepted}i,\
         dropped={dropped}i,dns_responses={dns}i,ignored={ignored}i,\
         rule_hits={rule_hits}i,rule_misses={rule_misses}i",
        rules = s.rules,
        uptime = s.uptime,
        connections = s.connections,
        accepted = s.accepted,
        dropped = s.dropped,
        dns = s.dns_responses,
        ignored = s.ignored,
        rule_hits = s.rule_hits,
        rule_misses = s.rule_misses,
    ));
    buf.push(' ');
    buf.push_str(&ts.to_string());
    buf.push('\n');

    // Per-subscription health as tagged measurement lines.
    if let Some(sub) = &s.subscription_stats {
        for (status, count) in &sub.by_status {
            let st = escape_influx_tag_value(status);
            buf.push_str(&format!(
                "opensnitch_subscription_by_status,status={st} count={count}i {ts}\n"
            ));
        }
        for (group, count) in &sub.by_group {
            let g = escape_influx_tag_value(group);
            buf.push_str(&format!(
                "opensnitch_subscription_by_group,group={g} count={count}i {ts}\n"
            ));
        }
        for (node, count) in &sub.by_node {
            let n = escape_influx_tag_value(node);
            buf.push_str(&format!(
                "opensnitch_subscription_by_node,node={n} count={count}i {ts}\n"
            ));
        }
        let mut rule_pairs: Vec<_> = sub.rule_subscriptions.iter().collect();
        rule_pairs.sort_by_key(|e| e.rule.as_str());
        for entry in rule_pairs {
            let r = escape_influx_tag_value(&entry.rule);
            for sub_name in &entry.subscriptions {
                let sn = escape_influx_tag_value(sub_name);
                buf.push_str(&format!(
                    "opensnitch_subscription_rule,rule={r},subscription={sn} info=1i {ts}\n"
                ));
            }
        }
    }

    // Breakdown maps as tagged measurement lines.
    influx_breakdown(&mut buf, "opensnitch_by_proto", "proto", &s.by_proto, ts);
    influx_breakdown(&mut buf, "opensnitch_by_address", "address", &s.by_address, ts);
    influx_breakdown(&mut buf, "opensnitch_by_host", "host", &s.by_host, ts);
    influx_breakdown(&mut buf, "opensnitch_by_port", "port", &s.by_port, ts);
    influx_breakdown(&mut buf, "opensnitch_by_uid", "uid", &s.by_uid, ts);
    influx_breakdown(&mut buf, "opensnitch_by_executable", "executable", &s.by_executable, ts);
    influx_breakdown(&mut buf, "opensnitch_by_rule", "rule", &s.by_rule, ts);

    buf
}

fn influx_breakdown(buf: &mut String, measurement: &str, tag_key: &str, pairs: &[(String, u64)], ts: u64) {
    for (key, value) in pairs {
        let escaped_key = escape_influx_tag_value(key);
        buf.push_str(&format!(
            "{measurement},{tag_key}={escaped_key} connections={value}i {ts}\n"
        ));
    }
}

/// Escape InfluxDB line protocol tag values: escape `,`, ` `, `=`, and `\`.
fn escape_influx_tag_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            ',' => out.push_str("\\,"),
            ' ' => out.push_str("\\ "),
            '=' => out.push_str("\\="),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Prometheus protobuf renderer (push-gateway proto body)
//
// Reuses the shared `prom_proto` types from the scrape adapter so both
// endpoints emit exactly the same MetricFamily schema.
// ---------------------------------------------------------------------------

fn render_prometheus_proto_push(s: &CompactSnapshot) -> Vec<u8> {
    use prost::Message as _;
    use crate::models::prometheus_wire::*;

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
        "Total connections accepted", s.accepted));
    fams.push(counter_fam!("opensnitch_dropped_total",
        "Total connections dropped", s.dropped));
    fams.push(counter_fam!("opensnitch_dns_responses_total",
        "Total DNS responses tracked", s.dns_responses));
    fams.push(counter_fam!("opensnitch_ignored_total",
        "Total connections ignored", s.ignored));
    fams.push(counter_fam!("opensnitch_rule_hits_total",
        "Total rule matches", s.rule_hits));
    fams.push(counter_fam!("opensnitch_rule_misses_total",
        "Total rule misses", s.rule_misses));
    fams.push(gauge_fam!("opensnitch_rules",
        "Current number of loaded rules", s.rules));
    fams.push(gauge_fam!("opensnitch_uptime_seconds",
        "Daemon uptime in seconds", s.uptime));
    subscription_proto_families_push(&mut fams, s.subscription_stats.as_ref());

    for (metric_name, label_name, pairs) in [
        ("opensnitch_connections_by_proto",      "proto",       &s.by_proto),
        ("opensnitch_connections_by_address",    "address",     &s.by_address),
        ("opensnitch_connections_by_host",       "host",        &s.by_host),
        ("opensnitch_connections_by_port",       "port",        &s.by_port),
        ("opensnitch_connections_by_uid",        "uid",         &s.by_uid),
        ("opensnitch_connections_by_executable", "executable",  &s.by_executable),
        ("opensnitch_rule_hits_by_rule",          "rule",        &s.by_rule),
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

    let mut buf = Vec::with_capacity(4096);
    for f in &fams {
        f.encode_length_delimited(&mut buf).ok();
    }
    buf
}

// ---------------------------------------------------------------------------
// Fan-out adapter
// ---------------------------------------------------------------------------

/// Fan-out adapter: dispatches `export_snapshot` to multiple inner exporters.
///
/// Used when more than one exporter is active simultaneously (e.g. both Prometheus
/// scrape endpoint and InfluxDB push).
pub struct MultiStatsExporter {
    exporters: Vec<Arc<dyn StatsExporterPort>>,
}

impl MultiStatsExporter {
    pub fn new(exporters: Vec<Arc<dyn StatsExporterPort>>) -> Arc<Self> {
        Arc::new(Self { exporters })
    }
}

impl StatsExporterPort for MultiStatsExporter {
    fn export_snapshot(&self, snapshot: &MetricsSnapshot) {
        for exporter in &self.exporters {
            exporter.export_snapshot(snapshot);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/metrics/stats_exporter_push.rs"]
mod push_exporter_tests;
