use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::models::metrics_snapshot::MetricsSnapshot;
use crate::platform::ports::stats_exporter_port::StatsExporterPort;
use transport_wire_core::WireSubscriptionStatistics;

pub const INFLUX_URL_ENV: &str = "OPENSNITCH_INFLUXDB_URL";
pub(crate) const INFLUX_TOKEN_ENV: &str = "OPENSNITCH_INFLUXDB_TOKEN";
pub(crate) const INFLUX_GZIP_ENV: &str = "OPENSNITCH_INFLUXDB_GZIP";
pub(crate) const INFLUX_BUCKET_ENV: &str = "OPENSNITCH_INFLUXDB_BUCKET";
pub(crate) const INFLUX_ORG_ENV: &str = "OPENSNITCH_INFLUXDB_ORG";

const CHANNEL_CAPACITY: usize = 4;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct InfluxDbConfig {
    pub url: String,
    pub token: Option<String>,
    pub gzip: bool,
    pub bucket: String,
    pub org: String,
}

pub struct InfluxDbStatsExporter {
    tx: mpsc::Sender<CompactSnapshot>,
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

impl InfluxDbStatsExporter {
    pub fn new(config: InfluxDbConfig, shutdown: CancellationToken) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let exporter = Arc::new(Self { tx });
        tokio::spawn(push_worker(rx, config, shutdown));
        exporter
    }
}

impl StatsExporterPort for InfluxDbStatsExporter {
    fn export_snapshot(&self, snapshot: &MetricsSnapshot) {
        let compact = CompactSnapshot::from(snapshot);
        if self.tx.try_send(compact).is_err() {
            debug!("influxdb stats exporter: channel full - snapshot dropped");
        }
    }
}

async fn push_worker(
    mut rx: mpsc::Receiver<CompactSnapshot>,
    config: InfluxDbConfig,
    shutdown: CancellationToken,
) {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let endpoint = build_endpoint(&config);
    info!(endpoint = %endpoint, "influxdb stats exporter started");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            maybe = rx.recv() => {
                let Some(snapshot) = maybe else { break };
                if let Err(err) = post_snapshot(&client, &config, &endpoint, &snapshot).await {
                    debug!("influxdb stats exporter: push failed: {err}");
                }
            }
        }
    }

    info!("influxdb stats exporter stopped");
}

fn build_endpoint(config: &InfluxDbConfig) -> String {
    let url = config.url.trim_end_matches('/');
    if url.contains("precision=") {
        return url.to_string();
    }
    if url.contains('?') {
        if url.contains("bucket=") {
            format!("{url}&precision=s")
        } else {
            format!("{url}&bucket={}&precision=s", config.bucket)
        }
    } else {
        let mut qs = format!("?bucket={}&precision=s", config.bucket);
        if !config.org.is_empty() {
            qs.push_str("&org=");
            qs.push_str(&config.org);
        }
        format!("{url}{qs}")
    }
}

async fn post_snapshot(
    client: &reqwest::Client,
    config: &InfluxDbConfig,
    endpoint: &str,
    snapshot: &CompactSnapshot,
) -> Result<(), reqwest::Error> {
    let body_bytes = super::encoder_influxdb::render_line_protocol(snapshot).into_bytes();

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
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(final_body);

    if gzip_encoded {
        req = req.header("Content-Encoding", "gzip");
    }

    if let Some(ref token) = config.token {
        req = req.header("Authorization", format!("Token {token}"));
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        debug!(
            status = resp.status().as_u16(),
            endpoint, "influxdb stats exporter: non-2xx response"
        );
    }
    Ok(())
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
