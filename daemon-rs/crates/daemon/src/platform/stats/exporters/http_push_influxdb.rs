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
    tx: mpsc::Sender<Arc<CompactSnapshot>>,
}

pub(crate) type CompactSnapshot = MetricsExportSnapshot;

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
        if self.tx.try_send(snapshot.export_view()).is_err() {
            debug!("influxdb stats exporter: channel full - snapshot dropped");
        }
    }
}

async fn push_worker(
    mut rx: mpsc::Receiver<Arc<CompactSnapshot>>,
    config: InfluxDbConfig,
    shutdown: CancellationToken,
) {
    let client = build_http_client();

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
    client: &HttpClient,
    config: &InfluxDbConfig,
    endpoint: &str,
    snapshot: &CompactSnapshot,
) -> Result<()> {
    let body_bytes = super::encoder_influxdb::render_line_protocol(snapshot).into_bytes();

    let (final_body, gzip_encoded) = if config.gzip {
        match gzip_compress(&body_bytes) {
            Some(c) => (c, true),
            None => (body_bytes, false),
        }
    } else {
        (body_bytes, false)
    };

    let mut headers: Vec<(HeaderName, String)> =
        vec![(CONTENT_TYPE, "text/plain; charset=utf-8".to_string())];

    if gzip_encoded {
        headers.push((CONTENT_ENCODING, "gzip".to_string()));
    }

    if let Some(ref token) = config.token {
        headers.push((AUTHORIZATION, format!("Token {token}")));
    }

    let request = build_request(Method::POST, endpoint, &headers, final_body)?;
    let response = send_request(client, request, HTTP_TIMEOUT, None).await?;
    if !response.status.is_success() {
        debug!(
            status = response.status.as_u16(),
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
