//! Runtime model for metrics export configuration.
//!
//! Loaded from `metrics.json` co-located with the daemon config file.
//! This is a pure data model (serde-only): no adapter imports, no I/O beyond
//! the `load_sibling` constructor.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Prometheus scrape config
// ---------------------------------------------------------------------------

/// Configuration for the `/metrics` Prometheus scrape endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrometheusConfig {
    /// TCP address to listen on, e.g. `"127.0.0.1:9100"`.
    /// Absent or empty disables the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
}

// ---------------------------------------------------------------------------
// Push export config
// ---------------------------------------------------------------------------

/// Push format variant (JSON value matches the env-var / CLI vocabulary).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PushFormatConfig {
    /// Prometheus text 0.0.4 posted to `{url}/metrics/job/{job}`.
    #[default]
    Pushgateway,
    /// Prometheus protobuf (MetricFamily delimited) posted to
    /// `{url}/metrics/job/{job}`.
    PushgatewayProto,
    /// InfluxDB line protocol posted to the URL verbatim.
    InfluxDb,
}

#[cfg_attr(not(feature = "metrics-export"), allow(dead_code))]
impl PushFormatConfig {
    /// Return the canonical kebab-case name used by env vars / CLI.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pushgateway => "pushgateway",
            Self::PushgatewayProto => "pushgateway-proto",
            Self::InfluxDb => "influxdb",
        }
    }

    /// Default sentinel: `true` when this is the default value and the caller
    /// should let a lower-precedence source (env var) override it.
    pub fn is_default(&self) -> bool {
        *self == Self::Pushgateway
    }
}

/// Configuration for the push-style stats exporter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PushExportConfig {
    /// Remote push endpoint URL.  Absent/empty disables the push exporter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Output format (default: `pushgateway`).
    #[serde(default)]
    pub format: PushFormatConfig,
    /// Job label for push-gateway / Mimir (default: `"opensnitchd"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<String>,
    /// Bearer / API token (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Gzip-compress push bodies (`Content-Encoding: gzip`).
    #[serde(default)]
    pub gzip: bool,
    /// InfluxDB bucket (default: `"opensnitch"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// InfluxDB organisation (default: empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

// ---------------------------------------------------------------------------
// Top-level metrics config
// ---------------------------------------------------------------------------

/// Top-level metrics export configuration loaded from `metrics.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub prometheus: PrometheusConfig,
    #[serde(default)]
    pub push: PushExportConfig,
}

impl MetricsConfig {
    /// Try to load `metrics.json` co-located with `daemon_config_path`.
    ///
    /// Returns `MetricsConfig::default()` when the file is absent — that is
    /// not an error; all fields default to disabled.  Returns an error only
    /// when the file exists but cannot be parsed.
    pub fn load_sibling(daemon_config_path: &Path) -> anyhow::Result<Self> {
        let path = metrics_json_sibling(daemon_config_path);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
        serde_json::from_str::<Self>(&raw)
            .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", path.display()))
    }
}

// ---------------------------------------------------------------------------
// Metrics-specific CLI overrides
// ---------------------------------------------------------------------------

/// CLI switches that feed into the §7 precedence stack for metrics config.
/// They have highest precedence, overriding env vars and JSON config baseline values.
///
/// Parsed in `main.rs` alongside the existing `CliOverrides` flags.
#[derive(Debug, Default, Clone)]
pub struct MetricsCliOverrides {
    /// `--metrics-prometheus-addr <host:port>` — overrides `prometheus.addr`.
    pub prometheus_addr: Option<String>,
    /// `--metrics-push-url <url>` — overrides `push.url`.
    pub push_url: Option<String>,
    /// `--metrics-push-format <fmt>` — overrides `push.format`
    /// (accepts the same strings as `push.format` in JSON).
    pub push_format: Option<String>,
    /// `--metrics-push-job <name>` — overrides `push.job`.
    pub push_job: Option<String>,
    /// `--metrics-push-token <token>` — overrides `push.token`.
    pub push_token: Option<String>,
    /// `--metrics-push-gzip` (boolean flag, no argument) — force-enable gzip.
    pub push_gzip: Option<bool>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Path of the `metrics.json` sibling to a given daemon config file.
///
/// e.g. `/etc/opensnitchd/default-config.json`
///      → `/etc/opensnitchd/metrics.json`
pub fn metrics_json_sibling(daemon_config_path: &Path) -> PathBuf {
    daemon_config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("metrics.json")
}
