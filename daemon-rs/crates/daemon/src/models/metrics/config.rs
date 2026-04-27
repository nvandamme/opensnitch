//! Runtime model for metrics export configuration.
//!
//! Loaded from `metrics.json` co-located with the daemon config file.
//! This is a pure data model (serde-only): no adapter imports, no I/O beyond
//! the `load_sibling` constructor.

use std::path::{Path, PathBuf};

use crate::services::storage::StorageService;
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
    /// OpenMetrics text 1.0.0 posted to `{url}/metrics/job/{job}`.
    PushgatewayOpenmetrics,
    /// Prometheus protobuf (MetricFamily delimited) posted to
    /// `{url}/metrics/job/{job}`.
    PushgatewayProto,
    /// InfluxDB line protocol posted to the configured write endpoint.
    InfluxDb,
}

#[cfg(any(
    feature = "metrics-http-push-text",
    feature = "metrics-http-push-openmetrics",
    feature = "metrics-http-push-protobuf",
    feature = "metrics-http-push-influxdb"
))]
impl PushFormatConfig {
    /// Return the canonical kebab-case name used by env vars / CLI.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pushgateway => "pushgateway",
            Self::PushgatewayOpenmetrics => "pushgateway-openmetrics",
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
    /// Output format (default: `pushgateway`; Prometheus-only).
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
// Syslog export config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyslogProtocolConfig {
    #[default]
    Udp,
    Tcp,
}

impl SyslogProtocolConfig {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyslogFormatConfig {
    Rfc3164,
    #[default]
    Rfc5424,
}

impl SyslogFormatConfig {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rfc3164 => "rfc3164",
            Self::Rfc5424 => "rfc5424",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogExportConfig {
    /// Remote syslog target (`host:port`). Absent or empty keeps local syslog mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Remote transport protocol. Ignored for local syslog mode.
    #[serde(default)]
    pub protocol: SyslogProtocolConfig,
    /// RFC framing used for remote syslog mode.
    #[serde(default)]
    pub format: SyslogFormatConfig,
    /// Syslog app-name / tag. Defaults to `opensnitchd-rs-metrics`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

impl Default for SyslogExportConfig {
    fn default() -> Self {
        Self {
            server: None,
            protocol: SyslogProtocolConfig::Udp,
            format: SyslogFormatConfig::Rfc5424,
            tag: None,
        }
    }
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
    #[serde(default)]
    pub syslog: SyslogExportConfig,
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
        StorageService::parse_with_storage_format_for_path::<Self>(&path, &raw)
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
    /// `--metrics-syslog-server <host:port>` — overrides `syslog.server`.
    pub syslog_server: Option<String>,
    /// `--metrics-syslog-protocol <udp|tcp>` — overrides `syslog.protocol`.
    pub syslog_protocol: Option<String>,
    /// `--metrics-syslog-format <rfc3164|rfc5424>` — overrides `syslog.format`.
    pub syslog_format: Option<String>,
    /// `--metrics-syslog-tag <name>` — overrides `syslog.tag`.
    pub syslog_tag: Option<String>,
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
