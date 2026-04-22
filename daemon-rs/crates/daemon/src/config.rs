use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::models::{
    config_storage::{RawConfig, RawLoggerConfig},
    firewall_state::FirewallBackend,
};
use crate::utils::name_parsing::{ParseFromName, normalized_name};

fn canonical_config_json_key(key: &str) -> Option<&'static str> {
    let lowered = key.to_ascii_lowercase();
    match lowered.as_str() {
        "server" => Some("Server"),
        "loglevel" => Some("LogLevel"),
        "logutc" => Some("LogUTC"),
        "logmicro" => Some("LogMicro"),
        "defaultaction" => Some("DefaultAction"),
        "defaultduration" => Some("DefaultDuration"),
        "interceptunknown" => Some("InterceptUnknown"),
        "procmonitormethod" => Some("ProcMonitorMethod"),
        "firewall" => Some("Firewall"),
        "fwoptions" => Some("FwOptions"),
        "rules" => Some("Rules"),
        "tasksoptions" => Some("TasksOptions"),
        "tasks" => Some("Tasks"),
        "audit" => Some("Audit"),
        "ebpf" => Some("Ebpf"),
        "stats" => Some("Stats"),
        "internal" => Some("Internal"),
        "address" => Some("Address"),
        "authentication" => Some("Authentication"),
        "logfile" => Some("LogFile"),
        "loggers" => Some("Loggers"),
        "type" => Some("Type"),
        "tlsoptions" => Some("TLSOptions"),
        "cacert" => Some("CACert"),
        "servercert" => Some("ServerCert"),
        "serverkey" => Some("ServerKey"),
        "clientcert" => Some("ClientCert"),
        "clientkey" => Some("ClientKey"),
        "clientauthtype" => Some("ClientAuthType"),
        "skipverify" => Some("SkipVerify"),
        "name" => Some("Name"),
        "format" => Some("Format"),
        "protocol" => Some("Protocol"),
        "writetimeout" => Some("WriteTimeout"),
        "connecttimeout" => Some("ConnectTimeout"),
        "tag" => Some("Tag"),
        "workers" => Some("Workers"),
        "maxconnectattempts" => Some("MaxConnectAttempts"),
        "monitorinterval" => Some("MonitorInterval"),
        "configpath" => Some("ConfigPath"),
        "queuenum" => Some("QueueNum"),
        "queuebypass" => Some("QueueBypass"),
        "path" => Some("Path"),
        "enablechecksums" => Some("EnableChecksums"),
        "audispsocketpath" => Some("AudispSocketPath"),
        "modulespath" => Some("ModulesPath"),
        "maxevents" => Some("MaxEvents"),
        "maxstats" => Some("MaxStats"),
        "gcpercent" => Some("GCPercent"),
        "flushconnsonstart" => Some("FlushConnsOnStart"),
        _ => None,
    }
}

fn normalize_config_json_keys(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(obj) => {
            let mut normalized = serde_json::Map::with_capacity(obj.len());
            for (key, value) in obj {
                let normalized_key = canonical_config_json_key(&key).unwrap_or(key.as_str());
                normalized.insert(
                    normalized_key.to_string(),
                    normalize_config_json_keys(value),
                );
            }
            serde_json::Value::Object(normalized)
        }
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .into_iter()
                .map(normalize_config_json_keys)
                .collect::<Vec<_>>(),
        ),
        _ => value,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoggerSinkConfig {
    pub name: String,
    pub format: String,
    pub protocol: String,
    pub server: String,
    pub write_timeout: String,
    pub connect_timeout: String,
    pub tag: String,
    pub workers: usize,
    pub max_connect_attempts: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthType {
    Simple,
    TlsSimple,
    TlsMutual,
}

impl Default for ClientAuthType {
    fn default() -> Self {
        Self::Simple
    }
}

impl ParseFromName for ClientAuthType {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "tls-simple" => Self::TlsSimple,
            "tls-mutual" => Self::TlsMutual,
            _ => Self::Simple,
        }
    }
}

impl ClientAuthType {
    pub fn from_name(name: &str) -> Self {
        <Self as ParseFromName>::parse_from_name(name)
    }

    pub fn as_name(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::TlsSimple => "tls-simple",
            Self::TlsMutual => "tls-mutual",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientTlsOptions {
    pub ca_cert: String,
    pub server_cert: String,
    pub server_key: String,
    pub client_cert: String,
    pub client_key: String,
    pub client_auth_type: String,
    pub skip_verify: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ClientAuthConfig {
    pub auth_type: ClientAuthType,
    pub tls_options: ClientTlsOptions,
}

impl From<RawLoggerConfig> for LoggerSinkConfig {
    fn from(raw: RawLoggerConfig) -> Self {
        Self {
            name: raw.name,
            format: raw.format,
            protocol: raw.protocol,
            server: raw.server,
            write_timeout: raw.write_timeout,
            connect_timeout: raw.connect_timeout,
            tag: raw.tag,
            workers: raw.workers.unwrap_or(0),
            max_connect_attempts: raw.max_connect_attempts.unwrap_or(0),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StatsConfig {
    pub max_events: usize,
    pub max_stats: usize,
    pub workers: usize,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            max_events: 250,
            max_stats: 25,
            workers: 6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    Allow,
    Deny,
    Reject,
}

impl DefaultAction {
    pub fn from_name(name: &str) -> Self {
        <Self as ParseFromName>::parse_from_name(name)
    }

    pub fn allows(self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn rejects(self) -> bool {
        matches!(self, Self::Reject)
    }
}

impl ParseFromName for DefaultAction {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "reject" => Self::Reject,
            "deny" => Self::Deny,
            _ => Self::Allow,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultDuration {
    Once,
    Restart,
    Always,
}

impl DefaultDuration {
    pub fn from_name(name: &str) -> Self {
        <Self as ParseFromName>::parse_from_name(name)
    }
}

impl ParseFromName for DefaultDuration {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "always" => Self::Always,
            "untilrestart" => Self::Restart,
            _ => Self::Once,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcMonitorMethod {
    Proc,
    Ebpf,
    Audit,
}

impl ProcMonitorMethod {
    pub fn from_name(name: &str) -> Self {
        <Self as ParseFromName>::parse_from_name(name)
    }
}

impl ParseFromName for ProcMonitorMethod {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "audit" => Self::Audit,
            "ebpf" => Self::Ebpf,
            _ => Self::Proc,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub client_addr: String,
    pub log_level: u32,
    pub log_utc: bool,
    pub log_micro: bool,
    pub log_file: Option<PathBuf>,
    pub loggers: Vec<LoggerSinkConfig>,
    pub client_auth: ClientAuthConfig,
    pub rules_enable_checksums: bool,
    pub default_action: DefaultAction,
    pub default_duration: DefaultDuration,
    pub intercept_unknown: bool,
    pub proc_monitor_method: ProcMonitorMethod,
    pub ebpf_modules_path: PathBuf,
    pub firewall_backend: FirewallBackend,
    pub firewall_monitor_interval: String,
    pub firewall_queue_num: u16,
    pub firewall_queue_bypass: bool,
    pub firewall_config_path: PathBuf,
    pub rules_path: PathBuf,
    pub tasks_config_path: PathBuf,
    pub stats: StatsConfig,
    pub raw_json: String,
    pub config_path: PathBuf,
    pub audit_socket_path: PathBuf,
    pub flush_conns_on_start: bool,
    pub gc_percent: Option<i32>,
}

impl Default for Config {
    fn default() -> Self {
        let config_path = dev_default_path("daemon/data/default-config.json");
        let rules_path = dev_default_path("daemon/data/rules");
        let firewall_config_path = dev_default_path("daemon/data/system-fw.json");
        let tasks_config_path = dev_default_path("daemon/data/tasks/tasks.json");

        Self {
            client_addr: "http://127.0.0.1:50051".to_string(),
            log_level: 0,
            log_utc: true,
            log_micro: false,
            log_file: None,
            loggers: Vec::new(),
            client_auth: ClientAuthConfig::default(),
            rules_enable_checksums: false,
            default_action: DefaultAction::Allow,
            default_duration: DefaultDuration::Once,
            intercept_unknown: false,
            proc_monitor_method: ProcMonitorMethod::Ebpf,
            ebpf_modules_path: PathBuf::from("/usr/lib/opensnitchd/ebpf"),
            firewall_backend: FirewallBackend::default(),
            firewall_monitor_interval: "10s".to_string(),
            firewall_queue_num: 0,
            firewall_queue_bypass: true,
            firewall_config_path,
            rules_path,
            tasks_config_path,
            stats: StatsConfig::default(),
            raw_json: "{}".to_string(),
            config_path,
            audit_socket_path: PathBuf::from("/var/run/audispd_events"),
            flush_conns_on_start: true,
            gc_percent: None,
        }
    }
}

impl Config {
    pub fn load_from_default_locations() -> Result<Self> {
        let env_path = std::env::var_os("OPENSNITCH_CONFIG_FILE").map(PathBuf::from);
        let default_path = PathBuf::from("/etc/opensnitchd/default-config.json");
        let config_path = env_path
            .filter(|path| path.exists())
            .or_else(|| default_path.exists().then_some(default_path))
            .unwrap_or_else(|| dev_default_path("daemon/data/default-config.json"));

        Self::load_from_path(&config_path)
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw_json = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        Self::from_raw_json(path, raw_json)
    }

    pub fn from_raw_json(path: &Path, raw_json: String) -> Result<Self> {
        let parsed_value = serde_json::from_str::<serde_json::Value>(&raw_json)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        let normalized_value = normalize_config_json_keys(parsed_value);
        let raw: RawConfig = serde_json::from_value(normalized_value)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;

        Ok(Self {
            stats: StatsConfig {
                max_events: raw
                    .stats
                    .max_events
                    .unwrap_or(StatsConfig::default().max_events),
                max_stats: raw
                    .stats
                    .max_stats
                    .unwrap_or(StatsConfig::default().max_stats),
                workers: raw.stats.workers.unwrap_or(StatsConfig::default().workers),
            },
            client_addr: raw.server.address,
            log_level: raw.log_level.unwrap_or(0),
            log_utc: raw.log_utc.unwrap_or(true),
            log_micro: raw.log_micro.unwrap_or(false),
            log_file: {
                let value = raw.server.log_file.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(value))
                }
            },
            loggers: raw
                .server
                .loggers
                .into_iter()
                .map(LoggerSinkConfig::from)
                .collect(),
            client_auth: ClientAuthConfig {
                auth_type: ClientAuthType::from_name(&raw.server.authentication.r#type),
                tls_options: ClientTlsOptions {
                    ca_cert: raw.server.authentication.tls_options.ca_cert,
                    server_cert: raw.server.authentication.tls_options.server_cert,
                    server_key: raw.server.authentication.tls_options.server_key,
                    client_cert: raw.server.authentication.tls_options.client_cert,
                    client_key: raw.server.authentication.tls_options.client_key,
                    client_auth_type: raw.server.authentication.tls_options.client_auth_type,
                    skip_verify: raw
                        .server
                        .authentication
                        .tls_options
                        .skip_verify
                        .unwrap_or(false),
                },
            },
            rules_enable_checksums: raw.rules.enable_checksums.unwrap_or(false),
            default_action: DefaultAction::from_name(&raw.default_action),
            default_duration: DefaultDuration::from_name(&raw.default_duration),
            intercept_unknown: raw.intercept_unknown.unwrap_or(false),
            proc_monitor_method: ProcMonitorMethod::from_name(&raw.proc_monitor_method),
            ebpf_modules_path: if raw.ebpf.modules_path.trim().is_empty() {
                PathBuf::from("/usr/lib/opensnitchd/ebpf")
            } else {
                PathBuf::from(raw.ebpf.modules_path.trim())
            },
            firewall_backend: FirewallBackend::from_name(&raw.firewall),
            firewall_monitor_interval: {
                let value = raw.fw_options.monitor_interval.trim();
                if value.is_empty() {
                    "10s".to_string()
                } else {
                    value.to_string()
                }
            },
            firewall_queue_num: raw.fw_options.queue_num.unwrap_or(0),
            firewall_queue_bypass: raw.fw_options.queue_bypass.unwrap_or(true),
            firewall_config_path: resolve_runtime_path(
                &raw.fw_options.config_path,
                "daemon/data/system-fw.json",
            ),
            flush_conns_on_start: raw.internal.flush_conns_on_start.unwrap_or(true),
            gc_percent: raw.internal.gc_percent,
            rules_path: resolve_runtime_path(&raw.rules.path, "daemon/data/rules"),
            tasks_config_path: resolve_runtime_path(
                &raw.tasks_options.config_path,
                "daemon/data/tasks/tasks.json",
            ),
            raw_json,
            config_path: path.to_path_buf(),
            audit_socket_path: if raw.audit.audisp_socket_path.trim().is_empty() {
                PathBuf::from("/var/run/audispd_events")
            } else {
                PathBuf::from(raw.audit.audisp_socket_path.trim())
            },
        })
    }

    pub fn with_client_addr_override(mut self, client_addr: Option<&str>) -> Self {
        if let Some(client_addr) = client_addr.filter(|value| !value.is_empty()) {
            self.client_addr = client_addr.to_string();
        }
        self
    }
}

fn resolve_runtime_path(configured: &str, dev_fallback_rel: &str) -> PathBuf {
    let configured = configured.trim();
    if !configured.is_empty() {
        let configured_path = PathBuf::from(configured);
        if configured_path.exists() {
            return configured_path;
        }
    }

    dev_default_path(dev_fallback_rel)
}

fn dev_default_path(rel_path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(rel_path)
}
