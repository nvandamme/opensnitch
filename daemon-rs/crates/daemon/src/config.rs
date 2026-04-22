use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

pub use crate::models::config_runtime::{
    AskFallbackPolicy, ClientAuthConfig, ClientAuthType, ClientTlsOptions, Config, DefaultAction, DefaultDuration,
    LoggerSinkConfig, ProcMonitorMethod, StatsConfig,
};
use crate::models::{
    config_storage::{RawConfig, RawLoggerConfig},
    firewall_state::FirewallBackend,
};
use crate::services::firewall::parse_firewall_backend;
use crate::utils::json_value::object_get_case_insensitive;
use crate::utils::name_parsing::{case_folded, normalized_name};

impl Default for ClientAuthType {
    fn default() -> Self {
        Self::Simple
    }
}

impl ClientAuthType {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "tls-simple" => Self::TlsSimple,
            "tls-mutual" => Self::TlsMutual,
            _ => Self::Simple,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }

    pub fn as_name(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::TlsSimple => "tls-simple",
            Self::TlsMutual => "tls-mutual",
        }
    }
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

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            max_events: 250,
            max_stats: 25,
            workers: 6,
        }
    }
}

impl DefaultAction {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "reject" => Self::Reject,
            "drop" | "deny" => Self::Deny,
            _ => Self::Allow,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }

    pub fn from_raw_config_json(raw_config_json: &str) -> Option<Self> {
        let raw = serde_json::from_str::<serde_json::Value>(raw_config_json).ok()?;
        let action = raw
            .as_object()
            .and_then(|obj| object_get_case_insensitive(obj, &["DefaultAction"]))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        Some(Self::from_name(action))
    }

    pub fn allows(self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn rejects(self) -> bool {
        matches!(self, Self::Reject)
    }
}

impl AskFallbackPolicy {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "allow" => Self::Allow,
            "deny" | "drop" => Self::Drop,
            "default" => Self::DefaultAction,
            _ => Self::DefaultAction,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }
}

impl DefaultDuration {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "always" => Self::Always,
            "untilrestart" => Self::Restart,
            _ => Self::Once,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }
}

impl ProcMonitorMethod {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "audit" => Self::Audit,
            "ebpf" => Self::Ebpf,
            _ => Self::Proc,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }
}

impl Default for Config {
    fn default() -> Self {
        let config_path = Self::dev_default_path("daemon/data/default-config.json");
        let rules_path = Self::dev_default_path("daemon/data/rules");
        let firewall_config_path = Self::dev_default_path("daemon/data/system-fw.json");
        let tasks_config_path = Self::dev_default_path("daemon/data/tasks/tasks.json");

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
            ask_timeout_policy: AskFallbackPolicy::DefaultAction,
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
    fn canonical_config_json_key(key: &str) -> Option<&'static str> {
        let lowered = case_folded(key);
        match lowered.as_str() {
            "server" => Some("Server"),
            "loglevel" => Some("LogLevel"),
            "logutc" => Some("LogUTC"),
            "logmicro" => Some("LogMicro"),
            "defaultaction" => Some("DefaultAction"),
            "asktimeoutpolicy" => Some("AskTimeoutPolicy"),
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
                    let normalized_key =
                        Self::canonical_config_json_key(&key).unwrap_or(key.as_str());
                    normalized.insert(
                        normalized_key.to_string(),
                        Self::normalize_config_json_keys(value),
                    );
                }
                serde_json::Value::Object(normalized)
            }
            serde_json::Value::Array(values) => serde_json::Value::Array(
                values
                    .into_iter()
                    .map(Self::normalize_config_json_keys)
                    .collect::<Vec<_>>(),
            ),
            _ => value,
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

        Self::dev_default_path(dev_fallback_rel)
    }

    fn dev_default_path(rel_path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(rel_path)
    }

    pub fn load_from_default_locations() -> Result<Self> {
        let env_path = std::env::var_os("OPENSNITCH_CONFIG_FILE").map(PathBuf::from);
        let default_path = PathBuf::from("/etc/opensnitchd/default-config.json");
        let config_path = env_path
            .filter(|path| path.exists())
            .or_else(|| default_path.exists().then_some(default_path))
            .unwrap_or_else(|| Self::dev_default_path("daemon/data/default-config.json"));

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
        let normalized_value = Self::normalize_config_json_keys(parsed_value);
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
            ask_timeout_policy: AskFallbackPolicy::from_name(
                raw.ask_timeout_policy.as_deref().unwrap_or_default(),
            ),
            default_duration: DefaultDuration::from_name(&raw.default_duration),
            intercept_unknown: raw.intercept_unknown.unwrap_or(false),
            proc_monitor_method: ProcMonitorMethod::from_name(&raw.proc_monitor_method),
            ebpf_modules_path: if raw.ebpf.modules_path.trim().is_empty() {
                PathBuf::from("/usr/lib/opensnitchd/ebpf")
            } else {
                PathBuf::from(raw.ebpf.modules_path.trim())
            },
            firewall_backend: parse_firewall_backend(&raw.firewall),
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
            firewall_config_path: Self::resolve_runtime_path(
                &raw.fw_options.config_path,
                "daemon/data/system-fw.json",
            ),
            flush_conns_on_start: raw.internal.flush_conns_on_start.unwrap_or(true),
            gc_percent: raw.internal.gc_percent,
            rules_path: Self::resolve_runtime_path(&raw.rules.path, "daemon/data/rules"),
            tasks_config_path: Self::resolve_runtime_path(
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
