use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct RawConfig {
    #[serde(rename = "Server", default)]
    pub server: RawServerConfig,
    #[serde(rename = "LogLevel", default)]
    pub log_level: Option<u32>,
    #[serde(rename = "LogUTC", default)]
    pub log_utc: Option<bool>,
    #[serde(rename = "LogMicro", default)]
    pub log_micro: Option<bool>,
    #[serde(rename = "DefaultAction", default)]
    pub default_action: String,
    #[serde(rename = "AskTimeoutPolicy", default)]
    pub ask_timeout_policy: Option<String>,
    #[serde(rename = "DefaultDuration", default)]
    pub default_duration: String,
    #[serde(rename = "InterceptUnknown", default)]
    pub intercept_unknown: Option<bool>,
    #[serde(rename = "ProcMonitorMethod", default)]
    pub proc_monitor_method: String,
    #[serde(rename = "Firewall", default)]
    pub firewall: String,
    #[serde(rename = "FwOptions", default)]
    pub fw_options: RawFwOptions,
    #[serde(rename = "Rules", default)]
    pub rules: RawRulesOptions,
    #[serde(rename = "TasksOptions", alias = "Tasks", default)]
    pub tasks_options: RawTasksOptions,
    #[serde(rename = "Audit", default)]
    pub audit: RawAuditOptions,
    #[serde(rename = "Ebpf", default)]
    pub ebpf: RawEbpfOptions,
    #[serde(rename = "Stats", default)]
    pub stats: RawStatsOptions,
    #[serde(rename = "Internal", default)]
    pub internal: RawInternalOptions,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawServerConfig {
    #[serde(rename = "Address", default)]
    pub address: String,
    #[serde(rename = "Authentication", default)]
    pub authentication: RawServerAuth,
    #[serde(rename = "LogFile", default)]
    pub log_file: String,
    #[serde(rename = "Loggers", default)]
    pub loggers: Vec<RawLoggerConfig>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawServerAuth {
    #[serde(rename = "Mode", default)]
    pub mode: String,
    #[serde(rename = "Type", default)]
    pub r#type: String,
    #[serde(rename = "TLSOptions", default)]
    pub tls_options: RawServerTlsOptions,
    #[serde(rename = "AllowedPrincipals", default)]
    pub allowed_principals: Option<Vec<RawPrincipalEntry>>,
    #[serde(rename = "AllowedUsers", default)]
    pub allowed_users: Option<Vec<String>>,
    #[serde(rename = "AllowedGroups", default)]
    pub allowed_groups: Option<Vec<String>>,
    #[serde(rename = "RemotePrincipalBindings", default)]
    pub remote_principal_bindings: Option<Vec<RawRemotePrincipalBinding>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawPrincipalEntry {
    #[serde(rename = "UID", alias = "Uid", alias = "uid", default)]
    pub uid: Option<u32>,
    #[serde(rename = "GID", alias = "Gid", alias = "gid", default)]
    pub gid: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawRemotePrincipalBinding {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "CertFingerprint", default)]
    pub cert_fingerprint: String,
    #[serde(rename = "CertSubject", default)]
    pub cert_subject: String,
    #[serde(rename = "CertSAN", default)]
    pub cert_san: String,
    #[serde(rename = "LocalPrincipal", default)]
    pub local_principal: Option<RawPrincipalEntry>,
    #[serde(rename = "LocalUser", default)]
    pub local_user: String,
    #[serde(rename = "Capabilities", default)]
    pub capabilities: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawServerTlsOptions {
    #[serde(rename = "CACert", default)]
    pub ca_cert: String,
    #[serde(rename = "ServerCert", default)]
    pub server_cert: String,
    #[serde(rename = "ServerKey", default)]
    pub server_key: String,
    #[serde(rename = "ClientCert", default)]
    pub client_cert: String,
    #[serde(rename = "ClientKey", default)]
    pub client_key: String,
    #[serde(rename = "ClientAuthType", default)]
    pub client_auth_type: String,
    #[serde(rename = "SkipVerify", default)]
    pub skip_verify: Option<bool>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct RawLoggerConfig {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Format", default)]
    pub format: String,
    #[serde(rename = "Protocol", default)]
    pub protocol: String,
    #[serde(rename = "Server", default)]
    pub server: String,
    #[serde(rename = "WriteTimeout", default)]
    pub write_timeout: String,
    #[serde(rename = "ConnectTimeout", default)]
    pub connect_timeout: String,
    #[serde(rename = "Tag", default)]
    pub tag: String,
    #[serde(rename = "Workers", default)]
    pub workers: Option<usize>,
    #[serde(rename = "MaxConnectAttempts", default)]
    pub max_connect_attempts: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFwOptions {
    #[serde(rename = "MonitorInterval", default)]
    pub monitor_interval: String,
    #[serde(rename = "ConfigPath", default)]
    pub config_path: String,
    #[serde(rename = "QueueNum", default)]
    pub queue_num: Option<u16>,
    #[serde(rename = "QueueBypass", default)]
    pub queue_bypass: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawRulesOptions {
    #[serde(rename = "Path", default)]
    pub path: String,
    #[serde(rename = "EnableChecksums", default)]
    pub enable_checksums: Option<bool>,
    #[serde(rename = "NetworkAliasesFile", default)]
    pub network_aliases_file: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawTasksOptions {
    #[serde(rename = "ConfigPath", default)]
    pub config_path: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawAuditOptions {
    #[serde(rename = "AudispSocketPath", default)]
    pub audisp_socket_path: String,
    /// File path for the NDJSON audit sink. Empty string = disabled.
    #[serde(rename = "SinkFile", default)]
    pub sink_file: String,
    /// Enable local syslog as an audit sink.
    #[serde(rename = "SinkSyslog", default)]
    pub sink_syslog: Option<bool>,
    /// Emit audit events as tracing log lines (default: true).
    #[serde(rename = "SinkLogLines", default)]
    pub sink_log_lines: Option<bool>,
    /// Emit high-volume hot-path audit events when enabled (default: false).
    #[serde(rename = "VerboseHotPath", default)]
    pub verbose_hot_path: Option<bool>,
    /// Optional minimum severity threshold for sink output.
    #[serde(rename = "MinSeverity", default)]
    pub min_severity: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawEbpfOptions {
    #[serde(rename = "ModulesPath", default)]
    pub modules_path: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawStatsOptions {
    #[serde(rename = "MaxEvents", default)]
    pub max_events: Option<usize>,
    #[serde(rename = "MaxStats", default)]
    pub max_stats: Option<usize>,
    #[serde(rename = "Workers", default)]
    pub workers: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawInternalOptions {
    #[serde(rename = "GCPercent", default)]
    pub gc_percent: Option<i32>,
    #[serde(rename = "FlushConnsOnStart", default)]
    pub flush_conns_on_start: Option<bool>,
}
