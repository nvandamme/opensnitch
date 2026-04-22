use std::path::PathBuf;

use crate::models::firewall_state::FirewallBackend;
use crate::models::audit::AuditSeverity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalPrincipal {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemotePrincipalBinding {
    pub name: String,
    pub cert_fingerprint: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_san: Option<String>,
    pub local_principal: LocalPrincipal,
    pub capabilities: Vec<String>,
}

/// Active audit event sink configuration.
///
/// Sinks are additive: multiple can be active simultaneously.
/// - `sink_log_lines`: emit events via the `tracing` subscriber (default on — preserves
///   legacy behavior where audit events appear in daemon logs).
/// - `sink_syslog`: emit to local syslog via `LOG_DAEMON` facility / NOTICE severity.
///   Ideal for OpenWrt and flash-constrained systems where `syslogd` handles rotation.
/// - `sink_file`: append NDJSON records to a file path. Rotate externally with
///   `logrotate(8)` or `newsyslog(8)`.
#[derive(Debug, Clone)]
pub struct AuditSinkConfig {
    /// Append NDJSON audit records to this file path.
    pub sink_file: Option<PathBuf>,
    /// Emit audit events to local syslog (LOG_DAEMON / NOTICE).
    pub sink_syslog: bool,
    /// Emit audit events as `tracing` log lines (default: `true`).
    pub sink_log_lines: bool,
    /// Enable verbose hot-path audit emits (default: `false`).
    pub verbose_hot_path: bool,
    /// Lowest severity forwarded to sinks (default: `Debug`).
    pub min_severity: AuditSeverity,
}

impl Default for AuditSinkConfig {
    fn default() -> Self {
        Self {
            sink_file: None,
            sink_syslog: false,
            sink_log_lines: true,
            verbose_hot_path: false,
            min_severity: AuditSeverity::Debug,
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Legacy,
    LocalOnly,
    LocalRemoteCapabilities,
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

#[derive(Debug, Clone, Copy)]
pub struct StatsConfig {
    pub max_events: usize,
    pub max_stats: usize,
    pub workers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    Allow,
    Deny,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultDuration {
    Once,
    Restart,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcMonitorMethod {
    Proc,
    Ebpf,
    Audit,
}

impl std::fmt::Display for ProcMonitorMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proc => f.write_str("proc"),
            Self::Ebpf => f.write_str("ebpf"),
            Self::Audit => f.write_str("audit"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskFallbackPolicy {
    DefaultAction,
    Allow,
    Drop,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub client_addr: String,
    pub log_level: u32,
    pub log_utc: bool,
    pub log_micro: bool,
    pub log_file: Option<PathBuf>,
    pub loggers: Vec<LoggerSinkConfig>,
    pub auth_mode: AuthMode,
    pub client_auth: ClientAuthConfig,
    /// Optional local client principal allowlist.
    ///
    /// - `None`: legacy behavior (unrestricted local control compatibility).
    /// - `Some(vec![])`: explicit deny-all for local privileged control.
    pub local_control_allowed_principals: Option<Vec<LocalPrincipal>>,
    /// Optional local client group GID allowlist (supplementary groups).
    ///
    /// - `None`: no group-based enforcement (legacy).
    /// - `Some(gids)`: peer is allowed if any of its supplementary GIDs are in this set.
    pub local_control_allowed_group_gids: Option<Vec<u32>>,
    /// Optional remote principal binding table for future `local+remote` authorization.
    ///
    /// - `None`: no remote bindings configured.
    /// - `Some(vec![])`: explicit empty binding table.
    pub remote_principal_bindings: Option<Vec<RemotePrincipalBinding>>,
    pub rules_enable_checksums: bool,
    pub default_action: DefaultAction,
    pub ask_timeout_policy: AskFallbackPolicy,
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
    pub network_aliases_path: PathBuf,
    pub tasks_config_path: PathBuf,
    pub stats: StatsConfig,
    pub raw_json: String,
    pub config_path: PathBuf,
    pub audit_socket_path: PathBuf,
    /// Active audit sink configuration (log-lines / syslog / NDJSON file).
    pub audit_sinks: AuditSinkConfig,
    pub flush_conns_on_start: bool,
    pub gc_percent: Option<i32>,
}
