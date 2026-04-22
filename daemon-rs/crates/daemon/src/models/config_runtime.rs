use std::path::PathBuf;

use crate::models::firewall_state::FirewallBackend;

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
    pub client_auth: ClientAuthConfig,
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
    pub tasks_config_path: PathBuf,
    pub stats: StatsConfig,
    pub raw_json: String,
    pub config_path: PathBuf,
    pub audit_socket_path: PathBuf,
    pub flush_conns_on_start: bool,
    pub gc_percent: Option<i32>,
}
