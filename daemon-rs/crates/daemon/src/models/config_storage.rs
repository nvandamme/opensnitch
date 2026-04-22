use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct RawConfig {
    #[serde(rename = "Server", default)]
    pub server: RawServerConfig,
    #[serde(rename = "LogLevel", default)]
    pub log_level: Option<u32>,
    #[serde(rename = "DefaultAction", default)]
    pub default_action: String,
    #[serde(rename = "ProcMonitorMethod", default)]
    pub proc_monitor_method: String,
    #[serde(rename = "Firewall", default)]
    pub firewall: String,
    #[serde(rename = "FwOptions", default)]
    pub fw_options: RawFwOptions,
    #[serde(rename = "Rules", default)]
    pub rules: RawRulesOptions,
    #[serde(rename = "TasksOptions", default)]
    pub tasks_options: RawTasksOptions,
    #[serde(rename = "Audit", default)]
    pub audit: RawAuditOptions,
    #[serde(rename = "Stats", default)]
    pub stats: RawStatsOptions,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawServerConfig {
    #[serde(rename = "Address", default)]
    pub address: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFwOptions {
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
