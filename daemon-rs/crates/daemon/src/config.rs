use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::models::{config_storage::RawConfig, firewall_state::FirewallBackend};
use crate::utils::name_parsing::{ParseFromName, normalized_name};

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
    pub default_action: DefaultAction,
    pub proc_monitor_method: ProcMonitorMethod,
    pub firewall_backend: FirewallBackend,
    pub firewall_queue_num: u16,
    pub firewall_queue_bypass: bool,
    pub firewall_config_path: PathBuf,
    pub rules_path: PathBuf,
    pub tasks_config_path: PathBuf,
    pub stats: StatsConfig,
    pub raw_json: String,
    pub config_path: PathBuf,
    pub audit_socket_path: PathBuf,
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
            default_action: DefaultAction::Allow,
            proc_monitor_method: ProcMonitorMethod::Ebpf,
            firewall_backend: FirewallBackend::default(),
            firewall_queue_num: 0,
            firewall_queue_bypass: true,
            firewall_config_path,
            rules_path,
            tasks_config_path,
            stats: StatsConfig::default(),
            raw_json: "{}".to_string(),
            config_path,
            audit_socket_path: PathBuf::from("/var/run/audispd_events"),
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
        let raw: RawConfig = serde_json::from_str(&raw_json)
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
            default_action: DefaultAction::from_name(&raw.default_action),
            proc_monitor_method: ProcMonitorMethod::from_name(&raw.proc_monitor_method),
            firewall_backend: FirewallBackend::from_name(&raw.firewall),
            firewall_queue_num: raw.fw_options.queue_num.unwrap_or(0),
            firewall_queue_bypass: raw.fw_options.queue_bypass.unwrap_or(true),
            firewall_config_path: resolve_runtime_path(
                &raw.fw_options.config_path,
                "daemon/data/system-fw.json",
            ),
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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{Config, DefaultAction, ProcMonitorMethod};
    use crate::{models::firewall_state::FirewallBackend, utils::test_support::TestDir};

    #[test]
    fn from_raw_json_parses_expected_config_values() {
        let dir = TestDir::new("opensnitch-config-parse");
        let config_path = dir.path.join("default-config.json");
        let fw_path = dir.path.join("system-fw.json");
        let rules_path = dir.path.join("rules");
        let tasks_path = dir.path.join("tasks.json");

        fs::create_dir_all(&rules_path).expect("create rules dir");
        fs::write(&fw_path, "{}").expect("create firewall file");
        fs::write(&tasks_path, "[]").expect("create tasks file");

        let raw = format!(
            r#"{{
  "Server": {{"Address": "http://127.0.0.1:50051"}},
  "LogLevel": 4,
  "DefaultAction": "allow",
  "ProcMonitorMethod": "proc",
  "Firewall": "nftables",
  "FwOptions": {{
    "ConfigPath": "{fw}",
    "QueueNum": 7,
    "QueueBypass": false
  }},
  "Rules": {{"Path": "{rules}"}},
  "TasksOptions": {{"ConfigPath": "{tasks}"}},
  "Audit": {{"AudispSocketPath": "/tmp/audisp.sock"}},
  "Stats": {{"MaxEvents": 111, "MaxStats": 33, "Workers": 4}}
}}"#,
            fw = fw_path.display(),
            rules = rules_path.display(),
            tasks = tasks_path.display()
        );

        let cfg = Config::from_raw_json(&config_path, raw.clone()).expect("parse config");

        assert_eq!(cfg.client_addr, "http://127.0.0.1:50051");
        assert_eq!(cfg.log_level, 4);
        assert!(matches!(cfg.default_action, DefaultAction::Allow));
        assert!(matches!(cfg.proc_monitor_method, ProcMonitorMethod::Proc));
        assert!(matches!(cfg.firewall_backend, FirewallBackend::Nftables));
        assert_eq!(cfg.firewall_queue_num, 7);
        assert!(!cfg.firewall_queue_bypass);
        assert_eq!(cfg.firewall_config_path, fw_path);
        assert_eq!(cfg.rules_path, rules_path);
        assert_eq!(cfg.tasks_config_path, tasks_path);
        assert_eq!(cfg.audit_socket_path.to_string_lossy(), "/tmp/audisp.sock");
        assert_eq!(cfg.stats.max_events, 111);
        assert_eq!(cfg.stats.max_stats, 33);
        assert_eq!(cfg.stats.workers, 4);
        assert_eq!(cfg.raw_json, raw);
    }

    #[test]
    fn from_raw_json_invalid_proc_monitor_falls_back_to_proc() {
        let dir = TestDir::new("opensnitch-config-proc-fallback");
        let config_path = dir.path.join("default-config.json");

        let raw = r#"{
  "Server": {"Address": "http://127.0.0.1:50051"},
  "ProcMonitorMethod": "invalid-monitor",
  "Firewall": "nftables"
}"#
        .to_string();

        let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
        assert!(matches!(cfg.proc_monitor_method, ProcMonitorMethod::Proc));
    }
}
