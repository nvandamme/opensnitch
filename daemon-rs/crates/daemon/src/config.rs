use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::models::firewall::FirewallBackend;

#[derive(Debug, Clone)]
pub struct Config {
    pub client_addr: String,
    pub log_level: u32,
    pub firewall_backend: FirewallBackend,
    pub firewall_config_path: PathBuf,
    pub rules_path: PathBuf,
    pub raw_json: String,
    pub config_path: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(rename = "Server", default)]
    server: RawServerConfig,
    #[serde(rename = "LogLevel", default)]
    log_level: Option<u32>,
    #[serde(rename = "Firewall", default)]
    firewall: String,
    #[serde(rename = "FwOptions", default)]
    fw_options: RawFwOptions,
    #[serde(rename = "Rules", default)]
    rules: RawRulesOptions,
}

#[derive(Debug, Default, Deserialize)]
struct RawServerConfig {
    #[serde(rename = "Address", default)]
    address: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawFwOptions {
    #[serde(rename = "ConfigPath", default)]
    config_path: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawRulesOptions {
    #[serde(rename = "Path", default)]
    path: String,
}

impl Default for Config {
    fn default() -> Self {
        let config_path = dev_default_path("daemon/data/default-config.json");
        let rules_path = dev_default_path("daemon/data/rules");
        let firewall_config_path = dev_default_path("daemon/data/system-fw.json");

        Self {
            client_addr: "http://127.0.0.1:50051".to_string(),
            log_level: 0,
            firewall_backend: FirewallBackend::default(),
            firewall_config_path,
            rules_path,
            raw_json: "{}".to_string(),
            config_path,
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
        let raw: RawConfig = serde_json::from_str(&raw_json)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;

        Ok(Self {
            client_addr: raw.server.address,
            log_level: raw.log_level.unwrap_or(0),
            firewall_backend: FirewallBackend::from_name(&raw.firewall),
            firewall_config_path: resolve_runtime_path(
                &raw.fw_options.config_path,
                "daemon/data/system-fw.json",
            ),
            rules_path: resolve_runtime_path(&raw.rules.path, "daemon/data/rules"),
            raw_json,
            config_path: path.to_path_buf(),
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").join(rel_path)
}
