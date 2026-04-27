use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result};

use crate::{
    config::Config,
    models::firewall::storage::{
        PersistedFirewallChain, PersistedFirewallGroup, PersistedFirewallRule,
        PersistedFirewallZone, RawFirewallConfig,
    },
    models::rule::storage::RuleFile,
    platform::firewall::config::{FirewallChain, FirewallConfig, FirewallRule, FirewallZone},
    platform::firewall::state::FirewallBackend,
    services::storage::StorageService,
};

#[cfg(feature = "openwrt")]
use crate::platform::firewall::openwrt_uci::OpenWrtUciFirewallAdapter;

pub(crate) struct FileLoadableStateStore;

impl FileLoadableStateStore {
    pub(crate) async fn load_config(path: &Path) -> Result<Config> {
        let raw_json = StorageService::global()
            .read_to_string_and_notify("config", path)
            .await?;
        Config::from_raw_json(path, raw_json)
    }

    pub(crate) async fn load_rule_file(path: &Path) -> Result<RuleFile> {
        let mut rule_file: RuleFile = StorageService::global()
            .read_and_parse_with_storage_format_and_notify("rule", path)
            .await?;
        rule_file.normalize_legacy_operator_lists()?;
        Ok(rule_file)
    }

    pub(crate) async fn load_alias_map(
        path: &Path,
    ) -> Result<Option<HashMap<String, Vec<String>>>> {
        if !path.exists() {
            return Ok(None);
        }
        StorageService::global()
            .read_and_parse_with_storage_format_if_exists_and_notify("rule", path)
            .await
    }

    pub(crate) fn load_firewall(
        path: &Path,
        backend: FirewallBackend,
    ) -> Result<Option<FirewallConfig>> {
        if !path.exists() {
            tracing::error!(
                "Error reading firewall configuration from disk {}: open {}: no such file or directory",
                path.display(),
                path.display()
            );
            return Ok(None);
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read firewall config {}", path.display()))?;

        #[cfg(feature = "openwrt")]
        if matches!(backend, FirewallBackend::OpenWrtUci) {
            return OpenWrtUciFirewallAdapter::load_firewall_from_uci_text(&raw)
                .map(Some)
                .with_context(|| {
                    format!("failed to parse OpenWrt firewall config {}", path.display())
                });
        }

        #[cfg(not(feature = "openwrt"))]
        let _ = backend;

        let parsed: RawFirewallConfig =
            StorageService::parse_with_storage_format_for_path(path, &raw)
                .with_context(|| format!("failed to parse firewall config {}", path.display()))?;

        let mut rules = Vec::new();
        let mut chains = Vec::new();
        let zones = parsed.zones.into_iter().map(FirewallZone::from).collect();
        for g in parsed.system_rules {
            if let Some(r) = g.rule {
                rules.push(FirewallRule::from(r));
            }
            chains.extend(g.chains.into_iter().map(FirewallChain::from));
        }

        Ok(Some(FirewallConfig {
            enabled: parsed.enabled,
            version: parsed.version,
            rules,
            chains,
            zones,
        }))
    }

    pub(crate) fn save_firewall(
        path: &Path,
        sysfw: &FirewallConfig,
        backend: FirewallBackend,
    ) -> Result<()> {
        #[cfg(feature = "openwrt")]
        if matches!(backend, FirewallBackend::OpenWrtUci) {
            OpenWrtUciFirewallAdapter::persist_firewall_config_at_path(Some(path), sysfw)?;
            tracing::info!(
                path = %path.display(),
                version = sysfw.version,
                "persisted firewall config through OpenWrt UCI CLI"
            );
            return Ok(());
        }

        #[cfg(not(feature = "openwrt"))]
        let _ = backend;

        let mut system_rules: Vec<PersistedFirewallGroup> = sysfw
            .rules
            .iter()
            .cloned()
            .map(|rule| PersistedFirewallGroup {
                rule: Some(PersistedFirewallRule::from(rule)),
                chains: Vec::new(),
            })
            .collect();

        for chain in &sysfw.chains {
            system_rules.push(PersistedFirewallGroup {
                rule: None,
                chains: vec![PersistedFirewallChain::from(chain.clone())],
            });
        }

        let persisted = crate::models::firewall::storage::PersistedFirewallConfig {
            enabled: sysfw.enabled,
            version: sysfw.version,
            system_rules,
            zones: sysfw
                .zones
                .iter()
                .cloned()
                .map(PersistedFirewallZone::from)
                .collect(),
        };

        StorageService::global().convert_and_write_with_storage_format_to_path_sync_and_notify(
            "firewall", path, &persisted, true,
        )?;

        tracing::info!(
            path = %path.display(),
            version = sysfw.version,
            "persisted firewall config to disk"
        );

        Ok(())
    }
}
