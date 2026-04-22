use std::{fs, path::Path};

use anyhow::Result;

use crate::models::firewall_config::{FirewallChain, FirewallConfig, FirewallRule};
use crate::models::firewall_storage::{
    PersistedFirewallChain, PersistedFirewallGroup, PersistedFirewallRule, RawFirewallConfig,
};

use super::FirewallService;

impl FirewallService {
    pub(super) fn load_system_firewall_from_path(path: &Path) -> Result<Option<FirewallConfig>> {
        use anyhow::Context;

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
        let parsed: RawFirewallConfig = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse firewall config {}", path.display()))?;

        let mut rules = Vec::new();
        let mut chains = Vec::new();
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
        }))
    }

    pub(super) fn save_system_firewall_to_path(path: &Path, sysfw: &FirewallConfig) -> Result<()> {
        use anyhow::Context;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create firewall config dir {}", parent.display())
            })?;
        }

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
        let persisted = crate::models::firewall_storage::PersistedFirewallConfig {
            enabled: sysfw.enabled,
            version: sysfw.version,
            system_rules,
        };

        let raw = serde_json::to_string_pretty(&persisted)
            .context("failed to serialize system firewall config")?;
        fs::write(path, raw)
            .with_context(|| format!("failed to write firewall config {}", path.display()))?;
        tracing::info!(
            path = %path.display(),
            version = sysfw.version,
            "persisted firewall config to disk"
        );
        Ok(())
    }
}
