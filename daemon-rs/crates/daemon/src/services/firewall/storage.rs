use std::{fs, path::Path};

use anyhow::Result;
use opensnitch_proto::pb;

use crate::models::firewall_storage::{PersistedFwChains, RawSysFirewall};

use super::FirewallService;

impl FirewallService {
    pub(super) fn load_system_firewall_from_path(path: &Path) -> Result<Option<pb::SysFirewall>> {
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
        let parsed: RawSysFirewall = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse firewall config {}", path.display()))?;

        Ok(Some(pb::SysFirewall {
            enabled: parsed.enabled,
            version: parsed.version,
            system_rules: parsed
                .system_rules
                .into_iter()
                .map(pb::FwChains::from)
                .collect(),
        }))
    }

    pub(super) fn save_system_firewall_to_path(path: &Path, sysfw: &pb::SysFirewall) -> Result<()> {
        use anyhow::Context;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create firewall config dir {}", parent.display())
            })?;
        }

        let persisted = crate::models::firewall_storage::PersistedSysFirewall {
            enabled: sysfw.enabled,
            version: sysfw.version,
            system_rules: sysfw
                .system_rules
                .iter()
                .cloned()
                .map(PersistedFwChains::from)
                .collect(),
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
