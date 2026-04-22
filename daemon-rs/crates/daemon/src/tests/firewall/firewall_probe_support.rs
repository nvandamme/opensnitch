use std::path::Path;

use anyhow::Result;

use std::sync::Arc;

use crate::{
    models::{firewall_config::FirewallConfig, firewall_runtime::FirewallRuntime},
    services::firewall::FirewallService,
};

impl FirewallService {
    pub(crate) fn snapshot(&self) -> Arc<FirewallRuntime> {
        self.get_snapshot()
    }

    pub(crate) fn system_firewall(&self) -> Arc<Option<FirewallConfig>> {
        self.runtime_snapshot().system_firewall.clone()
    }

    pub(crate) fn probe_load_system_firewall(path: &Path) -> Result<Option<FirewallConfig>> {
        Self::load_system_firewall_from_path(path)
    }

    pub(crate) fn probe_save_system_firewall(path: &Path, fw: &FirewallConfig) -> Result<()> {
        Self::save_system_firewall_to_path(path, fw)
    }
}
