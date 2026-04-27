use std::path::Path;

use anyhow::Result;

use crate::platform::firewall::state::FirewallBackend;
use crate::{
    platform::firewall::config::FirewallConfig, services::storage::FileLoadableStateStore,
};

use super::FirewallService;

impl FirewallService {
    // Retained for optional introspection/recovery paths and backend parity helpers.
    #[allow(dead_code)]
    pub(super) fn load_system_firewall_from_path(path: &Path) -> Result<Option<FirewallConfig>> {
        Self::load_system_firewall_from_backend_and_path(path, FirewallBackend::Nftables)
    }

    pub(super) fn load_system_firewall_from_backend_and_path(
        path: &Path,
        backend: FirewallBackend,
    ) -> Result<Option<FirewallConfig>> {
        FileLoadableStateStore::load_firewall(path, backend)
    }
    // Retained for optional introspection/recovery paths and backend parity helpers.
    #[allow(dead_code)]
    pub(super) fn save_system_firewall_to_path(path: &Path, sysfw: &FirewallConfig) -> Result<()> {
        Self::save_system_firewall_to_backend_and_path(path, sysfw, FirewallBackend::Nftables)
    }

    pub(super) fn save_system_firewall_to_backend_and_path(
        path: &Path,
        sysfw: &FirewallConfig,
        backend: FirewallBackend,
    ) -> Result<()> {
        FileLoadableStateStore::save_firewall(path, sysfw, backend)
    }
}
