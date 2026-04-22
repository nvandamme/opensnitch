use std::path::Path;

use anyhow::Result;

use crate::models::firewall_state::FirewallBackend;
use crate::{
    models::firewall_config::FirewallConfig,
    platform::{
        adapters::loadable_state_file_store::FileLoadableStateStoreAdapter,
        ports::loadable_state_store_port::FirewallStorePort,
    },
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
        FileLoadableStateStoreAdapter::load_firewall(path, backend)
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
        FileLoadableStateStoreAdapter::save_firewall(path, sysfw, backend)
    }
}
