use std::path::Path;

use anyhow::Result;
use opensnitch_proto::pb;

use std::sync::Arc;

use crate::services::firewall::{FirewallService, state::FirewallRuntime};

impl FirewallService {
    pub(crate) fn snapshot(&self) -> Arc<FirewallRuntime> {
        self.get_snapshot()
    }

    pub(crate) fn system_firewall(&self) -> Arc<Option<pb::SysFirewall>> {
        self.runtime_snapshot().system_firewall.clone()
    }

    pub(crate) fn probe_load_system_firewall(path: &Path) -> Result<Option<pb::SysFirewall>> {
        Self::load_system_firewall_from_path(path)
    }

    pub(crate) fn probe_save_system_firewall(path: &Path, sysfw: &pb::SysFirewall) -> Result<()> {
        Self::save_system_firewall_to_path(path, sysfw)
    }
}
