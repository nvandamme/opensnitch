//! Port facade for nftables drift-monitor adapter wiring.

use tokio_util::sync::CancellationToken;

use crate::services::{firewall::FirewallService, rule::RuleService};

pub(crate) struct NftMonitorPort;

impl NftMonitorPort {
    pub(crate) fn spawn_nft_drift_listener(
        firewall: FirewallService,
        rules: RuleService,
        shutdown: CancellationToken,
    ) {
        crate::platform::adapters::nft_monitor::spawn_nft_drift_listener(firewall, rules, shutdown)
    }
}
