#![cfg(feature = "openwrt")]

use anyhow::Result;

/// Runtime command runner abstraction for OpenWrt `uci` CLI calls.
///
/// This is a system-command boundary used by OpenWrt persistence adapters.
// Staged OpenWrt port surface; concrete runtime call sites land in follow-up slices.
#[allow(dead_code)]
pub trait FirewallUciCommandRunnerPort {
    fn run_uci_cli_command(&self, command: &str) -> Result<()>;
}

/// OpenWrt firewall persistence boundary.
///
/// Implementations compile and apply UCI-compatible persistence mutations for
/// OpenWrt firewall authority paths.
// Staged OpenWrt port surface; concrete runtime call sites land in follow-up slices.
#[allow(dead_code)]
pub trait FirewallPersistencePort {
    fn build_firewall_persistence_plan(raw_uci_file_syntax: &str) -> Result<Vec<String>>;

    fn apply_cli_plan(commands: &[String], runner: &dyn FirewallUciCommandRunnerPort)
    -> Result<()>;

    fn persist_firewall_from_uci_text(
        raw_uci_file_syntax: &str,
        runner: &dyn FirewallUciCommandRunnerPort,
    ) -> Result<()>;
}
