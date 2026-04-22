use std::process::Command as StdCommand;

use anyhow::Result;

use crate::{
    config::Config,
    models::firewall_config::FirewallConfig,
    models::firewall_state::FirewallBackend,
};

#[cfg(not(test))]
use crate::utils::command_path::resolve_command_path;

use super::firewall::FirewallService;

pub(super) const SYSFW_TAG_PREFIX: &str = "opensnitch-sysfw:";
pub(super) const FIREWALLD_RICH_STATE_SUFFIX: &str = ".firewalld.rich.rules";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FirewallPersistenceAuthority {
    Firewalld,
    Ufw,
    DirectBackend,
}

impl FirewallService {
    pub(super) fn command_status_success(program: &str, args: &[&str]) -> bool {
        StdCommand::new(program)
            .args(args)
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    pub(super) fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
        let output = StdCommand::new(program).args(args).output().ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Resolve the persistence authority for this specific service instance.
    ///
    /// In test builds, `self.authority_override` is checked first so that each
    /// test can select a manager independently without touching process-global
    /// state. When no override is active the result falls through to the normal
    /// host-probing path.
    pub(super) fn resolve_authority_for_persistence(
        &self,
        config: &Config,
    ) -> FirewallPersistenceAuthority {
        if let Some(override_auth) = self.authority_override {
            return override_auth;
        }
        Self::resolve_persistence_authority(config)
    }

    fn resolve_persistence_authority(_config: &Config) -> FirewallPersistenceAuthority {
        #[cfg(test)]
        {
            // No instance override is active (would have been caught above). In
            // test builds we never probe the host; every test that wants a
            // specific manager sets it via `FirewallService::with_test_manager`.
            return FirewallPersistenceAuthority::DirectBackend;
        }

        #[cfg(not(test))]
        {
            if resolve_command_path("firewall-cmd").is_some() {
                if Self::command_status_success("firewall-cmd", &["--state"]) {
                    return FirewallPersistenceAuthority::Firewalld;
                }

                if resolve_command_path("systemctl").is_some()
                    && Self::command_status_success(
                        "systemctl",
                        &["is-active", "--quiet", "firewalld"],
                    )
                {
                    return FirewallPersistenceAuthority::Firewalld;
                }
            }

            if resolve_command_path("ufw").is_some()
                && let Some(stdout) = Self::command_stdout("ufw", &["status"])
                && stdout.to_ascii_lowercase().contains("status: active")
            {
                return FirewallPersistenceAuthority::Ufw;
            }

            FirewallPersistenceAuthority::DirectBackend
        }
    }

    pub(super) fn persist_system_firewall_with_authority(
        authority: FirewallPersistenceAuthority,
        path: &std::path::Path,
        sysfw: &FirewallConfig,
        backend: FirewallBackend,
    ) -> Result<()> {
        match authority {
            FirewallPersistenceAuthority::Firewalld => {
                Self::persist_system_firewall_via_firewalld(path, sysfw)
            }
            FirewallPersistenceAuthority::Ufw => Self::persist_system_firewall_via_ufw(sysfw),
            FirewallPersistenceAuthority::DirectBackend => {
                Self::save_system_firewall_to_backend_and_path(path, sysfw, backend)
            }
        }
    }
}
