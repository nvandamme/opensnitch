use std::sync::Arc;

use anyhow::{Result, anyhow};

use crate::{
    models::{firewall_config::FirewallConfig, firewall_state::FirewallBackend},
    platform::adapters::{
        firewall_netlink::FirewallNetlinkAdapter, firewall_nftables::FirewallNftablesAdapter,
    },
    platform::ports::firewall_port::InterceptionHealth,
    platform::ports::firewall_port::{
        FirewallIntrospectionPort, FirewallPersistencePort, IptablesFirewallPort,
        NftablesFirewallPort,
    },
    services::lifecycle::ServiceState,
    utils::command_path::resolve_command_path,
};

use super::{FirewallService, runtime_store::FirewallRuntime};

#[cfg(feature = "openwrt")]
use crate::platform::adapters::openwrt_uci_firewall::OpenWrtUciFirewallAdapter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Optional introspection source ordering used by selected diagnostics/control paths.
#[allow(dead_code)]
enum FirewallIntrospectionSource {
    Netlink,
    Nftables,
    Iptables,
    #[cfg(feature = "openwrt")]
    OpenWrtUci,
}

impl FirewallService {
    fn persistence_backend_for_generic_linux(preferred: FirewallBackend) -> FirewallBackend {
        // Generic Linux policy: nftables is the primary backend when available,
        // with iptables used only as a compatibility fallback when nft is absent.
        if resolve_command_path("nft").is_some() {
            return FirewallBackend::Nftables;
        }
        if resolve_command_path("iptables").is_some() {
            return FirewallBackend::Iptables;
        }
        preferred
    }

    fn persistence_backend_for_target(preferred: FirewallBackend) -> FirewallBackend {
        #[cfg(feature = "openwrt")]
        if matches!(preferred, FirewallBackend::OpenWrtUci) {
            // OpenWrt persistence is UCI/firewall4-owned. Keep an explicit runtime
            // backend marker and avoid generic Linux auto-selection fallback here.
            return FirewallBackend::OpenWrtUci;
        }

        #[cfg(not(feature = "openwrt"))]
        if matches!(preferred, FirewallBackend::OpenWrtUci) {
            // Without the OpenWrt feature, keep backend resolution on the
            // generic Linux runtime path.
            return Self::persistence_backend_for_generic_linux(FirewallBackend::Nftables);
        }

        Self::persistence_backend_for_generic_linux(preferred)
    }

    // Retained for optional diagnostics/control workflows that inspect backend state.
    #[allow(dead_code)]
    fn firewall_introspection_sources_for_target(
        preferred: FirewallBackend,
    ) -> Vec<FirewallIntrospectionSource> {
        // Introspection/live runtime state is netlink-first and detached from
        // persistence backend ownership.
        let mut order = vec![FirewallIntrospectionSource::Netlink];

        match Self::persistence_backend_for_target(preferred) {
            FirewallBackend::Nftables | FirewallBackend::Iptables => {
                order.push(FirewallIntrospectionSource::Nftables);
                order.push(FirewallIntrospectionSource::Iptables);
            }
            #[cfg(feature = "openwrt")]
            FirewallBackend::OpenWrtUci => {
                order.push(FirewallIntrospectionSource::OpenWrtUci);
            }
            #[cfg(not(feature = "openwrt"))]
            FirewallBackend::OpenWrtUci => {
                order.push(FirewallIntrospectionSource::Nftables);
                order.push(FirewallIntrospectionSource::Iptables);
            }
        }

        order
    }

    // Retained for optional diagnostics/control workflows that inspect backend state.
    #[allow(dead_code)]
    fn firewall_introspection_source_name(source: FirewallIntrospectionSource) -> &'static str {
        match source {
            FirewallIntrospectionSource::Netlink => "netlink",
            FirewallIntrospectionSource::Nftables => "nftables",
            FirewallIntrospectionSource::Iptables => "iptables",
            #[cfg(feature = "openwrt")]
            FirewallIntrospectionSource::OpenWrtUci => "openwrt-uci",
        }
    }

    pub(super) fn runtime_snapshot(&self) -> Arc<FirewallRuntime> {
        self.runtime.snapshot()
    }

    pub(super) fn publish_runtime_snapshot(&self, next: FirewallRuntime) {
        self.runtime.publish(next);
        self.lifecycle
            .clear_error_and_transition(ServiceState::Running);
    }

    pub(super) fn build_and_publish_runtime<F>(&self, build: F) -> Arc<FirewallRuntime>
    where
        F: FnOnce(&FirewallRuntime) -> FirewallRuntime,
    {
        let next = self.runtime.build_and_publish(build);
        self.lifecycle
            .clear_error_and_transition(ServiceState::Running);
        next
    }

    pub(super) fn emit_error(&self, message: String) {
        let _ = self.error_tx.send(message);
    }

    pub(super) async fn disable_rules(&self) -> Result<()> {
        let snapshot = self.runtime_snapshot();
        let backend = snapshot.state.backend;
        let queue_num = snapshot.queue_num;
        let queue_bypass = snapshot.queue_bypass;

        Self::clear_system_firewall_for_backend(
            backend,
            snapshot.system_firewall.as_ref().as_ref(),
        )
        .await;
        if let Err(err) = Self::disable_backend_rules(backend, queue_num, queue_bypass).await {
            self.emit_error(format!("failed to disable firewall backend rules: {err}"));
            return Err(err);
        }

        self.build_and_publish_runtime(|current: &FirewallRuntime| {
            let mut next = current.clone();
            next.state.enabled = false;
            next
        });
        tracing::info!(backend = ?backend, "firewall backend disabled");
        Ok(())
    }

    pub(super) async fn clear_system_firewall_for_backend(
        backend: FirewallBackend,
        sysfw: Option<&FirewallConfig>,
    ) {
        let Some(sysfw) = sysfw else {
            return;
        };

        match Self::persistence_backend_for_target(backend) {
            FirewallBackend::Iptables => {
                let _ = IptablesFirewallPort::clear_system_firewall(sysfw).await;
            }
            FirewallBackend::Nftables => {
                let _ = NftablesFirewallPort::clear_system_firewall(sysfw).await;
            }
            #[cfg(feature = "openwrt")]
            FirewallBackend::OpenWrtUci => {
                let _ = NftablesFirewallPort::clear_system_firewall(sysfw).await;
            }
            #[cfg(not(feature = "openwrt"))]
            FirewallBackend::OpenWrtUci => {
                let _ = NftablesFirewallPort::clear_system_firewall(sysfw).await;
            }
        }
    }

    pub(super) async fn disable_backend_rules(
        backend: FirewallBackend,
        queue_num: u16,
        queue_bypass: bool,
    ) -> Result<()> {
        match Self::persistence_backend_for_target(backend) {
            FirewallBackend::Nftables => {
                NftablesFirewallPort::disable(queue_num, queue_bypass).await
            }
            FirewallBackend::Iptables => {
                IptablesFirewallPort::disable(queue_num, queue_bypass).await
            }
            #[cfg(feature = "openwrt")]
            FirewallBackend::OpenWrtUci => {
                NftablesFirewallPort::disable(queue_num, queue_bypass).await
            }
            #[cfg(not(feature = "openwrt"))]
            FirewallBackend::OpenWrtUci => {
                NftablesFirewallPort::disable(queue_num, queue_bypass).await
            }
        }
    }

    pub(super) async fn ensure_backend_rules(
        &self,
        backend: FirewallBackend,
        queue_num: u16,
        queue_bypass: bool,
    ) -> Result<()> {
        match Self::persistence_backend_for_target(backend) {
            FirewallBackend::Nftables => {
                if let Err(err) = NftablesFirewallPort::ensure(queue_num, queue_bypass).await {
                    tracing::error!("Error while adding interception tables: {err}");
                    self.emit_error(format!("Error while adding interception tables: {err}"));
                    tracing::info!("Using nftables firewall");
                    return Err(err);
                }
                tracing::info!("Using nftables firewall");
                Ok(())
            }
            FirewallBackend::Iptables => {
                if let Err(err) = IptablesFirewallPort::ensure(queue_num, queue_bypass).await {
                    self.emit_error(format!(
                        "failed to ensure iptables interception rules: {err}"
                    ));
                    return Err(err);
                }
                Ok(())
            }
            #[cfg(feature = "openwrt")]
            FirewallBackend::OpenWrtUci => {
                if let Err(err) = NftablesFirewallPort::ensure(queue_num, queue_bypass).await {
                    self.emit_error(format!(
                        "failed to ensure OpenWrt interception rules via nftables runtime path: {err}"
                    ));
                    return Err(err);
                }
                tracing::info!("Using OpenWrt UCI authority with nftables runtime path");
                Ok(())
            }
            #[cfg(not(feature = "openwrt"))]
            FirewallBackend::OpenWrtUci => {
                NftablesFirewallPort::ensure(queue_num, queue_bypass).await
            }
        }
    }

    pub(super) async fn apply_system_firewall_for_backend(
        &self,
        backend: FirewallBackend,
        sysfw: &FirewallConfig,
        queue_num: u16,
    ) -> Result<()> {
        match Self::persistence_backend_for_target(backend) {
            FirewallBackend::Nftables => {
                if let Err(err) =
                    NftablesFirewallPort::apply_system_firewall(sysfw, queue_num).await
                {
                    self.emit_error(format!("failed to apply nftables system firewall: {err}"));
                    return Err(err);
                }
                Ok(())
            }
            FirewallBackend::Iptables => {
                if let Err(err) =
                    IptablesFirewallPort::apply_system_firewall(sysfw, queue_num).await
                {
                    self.emit_error(format!("failed to apply iptables system firewall: {err}"));
                    return Err(err);
                }
                Ok(())
            }
            #[cfg(feature = "openwrt")]
            FirewallBackend::OpenWrtUci => {
                if let Err(err) =
                    NftablesFirewallPort::apply_system_firewall(sysfw, queue_num).await
                {
                    self.emit_error(format!(
                        "failed to apply OpenWrt runtime firewall via nftables path: {err}"
                    ));
                    return Err(err);
                }
                Ok(())
            }
            #[cfg(not(feature = "openwrt"))]
            FirewallBackend::OpenWrtUci => {
                NftablesFirewallPort::apply_system_firewall(sysfw, queue_num).await
            }
        }
    }

    pub(super) async fn backend_rules_health(
        backend: FirewallBackend,
        queue_num: u16,
        queue_bypass: bool,
    ) -> Result<InterceptionHealth> {
        match Self::persistence_backend_for_target(backend) {
            FirewallBackend::Nftables => {
                NftablesFirewallPort::interception_rules_health(queue_num, queue_bypass).await
            }
            FirewallBackend::Iptables => {
                IptablesFirewallPort::interception_rules_health(queue_num, queue_bypass).await
            }
            #[cfg(feature = "openwrt")]
            FirewallBackend::OpenWrtUci => {
                NftablesFirewallPort::interception_rules_health(queue_num, queue_bypass).await
            }
            #[cfg(not(feature = "openwrt"))]
            FirewallBackend::OpenWrtUci => {
                NftablesFirewallPort::interception_rules_health(queue_num, queue_bypass).await
            }
        }
    }
    // Retained for optional diagnostics/control workflows that inspect backend state.
    #[allow(dead_code)]
    pub async fn introspect_system_firewall(&self) -> Result<FirewallConfig> {
        let preferred = self.runtime_snapshot().state.backend;
        let order = Self::firewall_introspection_sources_for_target(preferred);
        let mut last_err = None;

        for source in order {
            let result = match source {
                FirewallIntrospectionSource::Netlink => {
                    FirewallNetlinkAdapter::extract_system_firewall().await
                }
                FirewallIntrospectionSource::Nftables => {
                    FirewallNftablesAdapter::extract_system_firewall().await
                }
                FirewallIntrospectionSource::Iptables => {
                    IptablesFirewallPort::introspect_system_firewall().await
                }
                #[cfg(feature = "openwrt")]
                FirewallIntrospectionSource::OpenWrtUci => {
                    OpenWrtUciFirewallAdapter::extract_system_firewall_via_uci_show().await
                }
            };

            match result {
                Ok(snapshot) => return Ok(snapshot),
                Err(err) => {
                    tracing::warn!(
                        source = Self::firewall_introspection_source_name(source),
                        detail = %err,
                        "firewall introspection source failed; trying fallback"
                    );
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("no firewall introspection backend available")))
    }
    #[cfg(test)]
    pub(crate) fn probe_runtime_backend_for_target(preferred: FirewallBackend) -> FirewallBackend {
        Self::persistence_backend_for_target(preferred)
    }

    #[cfg(test)]
    pub(crate) fn probe_firewall_introspection_sources(
        preferred: FirewallBackend,
    ) -> Vec<&'static str> {
        Self::firewall_introspection_sources_for_target(preferred)
            .into_iter()
            .map(Self::firewall_introspection_source_name)
            .collect()
    }
}
