use std::sync::Arc;

use anyhow::Result;
use opensnitch_proto::pb;

use crate::{
    models::firewall_state::FirewallBackend,
    platform::ports::firewall_port::{
        FirewallPlatformPort, IptablesFirewallPort, NftablesFirewallPort,
    },
};

use super::{FirewallService, state::FirewallRuntime};

impl FirewallService {
    pub(super) fn runtime_snapshot(&self) -> Arc<FirewallRuntime> {
        self.intent.snapshot()
    }

    pub(super) fn publish_runtime_snapshot(&self, next: FirewallRuntime) {
        self.intent.publish_snapshot(next);
    }

    pub(super) fn build_and_publish_runtime<F>(&self, build: F) -> Arc<FirewallRuntime>
    where
        F: FnOnce(&FirewallRuntime) -> FirewallRuntime,
    {
        self.intent.build_and_publish(build)
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
        sysfw: Option<&pb::SysFirewall>,
    ) {
        let Some(sysfw) = sysfw else {
            return;
        };

        match backend {
            FirewallBackend::Iptables => {
                let _ = IptablesFirewallPort::clear_system_firewall(sysfw).await;
            }
            FirewallBackend::Nftables => {
                let _ = NftablesFirewallPort::clear_system_firewall(sysfw).await;
            }
        }
    }

    pub(super) async fn disable_backend_rules(
        backend: FirewallBackend,
        queue_num: u16,
        queue_bypass: bool,
    ) -> Result<()> {
        match backend {
            FirewallBackend::Nftables => {
                NftablesFirewallPort::disable(queue_num, queue_bypass).await
            }
            FirewallBackend::Iptables => {
                IptablesFirewallPort::disable(queue_num, queue_bypass).await
            }
        }
    }

    pub(super) async fn ensure_backend_rules(
        &self,
        backend: FirewallBackend,
        queue_num: u16,
        queue_bypass: bool,
    ) -> Result<()> {
        match backend {
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
        }
    }

    pub(super) async fn apply_system_firewall_for_backend(
        &self,
        backend: FirewallBackend,
        sysfw: &pb::SysFirewall,
        queue_num: u16,
    ) -> Result<()> {
        match backend {
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
        }
    }

    pub(super) async fn backend_rules_healthy(
        backend: FirewallBackend,
        queue_num: u16,
        queue_bypass: bool,
    ) -> Result<bool> {
        match backend {
            FirewallBackend::Nftables => {
                NftablesFirewallPort::interception_rules_valid(queue_num, queue_bypass).await
            }
            FirewallBackend::Iptables => {
                IptablesFirewallPort::interception_rules_valid(queue_num, queue_bypass).await
            }
        }
    }
}
