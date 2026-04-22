use std::{future::Future, pin::Pin, time::Duration};

use anyhow::{Result, anyhow};
use opensnitch_proto::pb;
use tokio::time::timeout;

use crate::models::firewall_config::FirewallConfig;
use crate::platform::adapters::{
    firewall_iptables::FirewallIptablesAdapter, firewall_nft::FirewallNftAdapter,
    firewall_nft_netlink::FirewallNftNetlinkAdapter,
};
use crate::tunables::RuntimeTunables;
use crate::utils::netlink_recovery::NetlinkRecoveryGate;

const OPENSNITCH_NFT_NETLINK_EXPERIMENT_ENV: &str = "OPENSNITCH_NFT_NETLINK_EXPERIMENT";
const NFT_NETLINK_REQUEST_TIMEOUT: Duration = Duration::from_millis(800);
const NFT_NETLINK_RECOVERY_POLL_INTERVAL: Duration = Duration::from_millis(800);
static NFT_NETLINK_RECOVERY: NetlinkRecoveryGate =
    NetlinkRecoveryGate::new("nftables-netlink", NFT_NETLINK_RECOVERY_POLL_INTERVAL);

#[derive(Debug, Clone)]
pub(crate) struct InterceptionHealth {
    pub valid: bool,
    pub detail: Option<String>,
}

fn nft_netlink_experiment_enabled() -> bool {
    std::env::var(OPENSNITCH_NFT_NETLINK_EXPERIMENT_ENV)
        .ok()
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(true)
}

async fn with_nft_netlink_timeout<T>(
    operation: &'static str,
    fut: impl Future<Output = Result<T>>,
) -> Result<T> {
    match timeout(NFT_NETLINK_REQUEST_TIMEOUT, fut).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!(
            "{operation} request timed out waiting for nftables netlink ACK after {}s",
            NFT_NETLINK_REQUEST_TIMEOUT.as_secs()
        )),
    }
}

fn nft_netlink_available() -> bool {
    NFT_NETLINK_RECOVERY.is_available()
}

fn nft_netlink_recovery_probe() -> bool {
    FirewallNftNetlinkAdapter::preflight().is_ok()
}

fn sync_nft_netlink_recovery_tunables() {
    let tunables = RuntimeTunables::global();
    let retry_ms = tunables.netlink_fallback_retry_delay_ms as u64;
    let poll_ms = tunables.netlink_recovery_poll_interval_ms as u64;
    NFT_NETLINK_RECOVERY.set_retry_delay(Duration::from_millis(retry_ms));
    NFT_NETLINK_RECOVERY.set_poll_interval(Duration::from_millis(poll_ms));
}

fn mark_nft_netlink_fallback(operation: &'static str, err: &anyhow::Error) {
    sync_nft_netlink_recovery_tunables();
    tracing::warn!(
        detail = %err,
        recovery_retry_ms = NFT_NETLINK_RECOVERY.retry_delay_ms(),
        recovery_poll_ms = NFT_NETLINK_RECOVERY.poll_interval_ms(),
        "{operation} failed; falling back to nft CLI adapter"
    );
    NFT_NETLINK_RECOVERY.mark_degraded(nft_netlink_recovery_probe);
}

pub(crate) trait FirewallPlatformPort {
    fn ensure(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    fn disable(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    fn interception_rules_valid(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send>>;

    fn interception_rules_health(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<InterceptionHealth>> + Send>>;

    fn apply_system_firewall<'a>(
        sysfw: &'a FirewallConfig,
        queue_num: u16,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    fn clear_system_firewall<'a>(
        sysfw: &'a FirewallConfig,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

pub(crate) struct NftablesFirewallPort;

impl FirewallPlatformPort for NftablesFirewallPort {
    fn ensure(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move {
            if nft_netlink_experiment_enabled() && nft_netlink_available() {
                match with_nft_netlink_timeout(
                    "nftables ensure",
                    FirewallNftNetlinkAdapter::ensure(queue_num, queue_bypass),
                )
                .await
                {
                    Ok(()) => return Ok(()),
                    Err(err) => mark_nft_netlink_fallback("nftables netlink ensure", &err),
                }
            }

            FirewallNftAdapter::ensure(queue_num, queue_bypass).await
        })
    }

    fn disable(
        _queue_num: u16,
        _queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move {
            if nft_netlink_experiment_enabled() && nft_netlink_available() {
                match with_nft_netlink_timeout(
                    "nftables disable",
                    FirewallNftNetlinkAdapter::disable(),
                )
                .await
                {
                    Ok(()) => return Ok(()),
                    Err(err) => mark_nft_netlink_fallback("nftables netlink disable", &err),
                }
            }

            FirewallNftAdapter::disable().await
        })
    }

    fn interception_rules_valid(
        _queue_num: u16,
        _queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send>> {
        Box::pin(async move {
            if nft_netlink_experiment_enabled() && nft_netlink_available() {
                match with_nft_netlink_timeout(
                    "nftables health check",
                    FirewallNftNetlinkAdapter::interception_rules_valid(),
                )
                .await
                {
                    Ok(valid) => return Ok(valid),
                    Err(err) => mark_nft_netlink_fallback("nftables netlink health check", &err),
                }
            }

            FirewallNftAdapter::interception_rules_valid().await
        })
    }

    fn interception_rules_health(
        _queue_num: u16,
        _queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<InterceptionHealth>> + Send>> {
        Box::pin(async move {
            let valid = Self::interception_rules_valid(0, false).await?;
            if valid {
                return Ok(InterceptionHealth {
                    valid: true,
                    detail: None,
                });
            }

            // Provide richer mismatch diagnostics from the nft compatibility path.
            FirewallNftAdapter::interception_rules_health_report().await
        })
    }

    fn apply_system_firewall<'a>(
        sysfw: &'a FirewallConfig,
        queue_num: u16,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let sysfw_pb = pb::SysFirewall::from(sysfw);
        Box::pin(async move {
            if nft_netlink_experiment_enabled() && nft_netlink_available() {
                match with_nft_netlink_timeout(
                    "nftables system firewall apply",
                    FirewallNftNetlinkAdapter::apply_system_firewall(&sysfw_pb, queue_num),
                )
                .await
                {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        mark_nft_netlink_fallback("nftables netlink system firewall apply", &err)
                    }
                }
            }

            FirewallNftAdapter::apply_system_firewall(&sysfw_pb, queue_num).await
        })
    }

    fn clear_system_firewall<'a>(
        sysfw: &'a FirewallConfig,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let sysfw_pb = pb::SysFirewall::from(sysfw);
        Box::pin(async move {
            if nft_netlink_experiment_enabled() && nft_netlink_available() {
                match with_nft_netlink_timeout(
                    "nftables system firewall clear",
                    FirewallNftNetlinkAdapter::clear_system_firewall(&sysfw_pb),
                )
                .await
                {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        mark_nft_netlink_fallback("nftables netlink system firewall clear", &err)
                    }
                }
            }

            FirewallNftAdapter::clear_system_firewall(&sysfw_pb).await
        })
    }
}

pub(crate) struct IptablesFirewallPort;

impl FirewallPlatformPort for IptablesFirewallPort {
    fn ensure(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { FirewallIptablesAdapter::ensure(queue_num, queue_bypass).await })
    }

    fn disable(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { FirewallIptablesAdapter::disable(queue_num, queue_bypass).await })
    }

    fn interception_rules_valid(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send>> {
        Box::pin(async move {
            FirewallIptablesAdapter::interception_rules_valid(queue_num, queue_bypass).await
        })
    }

    fn interception_rules_health(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<InterceptionHealth>> + Send>> {
        Box::pin(async move {
            let valid = Self::interception_rules_valid(queue_num, queue_bypass).await?;
            Ok(InterceptionHealth {
                valid,
                detail: if valid {
                    None
                } else {
                    Some("iptables interception rules are missing or duplicated".to_string())
                },
            })
        })
    }

    fn apply_system_firewall<'a>(
        sysfw: &'a FirewallConfig,
        _queue_num: u16,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let sysfw_pb = pb::SysFirewall::from(sysfw);
        Box::pin(async move { FirewallIptablesAdapter::apply_system_firewall(&sysfw_pb).await })
    }

    fn clear_system_firewall<'a>(
        sysfw: &'a FirewallConfig,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let sysfw_pb = pb::SysFirewall::from(sysfw);
        Box::pin(async move { FirewallIptablesAdapter::clear_system_firewall(&sysfw_pb).await })
    }
}
