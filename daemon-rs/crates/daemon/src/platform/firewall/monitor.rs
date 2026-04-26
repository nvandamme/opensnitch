use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::platform::netlink::control::should_process_nlmsg_payload;
use crate::platform::netlink::io::open_and_listen_multicast_socket;
use crate::services::{firewall::FirewallService, rule::RuleService};

fn should_process_nft_event_message(msg_type: u16, payload: &[u8]) -> Result<bool> {
    should_process_nlmsg_payload(msg_type, payload)
}

/// NFNLGRP_NFTABLES (group 7) — emitted by the kernel on any nftables ruleset
/// change: table/chain/rule add, delete, or flush.  Subscribing to this group
/// gives near-instant drift detection without polling.
///
/// Spawn a background tokio task that subscribes to the NFNLGRP_NFTABLES
/// multicast group on the `NETLINK_NETFILTER` (12) socket family and calls
/// [`FirewallService::heal_if_drifted`] whenever the kernel emits a nftables
/// ruleset-change notification, then refreshes rule caches so firewall-native
/// alias/zone changes can flow into the rule engine.
///
/// The task exits silently when `shutdown` is cancelled or when the underlying
/// netlink socket errors (e.g. socket closed, receive error).
///
/// Errors opening or subscribing to the socket are logged at `warn` level and
/// the function returns early — the 20 s timer-based drift-heal loop in
/// `workers/firewall/firewall_worker.rs` remains the safety-net fallback.
pub(crate) fn spawn_nft_drift_listener(
    firewall: FirewallService,
    rules: RuleService,
    shutdown: CancellationToken,
) {
    // NETLINK_NETFILTER = 12 (libc::NETLINK_NETFILTER as u16)
    let mut sock = match open_and_listen_multicast_socket(
        nix::libc::NETLINK_NETFILTER as u16,
        nix::libc::NFNLGRP_NFTABLES as u32,
    ) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(
                "failed to open/subscribe NETLINK_NETFILTER socket for nftables drift listener: {err}; \
                 nftables event-driven drift detection disabled"
            );
            return;
        }
    };

    tracing::info!(
        group = nix::libc::NFNLGRP_NFTABLES,
        "nftables event-driven drift detection active (NFNLGRP_NFTABLES)"
    );

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::debug!("nftables drift listener: shutdown requested");
                    break;
                }
                result = sock.recv() => {
                    match result {
                        Ok((meta, payload)) => {
                            match should_process_nft_event_message(meta.message_type, payload) {
                                Ok(true) => {}
                                Ok(false) => continue,
                                Err(err) => {
                                    tracing::warn!("nftables netlink control/error message: {err}");
                                    continue;
                                }
                            }
                            tracing::debug!("nftables rule-change event received; checking firewall drift");
                            if let Err(err) = firewall.heal_if_drifted().await {
                                tracing::warn!("firewall drift heal after nft event failed: {err}");
                                continue;
                            }
                            if let Err(err) = rules.rebuild_caches_from_snapshot().await {
                                tracing::warn!("failed to rebuild rule caches after nftables event: {err}");
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                "nftables netlink recv error: {err}; \
                                 nftables event-driven drift detection disabled"
                            );
                            break;
                        }
                    }
                }
            }
        }
    });
}

#[cfg(test)]
pub(crate) fn probe_should_process_nft_event_message(
    msg_type: u16,
    payload: &[u8],
) -> Result<bool> {
    should_process_nft_event_message(msg_type, payload)
}
