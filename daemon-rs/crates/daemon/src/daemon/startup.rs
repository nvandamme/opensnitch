use std::sync::Arc;

use tokio::time::timeout;
use tracing::info;

use super::Daemon;
use crate::utils::systemd_notify::{NotifyState, notify};
use crate::{config::Config, services::client::ClientService};

impl Daemon {
    pub(super) async fn startup_ui_handshake_once((daemon, config): (Daemon, Arc<Config>)) {
        match timeout(
            Self::STARTUP_UI_CONNECT_TIMEOUT,
            ClientService::connect_with_config(&config),
        )
        .await
        {
            Ok(Ok(mut client)) => {
                match timeout(
                    Self::STARTUP_UI_HANDSHAKE_TIMEOUT,
                    daemon.startup_handshake(&mut client),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        info!(addr = %config.client_addr, "startup UI handshake unavailable during bootstrap (transient, non-blocking; notification flow will continue retries): {err}");
                    }
                    Err(_) => {
                        info!(addr = %config.client_addr, timeout = ?Self::STARTUP_UI_HANDSHAKE_TIMEOUT, "startup UI handshake unavailable during bootstrap (timeout, non-blocking; notification flow will continue retries)");
                    }
                }
            }
            Ok(Err(err)) => {
                info!(addr = %config.client_addr, "startup UI connect unavailable during bootstrap (transient, non-blocking; notification flow will continue retries): {err}");
            }
            Err(_) => {
                info!(addr = %config.client_addr, timeout = ?Self::STARTUP_UI_CONNECT_TIMEOUT, "startup UI connect unavailable during bootstrap (timeout, non-blocking; notification flow will continue retries)");
            }
        }
    }

    pub(super) fn publish_startup_status_once(message: String) {
        notify(NotifyState::Status(&message));
    }

    pub(super) async fn startup_handshake(&self, client: &mut ClientService) -> anyhow::Result<()> {
        let config = self.runtime.config.get_snapshot();
        let rules = self.runtime.rules.get_proto_snapshot();
        let rules_count = rules.len() as u64;
        let firewall = self.runtime.firewall.get_snapshot();
        let subscribe_cfg = ClientService::build_subscribe_config_from_snapshots(
            &config,
            &rules,
            firewall.state.enabled,
            &firewall.system_firewall,
        );
        let subscribe_reply = client.subscribe(subscribe_cfg).await?;

        if let Some(connected_default_action) =
            Self::parse_default_action_from_client_config(&subscribe_reply.config)
        {
            self.runtime
                .client
                .set_connected_default_action(connected_default_action);
            tracing::info!(
                ?connected_default_action,
                "updated connected-mode default action from subscribe payload"
            );
        }

        tracing::info!(
            client_name = %subscribe_reply.name,
            client_version = %subscribe_reply.version,
            "subscribed to control client"
        );

        let ping_reply = client
            .ping(opensnitch_proto::pb::PingRequest {
                id: 1,
                stats: Some(self.runtime.stats.snapshot(rules_count).stats),
            })
            .await?;

        tracing::info!(ping_id = ping_reply.id, "ping successful");

        Ok(())
    }
}
