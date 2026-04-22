use opensnitch_proto::pb;
use tokio::sync::broadcast;

use super::CommandControlService;
use super::control::CONTROL_COMMAND_NOTIFICATION_LABEL;
use crate::{
    models::{
        audit::{AuditEvent, AuditEventKind, FirewallAction, FirewallLifecycle},
        firewall_config::FirewallConfig,
    },
    services::{
        client::ClientService,
        config::ConfigService,
        firewall::FirewallService,
        policy_tx::{PolicyTxError, PolicyTxRequest},
        rule::RuleService,
    },
    utils::notification_reply::{send_notification_reply, status_payload},
};

impl CommandControlService {
    pub(crate) async fn set_firewall(
        &self,
        notification_id: u64,
        enabled: bool,
        config: &ConfigService,
        firewall: &FirewallService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
    ) {
        tracing::info!(
            notification_id,
            enabled,
            "received firewall interception command"
        );
        let current = config.get_snapshot();
        let previous = firewall.get_snapshot();
        let owner = Self::owner_from_client(client_service);

        let tx = Self::policy_tx()
            .execute(
                PolicyTxRequest {
                    idempotency_key: format!("firewall-set:{notification_id}:{enabled}"),
                    owner,
                    expected_revision: None,
                    operations: vec![format!("firewall_set_enabled:{enabled}")],
                },
                || async {
                    if enabled {
                        tracing::info!(backend = ?current.firewall_backend, path = %current.firewall_config_path.display(), "reloading firewall from runtime config");
                        firewall
                            .reload_from_config(&current)
                            .await
                            .map_err(|err| format!("failed to reload firewall config: {err}"))?;
                        firewall
                            .set_enabled(true)
                            .await
                            .map_err(|err| format!("failed to enable firewall: {err}"))?;
                    } else {
                        firewall
                            .set_enabled(false)
                            .await
                            .map_err(|err| format!("failed to disable firewall: {err}"))?;
                    }
                    Ok(())
                },
                || async {
                    let prev_sysfw = previous.system_firewall.as_ref().as_ref().cloned();
                    firewall
                        .replace_system_firewall(prev_sysfw, &current)
                        .await
                        .map_err(|err| {
                            format!("rollback failed to restore firewall rules payload: {err}")
                        })?;
                    firewall
                        .set_enabled(previous.state.enabled)
                        .await
                        .map_err(|err| {
                            format!("rollback failed to restore firewall enabled state: {err}")
                        })
                },
            )
            .await;

        match tx {
            Ok(_) | Err(PolicyTxError::DuplicateCommitted { .. }) => {
                tracing::info!(enabled, "updated firewall enabled state");
                if enabled {
                    self.audit
                        .emit(AuditEvent::cold(AuditEventKind::FirewallAction(
                            FirewallAction::EnsureRulesApplied,
                        )));
                } else {
                    self.audit
                        .emit(AuditEvent::cold(AuditEventKind::FirewallAction(
                            FirewallAction::EnsureRulesSkipped,
                        )));
                }
                let _ = send_notification_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Ok,
                    status_payload("ok"),
                    CONTROL_COMMAND_NOTIFICATION_LABEL,
                )
                .await;
            }
            Err(err) => {
                let message = Self::tx_error_message(err);
                tracing::error!("{message}");
                self.audit
                    .emit(AuditEvent::cold(AuditEventKind::FirewallAction(
                        FirewallAction::CommandFailed {
                            reason: message.clone().into(),
                        },
                    )));
                let _ = send_notification_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Error,
                    message,
                    CONTROL_COMMAND_NOTIFICATION_LABEL,
                )
                .await;
            }
        }
    }

    pub(crate) async fn reload_firewall(
        &self,
        notification_id: u64,
        fw_config: Option<FirewallConfig>,
        config: &ConfigService,
        rules: &RuleService,
        firewall: &FirewallService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
    ) {
        let Some(fw_config) = fw_config else {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                "Error reloading firewall, invalid rules".to_string(),
                CONTROL_COMMAND_NOTIFICATION_LABEL,
            )
            .await;
            return;
        };

        let current = config.get_snapshot();
        let previous = firewall.get_snapshot();
        let owner = Self::owner_from_client(client_service);
        tracing::info!(notification_id, backend = ?current.firewall_backend, "received firewall reload command");
        crate::platform::ffi::nfqueue::NfqueueRuntimeState::set_default_action(
            current.default_action,
        );

        let mut firewall_errors = firewall.subscribe_errors();
        let tx = Self::policy_tx()
            .execute(
                PolicyTxRequest {
                    idempotency_key: format!(
                        "firewall-reload:{notification_id}:{}",
                        fw_config.version
                    ),
                    owner,
                    expected_revision: None,
                    operations: vec![format!("firewall_reload:version:{}", fw_config.version)],
                },
                || async {
                    tracing::info!(
                        version = fw_config.version,
                        "applying firewall payload from notification"
                    );
                    firewall
                        .replace_system_firewall(Some(fw_config), &current)
                        .await
                        .map_err(|err| format!("failed to apply firewall rules payload: {err}"))
                },
                || async {
                    let prev_sysfw = previous.system_firewall.as_ref().as_ref().cloned();
                    firewall
                        .replace_system_firewall(prev_sysfw, &current)
                        .await
                        .map_err(|err| {
                            format!("rollback failed to restore firewall rules payload: {err}")
                        })
                },
            )
            .await;

        match tx {
            Ok(_) | Err(PolicyTxError::DuplicateCommitted { .. }) => {
                let aggregated_errors = Self::collect_firewall_errors_impl(
                    &mut firewall_errors,
                    std::time::Duration::from_secs(2),
                )
                .await;

                if let Some(errors) = aggregated_errors {
                    tracing::error!("{errors}");
                    let _ = send_notification_reply(
                        task_reply_tx,
                        notification_id,
                        pb::NotificationReplyCode::Error,
                        errors,
                        CONTROL_COMMAND_NOTIFICATION_LABEL,
                    )
                    .await;
                    return;
                }

                tracing::debug!("reload firewall timeout fired, no errors?");
                // Firewall rules are now applied; rebuild the rule match caches
                // (including network aliases) so that any firewall-native zone/set
                // definitions are picked up by the rule engine.
                if let Err(err) = rules.rebuild_caches_from_snapshot().await {
                    tracing::warn!("failed to rebuild rule caches after firewall reload: {err}");
                }
                self.audit
                    .emit(AuditEvent::cold(AuditEventKind::FirewallLifecycle(
                        FirewallLifecycle::ReloadCompleted,
                    )));
                let _ = send_notification_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Ok,
                    status_payload("ok"),
                    CONTROL_COMMAND_NOTIFICATION_LABEL,
                )
                .await;
            }
            Err(err) => {
                let message = Self::tx_error_message(err);
                tracing::error!("{message}");
                self.audit
                    .emit(AuditEvent::cold(AuditEventKind::FirewallAction(
                        FirewallAction::CommandFailed {
                            reason: message.clone().into(),
                        },
                    )));
                let _ = send_notification_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Error,
                    message,
                    CONTROL_COMMAND_NOTIFICATION_LABEL,
                )
                .await;
            }
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn collect_firewall_errors(
        &self,
        firewall_errors: &mut broadcast::Receiver<String>,
        timeout: std::time::Duration,
    ) -> Option<String> {
        Self::collect_firewall_errors_impl(firewall_errors, timeout).await
    }

    async fn collect_firewall_errors_impl(
        firewall_errors: &mut broadcast::Receiver<String>,
        timeout: std::time::Duration,
    ) -> Option<String> {
        let timeout_sleep = tokio::time::sleep(timeout);
        tokio::pin!(timeout_sleep);

        let mut aggregated = Vec::new();
        loop {
            tokio::select! {
                _ = &mut timeout_sleep => {
                    break;
                }
                recv = firewall_errors.recv() => {
                    match recv {
                        Ok(err) => {
                            aggregated.push(err);
                            while let Ok(next) = firewall_errors.try_recv() {
                                aggregated.push(next);
                            }
                            break;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            aggregated.push(format!("firewall errors stream lagged; skipped {skipped} messages"));
                        }
                    }
                }
            }
        }

        if aggregated.is_empty() {
            None
        } else {
            Some(aggregated.join(","))
        }
    }
}
