use std::{future::Future, pin::Pin};

use opensnitch_proto::pb;
use tokio_util::sync::CancellationToken;

use crate::{
    config::{Config, ProcMonitorMethod},
    models::{
        audit::{AuditEvent, AuditEventKind, ConfigAction},
        command_rpc::ClientCommand,
    },
    services::{
        audit::AuditService,
        client::ClientService,
        config::ConfigService,
        firewall::FirewallService,
        policy_tx::{
            PolicyOwner, PolicyTxCoordinator, PolicyTxError, PolicyTxRequest, global_policy_tx,
        },
        rule::RuleService,
        stats::StatsService,
    },
    utils::notification_reply::{send_notification_reply, status_payload},
    workers::runtime::control::{WorkerCommand, WorkerCommandResult},
};

/// Selective reload scope passed to [`DaemonReloadPort::daemon_reload`].
/// Mirrors [`crate::daemon::reload::ReloadScope`] without depending on the
/// daemon module.
#[derive(Debug, Clone)]
pub(crate) struct DaemonReloadScope {
    pub(crate) services: Vec<String>,
}

/// Port for calling [`Daemon::reload`].
/// Implemented in the daemon module; injected here via trait object to avoid
/// a circular dependency between the commands layer and the daemon layer.
pub(crate) trait DaemonReloadPort: Send + Sync {
    /// `scope: None`    → full reload (all services).
    /// `scope: Some(_)` → selective reload (skip unchanged services).
    fn daemon_reload<'a>(
        &'a self,
        updated: &'a Config,
        scope: Option<DaemonReloadScope>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
}

pub(crate) trait ProcWorkerReconfigurePort: Send + Sync {
    fn reconfigure_proc_workers(
        &self,
        method: Option<ProcMonitorMethod>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>>;
}

pub(crate) trait ProcWorkerControlPort: Send + Sync {
    fn control_proc_workers(
        &self,
        command: WorkerCommand,
    ) -> Pin<Box<dyn Future<Output = WorkerCommandResult> + Send + '_>>;
}

#[derive(Clone)]
pub(crate) struct CommandControlService {
    pub(super) audit: AuditService,
}

pub(crate) enum ControlCommandDispatch {
    HandledContinue,
    HandledBreak,
    Unhandled(ClientCommand),
}

pub(super) const CONTROL_COMMAND_NOTIFICATION_LABEL: &str = "control command notification";

impl Default for CommandControlService {
    fn default() -> Self {
        Self::new(AuditService::new(64))
    }
}

impl CommandControlService {
    pub(crate) fn new(audit: AuditService) -> Self {
        Self { audit }
    }

    pub(super) fn policy_tx() -> &'static PolicyTxCoordinator {
        global_policy_tx()
    }

    pub(super) fn owner_from_client(client_service: &ClientService) -> PolicyOwner {
        client_service
            .primary_owner()
            .map(PolicyOwner::from)
            .unwrap_or(PolicyOwner::System)
    }

    pub(super) fn tx_error_message(err: PolicyTxError) -> String {
        match err {
            PolicyTxError::ApplyFailed { error } => error,
            PolicyTxError::RollbackFailed {
                apply_error,
                rollback_error,
            } => format!("{apply_error}; rollback failed: {rollback_error}"),
            PolicyTxError::DuplicateInFlight { tx_id } => {
                format!("duplicate in-flight tx {tx_id}")
            }
            PolicyTxError::Conflict { expected, actual } => {
                format!("revision conflict: expected {expected}, actual {actual}")
            }
            PolicyTxError::PersistFailed(error) => {
                format!("transaction persistence failed: {error}")
            }
            PolicyTxError::DuplicateCommitted { tx_id, revision } => {
                format!("duplicate committed tx {tx_id} @ revision {revision}")
            }
        }
    }

    pub(super) fn selective_reload_services(
        &self,
        reload_proc: bool,
        reload_fw: bool,
    ) -> Vec<String> {
        const ALWAYS_RELOAD: [&str; 9] = [
            "config",
            "client",
            "rules",
            "connections",
            "dns",
            "stats",
            "subscription",
            "task",
            "storage",
        ];

        let mut services = ALWAYS_RELOAD
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>();

        if reload_fw {
            services.push("firewall".to_string());
        }

        if reload_proc {
            services.push("process".to_string());
        }

        services
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn try_handle_client_command(
        &self,
        cmd: ClientCommand,
        config: &ConfigService,
        rules: &RuleService,
        firewall: &FirewallService,
        _stats: &StatsService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
        reconfigure_proc_workers: &dyn ProcWorkerReconfigurePort,
        control_proc_workers: &dyn ProcWorkerControlPort,
        daemon_reload: &dyn DaemonReloadPort,
        shutdown: &CancellationToken,
    ) -> ControlCommandDispatch {
        match cmd {
            ClientCommand::SetInterception {
                notification_id,
                enabled,
            } => {
                self.set_interception(
                    notification_id,
                    enabled,
                    config,
                    firewall,
                    task_reply_tx,
                    client_service,
                    reconfigure_proc_workers,
                    control_proc_workers,
                )
                .await;
                ControlCommandDispatch::HandledContinue
            }
            ClientCommand::SetFirewall {
                notification_id,
                enabled,
            } => {
                self.set_firewall(
                    notification_id,
                    enabled,
                    config,
                    firewall,
                    task_reply_tx,
                    client_service,
                )
                .await;
                ControlCommandDispatch::HandledContinue
            }
            ClientCommand::ReloadFirewall {
                notification_id,
                firewall: fw_config,
            } => {
                self.reload_firewall(
                    notification_id,
                    fw_config,
                    config,
                    rules,
                    firewall,
                    task_reply_tx,
                    client_service,
                )
                .await;
                ControlCommandDispatch::HandledContinue
            }
            ClientCommand::ApplyConfig {
                notification_id,
                raw_json,
            } => {
                self.apply_config(
                    notification_id,
                    raw_json,
                    config,
                    task_reply_tx,
                    daemon_reload,
                )
                .await;
                ControlCommandDispatch::HandledContinue
            }
            ClientCommand::SetLogLevel {
                notification_id,
                level,
            } => {
                self.set_log_level(notification_id, level, config, task_reply_tx)
                    .await;
                ControlCommandDispatch::HandledContinue
            }
            ClientCommand::Shutdown { notification_id } => {
                self.shutdown(notification_id, shutdown, task_reply_tx)
                    .await;
                ControlCommandDispatch::HandledBreak
            }
            other => ControlCommandDispatch::Unhandled(other),
        }
    }

    pub(crate) fn reconfigure_target(
        &self,
        enabled: bool,
        method: ProcMonitorMethod,
    ) -> Option<ProcMonitorMethod> {
        if enabled { Some(method) } else { None }
    }

    pub(crate) fn is_valid_log_level(&self, level: i32) -> bool {
        (-1..=5).contains(&level)
    }

    pub(crate) async fn set_interception(
        &self,
        notification_id: u64,
        enabled: bool,
        config: &ConfigService,
        firewall: &FirewallService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
        reconfigure_proc_workers: &dyn ProcWorkerReconfigurePort,
        control_proc_workers: &dyn ProcWorkerControlPort,
    ) {
        let current = config.get_snapshot();
        let previous = firewall.get_snapshot();
        let method = config.get_snapshot().proc_monitor_method;
        let owner = Self::owner_from_client(client_service);

        let tx = Self::policy_tx()
            .execute(
                PolicyTxRequest {
                    idempotency_key: format!("interception-set:{notification_id}:{enabled}"),
                    owner,
                    expected_revision: None,
                    operations: vec![format!("interception_set_enabled:{enabled}")],
                },
                || async {
                    firewall
                        .set_interception(enabled)
                        .await
                        .map_err(|err| format!("failed to update interception state: {err}"))?;

                    if enabled {
                        reconfigure_proc_workers
                            .reconfigure_proc_workers(self.reconfigure_target(true, method))
                            .await
                            .map_err(|err| {
                                format!("failed to reconfigure process monitor workers: {err}")
                            })?;
                        let _ = control_proc_workers
                            .control_proc_workers(WorkerCommand::Start)
                            .await;
                    } else {
                        let _ = control_proc_workers
                            .control_proc_workers(WorkerCommand::Stop)
                            .await;
                    }

                    Ok(())
                },
                || async {
                    firewall
                        .set_interception(previous.interception_enabled)
                        .await
                        .map_err(|err| {
                            format!("rollback failed to restore interception state: {err}")
                        })?;

                    if previous.interception_enabled {
                        reconfigure_proc_workers
                            .reconfigure_proc_workers(self.reconfigure_target(true, method))
                            .await
                            .map_err(|err| {
                                format!("rollback failed to reconfigure process workers: {err}")
                            })?;
                        let _ = control_proc_workers
                            .control_proc_workers(WorkerCommand::Start)
                            .await;
                    } else {
                        let _ = control_proc_workers
                            .control_proc_workers(WorkerCommand::Stop)
                            .await;
                    }

                    let _ = firewall.reload_from_config(&current).await;
                    Ok(())
                },
            )
            .await;

        match tx {
            Ok(_) | Err(PolicyTxError::DuplicateCommitted { .. }) => {
                tracing::info!(enabled, "updated interception state");
                self.audit
                    .emit(AuditEvent::cold(AuditEventKind::ConfigAction(
                        ConfigAction::FieldUpdated {
                            key: "interception_enabled",
                        },
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
                tracing::error!(enabled, "{message}");
                self.audit
                    .emit(AuditEvent::cold(AuditEventKind::ConfigAction(
                        ConfigAction::UpdateFailed {
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

    pub(crate) async fn shutdown(
        &self,
        notification_id: u64,
        shutdown: &CancellationToken,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        let _ = send_notification_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Ok,
            status_payload("stopping"),
            CONTROL_COMMAND_NOTIFICATION_LABEL,
        )
        .await;
        shutdown.cancel();
    }
}
