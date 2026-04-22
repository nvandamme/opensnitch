use std::{future::Future, pin::Pin};

use opensnitch_proto::pb;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::{
    config::{Config, ProcMonitorMethod},
    models::command_rpc::ClientCommand,
    services::{
        client::ClientService,
        config::ConfigService,
        firewall::FirewallService,
        policy_tx::{PolicyOwner, PolicyTxCoordinator, PolicyTxError, PolicyTxRequest, global_policy_tx},
        rule::RuleService,
        stats::StatsService,
    },
    utils::config_reload::{
        has_firewall_runtime_change, has_proc_runtime_change, log_config_delta,
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

#[derive(Clone, Default)]
pub(crate) struct CommandControlService;

pub(crate) enum ControlCommandDispatch {
    HandledContinue,
    HandledBreak,
    Unhandled(ClientCommand),
}

const CONTROL_COMMAND_NOTIFICATION_LABEL: &str = "control command notification";

impl CommandControlService {
    fn policy_tx() -> &'static PolicyTxCoordinator {
        global_policy_tx()
    }

    fn owner_from_client(client_service: &ClientService) -> PolicyOwner {
        client_service
            .primary_owner()
            .map(PolicyOwner::from)
            .unwrap_or(PolicyOwner::System)
    }

    fn tx_error_message(err: PolicyTxError) -> String {
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

    fn selective_reload_services(
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
        _rules: &RuleService,
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
                sys_firewall,
            } => {
                self.reload_firewall(
                    notification_id,
                    sys_firewall,
                    config,
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
                self.shutdown(notification_id, shutdown, task_reply_tx).await;
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
        sys_firewall: Option<pb::SysFirewall>,
        config: &ConfigService,
        firewall: &FirewallService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
    ) {
        let Some(sys_firewall) = sys_firewall else {
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
                        sys_firewall.version
                    ),
                    owner,
                    expected_revision: None,
                    operations: vec![format!("firewall_reload:version:{}", sys_firewall.version)],
                },
                || async {
                    tracing::info!(
                        version = sys_firewall.version,
                        "applying firewall payload from notification"
                    );
                    firewall
                        .replace_system_firewall(Some(sys_firewall), &current)
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

    pub(crate) async fn apply_config(
        &self,
        notification_id: u64,
        raw_json: String,
        config: &ConfigService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        daemon_reload: &dyn DaemonReloadPort,
    ) {
        tracing::debug!(notification_id, "received apply-config command");
        let previous = config.get_snapshot();
        let updated = match config.parse_raw_json(&raw_json).await {
            Ok(updated) => updated,
            Err(err) => {
                tracing::error!("failed to apply config update: {err}");
                let _ = send_notification_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Error,
                    format!("failed to apply config update: {err}"),
                    CONTROL_COMMAND_NOTIFICATION_LABEL,
                )
                .await;
                return;
            }
        };

        let reload_proc = has_proc_runtime_change(&previous, &updated);
        let reload_fw = has_firewall_runtime_change(&previous, &updated, false);

        log_config_delta(&previous, &updated, false);
        tracing::info!(
            notification_id,
            addr = %updated.client_addr,
            log_level = updated.log_level,
            ?updated.default_action,
            ?updated.proc_monitor_method,
            ?updated.firewall_backend,
            "applying config update to runtime services"
        );

        if let Err(err) = daemon_reload
            .daemon_reload(
                &updated,
                Some(DaemonReloadScope {
                    services: self.selective_reload_services(reload_proc, reload_fw),
                }),
            )
            .await
        {
            tracing::error!("config update failed during daemon reload: {err}");
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("config update failed: {err}"),
                CONTROL_COMMAND_NOTIFICATION_LABEL,
            )
            .await;
            return;
        }

        if (reload_proc || reload_fw) && updated.flush_conns_on_start {
            crate::utils::config_reload::flush_established_connections().await;
        } else {
            tracing::debug!("[config] not flushing established connections");
        }

        if let Err(err) = config.persist_raw_json(&raw_json).await {
            tracing::error!("failed to persist config payload after runtime apply: {err}");
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("failed to persist config payload after runtime apply: {err}"),
                CONTROL_COMMAND_NOTIFICATION_LABEL,
            )
            .await;
            return;
        }
        config.set_snapshot(updated.clone()).await;
        tracing::info!(notification_id, "config update applied successfully");
        let _ = send_notification_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Ok,
            status_payload("ok"),
            CONTROL_COMMAND_NOTIFICATION_LABEL,
        )
        .await;
    }

    pub(crate) async fn set_log_level(
        &self,
        notification_id: u64,
        level: i32,
        config: &ConfigService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        if !self.is_valid_log_level(level) {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("invalid log level: {level}"),
                CONTROL_COMMAND_NOTIFICATION_LABEL,
            )
            .await;
            return;
        }

        let mapped_level = if level < 0 { 0 } else { level as u32 };
        config.set_log_level(mapped_level).await;
        let snapshot = config.get_snapshot();
        if let Err(err) = crate::logging::LoggingState::apply_config(&snapshot) {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("failed to apply runtime log level: {err}"),
                CONTROL_COMMAND_NOTIFICATION_LABEL,
            )
            .await;
            return;
        }
        tracing::info!(level, "updated daemon log level setting");
        let _ = send_notification_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Ok,
            serde_json::json!({
                "status": "ok",
                "logLevel": level,
            })
            .to_string(),
            CONTROL_COMMAND_NOTIFICATION_LABEL,
        )
        .await;
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
