use std::{future::Future, pin::Pin, sync::Arc};

use opensnitch_proto::pb;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::{
    config::ProcMonitorMethod,
    services::{
        config_service::ConfigService, firewall_service::FirewallService,
        rule_service::RuleService, stats_service::StatsService,
    },
    workers::control::{WorkerCommand, WorkerCommandResult},
};

pub(crate) type ProcWorkerReconfigure = Arc<
    dyn Fn(Option<ProcMonitorMethod>) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
        + Send
        + Sync,
>;

pub(crate) type ProcWorkerControl = Arc<
    dyn Fn(WorkerCommand) -> Pin<Box<dyn Future<Output = WorkerCommandResult> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone, Default)]
pub(crate) struct CommandControlService;

impl CommandControlService {
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
        reconfigure_proc_workers: &ProcWorkerReconfigure,
        control_proc_workers: &ProcWorkerControl,
    ) {
        if let Err(err) = firewall.set_interception(enabled).await {
            tracing::error!(enabled, "failed to update interception state: {err}");
            Self::send_task_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("failed to update interception state: {err}"),
            )
            .await;
            return;
        }

        let method = config.snapshot_arc().proc_monitor_method;
        if enabled {
            if let Err(err) = reconfigure_proc_workers(self.reconfigure_target(true, method)).await
            {
                tracing::error!("failed to reconfigure process monitor workers: {err}");
                Self::send_task_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Error,
                    format!("failed to reconfigure process monitor workers: {err}"),
                )
                .await;
                return;
            }
            let _ = control_proc_workers(WorkerCommand::Start).await;
        } else {
            let _ = control_proc_workers(WorkerCommand::Stop).await;
        }
        tracing::info!(enabled, "updated interception state");
        Self::send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Ok,
            serde_json::json!({"status": "ok"}).to_string(),
        )
        .await;
    }

    pub(crate) async fn set_firewall(
        &self,
        notification_id: u64,
        enabled: bool,
        config: &ConfigService,
        firewall: &FirewallService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        tracing::info!(
            notification_id,
            enabled,
            "received firewall interception command"
        );
        if enabled {
            let current = config.snapshot_arc();
            tracing::info!(backend = ?current.firewall_backend, path = %current.firewall_config_path.display(), "reloading firewall from runtime config");
            if let Err(err) = firewall.reload_from_config(&current).await {
                tracing::error!("failed to reload firewall config: {err}");
                Self::send_task_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Error,
                    format!("failed to reload firewall config: {err}"),
                )
                .await;
                return;
            }
            if let Err(err) = firewall.set_enabled(true).await {
                tracing::error!("failed to enable firewall: {err}");
                Self::send_task_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Error,
                    format!("failed to enable firewall: {err}"),
                )
                .await;
                return;
            }
            tracing::info!("firewall interception enabled");
        } else if let Err(err) = firewall.set_enabled(false).await {
            tracing::error!("failed to disable firewall: {err}");
            Self::send_task_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("failed to disable firewall: {err}"),
            )
            .await;
            return;
        } else {
            tracing::info!("firewall interception disabled");
        }

        Self::send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Ok,
            serde_json::json!({"status": "ok"}).to_string(),
        )
        .await;
    }

    pub(crate) async fn reload_firewall(
        &self,
        notification_id: u64,
        sys_firewall: Option<pb::SysFirewall>,
        config: &ConfigService,
        firewall: &FirewallService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        let Some(sys_firewall) = sys_firewall else {
            Self::send_task_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                "Error reloading firewall, invalid rules".to_string(),
            )
            .await;
            return;
        };

        let current = config.snapshot_arc();
        tracing::info!(notification_id, backend = ?current.firewall_backend, "received firewall reload command");
        crate::ffi::nfqueue::NfqueueRuntimeState::set_default_action(current.default_action);
        let firewall = firewall.clone();
        let task_reply_tx = task_reply_tx.clone();
        tokio::spawn(async move {
            let mut firewall_errors = firewall.subscribe_errors();

            let reload = async {
                tracing::info!(
                    version = sys_firewall.version,
                    "applying firewall payload from notification"
                );
                firewall
                    .replace_system_firewall(Some(sys_firewall), &current)
                    .await
                    .map_err(|err| format!("failed to apply firewall rules payload: {err}"))?;
                tracing::info!("firewall payload applied successfully");
                Ok::<(), String>(())
            };

            match reload.await {
                Ok(()) => {
                    let aggregated_errors = Self::collect_firewall_errors_impl(
                        &mut firewall_errors,
                        std::time::Duration::from_secs(2),
                    )
                    .await;

                    if let Some(errors) = aggregated_errors {
                        tracing::error!("{errors}");
                        Self::send_task_reply(
                            &task_reply_tx,
                            notification_id,
                            pb::NotificationReplyCode::Error,
                            errors,
                        )
                        .await;
                        return;
                    }

                    tracing::debug!("reload firewall timeout fired, no errors?");
                    Self::send_task_reply(
                        &task_reply_tx,
                        notification_id,
                        pb::NotificationReplyCode::Ok,
                        serde_json::json!({"status": "ok"}).to_string(),
                    )
                    .await;
                }
                Err(err) => {
                    tracing::error!("{err}");
                    Self::send_task_reply(
                        &task_reply_tx,
                        notification_id,
                        pb::NotificationReplyCode::Error,
                        err,
                    )
                    .await;
                }
            }
        });
    }

    #[cfg(test)]
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
        rules: &RuleService,
        firewall: &FirewallService,
        stats: &StatsService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        reconfigure_proc_workers: &ProcWorkerReconfigure,
    ) {
        tracing::debug!(notification_id, "received apply-config command");
        let previous = config.snapshot_arc();
        match config.parse_raw_json(&raw_json).await {
            Ok(updated) => {
                let reload_proc = previous.proc_monitor_method != updated.proc_monitor_method
                    || previous.audit_socket_path != updated.audit_socket_path;
                let reload_fw = previous.firewall_backend.as_str()
                    != updated.firewall_backend.as_str()
                    || previous.firewall_config_path != updated.firewall_config_path
                    || previous.firewall_queue_num != updated.firewall_queue_num
                    || previous.firewall_queue_bypass != updated.firewall_queue_bypass;

                crate::utils::config_reload::log_config_delta(&previous, &updated, false);
                tracing::info!(
                    notification_id,
                    addr = %updated.client_addr,
                    log_level = updated.log_level,
                    ?updated.default_action,
                    ?updated.proc_monitor_method,
                    ?updated.firewall_backend,
                    "applying config update to runtime services"
                );
                crate::ffi::nfqueue::NfqueueRuntimeState::set_default_action(
                    updated.default_action,
                );
                stats.apply_config(updated.stats);
                crate::utils::config_reload::apply_gc_percent(updated.gc_percent);
                if let Err(err) = crate::logging::LoggingState::apply_config(&updated) {
                    tracing::error!(
                        "failed to apply runtime logging config after config change: {err}"
                    );
                    Self::send_task_reply(
                        task_reply_tx,
                        notification_id,
                        pb::NotificationReplyCode::Error,
                        format!("failed to apply runtime log level after config change: {err}"),
                    )
                    .await;
                    return;
                }
                if let Err(err) = rules.load_path(&updated.rules_path).await {
                    tracing::error!("failed to reload rules after config change: {err}");
                    Self::send_task_reply(
                        task_reply_tx,
                        notification_id,
                        pb::NotificationReplyCode::Error,
                        format!("failed to reload rules after config change: {err}"),
                    )
                    .await;
                    return;
                }
                if let Err(err) = firewall.reconcile_from_config(&updated).await {
                    tracing::error!("failed to reconcile firewall after config change: {err}");
                    Self::send_task_reply(
                        task_reply_tx,
                        notification_id,
                        pb::NotificationReplyCode::Error,
                        format!("failed to reconcile firewall after config change: {err}"),
                    )
                    .await;
                    return;
                }
                if let Err(err) = reconfigure_proc_workers(Some(updated.proc_monitor_method)).await
                {
                    tracing::error!("failed to reconfigure process monitor workers: {err}");
                    Self::send_task_reply(
                        task_reply_tx,
                        notification_id,
                        pb::NotificationReplyCode::Error,
                        format!("failed to reconfigure process monitor workers: {err}"),
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
                    Self::send_task_reply(
                        task_reply_tx,
                        notification_id,
                        pb::NotificationReplyCode::Error,
                        format!("failed to persist config payload after runtime apply: {err}"),
                    )
                    .await;
                    return;
                }
                config.set_snapshot(updated.clone()).await;
                tracing::info!(notification_id, "config update applied successfully");
                Self::send_task_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Ok,
                    serde_json::json!({"status": "ok"}).to_string(),
                )
                .await;
            }
            Err(err) => {
                tracing::error!("failed to apply config update: {err}");
                Self::send_task_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Error,
                    format!("failed to apply config update: {err}"),
                )
                .await;
            }
        }
    }

    pub(crate) async fn set_log_level(
        &self,
        notification_id: u64,
        level: i32,
        config: &ConfigService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        if !self.is_valid_log_level(level) {
            Self::send_task_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("invalid log level: {level}"),
            )
            .await;
            return;
        }

        let mapped_level = if level < 0 { 0 } else { level as u32 };
        config.set_log_level(mapped_level).await;
        let snapshot = config.snapshot_arc();
        if let Err(err) = crate::logging::LoggingState::apply_config(&snapshot) {
            Self::send_task_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("failed to apply runtime log level: {err}"),
            )
            .await;
            return;
        }
        tracing::info!(level, "updated daemon log level setting");
        Self::send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Ok,
            serde_json::json!({
                "status": "ok",
                "logLevel": level,
            })
            .to_string(),
        )
        .await;
    }

    pub(crate) async fn shutdown(
        &self,
        notification_id: u64,
        shutdown: &CancellationToken,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        Self::send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Ok,
            serde_json::json!({"status": "stopping"}).to_string(),
        )
        .await;
        shutdown.cancel();
    }

    async fn send_task_reply(
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        notification_id: u64,
        code: pb::NotificationReplyCode,
        data: String,
    ) {
        crate::commands::task_runtime::TaskRuntimeService
            .send_task_reply(task_reply_tx, notification_id, code, data)
            .await;
    }
}
