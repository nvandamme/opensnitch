use std::{future::Future, pin::Pin, sync::Arc};

use opensnitch_proto::pb;
use tokio_util::sync::CancellationToken;

use crate::{
    commands::task_runtime::send_task_reply,
    config::ProcMonitorMethod,
    services::{
        config_service::ConfigService, firewall_service::FirewallService,
        rule_service::RuleService, stats_service::StatsService,
    },
    workers::control::{WorkerCommand, WorkerCommandResult},
};

pub(crate) type ProcWorkerReconfigure = Arc<
    dyn Fn(Option<ProcMonitorMethod>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
>;

pub(crate) type ProcWorkerControl = Arc<
    dyn Fn(WorkerCommand) -> Pin<Box<dyn Future<Output = WorkerCommandResult> + Send>>
        + Send
        + Sync,
>;

fn reconfigure_target(enabled: bool, method: ProcMonitorMethod) -> Option<ProcMonitorMethod> {
    if enabled { Some(method) } else { None }
}

trait LogLevelExt {
    fn is_valid_log_level(self) -> bool;
}

impl LogLevelExt for i32 {
    fn is_valid_log_level(self) -> bool {
        (-1..=5).contains(&self)
    }
}

pub(crate) async fn set_interception(
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
        send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Error,
            format!("failed to update interception state: {err}"),
        )
        .await;
        return;
    }

    let method = config.snapshot().await.proc_monitor_method;
    if enabled {
        reconfigure_proc_workers(reconfigure_target(true, method)).await;
        let _ = control_proc_workers(WorkerCommand::Start).await;
    } else {
        let _ = control_proc_workers(WorkerCommand::Stop).await;
    }
    tracing::info!(enabled, "updated interception state");
    send_task_reply(
        task_reply_tx,
        notification_id,
        pb::NotificationReplyCode::Ok,
        serde_json::json!({"status": "ok"}).to_string(),
    )
    .await;
}

pub(crate) async fn set_firewall(
    notification_id: u64,
    enabled: bool,
    config: &ConfigService,
    firewall: &FirewallService,
    task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
) {
    if enabled {
        let current = config.snapshot().await;
        if let Err(err) = firewall.reload_from_config(&current).await {
            tracing::error!("failed to reload firewall config: {err}");
            send_task_reply(
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
            send_task_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("failed to enable firewall: {err}"),
            )
            .await;
            return;
        }
    } else if let Err(err) = firewall.set_enabled(false).await {
        tracing::error!("failed to disable firewall: {err}");
        send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Error,
            format!("failed to disable firewall: {err}"),
        )
        .await;
        return;
    }

    send_task_reply(
        task_reply_tx,
        notification_id,
        pb::NotificationReplyCode::Ok,
        serde_json::json!({"status": "ok"}).to_string(),
    )
    .await;
}

pub(crate) async fn reload_firewall(
    notification_id: u64,
    sys_firewall: Option<pb::SysFirewall>,
    config: &ConfigService,
    firewall: &FirewallService,
    task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
) {
    let current = config.snapshot().await;
    crate::ffi::nfqueue::set_default_action(current.default_action);
    if let Some(sys_firewall) = sys_firewall {
        if let Err(err) = firewall
            .replace_system_firewall(Some(sys_firewall), &current)
            .await
        {
            tracing::error!("failed to apply firewall rules payload: {err}");
            send_task_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("failed to apply firewall rules payload: {err}"),
            )
            .await;
            return;
        }
    } else if let Err(err) = firewall.reconcile_from_config(&current).await {
        tracing::error!("failed to reconcile firewall rules after reload: {err}");
        send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Error,
            format!("failed to reconcile firewall rules after reload: {err}"),
        )
        .await;
        return;
    }

    send_task_reply(
        task_reply_tx,
        notification_id,
        pb::NotificationReplyCode::Ok,
        serde_json::json!({"status": "ok"}).to_string(),
    )
    .await;
}

pub(crate) async fn apply_config(
    notification_id: u64,
    raw_json: String,
    config: &ConfigService,
    rules: &RuleService,
    firewall: &FirewallService,
    stats: &StatsService,
    task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    reconfigure_proc_workers: &ProcWorkerReconfigure,
) {
    match config.apply_raw_json(&raw_json).await {
        Ok(updated) => {
            crate::ffi::nfqueue::set_default_action(updated.default_action);
            stats.apply_config(updated.stats);
            if let Err(err) = crate::logging::set_opensnitch_log_level(updated.log_level as i32) {
                tracing::error!("failed to apply runtime log level after config change: {err}");
                send_task_reply(
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
                send_task_reply(
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
                send_task_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Error,
                    format!("failed to reconcile firewall after config change: {err}"),
                )
                .await;
                return;
            }
            reconfigure_proc_workers(Some(updated.proc_monitor_method)).await;
            send_task_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Ok,
                serde_json::json!({"status": "ok"}).to_string(),
            )
            .await;
        }
        Err(err) => {
            tracing::error!("failed to apply config update: {err}");
            send_task_reply(
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
    notification_id: u64,
    level: i32,
    config: &ConfigService,
    task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
) {
    if !level.is_valid_log_level() {
        send_task_reply(
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
    if let Err(err) = crate::logging::set_opensnitch_log_level(level) {
        send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Error,
            format!("failed to apply runtime log level: {err}"),
        )
        .await;
        return;
    }
    tracing::info!(level, "updated daemon log level setting");
    send_task_reply(
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
    notification_id: u64,
    shutdown: &CancellationToken,
    task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
) {
    send_task_reply(
        task_reply_tx,
        notification_id,
        pb::NotificationReplyCode::Ok,
        serde_json::json!({"status": "stopping"}).to_string(),
    )
    .await;
    shutdown.cancel();
}

#[cfg(test)]
mod tests {
    use crate::config::ProcMonitorMethod;

    use super::{LogLevelExt, reconfigure_target};

    #[test]
    fn log_level_validation_matches_supported_range() {
        assert!((-1_i32).is_valid_log_level());
        assert!(0_i32.is_valid_log_level());
        assert!(5_i32.is_valid_log_level());
        assert!(!(-2_i32).is_valid_log_level());
        assert!(!6_i32.is_valid_log_level());
    }

    #[test]
    fn reconfigure_target_disables_proc_workers_when_interception_is_off() {
        assert_eq!(
            reconfigure_target(true, ProcMonitorMethod::Audit),
            Some(ProcMonitorMethod::Audit)
        );
        assert_eq!(reconfigure_target(false, ProcMonitorMethod::Ebpf), None);
    }
}
