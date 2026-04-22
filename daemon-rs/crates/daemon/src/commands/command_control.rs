use std::{future::Future, pin::Pin, sync::Arc};

use opensnitch_proto::pb;
use tokio::process::Command;
use tokio::sync::broadcast;
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
    dyn Fn(Option<ProcMonitorMethod>) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
        + Send
        + Sync,
>;

pub(crate) type ProcWorkerControl = Arc<
    dyn Fn(WorkerCommand) -> Pin<Box<dyn Future<Output = WorkerCommandResult> + Send>>
        + Send
        + Sync,
>;

pub(crate) fn reconfigure_target(
    enabled: bool,
    method: ProcMonitorMethod,
) -> Option<ProcMonitorMethod> {
    if enabled { Some(method) } else { None }
}

fn log_config_delta(previous: &crate::config::Config, updated: &crate::config::Config) {
    if previous.log_file == updated.log_file {
        tracing::debug!("[config] config.server.logfile not changed");
    } else {
        let value = updated
            .log_file
            .as_ref()
            .map(|v| v.display().to_string())
            .unwrap_or_else(|| "/dev/stdout".to_string());
        tracing::debug!("[config] using config.server.logfile: {value}");
    }

    if previous.loggers == updated.loggers {
        tracing::debug!("[config] config.server.loggers not changed");
    } else {
        tracing::debug!(
            old = previous.loggers.len(),
            new = updated.loggers.len(),
            "[config] reloading config.server.loggers"
        );
    }

    if previous.stats.max_events == updated.stats.max_events
        && previous.stats.max_stats == updated.stats.max_stats
        && previous.stats.workers == updated.stats.workers
    {
        tracing::debug!("[config] config.stats not changed");
    } else {
        tracing::debug!("[config] reloading config.stats");
    }

    if previous.client_addr != updated.client_addr {
        tracing::debug!(
            "[config] using new config.server.address: {} -> {}",
            previous.client_addr,
            updated.client_addr
        );
        let reconnect = previous.client_addr != updated.client_addr;
        let connect = !updated.client_addr.is_empty();
        if previous.client_addr.is_empty() {
            let target_addr = updated
                .client_addr
                .strip_prefix("unix:")
                .unwrap_or(updated.client_addr.as_str());
            tracing::debug!(
                "[config] previous address was empty, connected: false, connecting to {}",
                target_addr
            );
        }
        tracing::debug!(
            "[config] server.address old: {}, new: {}, reconnect: {}, connect: {}",
            previous.client_addr,
            updated.client_addr,
            reconnect,
            connect
        );
        tracing::debug!(
            "[config] config.server.address.* changed, disconnecting from {}",
            previous.client_addr
        );
        if connect {
            let target_addr = updated
                .client_addr
                .strip_prefix("unix:")
                .unwrap_or(updated.client_addr.as_str());
            tracing::debug!(
                "[config] config.server. changed, connecting to {}",
                target_addr
            );
        }
    } else {
        tracing::debug!("[config] config.server.address.* not changed");
    }

    if previous.rules_enable_checksums == updated.rules_enable_checksums {
        tracing::debug!(
            "SetComputeChecksums(), no changes ({}, {})",
            previous.rules_enable_checksums,
            updated.rules_enable_checksums
        );
    } else if updated.rules_enable_checksums {
        tracing::debug!("SetComputeChecksums() enabled, recomputing cached checksums");
    } else {
        tracing::debug!("SetComputeChecksums() disabled, deleting saved checksums");
    }
    tracing::debug!(
        "[rules loader] EnableChecksums: {}",
        updated.rules_enable_checksums
    );

    if previous.gc_percent == updated.gc_percent {
        tracing::debug!("[config] config.Internal.GCPercent not changed");
    } else {
        tracing::debug!(old = ?previous.gc_percent, new = ?updated.gc_percent, "[config] reloading config.Internal.GCPercent");
    }

    if previous.rules_path != updated.rules_path {
        tracing::debug!(
            "[config] reloading config.rules.path, old: <{}> new: <{}>",
            previous.rules_path.display(),
            updated.rules_path.display()
        );
    } else {
        tracing::debug!("[config] config.rules.path not changed");
    }

    if previous.proc_monitor_method != updated.proc_monitor_method {
        tracing::debug!(
            "[config] reloading config.ProcMonMethod, old: {:?} -> new: {:?}",
            previous.proc_monitor_method,
            updated.proc_monitor_method
        );
    } else {
        tracing::debug!("[config] config.ProcMonMethod not changed");
    }

    if previous.audit_socket_path != updated.audit_socket_path {
        tracing::debug!("[config] reloading config.Audit");
    } else {
        tracing::debug!("[config] config.Audit not changed");
    }

    if previous.ebpf_modules_path == updated.ebpf_modules_path {
        tracing::debug!("[config] config.Ebpf.ModulesPath not changed");
    } else {
        tracing::debug!(
            "[config] reloading config.Ebpf.ModulesPath, old: {} -> new: {}",
            previous.ebpf_modules_path.display(),
            updated.ebpf_modules_path.display()
        );
    }

    if previous.proc_monitor_method == updated.proc_monitor_method
        && previous.audit_socket_path == updated.audit_socket_path
        && previous.ebpf_modules_path == updated.ebpf_modules_path
    {
        tracing::debug!("[config] config.procmon not changed");
    }

    if previous.firewall_backend.as_str() != updated.firewall_backend.as_str()
        || previous.firewall_config_path != updated.firewall_config_path
        || previous.firewall_queue_num != updated.firewall_queue_num
        || previous.firewall_queue_bypass != updated.firewall_queue_bypass
    {
        tracing::debug!("[config] reloading config.firewall");
    } else {
        tracing::debug!("[config] config.firewall not changed");
    }

    if previous.tasks_config_path != updated.tasks_config_path {
        tracing::debug!(
            "[tasks] Loader.Load() config file: {}",
            updated.tasks_config_path.display()
        );
    } else {
        tracing::debug!("[config] config.TasksOptions not changed");
    }
}

fn apply_gc_percent(gc_percent: Option<i32>) {
    if let Some(gc_percent) = gc_percent {
        tracing::debug!(
            gc_percent,
            "config.Internal.GCPercent requested; Rust runtime has no Go-style GC percent knob, keeping setting for parity metadata only"
        );
    }
}

async fn flush_established_connections() {
    tracing::debug!("[config] flushing established connections");

    let table = Command::new("conntrack").args(["-F"]).output().await;
    match table {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            tracing::error!(
                "error flushing ConntrackTable {}",
                if err.is_empty() {
                    "failed"
                } else {
                    err.as_str()
                }
            );
        }
        Err(err) => tracing::error!("error flushing ConntrackTable {err}"),
    }

    let expect = Command::new("conntrack")
        .args(["-F", "expect"])
        .output()
        .await;
    match expect {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            tracing::error!(
                "error flusing ConntrackExpectTable {}",
                if err.is_empty() {
                    "failed"
                } else {
                    err.as_str()
                }
            );
        }
        Err(err) => tracing::error!("error flusing ConntrackExpectTable {err}"),
    }
}

pub(crate) trait LogLevelExt {
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
        if let Err(err) = reconfigure_proc_workers(reconfigure_target(true, method)).await {
            tracing::error!("failed to reconfigure process monitor workers: {err}");
            send_task_reply(
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
    tracing::info!(
        notification_id,
        enabled,
        "received firewall interception command"
    );
    if enabled {
        let current = config.snapshot().await;
        tracing::info!(backend = ?current.firewall_backend, path = %current.firewall_config_path.display(), "reloading firewall from runtime config");
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
        tracing::info!("firewall interception enabled");
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
    } else {
        tracing::info!("firewall interception disabled");
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
    let Some(sys_firewall) = sys_firewall else {
        send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Error,
            "Error reloading firewall, invalid rules".to_string(),
        )
        .await;
        return;
    };

    let current = config.snapshot().await;
    tracing::info!(notification_id, backend = ?current.firewall_backend, "received firewall reload command");
    crate::ffi::nfqueue::set_default_action(current.default_action);
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
                let aggregated_errors = collect_firewall_errors(
                    &mut firewall_errors,
                    std::time::Duration::from_secs(2),
                )
                .await;

                if let Some(errors) = aggregated_errors {
                    tracing::error!("{errors}");
                    send_task_reply(
                        &task_reply_tx,
                        notification_id,
                        pb::NotificationReplyCode::Error,
                        errors,
                    )
                    .await;
                    return;
                }

                tracing::debug!("reload firewall timeout fired, no errors?");
                send_task_reply(
                    &task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Ok,
                    serde_json::json!({"status": "ok"}).to_string(),
                )
                .await;
            }
            Err(err) => {
                tracing::error!("{err}");
                send_task_reply(
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

async fn collect_firewall_errors(
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
    let previous = config.snapshot().await;
    match config.parse_raw_json(&raw_json).await {
        Ok(updated) => {
            let reload_proc = previous.proc_monitor_method != updated.proc_monitor_method
                || previous.audit_socket_path != updated.audit_socket_path;
            let reload_fw = previous.firewall_backend.as_str() != updated.firewall_backend.as_str()
                || previous.firewall_config_path != updated.firewall_config_path
                || previous.firewall_queue_num != updated.firewall_queue_num
                || previous.firewall_queue_bypass != updated.firewall_queue_bypass;

            log_config_delta(&previous, &updated);
            tracing::info!(
                notification_id,
                addr = %updated.client_addr,
                log_level = updated.log_level,
                ?updated.default_action,
                ?updated.proc_monitor_method,
                ?updated.firewall_backend,
                "applying config update to runtime services"
            );
            crate::ffi::nfqueue::set_default_action(updated.default_action);
            stats.apply_config(updated.stats);
            apply_gc_percent(updated.gc_percent);
            if let Err(err) = crate::logging::apply_config(&updated) {
                tracing::error!(
                    "failed to apply runtime logging config after config change: {err}"
                );
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
            if let Err(err) = reconfigure_proc_workers(Some(updated.proc_monitor_method)).await {
                tracing::error!("failed to reconfigure process monitor workers: {err}");
                send_task_reply(
                    task_reply_tx,
                    notification_id,
                    pb::NotificationReplyCode::Error,
                    format!("failed to reconfigure process monitor workers: {err}"),
                )
                .await;
                return;
            }
            if (reload_proc || reload_fw) && updated.flush_conns_on_start {
                flush_established_connections().await;
            } else {
                tracing::debug!("[config] not flushing established connections");
            }

            if let Err(err) = config.persist_raw_json(&raw_json).await {
                tracing::error!("failed to persist config payload after runtime apply: {err}");
                send_task_reply(
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
    let snapshot = config.snapshot().await;
    if let Err(err) = crate::logging::apply_config(&snapshot) {
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
    use super::collect_firewall_errors;

    #[tokio::test]
    async fn collect_firewall_errors_aggregates_pending_messages() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);
        let _ = tx.send("first error".to_string());
        let _ = tx.send("second error".to_string());

        let errors = collect_firewall_errors(&mut rx, std::time::Duration::from_millis(50)).await;
        assert_eq!(errors.as_deref(), Some("first error,second error"));
    }

    #[tokio::test]
    async fn collect_firewall_errors_returns_none_on_timeout_without_messages() {
        let (_tx, mut rx) = tokio::sync::broadcast::channel(8);

        let errors = collect_firewall_errors(&mut rx, std::time::Duration::from_millis(5)).await;
        assert!(errors.is_none());
    }
}
