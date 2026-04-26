use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::SystemTime,
};

use anyhow::Result;

use tokio_util::sync::CancellationToken;

use super::{ConfigService, ProcWorkerReconfigure};
use crate::{
    config::{Config, ProcMonitorMethod},
    models::ui_alert::UiAlert,
    services::{
        client::{AlertBuffer, enqueue_alert, warning_alert},
        firewall::FirewallService,
        rule::RuleService,
        stats::StatsService,
        storage::{FileLoadableStateStore, StorageService},
    },
    utils::{
        atomic_write::unique_sibling_temp_path,
        config_reload::{
            RuntimeApplyMessageContext, RuntimeApplyPolicy, apply_runtime_config_services,
            apply_runtime_core, has_firewall_runtime_change, has_proc_runtime_change,
            runtime_apply_stage_messages,
        },
    },
    workers::runtime::{control::WorkerControl, watch::control::WatchWorkerControl},
};

impl ConfigService {
    pub(super) async fn persist_raw_json_at(path: &Path, raw_json: &str) -> Result<()> {
        let tmp_path = unique_sibling_temp_path(path, "tmp");
        tracing::debug!(path = %path.display(), tmp = %tmp_path.display(), "persisting raw config payload");
        StorageService::global()
            .write_bytes_atomic_and_notify("config", &tmp_path, path, raw_json.as_bytes())
            .await?;
        Ok(())
    }

    pub async fn reload(&self) -> Result<Config> {
        let current = self.get_snapshot();
        let path = current.config_path.as_path();
        tracing::debug!(path = %path.display(), "loading config from disk");
        let config = FileLoadableStateStore::load_config(path).await?;
        tracing::info!(
            addr = %config.client_addr,
            log_level = config.log_level,
            ?config.default_action,
            ?config.proc_monitor_method,
            ?config.firewall_backend,
            "config loaded from disk"
        );
        self.publish_config_snapshot(config.clone());
        Ok(config)
    }
}

fn proc_monitor_label(method: ProcMonitorMethod) -> &'static str {
    match method {
        ProcMonitorMethod::Proc => "/proc",
        ProcMonitorMethod::Audit => "audit",
        ProcMonitorMethod::Ebpf => "ebpf",
    }
}

struct ConfigWatchControl {
    config: ConfigService,
    rules: RuleService,
    firewall: FirewallService,
    stats: StatsService,
    alert_buffer: AlertBuffer,
    alert_tx: tokio::sync::mpsc::Sender<UiAlert>,
    reconfigure_proc_workers: ProcWorkerReconfigure,
    config_path: PathBuf,
    targets: Vec<PathBuf>,
    last_mtime: Arc<tokio::sync::Mutex<Option<SystemTime>>>,
}

impl WatchWorkerControl for ConfigWatchControl {
    fn worker_name(&self) -> &'static str {
        "config-watch"
    }

    fn poll_interval(&self) -> std::time::Duration {
        Self::poll_every_secs(2)
    }

    fn targets(&self) -> Vec<PathBuf> {
        self.targets.clone()
    }

    fn scan<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        let config = self.config.clone();
        let rules = self.rules.clone();
        let firewall = self.firewall.clone();
        let stats = self.stats.clone();
        let alert_buffer = self.alert_buffer.clone();
        let alert_tx = self.alert_tx.clone();
        let reconfigure_proc_workers = self.reconfigure_proc_workers.clone();
        let config_path = self.config_path.clone();
        let last_mtime = self.last_mtime.clone();

        Box::pin(async move {
            StorageService::global().emit_scan("config", config_path.as_path());
            let mtime = StorageService::global()
                .modified_time_if_exists("config", config_path.as_path())
                .await
                .ok()
                .flatten();
            let previous_mtime = *last_mtime.lock().await;

            if crate::workers::runtime::watch::control::is_newer_mtime(mtime, previous_mtime) {
                tracing::debug!(path = %config_path.display(), "config file change detected, reloading runtime config");
                let snapshot = config.get_snapshot();
                match config.reload().await {
                    Ok(updated) => {
                        let reload_proc = has_proc_runtime_change(&snapshot, &updated);
                        let reload_fw = has_firewall_runtime_change(&snapshot, &updated, false);

                        crate::utils::config_reload::log_config_delta(&snapshot, &updated, true);
                        tracing::debug!(
                            addr = %updated.client_addr,
                            log_level = updated.log_level,
                            ?updated.default_action,
                            ?updated.proc_monitor_method,
                            ?updated.firewall_backend,
                            "applying watched config update"
                        );
                        apply_runtime_core(&updated, &stats);
                        tracing::info!(
                            "Stats, max events: {}, max stats: {}, max workers: {}",
                            updated.stats.max_stats,
                            updated.stats.max_events,
                            updated.stats.workers
                        );
                        for worker in 0..updated.stats.workers {
                            tracing::debug!("Stats worker #{} started.", worker);
                        }
                        tracing::info!(
                            max_events = updated.stats.max_events,
                            max_stats = updated.stats.max_stats,
                            workers = updated.stats.workers,
                            "stats settings reloaded"
                        );
                        let apply_report = apply_runtime_config_services(
                            &updated,
                            &rules,
                            &firewall,
                            RuntimeApplyPolicy::ContinueOnError,
                            true,
                        )
                        .await;

                        let rules_ok = apply_report.rules_error.is_none();
                        let firewall_ok = apply_report.firewall_error.is_none();

                        for (stage, err) in apply_report.into_stage_errors() {
                            let messages = runtime_apply_stage_messages(
                                RuntimeApplyMessageContext::ConfigWatch,
                                stage,
                            );

                            tracing::error!("{}: {err}", messages.log);
                            enqueue_alert(
                                &alert_buffer,
                                &alert_tx,
                                warning_alert(format!("{}: {err}", messages.external)),
                            );
                        }

                        tracing::info!("rules.Loader.Reload(): {}", updated.rules_path.display());
                        tracing::debug!("rules.Loader.Load(): {}", updated.rules_path.display());
                        if rules_ok {
                            tracing::info!(path = %updated.rules_path.display(), "rules path reloaded");
                        }
                        if firewall_ok {
                            tracing::info!(backend = ?updated.firewall_backend, "firewall backend reconciled after config reload");
                        }
                        tracing::debug!("monitor.End()");
                        tracing::info!(
                            "Process monitor method {}",
                            proc_monitor_label(snapshot.proc_monitor_method)
                        );
                        if let Err(err) =
                            reconfigure_proc_workers(Some(updated.proc_monitor_method)).await
                        {
                            tracing::error!(
                                "failed to reconfigure process monitor workers after config reload: {err}"
                            );
                            enqueue_alert(
                                &alert_buffer,
                                &alert_tx,
                                warning_alert(format!(
                                    "failed to reconfigure process monitor workers after config reload: {err}"
                                )),
                            );
                        } else {
                            tracing::info!(?updated.proc_monitor_method, "process monitor workers reconfigured after config reload");
                        }

                        if (reload_proc || reload_fw) && updated.flush_conns_on_start {
                            crate::utils::config_reload::flush_established_connections().await;
                        } else {
                            tracing::debug!("[config] not flushing established connections");
                        }
                    }
                    Err(err) => {
                        tracing::error!("failed to reload config from watched file: {err}");
                        enqueue_alert(
                            &alert_buffer,
                            &alert_tx,
                            warning_alert(format!(
                                "failed to reload config from watched file: {err}"
                            )),
                        );
                    }
                }
            }

            if mtime.is_some() {
                *last_mtime.lock().await = mtime;
            }
        })
    }
}

pub(super) fn start_config_watch_task(
    config: ConfigService,
    shutdown: CancellationToken,
    rules: RuleService,
    firewall: FirewallService,
    stats: StatsService,
    alert_buffer: AlertBuffer,
    alert_tx: tokio::sync::mpsc::Sender<UiAlert>,
    reconfigure_proc_workers: ProcWorkerReconfigure,
) -> Box<dyn WorkerControl> {
    let initial_snapshot = config.get_snapshot();
    let config_path = initial_snapshot.config_path.clone();
    let targets = ConfigWatchControl::path_targets(config_path.as_path());

    ConfigWatchControl {
        config,
        rules,
        firewall,
        stats,
        alert_buffer,
        alert_tx,
        reconfigure_proc_workers,
        config_path,
        targets,
        last_mtime: Arc::new(tokio::sync::Mutex::new(None)),
    }
    .build(shutdown)
}
