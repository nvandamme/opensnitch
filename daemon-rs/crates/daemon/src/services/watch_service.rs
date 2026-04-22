use std::{future::Future, pin::Pin, sync::Arc, time::SystemTime};

use opensnitch_proto::pb;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    commands::task_runtime,
    config::ProcMonitorMethod,
    services::{
        config_service::ConfigService, firewall_service::FirewallService,
        process_service::ProcessService, rule_service::RuleService,
        runtime_state_service::StatefulService, stats_service::StatsService,
    },
};

pub(crate) type ProcWorkerReconfigure = Arc<
    dyn Fn(Option<ProcMonitorMethod>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
>;

pub trait WatcherService: StatefulService {
    fn spawn_config_watch_task(&self) -> JoinHandle<()>;
    fn spawn_rules_watch_task(&self) -> JoinHandle<()>;
    fn spawn_tasks_watch_task(&self) -> JoinHandle<()>;
}

#[derive(Clone)]
pub struct WatchService {
    shutdown: CancellationToken,
    config: ConfigService,
    rules: RuleService,
    firewall: FirewallService,
    stats: StatsService,
    process: ProcessService,
    task_reply_tx: tokio::sync::mpsc::Sender<pb::NotificationReply>,
    reconfigure_proc_workers: ProcWorkerReconfigure,
}

impl WatchService {
    pub fn new(
        shutdown: CancellationToken,
        config: ConfigService,
        rules: RuleService,
        firewall: FirewallService,
        stats: StatsService,
        process: ProcessService,
        task_reply_tx: tokio::sync::mpsc::Sender<pb::NotificationReply>,
        reconfigure_proc_workers: ProcWorkerReconfigure,
    ) -> Self {
        Self {
            shutdown,
            config,
            rules,
            firewall,
            stats,
            process,
            task_reply_tx,
            reconfigure_proc_workers,
        }
    }
}

trait WatchedMtimeExt {
    fn is_newer_than(self, previous: Option<SystemTime>) -> bool;
}

impl WatchedMtimeExt for Option<SystemTime> {
    fn is_newer_than(self, previous: Option<SystemTime>) -> bool {
        matches!((previous, self), (Some(prev), Some(cur)) if cur > prev)
    }
}

impl WatcherService for WatchService {
    fn spawn_config_watch_task(&self) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let config = self.config.clone();
        let rules = self.rules.clone();
        let firewall = self.firewall.clone();
        let stats = self.stats.clone();
        let reconfigure_proc_workers = self.reconfigure_proc_workers.clone();

        tokio::spawn(async move {
            let mut last_mtime: Option<SystemTime> = None;

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                        let snapshot = config.snapshot().await;
                        let mtime = tokio::fs::metadata(&snapshot.config_path)
                            .await
                            .ok()
                            .and_then(|meta| meta.modified().ok());

                        if mtime.is_newer_than(last_mtime) {
                            match config.reload().await {
                                Ok(updated) => {
                                    crate::ffi::nfqueue::set_default_action(updated.default_action);
                                    stats.apply_config(updated.stats);
                                    if let Err(err) = crate::logging::set_opensnitch_log_level(updated.log_level as i32) {
                                        tracing::error!("failed to apply runtime log level after config file change: {err}");
                                    }
                                    if let Err(err) = rules.load_path(&updated.rules_path).await {
                                        tracing::error!("failed to reload rules after config file change: {err}");
                                    }
                                    if let Err(err) = firewall.reconcile_from_config(&updated).await {
                                        tracing::error!("failed to reconcile firewall after config file change: {err}");
                                    }
                                    reconfigure_proc_workers(Some(updated.proc_monitor_method)).await;
                                }
                                Err(err) => tracing::error!("failed to reload config from watched file: {err}"),
                            }
                        }

                        if mtime.is_some() {
                            last_mtime = mtime;
                        }
                    }
                }
            }
        })
    }

    fn spawn_rules_watch_task(&self) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let rules = self.rules.clone();

        tokio::spawn(async move {
            let mut last_state: Option<(u64, Option<SystemTime>)> = None;

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                        let path = rules.rules_path().await;
                        let state = read_rules_dir_state_async(&path).await;

                        let changed = match (&last_state, &state) {
                            (Some(prev), Some(cur)) => prev != cur,
                            (None, Some(_)) => false,
                            (Some(_), None) => true,
                            (None, None) => false,
                        };

                        if changed {
                            if let Err(err) = rules.reload().await {
                                tracing::error!(path = %path.display(), "failed to reload rules after directory change: {err}");
                            } else {
                                tracing::info!(path = %path.display(), "rules reloaded after directory change");
                            }
                        }

                        last_state = state;
                    }
                }
            }
        })
    }

    fn spawn_tasks_watch_task(&self) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let config = self.config.clone();
        let process = self.process.clone();
        let task_reply_tx = self.task_reply_tx.clone();

        tokio::spawn(async move {
            let mut task_handles: std::collections::HashMap<String, task_runtime::DiskTaskRuntime> =
                std::collections::HashMap::new();

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                        let snapshot = config.snapshot().await;
                        let path = snapshot.tasks_config_path;

                        if let Err(err) = task_runtime::sync_disk_tasks(
                            &path,
                            &mut task_handles,
                            process.clone(),
                            task_reply_tx.clone(),
                        )
                        .await
                        {
                            tracing::error!(path = %path.display(), "failed to sync disk tasks: {err}");
                        }
                    }
                }
            }

            task_runtime::stop_disk_tasks(&mut task_handles);
        })
    }
}

#[cfg(test)]
pub(crate) fn read_rules_dir_state(path: &std::path::Path) -> Option<(u64, Option<SystemTime>)> {
    let mut count = 0_u64;
    let mut latest: Option<SystemTime> = None;

    let entries = std::fs::read_dir(path).ok()?;
    for entry in entries.flatten() {
        let file_path = entry.path();
        if file_path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        count = count.saturating_add(1);
        if let Ok(meta) = entry.metadata()
            && let Ok(modified) = meta.modified()
        {
            latest = Some(match latest {
                Some(prev) if prev > modified => prev,
                _ => modified,
            });
        }
    }

    Some((count, latest))
}

async fn read_rules_dir_state_async(path: &std::path::Path) -> Option<(u64, Option<SystemTime>)> {
    let mut count = 0_u64;
    let mut latest: Option<SystemTime> = None;

    let mut entries = tokio::fs::read_dir(path).await.ok()?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let file_path = entry.path();
        if file_path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        count = count.saturating_add(1);

        if let Ok(meta) = entry.metadata().await
            && let Ok(modified) = meta.modified()
        {
            latest = Some(match latest {
                Some(prev) if prev > modified => prev,
                _ => modified,
            });
        }
    }

    Some((count, latest))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{Duration, SystemTime},
    };

    use super::{WatchedMtimeExt, read_rules_dir_state};
    use crate::utils::test_support::TestDir;

    #[test]
    fn config_file_changed_only_triggers_on_newer_timestamp() {
        let prev = SystemTime::UNIX_EPOCH + Duration::from_secs(5);
        let newer = SystemTime::UNIX_EPOCH + Duration::from_secs(6);

        assert!(!Some(newer).is_newer_than(None));
        assert!(!Some(prev).is_newer_than(Some(prev)));
        assert!(Some(newer).is_newer_than(Some(prev)));
    }

    #[test]
    fn read_rules_dir_state_counts_json_files_only() {
        let temp_dir = TestDir::new("opensnitch-watch-service");
        fs::write(temp_dir.path.join("one.json"), "{}").expect("write json rule");
        fs::write(temp_dir.path.join("two.txt"), "ignored").expect("write txt file");

        let state = read_rules_dir_state(&temp_dir.path).expect("rules dir state");
        assert_eq!(state.0, 1);
        assert!(state.1.is_some());
    }
}
