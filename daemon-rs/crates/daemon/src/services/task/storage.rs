use std::{collections::HashMap, io::ErrorKind, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::{
    RuntimeTaskHandles, TaskRuntimePayload, TaskService, TaskStorageRuntime,
    naming as task_runtime_naming, validation as task_runtime_validation,
};
use crate::{
    models::task_storage::{TaskDataFile, TasksListFile},
    models::ui_alert::UiAlert,
    services::storage::StorageService,
    services::{
        client::{AlertBuffer, enqueue_alert, warning_alert},
        config::ConfigService,
        process::ProcessService,
    },
    workers::runtime::{
        control::{
            WorkerCommand, WorkerCommandResult, WorkerControl, WorkerJoinStatus, WorkerState,
        },
        watch::control::WatchWorkerControl,
    },
};

impl TaskService {
    // Retained for optional storage-to-runtime task synchronization flows.
    #[allow(dead_code)]
    pub(crate) async fn sync_storage_tasks(
        &self,
        tasks_file: &std::path::Path,
        task_handles: &mut RuntimeTaskHandles,
        process: ProcessService,
        task_reply_tx: tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
    ) -> Result<()> {
        let desired = Self::load_storage_tasks(tasks_file).await?;
        self.apply_storage_task_diff(desired, task_handles, process, task_reply_tx)
    }

    /// Apply the diff between desired storage tasks and current runtime handles.
    /// This is the mutation-only half — call `load_storage_tasks` separately for
    /// the I/O phase so the caller can narrow mutex scope.
    pub(crate) fn apply_storage_task_diff(
        &self,
        desired: HashMap<String, (String, TaskRuntimePayload, String)>,
        task_handles: &mut RuntimeTaskHandles,
        process: ProcessService,
        task_reply_tx: tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
    ) -> Result<()> {
        task_handles.retain(|key, runtime| {
            if desired.contains_key(key) {
                true
            } else {
                runtime.token.cancel();
                runtime.handle.abort();
                false
            }
        });

        for (key, (task_name, task_data, fingerprint)) in desired {
            if !task_runtime_validation::storage_task_name_supported(task_name.as_str()) {
                tracing::debug!(task = %task_name, "skipping unsupported disk task");
                continue;
            }

            if let Some(runtime) = task_handles.get(&key)
                && runtime.fingerprint == fingerprint
            {
                continue;
            }

            if let Some(runtime) = task_handles.remove(&key) {
                tracing::info!(task = %key, "restarting disk task after config change");
                runtime.stop();
            }

            let token = CancellationToken::new();
            let handle = self.spawn_task_monitor_snapshot(
                task_name.as_str(),
                0,
                task_data,
                token.clone(),
                process.clone(),
                task_reply_tx.clone(),
            );
            task_handles.insert(key, TaskStorageRuntime::disk(handle, token, fingerprint));
        }

        Ok(())
    }

    fn storage_task_fingerprint(path: &std::path::Path, raw_task: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(raw_task.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub(crate) async fn load_storage_tasks(
        tasks_file: &std::path::Path,
    ) -> Result<HashMap<String, (String, TaskRuntimePayload, String)>> {
        let storage = StorageService::global();
        tracing::debug!(
            "[tasks] Loader.Load() config file: {}",
            tasks_file.display()
        );
        let tasks_list = match storage
            .read_and_parse_with_storage_format_if_exists_and_notify::<TasksListFile>(
                "task", tasks_file,
            )
            .await
        {
            Ok(Some(tasks_list)) => tasks_list,
            Ok(None) => {
                tracing::warn!(
                    "[tasks] LoadTaskFile, error loading tasks (), error reading tasks list file {}: {}",
                    tasks_file.display(),
                    ErrorKind::NotFound
                );
                return Ok(HashMap::new());
            }
            Err(err) => {
                tracing::warn!(
                    "[tasks] LoadTaskFile, error loading tasks (), error reading tasks list file {}: {}",
                    tasks_file.display(),
                    err
                );
                return Err(err);
            }
        };
        let tasks_base_dir = tasks_file
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let mut loaded = HashMap::new();
        for task in tasks_list.tasks.into_iter().filter(|task| task.enabled) {
            if task.config_file.trim().is_empty() {
                continue;
            }

            let config_path = {
                let configured = std::path::PathBuf::from(task.config_file.trim());
                if configured.is_absolute() {
                    configured
                } else {
                    tasks_base_dir.join(configured)
                }
            };

            let raw_task = match storage
                .read_to_string_if_exists_and_notify("task", &config_path)
                .await
            {
                Ok(Some(raw_task)) => raw_task,
                Ok(None) | Err(_) => continue,
            };
            let parsed = match StorageService::parse_with_storage_format_for_path::<TaskDataFile>(
                &config_path,
                &raw_task,
            ) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };

            let task_name = if !parsed.parent.trim().is_empty() {
                parsed.parent.trim().to_string()
            } else if !task.name.trim().is_empty() {
                task.name.trim().to_string()
            } else {
                parsed.name.trim().to_string()
            };
            let task_name = task_runtime_naming::normalized_task_name(&task_name);
            if task_name.is_empty() {
                continue;
            }

            let instance_name = if !parsed.name.trim().is_empty() {
                parsed.name.trim().to_string()
            } else {
                task_name.clone()
            };
            let fingerprint = Self::storage_task_fingerprint(&config_path, &raw_task);

            loaded.insert(
                format!("disk-task:{instance_name}"),
                (
                    task_name.clone(),
                    TaskRuntimePayload::from_task_data(&task_name, parsed.data),
                    fingerprint,
                ),
            );
        }

        Ok(loaded)
    }
}

struct TaskWatchControl {
    task_service: TaskService,
    process: ProcessService,
    task_reply_tx: tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
    alert_buffer: AlertBuffer,
    alert_tx: tokio::sync::mpsc::Sender<UiAlert>,
    tasks_config_path: PathBuf,
    targets: Vec<PathBuf>,
    task_handles: Arc<tokio::sync::Mutex<RuntimeTaskHandles>>,
}

impl WatchWorkerControl for TaskWatchControl {
    fn worker_name(&self) -> &'static str {
        "tasks-watch"
    }

    fn poll_interval(&self) -> Duration {
        Self::poll_every_secs(3)
    }

    fn targets(&self) -> Vec<PathBuf> {
        self.targets.clone()
    }

    fn scan<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let task_service = self.task_service.clone();
        let process = self.process.clone();
        let task_reply_tx = self.task_reply_tx.clone();
        let alert_buffer = self.alert_buffer.clone();
        let alert_tx = self.alert_tx.clone();
        let tasks_config_path = self.tasks_config_path.clone();
        let task_handles = self.task_handles.clone();

        Box::pin(async move {
            StorageService::global().emit_scan("task", tasks_config_path.as_path());

            // Load desired state (file I/O) without holding the mutex.
            let desired = match TaskService::load_storage_tasks(tasks_config_path.as_path()).await {
                Ok(desired) => desired,
                Err(err) => {
                    tracing::error!(path = %tasks_config_path.display(), "failed to load disk tasks: {err}");
                    enqueue_alert(
                        &alert_buffer,
                        &alert_tx,
                        warning_alert(format!("failed to load disk tasks: {err}")),
                    );
                    return;
                }
            };

            // Short lock scope: apply diff only.
            let mut task_handles = task_handles.lock().await;
            if let Err(err) = task_service.apply_storage_task_diff(
                desired,
                &mut task_handles,
                process.clone(),
                task_reply_tx.clone(),
            ) {
                tracing::error!(path = %tasks_config_path.display(), "failed to sync disk tasks: {err}");
                enqueue_alert(
                    &alert_buffer,
                    &alert_tx,
                    warning_alert(format!("failed to sync disk tasks: {err}")),
                );
            }
        })
    }
}

struct CompositeWatchWorkerControl {
    primary: Box<dyn WorkerControl>,
    cleanup: Box<dyn WorkerControl>,
}

impl WorkerControl for CompositeWatchWorkerControl {
    fn worker_name(&self) -> &'static str {
        self.primary.worker_name()
    }

    fn control(&self, command: WorkerCommand) -> WorkerCommandResult {
        let _ = self.cleanup.control(command);
        self.primary.control(command)
    }

    fn state(&self) -> WorkerState {
        self.primary.state()
    }

    fn is_finished(&self) -> bool {
        self.primary.is_finished()
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus {
        let primary_status = self.primary.join();
        let _ = self.cleanup.join();
        primary_status
    }
}

struct CleanupWorkerControl {
    shutdown: CancellationToken,
    runtime: tokio::runtime::Handle,
    handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl WorkerControl for CleanupWorkerControl {
    fn worker_name(&self) -> &'static str {
        "tasks-watch-cleanup"
    }

    fn control(&self, command: WorkerCommand) -> WorkerCommandResult {
        match command {
            WorkerCommand::Stop => {
                self.shutdown.cancel();
                WorkerCommandResult::Applied
            }
            WorkerCommand::Probe => WorkerCommandResult::Applied,
            WorkerCommand::Start => WorkerCommandResult::Unsupported,
        }
    }

    fn state(&self) -> WorkerState {
        let guard = self
            .handle
            .lock()
            .expect("cleanup worker handle mutex poisoned");
        match guard.as_ref() {
            Some(handle) if handle.is_finished() => WorkerState::Stopped,
            Some(_) => WorkerState::Running,
            None => WorkerState::Stopped,
        }
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus {
        self.shutdown.cancel();
        let handle = self
            .handle
            .lock()
            .expect("cleanup worker handle mutex poisoned")
            .take();
        let Some(handle) = handle else {
            return WorkerJoinStatus::Stopped;
        };
        match self.runtime.block_on(async { handle.await }) {
            Ok(()) => WorkerJoinStatus::Stopped,
            Err(err) if err.is_panic() => WorkerJoinStatus::Panicked,
            Err(_) => WorkerJoinStatus::Stopped,
        }
    }
}

pub(super) fn start_task_watch_task(
    task_service: TaskService,
    shutdown: CancellationToken,
    config: ConfigService,
    process: ProcessService,
    task_reply_tx: tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
    alert_buffer: AlertBuffer,
    alert_tx: tokio::sync::mpsc::Sender<UiAlert>,
) -> Box<dyn WorkerControl> {
    let initial_snapshot = config.get_snapshot();
    let tasks_config_path = initial_snapshot.tasks_config_path.clone();
    let mut targets = TaskWatchControl::path_targets(tasks_config_path.as_path());
    if let Some(parent) = tasks_config_path.parent() {
        targets.push(parent.to_path_buf());
    }
    targets.sort();
    targets.dedup();

    let task_handles = Arc::new(tokio::sync::Mutex::new(RuntimeTaskHandles::default()));

    let watch_handle = TaskWatchControl {
        task_service: task_service.clone(),
        process,
        task_reply_tx,
        alert_buffer,
        alert_tx,
        tasks_config_path,
        targets,
        task_handles: task_handles.clone(),
    }
    .build(shutdown.clone());

    let cleanup_shutdown = CancellationToken::new();
    let cleanup_token = cleanup_shutdown.clone();
    let cleanup_runtime = tokio::runtime::Handle::current();
    let shutdown_handles = task_handles;
    let cleanup_handle = tokio::spawn(async move {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = cleanup_token.cancelled() => {}
        }
        let mut task_handles = shutdown_handles.lock().await;
        TaskService::stop_runtime_tasks(&mut task_handles);
    });

    Box::new(CompositeWatchWorkerControl {
        primary: watch_handle,
        cleanup: Box::new(CleanupWorkerControl {
            shutdown: cleanup_shutdown,
            runtime: cleanup_runtime,
            handle: std::sync::Mutex::new(Some(cleanup_handle)),
        }),
    })
}
