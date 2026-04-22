use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{
    RuntimeTaskHandles, TaskLifecycleEvent, TaskRuntimePayload, TaskService, TaskStorageRuntime,
    runtime_lifecycle::TaskLifecycle,
};
use crate::{
    models::command_rpc::TaskNotification,
    services::{lifecycle::ServiceLifecycle, process::ProcessService},
    utils::notification_reply::send_notification_reply,
};

pub(crate) struct TaskRuntime {
    task_service: TaskService,
    process: ProcessService,
    task_reply_tx: tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
    pub(super) task_handles: RuntimeTaskHandles,
    task_lifecycle_tx: tokio::sync::mpsc::Sender<TaskLifecycleEvent>,
    task_lifecycle_handle: JoinHandle<()>,
    pub(super) lifecycle: TaskLifecycle,
}

impl TaskRuntime {
    pub(crate) fn new(
        task_service: TaskService,
        process: ProcessService,
        task_reply_tx: tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
        shutdown: CancellationToken,
    ) -> Self {
        let (task_lifecycle_tx, mut task_lifecycle_rx) =
            tokio::sync::mpsc::channel::<TaskLifecycleEvent>(128);
        let task_lifecycle_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = task_lifecycle_rx.recv() => {
                        match msg {
                            Some(TaskLifecycleEvent::Added { task_name, task_key }) => {
                                tracing::debug!(task = %task_name, key = %task_key, "Task Added");
                            }
                            Some(TaskLifecycleEvent::Removed { task_name, task_key }) => {
                                tracing::debug!(task = %task_name, key = %task_key, "Task removed");
                            }
                            Some(TaskLifecycleEvent::PausedAll { task_count }) => {
                                tracing::debug!(task_count, "runtime task manager pause-all acknowledged");
                            }
                            Some(TaskLifecycleEvent::ResumedAll { task_count }) => {
                                tracing::debug!(task_count, "runtime task manager resume-all acknowledged");
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        Self {
            task_service,
            process,
            task_reply_tx,
            task_handles: RuntimeTaskHandles::default(),
            task_lifecycle_tx,
            task_lifecycle_handle,
            lifecycle: TaskLifecycle::default(),
        }
    }

    pub(super) async fn emit_lifecycle_event(&self, event: TaskLifecycleEvent) {
        match self.task_lifecycle_tx.try_send(event) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                let _ = self.task_lifecycle_tx.send(event).await;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    pub(crate) async fn handle_start_task(&mut self, task: TaskNotification) {
        if !super::validation::is_runtime_task_name_supported(&task.name) {
            tracing::debug!(task = %task.name, "TaskStart ignored for unsupported runtime task");
            return;
        }

        let task_data_snapshot = TaskRuntimePayload::from_task_data_raw(&task.name, &task.data);

        if let Err(message) =
            super::validation::validate_task_start_input(&task.name, &task_data_snapshot)
        {
            let _ = send_notification_reply(
                &self.task_reply_tx,
                task.notification_id,
                transport_wire_core::WireNotificationReplyCode::Error,
                message,
                "task notification",
            )
            .await;
            return;
        }

        let task_key = super::naming::build_task_key(&task.name, &task_data_snapshot);
        if self.task_handles.contains_key(&task_key) {
            let _ = send_notification_reply(
                &self.task_reply_tx,
                task.notification_id,
                transport_wire_core::WireNotificationReplyCode::Error,
                format!("task with name {} already exists", task_key),
                "task notification",
            )
            .await;
            return;
        }

        let token = CancellationToken::new();
        let handle = self.task_service.spawn_task_monitor_snapshot(
            &task.name,
            task.notification_id,
            task_data_snapshot,
            token.clone(),
            self.process.clone(),
            self.task_reply_tx.clone(),
        );
        let event = TaskLifecycleEvent::Added {
            task_name: task.name.clone(),
            task_key: task_key.clone(),
        };
        self.task_handles
            .insert(task_key, TaskStorageRuntime::runtime(handle, token));
        self.emit_lifecycle_event(event).await;
    }

    pub(crate) async fn handle_stop_task(&mut self, task: TaskNotification) {
        if !super::validation::is_runtime_task_name_supported(&task.name) {
            tracing::debug!(task = %task.name, "TaskStop ignored for unsupported runtime task");
            return;
        }

        let task_data_snapshot = TaskRuntimePayload::from_task_data_raw(&task.name, &task.data);
        let task_key = super::naming::build_task_key(&task.name, &task_data_snapshot);
        if let Some(runtime) = self.task_handles.remove(&task_key) {
            runtime.stop();
            self.emit_lifecycle_event(TaskLifecycleEvent::Removed {
                task_name: task.name.clone(),
                task_key,
            })
            .await;
        } else {
            tracing::debug!(task = %task_key, "TaskStop requested for non-running task");
        }
    }

    pub(crate) async fn stop(mut self) {
        let _ = ServiceLifecycle::stop(&mut self).await;
        drop(self.task_lifecycle_tx);
        let _ = self.task_lifecycle_handle.await;
    }
}
