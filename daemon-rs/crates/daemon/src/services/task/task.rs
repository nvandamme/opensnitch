use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use opensnitch_proto::pb;
use tokio::{
    sync::{broadcast, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::{
    RuntimeTaskHandles, TaskLifecycleEvent, TaskRuntimeService, TaskStorageRuntime,
};
use crate::{
    models::command_rpc::TaskNotification,
    services::{
        lifecycle::{ServiceEvent, ServiceLifecycle, ServiceState, ServiceStatus},
        process::ProcessService,
    },
    utils::notification_reply::send_notification_reply,
};

pub(crate) struct TaskRuntime {
    task_runtime_service: TaskRuntimeService,
    process: ProcessService,
    task_reply_tx: tokio::sync::mpsc::Sender<pb::NotificationReply>,
    pub(super) task_handles: RuntimeTaskHandles,
    task_lifecycle_tx: tokio::sync::mpsc::Sender<TaskLifecycleEvent>,
    task_lifecycle_handle: JoinHandle<()>,
    pub(super) status_tx: watch::Sender<ServiceStatus>,
    pub(super) event_tx: broadcast::Sender<ServiceEvent>,
    pub(super) status_subscribers: Arc<AtomicUsize>,
    pub(super) event_subscribers: Arc<AtomicUsize>,
    pub(super) lifecycle_state: ServiceState,
    pub(super) last_error: Option<String>,
}

impl TaskRuntime {
    pub(crate) fn new(
        task_runtime_service: TaskRuntimeService,
        process: ProcessService,
        task_reply_tx: tokio::sync::mpsc::Sender<pb::NotificationReply>,
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
        let (status_tx, _) = watch::channel(ServiceStatus {
            state: ServiceState::Uninitialized,
            last_error: None,
        });
        let (event_tx, _) = broadcast::channel(256);
        let status_subscribers = Arc::new(AtomicUsize::new(0));
        let event_subscribers = Arc::new(AtomicUsize::new(0));

        Self {
            task_runtime_service,
            process,
            task_reply_tx,
            task_handles: RuntimeTaskHandles::default(),
            task_lifecycle_tx,
            task_lifecycle_handle,
            status_tx,
            event_tx,
            status_subscribers,
            event_subscribers,
            lifecycle_state: ServiceState::Uninitialized,
            last_error: None,
        }
    }

    pub(super) fn current_status(&self) -> ServiceStatus {
        ServiceStatus {
            state: self.lifecycle_state,
            last_error: self.last_error.clone(),
        }
    }

    fn publish_status(&self) {
        let _ = self.status_subscribers.load(Ordering::Relaxed);
        let _ = self.event_subscribers.load(Ordering::Relaxed);
        let _ = self.status_tx.send(self.current_status());
    }

    fn publish_state_change(
        &self,
        from: ServiceState,
        to: ServiceState,
        last_error: Option<String>,
    ) {
        let _ = self.event_tx.send(ServiceEvent::StateChanged {
            from,
            to,
            last_error,
        });
    }

    pub(super) fn transition_state(&mut self, to: ServiceState) {
        let from = self.lifecycle_state;
        self.lifecycle_state = to;
        self.publish_status();
        self.publish_state_change(from, to, self.last_error.clone());
    }

    pub(super) fn mark_last_error(&mut self, err: Option<String>) {
        self.last_error = err;
        self.publish_status();
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

        if let Err(message) = super::validation::validate_task_start_input(&task.name, &task.data) {
            let _ = send_notification_reply(
                &self.task_reply_tx,
                task.notification_id,
                pb::NotificationReplyCode::Error,
                message,
                "task notification",
            )
            .await;
            return;
        }

        let task_key = super::naming::build_task_key(&task.name, &task.data);
        if self.task_handles.contains_key(&task_key) {
            let _ = send_notification_reply(
                &self.task_reply_tx,
                task.notification_id,
                pb::NotificationReplyCode::Error,
                format!("task with name {} already exists", task_key),
                "task notification",
            )
            .await;
            return;
        }

        let token = CancellationToken::new();
        let task_data_snapshot = Arc::new(task.data);
        let handle = self.task_runtime_service.spawn_task_monitor_snapshot(
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

        let task_key = super::naming::build_task_key(&task.name, &task.data);
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

    pub(crate) async fn shutdown(mut self) {
        let _ = ServiceLifecycle::stop(&mut self).await;
        drop(self.task_lifecycle_tx);
        let _ = self.task_lifecycle_handle.await;
    }
}
