use tokio_util::sync::CancellationToken;

use super::RuntimeTaskHandles;
use crate::{
    models::ui_alert::UiAlert,
    services::{client::AlertBuffer, config::ConfigService, process::ProcessService},
    workers::runtime::control::WorkerControl,
};

#[derive(Clone, Default)]
pub(crate) struct TaskService;

impl TaskService {
    pub(crate) fn spawn_storage_tasks_watch_task(
        &self,
        shutdown: CancellationToken,
        config: ConfigService,
        process: ProcessService,
        task_reply_tx: tokio::sync::mpsc::Sender<opensnitch_proto::pb::NotificationReply>,
        alert_buffer: AlertBuffer,
        alert_tx: tokio::sync::mpsc::Sender<UiAlert>,
    ) -> Box<dyn WorkerControl> {
        super::storage::start_task_watch_task(
            self.clone(),
            shutdown,
            config,
            process,
            task_reply_tx,
            alert_buffer,
            alert_tx,
        )
    }

    pub(crate) fn stop_runtime_tasks(task_handles: &mut RuntimeTaskHandles) -> usize {
        let stopped = task_handles.len();
        for (_, runtime) in task_handles.drain() {
            runtime.stop();
        }
        stopped
    }
}
