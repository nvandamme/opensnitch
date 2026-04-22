use crate::{
    models::command_rpc::ClientCommand,
    services::{lifecycle::ServiceLifecycle, task::TaskRuntime},
};

pub(crate) enum TaskCommandDispatch {
    HandledContinue,
    Unhandled(ClientCommand),
}

#[derive(Clone, Default)]
pub(crate) struct TaskCommandService;

impl TaskCommandService {
    pub(crate) async fn try_handle_client_command(
        &self,
        cmd: ClientCommand,
        task_runtime: &mut TaskRuntime,
    ) -> TaskCommandDispatch {
        match cmd {
            ClientCommand::StartTask(task) => {
                task_runtime.handle_start_task(task).await;
                TaskCommandDispatch::HandledContinue
            }
            ClientCommand::StopTask(task) => {
                task_runtime.handle_stop_task(task).await;
                TaskCommandDispatch::HandledContinue
            }
            ClientCommand::PauseRuntimeTasks => {
                if let Err(err) = task_runtime.pause().await {
                    tracing::warn!("task runtime intent pause failed: {err}");
                }
                TaskCommandDispatch::HandledContinue
            }
            ClientCommand::ResumeRuntimeTasks => {
                if let Err(err) = task_runtime.resume().await {
                    tracing::warn!("task runtime intent resume failed: {err}");
                }
                TaskCommandDispatch::HandledContinue
            }
            ClientCommand::StopRuntimeTasks => {
                if let Err(err) = task_runtime.stop().await {
                    tracing::warn!("task runtime intent stop failed: {err}");
                }
                TaskCommandDispatch::HandledContinue
            }
            other => TaskCommandDispatch::Unhandled(other),
        }
    }
}
