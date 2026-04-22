use crate::{
    models::{
        audit::{AuditEvent, AuditEventKind, TaskAction},
        command_rpc::ClientCommand,
    },
    services::{audit::AuditService, lifecycle::ServiceLifecycle, task::TaskRuntime},
};

pub(crate) enum TaskCommandDispatch {
    HandledContinue,
    Unhandled(ClientCommand),
}

#[derive(Clone)]
pub(crate) struct TaskCommandService {
    audit: AuditService,
}

impl TaskCommandService {
    pub(crate) fn new(audit: AuditService) -> Self {
        Self { audit }
    }

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
                match task_runtime.pause().await {
                    Ok(()) => {
                        self.audit.emit(AuditEvent::cold(AuditEventKind::TaskAction(
                            TaskAction::TaskRuntimePaused,
                        )));
                    }
                    Err(err) => {
                        tracing::warn!("task runtime pause failed: {err}");
                        self.audit.emit(AuditEvent::cold(AuditEventKind::TaskAction(
                            TaskAction::TaskRuntimePauseFailed,
                        )));
                    }
                }
                TaskCommandDispatch::HandledContinue
            }
            ClientCommand::ResumeRuntimeTasks => {
                match task_runtime.resume().await {
                    Ok(()) => {
                        self.audit.emit(AuditEvent::cold(AuditEventKind::TaskAction(
                            TaskAction::TaskRuntimeResumed,
                        )));
                    }
                    Err(err) => {
                        tracing::warn!("task runtime resume failed: {err}");
                        self.audit.emit(AuditEvent::cold(AuditEventKind::TaskAction(
                            TaskAction::TaskRuntimeResumeFailed,
                        )));
                    }
                }
                TaskCommandDispatch::HandledContinue
            }
            ClientCommand::StopRuntimeTasks => {
                match task_runtime.stop().await {
                    Ok(()) => {
                        self.audit.emit(AuditEvent::cold(AuditEventKind::TaskAction(
                            TaskAction::TaskRuntimeStopped,
                        )));
                    }
                    Err(err) => {
                        tracing::warn!("task runtime stop failed: {err}");
                        self.audit.emit(AuditEvent::cold(AuditEventKind::TaskAction(
                            TaskAction::TaskRuntimeStopFailed,
                        )));
                    }
                }
                TaskCommandDispatch::HandledContinue
            }
            other => TaskCommandDispatch::Unhandled(other),
        }
    }
}
