use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    commands::{
        control::{
            CommandControlService, ControlCommandDispatch, ProcWorkerControlPort,
            ProcWorkerReconfigurePort,
        },
        rule::RuleCommandService,
        task::{TaskCommandDispatch, TaskCommandService},
    },
    models::command_rpc::ClientCommand,
    services::{
        config::ConfigService, firewall::FirewallService, lifecycle::ServiceLifecycle,
        process::ProcessService, rule::RuleService, stats::StatsService, task,
    },
};

pub struct CommandFlow {
    shutdown: CancellationToken,
    config: ConfigService,
    rules: RuleService,
    firewall: FirewallService,
    process: ProcessService,
    stats: StatsService,
    task_reply_tx: tokio::sync::mpsc::Sender<opensnitch_proto::pb::NotificationReply>,
    task_runtime: task::TaskRuntimeService,
    reconfigure_proc_workers: Arc<dyn ProcWorkerReconfigurePort>,
    control_proc_workers: Arc<dyn ProcWorkerControlPort>,
}

impl CommandFlow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shutdown: CancellationToken,
        config: ConfigService,
        rules: RuleService,
        firewall: FirewallService,
        process: ProcessService,
        stats: StatsService,
        task_reply_tx: tokio::sync::mpsc::Sender<opensnitch_proto::pb::NotificationReply>,
        task_runtime: task::TaskRuntimeService,
        reconfigure_proc_workers: Arc<dyn ProcWorkerReconfigurePort>,
        control_proc_workers: Arc<dyn ProcWorkerControlPort>,
    ) -> Self {
        Self {
            shutdown,
            config,
            rules,
            firewall,
            process,
            stats,
            task_reply_tx,
            task_runtime,
            reconfigure_proc_workers,
            control_proc_workers,
        }
    }

    pub fn spawn(
        self,
        mut client_cmd_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
    ) -> JoinHandle<()> {
        let Self {
            shutdown,
            config,
            rules,
            firewall,
            process,
            stats,
            task_reply_tx,
            task_runtime,
            reconfigure_proc_workers,
            control_proc_workers,
        } = self;

        let command_control = CommandControlService::default();
        let rule_command = RuleCommandService::default();
        let task_command = TaskCommandService::default();

        tokio::spawn(async move {
            let mut task_runtime_intent = task::TaskRuntime::new(
                task_runtime.clone(),
                process,
                task_reply_tx.clone(),
                shutdown.clone(),
            );
            if let Err(err) = task_runtime_intent.init().await {
                tracing::warn!("task runtime intent init failed: {err}");
            }
            if let Err(err) = task_runtime_intent.start().await {
                tracing::warn!("task runtime intent start failed: {err}");
            }

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = client_cmd_rx.recv() => {
                        match msg {
                            Some(cmd) => {
                                let Some(cmd) = rule_command
                                    .try_handle_client_command(cmd, &rules, &task_reply_tx)
                                    .await
                                else {
                                    continue;
                                };
                                let cmd = match command_control
                                    .try_handle_client_command(
                                        cmd,
                                        &config,
                                        &rules,
                                        &firewall,
                                        &stats,
                                        &task_reply_tx,
                                        reconfigure_proc_workers.as_ref(),
                                        control_proc_workers.as_ref(),
                                        &shutdown,
                                    )
                                    .await
                                {
                                    ControlCommandDispatch::HandledContinue => continue,
                                    ControlCommandDispatch::HandledBreak => break,
                                    ControlCommandDispatch::Unhandled(cmd) => cmd,
                                };
                                match task_command
                                    .try_handle_client_command(cmd, &mut task_runtime_intent)
                                    .await
                                {
                                    TaskCommandDispatch::HandledContinue => {}
                                    TaskCommandDispatch::Unhandled(cmd) => {
                                        tracing::warn!(?cmd, "command not handled by delegated command services");
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            task_runtime_intent.shutdown().await;
        })
    }
}
