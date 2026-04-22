use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    commands::{
        control::{
            CommandControlService, ControlCommandDispatch, DaemonReloadPort, ProcWorkerControlPort,
            ProcWorkerReconfigurePort,
        },
        rule::RuleCommandService,
        task::{TaskCommandDispatch, TaskCommandService},
    },
    models::command_rpc::ClientCommand,
    services::{
        audit::AuditService, client::ClientService, config::ConfigService,
        firewall::FirewallService, lifecycle::ServiceLifecycle, process::ProcessService,
        rule::RuleService, stats::StatsService, task,
    },
};

pub struct CommandFlow {
    shutdown: CancellationToken,
    client_service: ClientService,
    config: ConfigService,
    rules: RuleService,
    firewall: FirewallService,
    process: ProcessService,
    stats: StatsService,
    task_reply_tx: tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
    tasks: task::TaskService,
    reconfigure_proc_workers: Arc<dyn ProcWorkerReconfigurePort>,
    control_proc_workers: Arc<dyn ProcWorkerControlPort>,
    daemon_reload: Arc<dyn DaemonReloadPort>,
    audit: AuditService,
}

impl CommandFlow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shutdown: CancellationToken,
        client_service: ClientService,
        config: ConfigService,
        rules: RuleService,
        firewall: FirewallService,
        process: ProcessService,
        stats: StatsService,
        task_reply_tx: tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
        tasks: task::TaskService,
        reconfigure_proc_workers: Arc<dyn ProcWorkerReconfigurePort>,
        control_proc_workers: Arc<dyn ProcWorkerControlPort>,
        daemon_reload: Arc<dyn DaemonReloadPort>,
        audit: AuditService,
    ) -> Self {
        Self {
            shutdown,
            client_service,
            config,
            rules,
            firewall,
            process,
            stats,
            task_reply_tx,
            tasks,
            reconfigure_proc_workers,
            control_proc_workers,
            daemon_reload,
            audit,
        }
    }

    pub fn spawn(
        self,
        mut client_cmd_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
    ) -> JoinHandle<()> {
        let Self {
            shutdown,
            client_service,
            config,
            rules,
            firewall,
            process,
            stats,
            task_reply_tx,
            tasks: task_runtime,
            reconfigure_proc_workers,
            control_proc_workers,
            daemon_reload,
            audit,
        } = self;

        let command_control = CommandControlService::new(audit.clone());
        let rule_command = RuleCommandService::new(
            crate::services::policy_tx::global_policy_tx().clone(),
            audit.clone(),
        );
        let task_command = TaskCommandService::new(audit.clone());
        tokio::spawn(async move {
            let mut task_runtime = task::TaskRuntime::new(
                task_runtime.clone(),
                process,
                task_reply_tx.clone(),
                shutdown.clone(),
            );
            if let Err(err) = task_runtime.init().await {
                tracing::warn!("task runtime init failed: {err}");
            }
            if let Err(err) = task_runtime.start().await {
                tracing::warn!("task runtime start failed: {err}");
            }

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = client_cmd_rx.recv() => {
                        match msg {
                            Some(cmd) => {
                                let Some(cmd) = rule_command
                                    .try_handle_client_command(
                                        cmd,
                                        &rules,
                                        &task_reply_tx,
                                        &client_service,
                                    )
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
                                        &client_service,
                                        reconfigure_proc_workers.as_ref(),
                                        control_proc_workers.as_ref(),
                                        daemon_reload.as_ref(),
                                        &shutdown,
                                    )
                                    .await
                                {
                                    ControlCommandDispatch::HandledContinue => continue,
                                    ControlCommandDispatch::HandledBreak => break,
                                    ControlCommandDispatch::Unhandled(cmd) => cmd,
                                };
                                match task_command
                                    .try_handle_client_command(cmd, &mut task_runtime)
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

            task_runtime.stop().await;
        })
    }
}
