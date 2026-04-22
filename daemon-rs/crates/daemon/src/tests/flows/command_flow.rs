use std::sync::Arc;

use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

use crate::{
    commands::control::{
        DaemonReloadPort, DaemonReloadScope, ProcWorkerControlPort, ProcWorkerReconfigurePort,
    },
    config::Config,
    flows::command::CommandFlow,
    models::command_rpc::ClientCommand,
    services::{
        client::ClientService, config::ConfigService, firewall::FirewallService,
        process::ProcessService, rule::RuleService, stats::StatsService, task::TaskService,
    },
    workers::runtime::control::{WorkerCommand, WorkerCommandResult},
};

#[derive(Default)]
struct TestProcWorkerPorts;

impl ProcWorkerReconfigurePort for TestProcWorkerPorts {
    fn reconfigure_proc_workers(
        &self,
        _method: Option<crate::config::ProcMonitorMethod>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

impl ProcWorkerControlPort for TestProcWorkerPorts {
    fn control_proc_workers(
        &self,
        command: WorkerCommand,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = WorkerCommandResult> + Send + '_>> {
        let _ = command;
        Box::pin(async { WorkerCommandResult::Applied })
    }
}

impl DaemonReloadPort for TestProcWorkerPorts {
    fn daemon_reload<'a>(
        &'a self,
        _updated: &'a crate::config::Config,
        _scope: Option<DaemonReloadScope>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn command_flow_dispatches_log_level_and_shutdown() {
    let (client_cmd_tx, client_cmd_rx) = tokio::sync::mpsc::channel(8);
    let (task_reply_tx, mut task_reply_rx) = tokio::sync::mpsc::channel(8);
    let shutdown = CancellationToken::new();

    let config = Config::default();
    let config_service = ConfigService::new(config.clone());
    let firewall_service = FirewallService::new(&config).expect("build firewall service");
    let ports = Arc::new(TestProcWorkerPorts::default());

    let flow = CommandFlow::new(
        shutdown.clone(),
        ClientService::default(),
        config_service,
        RuleService::default(),
        firewall_service,
        ProcessService::default(),
        StatsService::default(),
        task_reply_tx,
        TaskService,
        ports.clone(),
        ports.clone(),
        ports.clone(),
        crate::services::audit::AuditService::new(64),
    );

    let join = flow.spawn(client_cmd_rx);

    client_cmd_tx
        .send(ClientCommand::SetLogLevel {
            notification_id: 7,
            level: 2,
        })
        .await
        .expect("send set-log-level command");

    let first_reply = timeout(Duration::from_secs(1), task_reply_rx.recv())
        .await
        .expect("set-log-level reply timeout")
        .expect("set-log-level reply missing");
    assert_eq!(first_reply.id, 7);

    client_cmd_tx
        .send(ClientCommand::Shutdown { notification_id: 8 })
        .await
        .expect("send shutdown command");

    let second_reply = timeout(Duration::from_secs(1), task_reply_rx.recv())
        .await
        .expect("shutdown reply timeout")
        .expect("shutdown reply missing");
    assert_eq!(second_reply.id, 8);

    timeout(Duration::from_secs(1), join)
        .await
        .expect("command flow join timeout")
        .expect("command flow join failed");

    assert!(shutdown.is_cancelled());
}
