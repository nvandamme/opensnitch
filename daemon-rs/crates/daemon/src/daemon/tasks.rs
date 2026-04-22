use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use super::{
    Daemon,
    proc_workers::{DaemonProcWorkerControlPort, DaemonProcWorkerReconfigurePort},
    reload::DaemonReloadPortAdapter,
};
use crate::{
    bus::BusRx,
    flows::{
        command::CommandFlow,
        connect::ConnectFlow,
        kernel::KernelFlow,
        notification::NotificationFlow,
        stats::{StatsFlow, WorkerTelemetrySnapshot},
        verdict::{VerdictFlow, VerdictSubmitFlow},
    },
    models::connection_state::ConnectionAttempt,
    services::{
        config::{ConfigService, ProcWorkerReconfigure as ConfigProcWorkerReconfigure},
        dns::DnsService,
        process::ProcessService,
        rule::RuleService,
        stats::StatsService,
    },
    workers::runtime::control::{RuntimeHandles, WorkerControl},
};

impl Daemon {
    pub(super) fn spawn_tasks(
        &self,
        handles: &mut RuntimeHandles,
        rx: BusRx,
        verdict_flow: VerdictFlow,
        notification_flow: NotificationFlow,
    ) {
        info!("starting runtime task set");
        let task_reply_rx = rx.task_reply_rx;
        let alert_rx = rx.alert_rx;
        handles.push_task(
            "notifications",
            self.spawn_notification_task(notification_flow, task_reply_rx, alert_rx),
        );
        debug!("notification task started");

        handles.push_task(
            "connect-attempts",
            self.spawn_connect_attempt_task(verdict_flow, self.runtime.stats.clone(), rx.connect_rx),
        );
        debug!("connect-attempt task started");

        handles.push_task(
            "kernel-events",
            self.spawn_kernel_task(
                self.runtime.process.clone(),
                self.runtime.dns.clone(),
                self.runtime.stats.clone(),
                rx.kernel_rx,
            ),
        );
        debug!("kernel-events task started");

        handles.push_task(
            "process-cache-cleanup",
            self.runtime
                .process
                .spawn_cleanup_task(self.runtime.shutdown.clone()),
        );
        debug!("process-cache-cleanup task started");

        handles.push_task(
            "client-commands",
            CommandFlow::new(
                self.runtime.shutdown.clone(),
                self.runtime.client.clone(),
                self.runtime.config.clone(),
                self.runtime.rules.clone(),
                self.runtime.firewall.clone(),
                self.runtime.process.clone(),
                self.runtime.stats.clone(),
                self.runtime.bus.task_reply_tx.clone(),
                self.runtime.tasks.clone(),
                Arc::new(DaemonProcWorkerReconfigurePort {
                    daemon: self.clone(),
                }),
                Arc::new(DaemonProcWorkerControlPort {
                    proc_workers: self.proc_workers_control(),
                }),
                Arc::new(DaemonReloadPortAdapter {
                    daemon: self.clone(),
                }),
            )
            .spawn(rx.client_cmd_rx),
        );
        debug!("client-command task started");

        handles.push_task(
            "verdict-replies",
            self.spawn_verdict_rpc_task(rx.verdict_rx, self.runtime.stats.clone()),
        );
        debug!("verdict-rpc task started");

        handles.push_task(
            "stats",
            self.spawn_stats_flow(
                self.runtime.config.clone(),
                self.runtime.rules.clone(),
                self.runtime.stats.clone(),
                self.runtime.dns.clone(),
            ),
        );
        debug!("stats task started");

        handles.push_task(
            "subscription-scheduler",
            self.runtime
                .subscriptions
                .spawn_scheduler(self.runtime.shutdown.clone(), self.runtime.stats.clone()),
        );
        debug!("subscription-scheduler task started");

        let daemon = self.clone();
        let reconfigure_proc_workers: ConfigProcWorkerReconfigure = Arc::new(move |method| {
            let daemon = daemon.clone();
            Box::pin(async move { daemon.reconfigure_proc_workers(method).await })
        });

        handles.push_worker_control(self.runtime.config.spawn_watch_task(
            self.runtime.shutdown.clone(),
            self.runtime.rules.clone(),
            self.runtime.firewall.clone(),
            self.runtime.stats.clone(),
            self.runtime.alert_buffer.clone(),
            self.runtime.bus.alert_tx.clone(),
            reconfigure_proc_workers,
        ));
        handles.push_worker_control(
            self.runtime
                .rules
                .spawn_watch_task(self.runtime.shutdown.clone()),
        );
        handles.push_worker_control(self.runtime.tasks.spawn_storage_tasks_watch_task(
            self.runtime.shutdown.clone(),
            self.runtime.config.clone(),
            self.runtime.process.clone(),
            self.runtime.bus.task_reply_tx.clone(),
            self.runtime.alert_buffer.clone(),
            self.runtime.bus.alert_tx.clone(),
        ));
        handles.push_worker_control(
            self.runtime
                .firewall
                .spawn_watch_task(self.runtime.shutdown.clone(), self.runtime.config.clone()),
        );
        debug!("watch tasks started");
    }

    pub(super) fn spawn_notification_task(
        &self,
        flow: NotificationFlow,
        task_reply_rx: tokio::sync::mpsc::Receiver<opensnitch_proto::pb::NotificationReply>,
        alert_rx: tokio::sync::mpsc::Receiver<crate::models::ui_alert::UiAlert>,
    ) -> JoinHandle<()> {
        let shutdown = self.runtime.shutdown.clone();

        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancelled() => {}
                res = flow.run(task_reply_rx, alert_rx) => {
                    if let Err(err) = res {
                        error!("notification flow failed: {err}");
                    }
                }
            }
        })
    }

    pub(crate) fn spawn_connect_attempt_task(
        &self,
        flow: VerdictFlow,
        stats: StatsService,
        connect_rx: tokio::sync::mpsc::Receiver<ConnectionAttempt>,
    ) -> JoinHandle<()> {
        ConnectFlow::new(
            self.runtime.shutdown.clone(),
            self.runtime.tunables,
            self.runtime.bus.verdict_tx.clone(),
        )
        .spawn(flow, stats, connect_rx)
    }

    pub(crate) fn spawn_kernel_task(
        &self,
        process: ProcessService,
        dns: DnsService,
        stats: StatsService,
        kernel_rx: tokio::sync::mpsc::Receiver<crate::models::kernel_event::KernelEvent>,
    ) -> JoinHandle<()> {
        KernelFlow::new(
            self.runtime.shutdown.clone(),
            self.runtime.tunables,
            self.runtime.kernel_pipeline_counters.clone(),
        )
            .spawn(process, dns, stats, kernel_rx)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn spawn_client_command_task(
        &self,
        client_cmd_rx: tokio::sync::mpsc::Receiver<crate::models::command_rpc::ClientCommand>,
    ) -> JoinHandle<()> {
        CommandFlow::new(
            self.runtime.shutdown.clone(),
            self.runtime.client.clone(),
            self.runtime.config.clone(),
            self.runtime.rules.clone(),
            self.runtime.firewall.clone(),
            self.runtime.process.clone(),
            self.runtime.stats.clone(),
            self.runtime.bus.task_reply_tx.clone(),
            self.runtime.tasks.clone(),
            Arc::new(DaemonProcWorkerReconfigurePort {
                daemon: self.clone(),
            }),
            Arc::new(DaemonProcWorkerControlPort {
                proc_workers: self.proc_workers_control(),
            }),
            Arc::new(DaemonReloadPortAdapter {
                daemon: self.clone(),
            }),
        )
        .spawn(client_cmd_rx)
    }

    pub(super) fn spawn_verdict_rpc_task(
        &self,
        verdict_rx: tokio::sync::mpsc::Receiver<crate::models::verdict_rpc::VerdictReply>,
        stats: StatsService,
    ) -> JoinHandle<()> {
        VerdictSubmitFlow::new(self.runtime.shutdown.clone()).spawn(verdict_rx, stats)
    }

    pub(super) fn spawn_stats_flow(
        &self,
        config: ConfigService,
        rules: RuleService,
        stats: StatsService,
        dns: DnsService,
    ) -> JoinHandle<()> {
        let proc_workers = self.proc_workers_control();
        let kernel_pipeline_counters = self.runtime.kernel_pipeline_counters.clone();
        let worker_name = proc_workers.worker_name();
        let worker_snapshot = Arc::new(move || {
            let snapshot = proc_workers.snapshot();
            WorkerTelemetrySnapshot {
                state: snapshot.state.as_str(),
                method: snapshot.method,
                configured_handles: snapshot.configured_handles,
                running_handles: snapshot.running_handles,
                shutdown_requested: snapshot.shutdown_requested,
            }
        });

        StatsFlow::new(
            self.runtime.shutdown.clone(),
            config,
            self.runtime.client.clone(),
            rules,
            stats,
            {
                let kernel_pipeline_counters = kernel_pipeline_counters.clone();
                Arc::new(move || kernel_pipeline_counters.ingress_stats())
            },
            {
                let kernel_pipeline_counters = kernel_pipeline_counters.clone();
                Arc::new(move || kernel_pipeline_counters.drop_stats())
            },
            worker_name,
            worker_snapshot,
            dns,
        )
        .spawn()
    }
}
