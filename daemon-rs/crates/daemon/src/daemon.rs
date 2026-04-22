use std::{
    collections::HashMap,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    bus::{Bus, BusRx, build_bus},
    client::client::Client,
    commands::{command_control, rule_command, task_runtime},
    config::ProcMonitorMethod,
    flows::{notification_flow::NotificationFlow, verdict_flow::VerdictFlow},
    models::{
        connection_state::ConnectionAttempt,
        kernel_event::{KernelEvent, ProcEventKind},
    },
    services::{
        config_service::ConfigService,
        dns_service::DnsService,
        firewall_service::FirewallService,
        process_service::ProcessService,
        rule_service::RuleService,
        stats_service::StatsService,
        watch_service::{ProcWorkerReconfigure, WatchService, WatcherService},
    },
    workers::{
        self,
        control::{
            RuntimeHandles, WorkerCommand, WorkerCommandResult, WorkerControl, WorkerJoinStatus,
            WorkerState,
        },
    },
};

const MAX_CONCURRENT_CONNECT_ATTEMPTS: usize = 32;
const KERNEL_DNS_QUEUE_CAPACITY: usize = 512;
const KERNEL_PROCESS_QUEUE_CAPACITY: usize = 512;
const KERNEL_FIREWALL_QUEUE_CAPACITY: usize = 128;
const KERNEL_PIPELINE_SEND_RETRIES: usize = 8;
const KERNEL_PIPELINE_SEND_BACKOFF: Duration = Duration::from_millis(10);

#[derive(Debug)]
enum ProcessKernelEvent {
    ProcStateChanged { pid: u32, kind: ProcEventKind },
    EbpfProcessMapHit { pid: u32, uid: u32, note: String },
}

#[derive(Debug, Clone, Copy)]
enum KernelPipeline {
    Dns,
    Process,
    Firewall,
}

impl KernelPipeline {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Process => "process",
            Self::Firewall => "firewall",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KernelPipelineDropStats {
    pub dns: u64,
    pub process: u64,
    pub firewall: u64,
}

impl KernelPipelineDropStats {
    fn saturating_delta(self, previous: Self) -> Self {
        Self {
            dns: self.dns.saturating_sub(previous.dns),
            process: self.process.saturating_sub(previous.process),
            firewall: self.firewall.saturating_sub(previous.firewall),
        }
    }

    fn total(self) -> u64 {
        self.dns
            .saturating_add(self.process)
            .saturating_add(self.firewall)
    }
}

#[derive(Default)]
struct KernelPipelineDropCounters {
    dns: AtomicU64,
    process: AtomicU64,
    firewall: AtomicU64,
}

static KERNEL_PIPELINE_DROP_COUNTERS: OnceLock<KernelPipelineDropCounters> = OnceLock::new();

fn kernel_pipeline_drop_counters() -> &'static KernelPipelineDropCounters {
    KERNEL_PIPELINE_DROP_COUNTERS.get_or_init(KernelPipelineDropCounters::default)
}

pub(crate) fn kernel_pipeline_drop_stats_snapshot() -> KernelPipelineDropStats {
    let counters = kernel_pipeline_drop_counters();
    KernelPipelineDropStats {
        dns: counters.dns.load(Ordering::Relaxed),
        process: counters.process.load(Ordering::Relaxed),
        firewall: counters.firewall.load(Ordering::Relaxed),
    }
}

fn increment_kernel_pipeline_drop(pipeline: KernelPipeline) -> u64 {
    let counters = kernel_pipeline_drop_counters();
    let previous = match pipeline {
        KernelPipeline::Dns => counters.dns.fetch_add(1, Ordering::Relaxed),
        KernelPipeline::Process => counters.process.fetch_add(1, Ordering::Relaxed),
        KernelPipeline::Firewall => counters.firewall.fetch_add(1, Ordering::Relaxed),
    };
    previous.saturating_add(1)
}

async fn dispatch_kernel_pipeline_event<T>(
    tx: &tokio::sync::mpsc::Sender<T>,
    event: T,
    shutdown: &CancellationToken,
    pipeline: KernelPipeline,
) -> bool {
    let mut pending = event;

    for _ in 0..KERNEL_PIPELINE_SEND_RETRIES {
        if shutdown.is_cancelled() {
            return false;
        }

        match tx.try_send(pending) {
            Ok(()) => return true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                pending = event;
                tokio::select! {
                    _ = shutdown.cancelled() => return false,
                    _ = tokio::time::sleep(KERNEL_PIPELINE_SEND_BACKOFF) => {}
                }
            }
        }
    }

    let dropped = increment_kernel_pipeline_drop(pipeline);
    warn!(
        pipeline = pipeline.as_str(),
        dropped_count = dropped,
        "kernel event pipeline queue saturated; dropping event"
    );
    true
}

#[derive(Clone)]
pub struct Daemon {
    inner: Arc<DaemonInner>,
}

struct DaemonInner {
    config: ConfigService,
    nfqueue_num: u16,
    default_action: crate::config::DefaultAction,
    audit_socket_path: std::path::PathBuf,
    proc_workers: Arc<std::sync::Mutex<ProcWorkersRuntime>>,
    bus: Bus,
    rules: RuleService,
    process: ProcessService,
    dns: DnsService,
    stats: StatsService,
    firewall: FirewallService,
    shutdown: CancellationToken,
}

struct ProcWorkersRuntime {
    current_method: ProcMonitorMethod,
    shutdown: CancellationToken,
    handles: Vec<Box<dyn WorkerControl>>,
}

#[derive(Debug, Clone, Copy)]
struct ProcWorkersSnapshot {
    method: ProcMonitorMethod,
    state: WorkerState,
    configured_handles: usize,
    running_handles: usize,
    shutdown_requested: bool,
}

#[derive(Clone)]
struct ProcWorkersControl {
    daemon: Daemon,
}

impl ProcWorkersControl {
    fn snapshot(&self) -> ProcWorkersSnapshot {
        self.daemon.proc_workers_snapshot()
    }

    fn start_workers(&self) -> WorkerCommandResult {
        self.daemon.control_proc_workers_sync(WorkerCommand::Start)
    }

    fn stop_workers(&self) -> WorkerCommandResult {
        self.daemon.control_proc_workers_sync(WorkerCommand::Stop)
    }

    fn probe_workers(&self) -> WorkerCommandResult {
        self.daemon.control_proc_workers_sync(WorkerCommand::Probe)
    }
}

impl WorkerControl for ProcWorkersControl {
    fn worker_name(&self) -> &'static str {
        "proc-workers"
    }

    fn control(&self, command: WorkerCommand) -> WorkerCommandResult {
        match command {
            WorkerCommand::Start => self.spawn_once(),
            WorkerCommand::Stop => self.stop_workers(),
            WorkerCommand::Probe => self.probe_workers(),
        }
    }

    fn spawn_once(&self) -> WorkerCommandResult {
        self.start_workers()
    }

    fn state(&self) -> WorkerState {
        self.snapshot().state
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus {
        self.stop();
        WorkerJoinStatus::Stopped
    }
}

impl Daemon {
    pub async fn run(client_addr: Option<&str>) -> Result<()> {
        let (daemon, rx) = Self::bootstrap(client_addr).await?;
        daemon.serve(rx).await
    }

    pub async fn bootstrap(client_addr: Option<&str>) -> Result<(Self, BusRx)> {
        let (bus, rx) = build_bus(512);
        let config = crate::config::Config::load_from_default_locations()?
            .with_client_addr_override(client_addr);
        let config_service = ConfigService::new(config.clone());
        let rules = RuleService::default();
        rules.load_path(&config.rules_path).await?;
        let firewall = FirewallService::new(&config)?;
        if let Err(err) = firewall.ensure_rules().await {
            warn!(
                backend = config.firewall_backend.as_str(),
                "firewall bootstrap skipped: {err}"
            );
        }

        let daemon = Self {
            inner: Arc::new(DaemonInner {
                config: config_service,
                nfqueue_num: config.firewall_queue_num,
                default_action: config.default_action,
                audit_socket_path: config.audit_socket_path.clone(),
                proc_workers: Arc::new(std::sync::Mutex::new(ProcWorkersRuntime {
                    current_method: config.proc_monitor_method,
                    shutdown: CancellationToken::new(),
                    handles: Vec::new(),
                })),
                bus,
                rules,
                process: ProcessService::default(),
                dns: DnsService::default(),
                stats: StatsService::default(),
                firewall,
                shutdown: CancellationToken::new(),
            }),
        };

        daemon.inner.stats.apply_config(config.stats);

        Ok((daemon, rx))
    }

    pub async fn serve(&self, rx: BusRx) -> Result<()> {
        let config = self.inner.config.snapshot().await;
        if let Err(err) = crate::logging::set_opensnitch_log_level(config.log_level as i32) {
            warn!("failed to apply startup log level from config: {err}");
        }
        let mut client = Client::connect(&config.client_addr).await?;
        self.startup_handshake(&mut client).await?;

        let verdict_flow = VerdictFlow::new(
            self.inner.bus.clone(),
            self.inner.config.clone(),
            self.inner.rules.clone(),
            self.inner.process.clone(),
            self.inner.dns.clone(),
            self.inner.stats.clone(),
        );

        let notification_flow =
            NotificationFlow::new(self.inner.bus.clone(), self.inner.config.clone());

        let mut handles = RuntimeHandles::new();
        self.spawn_workers(&mut handles).await;
        self.spawn_tasks(&mut handles, rx, verdict_flow, notification_flow);

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c received");
            }
            _ = self.inner.shutdown.cancelled() => {
                info!("shutdown requested");
            }
        }

        self.shutdown().await;
        self.stop_proc_workers().await;
        handles.join_all().await;

        Ok(())
    }

    async fn startup_handshake(&self, client: &mut Client) -> Result<()> {
        let config = self.inner.config.snapshot().await;
        let rules = self.inner.rules.list_proto().await;
        let firewall = self.inner.firewall.snapshot().await;
        let system_firewall = self.inner.firewall.system_firewall().await;
        let subscribe_cfg =
            client.build_subscribe_config(&config, rules, firewall.enabled, system_firewall);
        let subscribe_reply = client.subscribe(subscribe_cfg).await?;

        info!(
            client_name = %subscribe_reply.name,
            client_version = %subscribe_reply.version,
            "subscribed to control client"
        );

        let ping_reply = client
            .ping(opensnitch_proto::pb::PingRequest {
                id: 1,
                stats: Some(
                    self.inner
                        .stats
                        .snapshot(self.inner.rules.list_proto().await.len() as u64),
                ),
            })
            .await?;

        info!(ping_id = ping_reply.id, "ping successful");

        Ok(())
    }

    async fn spawn_workers(&self, handles: &mut RuntimeHandles) {
        handles.push_worker(
            "nfqueue",
            workers::nfqueue_worker::spawn(
                self.inner.bus.clone(),
                self.inner.nfqueue_num,
                self.inner.default_action,
                self.inner.shutdown.clone(),
            ),
        );

        let initial_method = self.inner.config.snapshot().await.proc_monitor_method;
        self.reconfigure_proc_workers(Some(initial_method)).await;

        handles.push_worker_control(Box::new(workers::dns_worker::DnsWorkerControl::new(
            self.inner.bus.clone(),
            self.inner.shutdown.clone(),
        )));

        handles.push_worker(
            "firewall",
            workers::firewall_worker::spawn(
                self.inner.bus.clone(),
                self.inner.firewall.clone(),
                self.inner.shutdown.clone(),
            ),
        );
    }

    fn spawn_proc_worker_handles(
        &self,
        method: ProcMonitorMethod,
        shutdown: CancellationToken,
    ) -> Vec<Box<dyn WorkerControl>> {
        match method {
            ProcMonitorMethod::Proc => vec![workers::control::boxed_thread_worker(
                "proc-netlink",
                workers::netlink_proc_worker::spawn(self.inner.bus.clone(), shutdown),
            )],
            ProcMonitorMethod::Ebpf => vec![
                Box::new(workers::ebpf_worker::EbpfWorkerControl::new(
                    self.inner.bus.clone(),
                    shutdown.clone(),
                )),
                workers::control::boxed_thread_worker(
                    "proc-netlink",
                    workers::netlink_proc_worker::spawn(self.inner.bus.clone(), shutdown),
                ),
            ],
            ProcMonitorMethod::Audit => vec![
                workers::control::boxed_thread_worker(
                    "proc-audit",
                    workers::audit_worker::spawn(
                        self.inner.bus.clone(),
                        self.inner.audit_socket_path.clone(),
                        shutdown.clone(),
                    ),
                ),
                workers::control::boxed_thread_worker(
                    "proc-netlink",
                    workers::netlink_proc_worker::spawn(self.inner.bus.clone(), shutdown),
                ),
            ],
        }
    }

    fn proc_workers_control(&self) -> ProcWorkersControl {
        ProcWorkersControl {
            daemon: self.clone(),
        }
    }

    fn proc_workers_snapshot(&self) -> ProcWorkersSnapshot {
        let runtime = self
            .inner
            .proc_workers
            .lock()
            .expect("proc workers mutex poisoned");

        let configured_handles = runtime.handles.len();
        let running_handles = runtime.handles.iter().filter(|h| !h.is_finished()).count();
        let shutdown_requested = runtime.shutdown.is_cancelled();
        let state = if running_handles > 0 {
            WorkerState::Running
        } else if shutdown_requested || configured_handles > 0 {
            WorkerState::Stopped
        } else {
            WorkerState::Unknown
        };

        ProcWorkersSnapshot {
            method: runtime.current_method,
            state,
            configured_handles,
            running_handles,
            shutdown_requested,
        }
    }

    fn control_proc_workers_sync(&self, command: WorkerCommand) -> WorkerCommandResult {
        let mut runtime = self
            .inner
            .proc_workers
            .lock()
            .expect("proc workers mutex poisoned");

        runtime.handles.retain(|h| !h.is_finished());

        match command {
            WorkerCommand::Stop => {
                runtime.shutdown.cancel();
                for worker in &runtime.handles {
                    worker.stop();
                }
                WorkerCommandResult::Applied
            }
            WorkerCommand::Start => {
                if runtime.shutdown.is_cancelled() {
                    runtime.shutdown = CancellationToken::new();
                    runtime.handles.clear();
                }

                if runtime.handles.is_empty() {
                    let method = runtime.current_method;
                    runtime.handles =
                        self.spawn_proc_worker_handles(method, runtime.shutdown.clone());
                }

                WorkerCommandResult::Applied
            }
            WorkerCommand::Probe => WorkerCommandResult::Applied,
        }
    }

    async fn reconfigure_proc_workers(&self, method: Option<ProcMonitorMethod>) {
        let to_join = {
            let mut runtime = self
                .inner
                .proc_workers
                .lock()
                .expect("proc workers mutex poisoned");

            if let Some(method) = method
                && runtime.current_method == method
                && runtime.handles.iter().any(|handle| !handle.is_finished())
            {
                return;
            }

            let old_shutdown = std::mem::replace(&mut runtime.shutdown, CancellationToken::new());
            old_shutdown.cancel();
            let to_join = std::mem::take(&mut runtime.handles);

            if let Some(method) = method {
                runtime.current_method = method;
                runtime.handles = self.spawn_proc_worker_handles(method, runtime.shutdown.clone());
            }

            to_join
        };

        if !to_join.is_empty() {
            let _ = tokio::task::spawn_blocking(move || {
                for worker in to_join {
                    let _ = worker.join();
                }
            })
            .await;
        }

        if let Some(method) = method {
            info!(method = ?method, "reconfigured process monitor workers");
        } else {
            info!("stopped process monitor workers");
        }
    }

    async fn stop_proc_workers(&self) {
        let to_join = {
            let mut runtime = self
                .inner
                .proc_workers
                .lock()
                .expect("proc workers mutex poisoned");
            runtime.shutdown.cancel();
            std::mem::take(&mut runtime.handles)
        };

        if to_join.is_empty() {
            return;
        }

        let _ = tokio::task::spawn_blocking(move || {
            for worker in to_join {
                let _ = worker.join();
            }
        })
        .await;
    }

    fn spawn_tasks(
        &self,
        handles: &mut RuntimeHandles,
        rx: BusRx,
        verdict_flow: VerdictFlow,
        notification_flow: NotificationFlow,
    ) {
        let task_reply_rx = rx.task_reply_rx;
        handles.push_task(
            "notifications",
            self.spawn_notification_task(notification_flow, task_reply_rx),
        );

        handles.push_task(
            "connect-attempts",
            self.spawn_connect_attempt_task(verdict_flow, self.inner.stats.clone(), rx.connect_rx),
        );

        handles.push_task(
            "kernel-events",
            self.spawn_kernel_task(
                self.inner.process.clone(),
                self.inner.dns.clone(),
                self.inner.stats.clone(),
                rx.kernel_rx,
            ),
        );

        handles.push_task(
            "client-commands",
            self.spawn_client_command_task(rx.client_cmd_rx),
        );

        handles.push_task(
            "verdict-replies",
            self.spawn_verdict_rpc_task(rx.verdict_rx, self.inner.stats.clone()),
        );

        handles.push_task(
            "stats-ping",
            self.spawn_stats_ping_task(
                self.inner.config.clone(),
                self.inner.rules.clone(),
                self.inner.stats.clone(),
            ),
        );

        let watch_service = self.build_watch_service();
        handles.push_task("config-watch", watch_service.spawn_config_watch_task());
        handles.push_task("rules-watch", watch_service.spawn_rules_watch_task());
        handles.push_task("tasks-watch", watch_service.spawn_tasks_watch_task());
    }

    fn spawn_notification_task(
        &self,
        flow: NotificationFlow,
        task_reply_rx: tokio::sync::mpsc::Receiver<opensnitch_proto::pb::NotificationReply>,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();

        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancelled() => {}
                res = flow.run(task_reply_rx) => {
                    if let Err(err) = res {
                        error!("notification flow failed: {err}");
                    }
                }
            }
        })
    }

    fn spawn_connect_attempt_task(
        &self,
        flow: VerdictFlow,
        stats: StatsService,
        mut connect_rx: tokio::sync::mpsc::Receiver<ConnectionAttempt>,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();
        let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECT_ATTEMPTS));
        let daemon_pid = std::process::id();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = connect_rx.recv() => {
                        match msg {
                            Some(attempt) => {
                                // Keep daemon-owned attempts on the hot path to avoid
                                // semaphore acquisition and per-attempt task spawn overhead.
                                if attempt.pid == daemon_pid {
                                    flow.fast_allow_daemon_owned(attempt.request_id).await;
                                    continue;
                                }

                                stats.on_connect_attempt(&attempt);

                                let permit: Option<OwnedSemaphorePermit> = tokio::select! {
                                    _ = shutdown.cancelled() => None,
                                    permit = permits.clone().acquire_owned() => permit.ok(),
                                };

                                let Some(permit) = permit else {
                                    break;
                                };

                                let flow = flow.clone();
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    flow.handle_connect_attempt(attempt).await;
                                });
                            }
                            None => break,
                        }
                    }
                }
            }
        })
    }

    fn spawn_kernel_task(
        &self,
        process: ProcessService,
        dns: DnsService,
        stats: StatsService,
        mut kernel_rx: tokio::sync::mpsc::Receiver<crate::models::kernel_event::KernelEvent>,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();

        tokio::spawn(async move {
            let (dns_tx, mut dns_rx) =
                tokio::sync::mpsc::channel::<(String, String)>(KERNEL_DNS_QUEUE_CAPACITY);
            let (process_tx, mut process_rx) =
                tokio::sync::mpsc::channel::<ProcessKernelEvent>(KERNEL_PROCESS_QUEUE_CAPACITY);
            let (firewall_tx, mut firewall_rx) = tokio::sync::mpsc::channel::<
                crate::models::firewall_state::FirewallState,
            >(KERNEL_FIREWALL_QUEUE_CAPACITY);

            let dns_shutdown = shutdown.clone();
            let dns_service = dns.clone();
            let dns_stats = stats.clone();
            let dns_handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = dns_shutdown.cancelled() => break,
                        msg = dns_rx.recv() => {
                            match msg {
                                Some((ip, host)) => {
                                    dns_stats.on_dns_resolved();
                                    dns_service.track(ip, host).await;
                                }
                                None => break,
                            }
                        }
                    }
                }
            });

            let process_shutdown = shutdown.clone();
            let process_service = process.clone();
            let process_handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = process_shutdown.cancelled() => break,
                        msg = process_rx.recv() => {
                            match msg {
                                Some(ProcessKernelEvent::ProcStateChanged { pid, kind }) => {
                                    process_service.sync_from_proc_event(pid, kind).await;
                                    debug!(pid, ?kind, "proc state changed event received");
                                }
                                Some(ProcessKernelEvent::EbpfProcessMapHit { pid, uid, note }) => {
                                    if pid != std::process::id() {
                                        let kind = if note.contains("sched_exit") {
                                            ProcEventKind::Exit
                                        } else {
                                            ProcEventKind::Exec
                                        };
                                        process_service.sync_from_proc_event(pid, kind).await;
                                    }
                                    debug!(pid, uid, note, "ebpf runtime status event received");
                                }
                                None => break,
                            }
                        }
                    }
                }
            });

            let firewall_shutdown = shutdown.clone();
            let firewall_handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = firewall_shutdown.cancelled() => break,
                        msg = firewall_rx.recv() => {
                            match msg {
                                Some(state) => {
                                    debug!(enabled = state.enabled, backend = state.backend.as_str(), "firewall state event received");
                                }
                                None => break,
                            }
                        }
                    }
                }
            });

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = kernel_rx.recv() => {
                        match msg {
                            Some(event) => {
                                match event {
                                    KernelEvent::DnsResolved { ip, host } => {
                                        if !dispatch_kernel_pipeline_event(
                                            &dns_tx,
                                            (ip, host),
                                            &shutdown,
                                            KernelPipeline::Dns,
                                        )
                                        .await
                                        {
                                            break;
                                        }
                                    }
                                    KernelEvent::ProcStateChanged { pid, kind } => {
                                        if !dispatch_kernel_pipeline_event(
                                            &process_tx,
                                            ProcessKernelEvent::ProcStateChanged { pid, kind },
                                            &shutdown,
                                            KernelPipeline::Process,
                                        )
                                        .await
                                        {
                                            break;
                                        }
                                    }
                                    KernelEvent::EbpfProcessMapHit { pid, uid, note } => {
                                        if !dispatch_kernel_pipeline_event(
                                            &process_tx,
                                            ProcessKernelEvent::EbpfProcessMapHit { pid, uid, note },
                                            &shutdown,
                                            KernelPipeline::Process,
                                        )
                                        .await
                                        {
                                            break;
                                        }
                                    }
                                    KernelEvent::FirewallState(state) => {
                                        if !dispatch_kernel_pipeline_event(
                                            &firewall_tx,
                                            state,
                                            &shutdown,
                                            KernelPipeline::Firewall,
                                        )
                                        .await
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            drop(dns_tx);
            drop(process_tx);
            drop(firewall_tx);

            let _ = tokio::join!(dns_handle, process_handle, firewall_handle);
        })
    }

    fn spawn_client_command_task(
        &self,
        mut client_cmd_rx: tokio::sync::mpsc::Receiver<crate::models::command_rpc::ClientCommand>,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();
        let config = self.inner.config.clone();
        let rules = self.inner.rules.clone();
        let firewall = self.inner.firewall.clone();
        let process = self.inner.process.clone();
        let stats = self.inner.stats.clone();
        let task_reply_tx = self.inner.bus.task_reply_tx.clone();
        let daemon = self.clone();
        let reconfigure_proc_workers: command_control::ProcWorkerReconfigure =
            Arc::new(move |method| {
                let daemon = daemon.clone();
                Box::pin(async move {
                    daemon.reconfigure_proc_workers(method).await;
                })
            });
        let proc_workers = self.proc_workers_control();
        let control_proc_workers: command_control::ProcWorkerControl = Arc::new(move |command| {
            let proc_workers = proc_workers.clone();
            Box::pin(async move { proc_workers.control(command) })
        });

        tokio::spawn(async move {
            let mut task_handles: HashMap<
                String,
                (tokio::task::JoinHandle<()>, CancellationToken),
            > = HashMap::new();

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = client_cmd_rx.recv() => {
                        match msg {
                            Some(cmd) => {
                                match cmd {
                                    crate::models::command_rpc::ClientCommand::SetInterception {
                                        notification_id,
                                        enabled,
                                    } => {
                                        command_control::set_interception(
                                            notification_id,
                                            enabled,
                                            &config,
                                            &firewall,
                                            &task_reply_tx,
                                            &reconfigure_proc_workers,
                                            &control_proc_workers,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::SetFirewall {
                                        notification_id,
                                        enabled,
                                    } => {
                                        command_control::set_firewall(
                                            notification_id,
                                            enabled,
                                            &config,
                                            &firewall,
                                            &task_reply_tx,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::ReloadFirewall {
                                        notification_id,
                                        sys_firewall,
                                    } => {
                                        command_control::reload_firewall(
                                            notification_id,
                                            sys_firewall,
                                            &config,
                                            &firewall,
                                            &task_reply_tx,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::ApplyConfig {
                                        notification_id,
                                        raw_json,
                                    } => {
                                        command_control::apply_config(
                                            notification_id,
                                            raw_json,
                                            &config,
                                            &rules,
                                            &firewall,
                                            &stats,
                                            &task_reply_tx,
                                            &reconfigure_proc_workers,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::EnableRules {
                                        notification_id,
                                        rules: updated_rules,
                                    } => {
                                        rule_command::enable_rules(
                                            notification_id,
                                            updated_rules,
                                            &rules,
                                            &task_reply_tx,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::DisableRules {
                                        notification_id,
                                        rules: updated_rules,
                                    } => {
                                        rule_command::disable_rules(
                                            notification_id,
                                            updated_rules,
                                            &rules,
                                            &task_reply_tx,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::StartTask(task) => {
                                        if !task_runtime::is_runtime_task_name_supported(&task.name) {
                                            task_runtime::send_task_reply(
                                                &task_reply_tx,
                                                task.notification_id,
                                                opensnitch_proto::pb::NotificationReplyCode::Ok,
                                                serde_json::json!({
                                                    "status": "ignored",
                                                    "task": task.name,
                                                })
                                                .to_string(),
                                            )
                                            .await;
                                            continue;
                                        }

                                        if let Err(message) = task_runtime::validate_task_start_input(&task.name, &task.data) {
                                            task_runtime::send_task_reply(
                                                &task_reply_tx,
                                                task.notification_id,
                                                opensnitch_proto::pb::NotificationReplyCode::Error,
                                                message,
                                            )
                                            .await;
                                            continue;
                                        }

                                        let task_key = task_runtime::build_task_key(&task.name, &task.data);
                                        if task_handles.contains_key(&task_key) {
                                            task_runtime::send_task_reply(
                                                &task_reply_tx,
                                                task.notification_id,
                                                opensnitch_proto::pb::NotificationReplyCode::Error,
                                                format!("task with name {} already exists", task_key),
                                            )
                                            .await;
                                            continue;
                                        }

                                        let token = CancellationToken::new();
                                        let handle = task_runtime::spawn_task_monitor(
                                            &task.name,
                                            task.notification_id,
                                            &task.data,
                                            token.clone(),
                                            process.clone(),
                                            task_reply_tx.clone(),
                                        );
                                        task_handles.insert(task_key, (handle, token));
                                        task_runtime::send_task_reply(
                                            &task_reply_tx,
                                            task.notification_id,
                                            opensnitch_proto::pb::NotificationReplyCode::Ok,
                                            serde_json::json!({
                                                "status": "started",
                                                "task": task.name,
                                            })
                                            .to_string(),
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::StopTask(task) => {
                                        if !task_runtime::is_runtime_task_name_supported(&task.name) {
                                            task_runtime::send_task_reply(
                                                &task_reply_tx,
                                                task.notification_id,
                                                opensnitch_proto::pb::NotificationReplyCode::Ok,
                                                serde_json::json!({
                                                    "status": "ignored",
                                                    "task": task.name,
                                                })
                                                .to_string(),
                                            )
                                            .await;
                                            continue;
                                        }

                                        let task_key = task_runtime::build_task_key(&task.name, &task.data);
                                        if let Some((handle, token)) = task_handles.remove(&task_key) {
                                            token.cancel();
                                            handle.abort();
                                            task_runtime::send_task_reply(
                                                &task_reply_tx,
                                                task.notification_id,
                                                opensnitch_proto::pb::NotificationReplyCode::Ok,
                                                serde_json::json!({
                                                    "status": "stopped",
                                                    "task": task.name,
                                                })
                                                .to_string(),
                                            )
                                            .await;
                                        } else {
                                            task_runtime::send_task_reply(
                                                &task_reply_tx,
                                                task.notification_id,
                                                opensnitch_proto::pb::NotificationReplyCode::Ok,
                                                serde_json::json!({
                                                    "status": "not-running",
                                                    "task": task.name,
                                                })
                                                .to_string(),
                                            )
                                            .await;
                                        }
                                    }
                                    crate::models::command_rpc::ClientCommand::UpsertRules {
                                        notification_id,
                                        rules: updated_rules,
                                    } => {
                                        rule_command::upsert_rules(
                                            notification_id,
                                            updated_rules,
                                            &rules,
                                            &task_reply_tx,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::DeleteRules {
                                        notification_id,
                                        rule_names,
                                    } => {
                                        rule_command::delete_rules(
                                            notification_id,
                                            rule_names,
                                            &rules,
                                            &task_reply_tx,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::StopRuntimeTasks => {
                                        let stopped = task_runtime::stop_runtime_tasks(&mut task_handles);
                                        tracing::info!(stopped, "stopped temporary runtime tasks after notification disconnect");
                                    }
                                    crate::models::command_rpc::ClientCommand::SetLogLevel {
                                        notification_id,
                                        level,
                                    } => {
                                        command_control::set_log_level(
                                            notification_id,
                                            level,
                                            &config,
                                            &task_reply_tx,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::Shutdown {
                                        notification_id,
                                    } => {
                                        command_control::shutdown(
                                            notification_id,
                                            &shutdown,
                                            &task_reply_tx,
                                        )
                                        .await;
                                        break;
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            task_runtime::stop_runtime_tasks(&mut task_handles);
        })
    }

    fn spawn_verdict_rpc_task(
        &self,
        mut verdict_rx: tokio::sync::mpsc::Receiver<crate::models::verdict_rpc::VerdictReply>,
        stats: StatsService,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = verdict_rx.recv() => {
                        match msg {
                            Some(reply) => {
                                stats.on_verdict(reply.allow);
                                crate::ffi::nfqueue::submit_verdict(
                                    reply.request_id,
                                    reply.allow,
                                    reply.reject,
                                );
                                tracing::info!(
                                    "verdict reply request_id={} allow={} reject={}",
                                    reply.request_id,
                                    reply.allow,
                                    reply.reject
                                );
                            }
                            None => break,
                        }
                    }
                }
            }
        })
    }

    fn spawn_stats_ping_task(
        &self,
        config: ConfigService,
        rules: RuleService,
        stats: StatsService,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();
        let proc_workers = self.proc_workers_control();

        tokio::spawn(async move {
            let mut ping_id = 2_u64;
            let mut last_drop_snapshot = kernel_pipeline_drop_stats_snapshot();
            let mut last_daemon_owned_fast_allow = stats.daemon_owned_fast_allow_count();
            let mut last_drop_log_at = tokio::time::Instant::now();

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                        if last_drop_log_at.elapsed() >= std::time::Duration::from_secs(30) {
                            let current = kernel_pipeline_drop_stats_snapshot();
                            let delta = current.saturating_delta(last_drop_snapshot);
                            if delta.total() > 0 {
                                warn!(
                                    dns = delta.dns,
                                    process = delta.process,
                                    firewall = delta.firewall,
                                    total = delta.total(),
                                    "non-connect kernel pipeline drops observed"
                                );
                            }

                            let daemon_owned_fast_allow_total = stats.daemon_owned_fast_allow_count();
                            let daemon_owned_fast_allow_delta = daemon_owned_fast_allow_total
                                .saturating_sub(last_daemon_owned_fast_allow);
                            if daemon_owned_fast_allow_delta > 0 {
                                debug!(
                                    delta = daemon_owned_fast_allow_delta,
                                    total = daemon_owned_fast_allow_total,
                                    "daemon-owned fast-allow attempts observed"
                                );
                            }

                            let snapshot = proc_workers.snapshot();
                            debug!(
                                worker = proc_workers.worker_name(),
                                state = snapshot.state.as_str(),
                                method = ?snapshot.method,
                                configured_handles = snapshot.configured_handles,
                                running_handles = snapshot.running_handles,
                                shutdown_requested = snapshot.shutdown_requested,
                                "worker state telemetry snapshot"
                            );

                            last_drop_snapshot = current;
                            last_daemon_owned_fast_allow = daemon_owned_fast_allow_total;
                            last_drop_log_at = tokio::time::Instant::now();
                        }

                        let rules_count = rules.list_proto().await.len() as u64;
                        let Some(snapshot) = stats.snapshot_if_pending(rules_count) else {
                            continue;
                        };

                        let req = opensnitch_proto::pb::PingRequest {
                            id: ping_id,
                            stats: Some(snapshot),
                        };

                        let client_addr = config.snapshot().await.client_addr;
                        let mut client = match Client::connect(&client_addr).await {
                            Ok(client) => client,
                            Err(err) => {
                                debug!(addr = %client_addr, "periodic ping connect failed: {err}");
                                ping_id = ping_id.saturating_add(1);
                                continue;
                            }
                        };

                        if let Err(err) = client.ping(req).await {
                            debug!(addr = %client_addr, "periodic ping failed: {err}");
                        }
                        ping_id = ping_id.saturating_add(1);
                    }
                }
            }
        })
    }

    fn build_watch_service(&self) -> WatchService {
        let daemon = self.clone();
        let reconfigure_proc_workers: ProcWorkerReconfigure = Arc::new(move |method| {
            let daemon = daemon.clone();
            Box::pin(async move {
                daemon.reconfigure_proc_workers(method).await;
            })
        });

        WatchService::new(
            self.inner.shutdown.clone(),
            self.inner.config.clone(),
            self.inner.rules.clone(),
            self.inner.firewall.clone(),
            self.inner.stats.clone(),
            self.inner.process.clone(),
            self.inner.bus.task_reply_tx.clone(),
            reconfigure_proc_workers,
        )
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::Arc,
        time::{Duration, Instant},
    };

    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::{
        Daemon, DaemonInner, KERNEL_PIPELINE_SEND_BACKOFF, KernelPipeline, ProcWorkersRuntime,
        dispatch_kernel_pipeline_event, kernel_pipeline_drop_stats_snapshot,
    };
    use crate::{
        bus::{Bus, build_bus},
        config::Config,
        flows::verdict_flow::VerdictFlow,
        models::{
            connection_state::{ConnectionAttempt, TransportProtocol},
            firewall_state::{FirewallBackend, FirewallState},
            kernel_event::{KernelEvent, ProcEventKind},
        },
        services::{
            config_service::ConfigService, dns_service::DnsService,
            firewall_service::FirewallService, process_service::ProcessService,
            rule_service::RuleService, stats_service::StatsService,
        },
    };

    fn build_test_daemon(bus: Bus) -> Daemon {
        let config = Config::default();
        let firewall = FirewallService::new(&config).expect("firewall service");

        Daemon {
            inner: Arc::new(DaemonInner {
                config: ConfigService::new(config.clone()),
                nfqueue_num: config.firewall_queue_num,
                default_action: config.default_action,
                audit_socket_path: config.audit_socket_path.clone(),
                proc_workers: Arc::new(std::sync::Mutex::new(ProcWorkersRuntime {
                    current_method: config.proc_monitor_method,
                    shutdown: CancellationToken::new(),
                    handles: Vec::new(),
                })),
                bus,
                rules: RuleService::default(),
                process: ProcessService::default(),
                dns: DnsService::default(),
                stats: StatsService::default(),
                firewall,
                shutdown: CancellationToken::new(),
            }),
        }
    }

    #[tokio::test]
    async fn dispatch_kernel_pipeline_event_stops_when_channel_is_closed() {
        let (tx, rx) = mpsc::channel::<u8>(1);
        drop(rx);

        let keep_running = dispatch_kernel_pipeline_event(
            &tx,
            7_u8,
            &CancellationToken::new(),
            KernelPipeline::Process,
        )
        .await;

        assert!(!keep_running);
    }

    #[tokio::test]
    async fn dispatch_kernel_pipeline_event_drops_after_bounded_backoff_when_full() {
        let (tx, mut rx) = mpsc::channel::<u8>(1);
        assert!(tx.try_send(1_u8).is_ok());

        let before = kernel_pipeline_drop_stats_snapshot();
        let started = Instant::now();
        let keep_running = dispatch_kernel_pipeline_event(
            &tx,
            2_u8,
            &CancellationToken::new(),
            KernelPipeline::Dns,
        )
        .await;
        let after = kernel_pipeline_drop_stats_snapshot();

        assert!(keep_running);
        assert!(started.elapsed() >= KERNEL_PIPELINE_SEND_BACKOFF);
        assert_eq!(rx.try_recv().ok(), Some(1_u8));
        assert!(rx.try_recv().is_err());
        assert!(after.dns >= before.dns.saturating_add(1));
    }

    #[tokio::test]
    async fn connect_attempt_progresses_under_mixed_non_connect_saturation() {
        let (bus, rx) = build_bus(64);
        let daemon = build_test_daemon(bus.clone());

        let verdict_flow = VerdictFlow::new(
            bus.clone(),
            daemon.inner.config.clone(),
            daemon.inner.rules.clone(),
            daemon.inner.process.clone(),
            daemon.inner.dns.clone(),
            daemon.inner.stats.clone(),
        );

        let crate::bus::BusRx {
            connect_rx,
            kernel_rx,
            client_cmd_rx: _,
            mut verdict_rx,
            task_reply_rx: _,
        } = rx;

        let connect_handle =
            daemon.spawn_connect_attempt_task(verdict_flow, daemon.inner.stats.clone(), connect_rx);
        let kernel_handle = daemon.spawn_kernel_task(
            daemon.inner.process.clone(),
            daemon.inner.dns.clone(),
            daemon.inner.stats.clone(),
            kernel_rx,
        );

        let flood_bus = bus.clone();
        let flood = tokio::spawn(async move {
            for i in 0..10_000_u32 {
                let event = match i % 3 {
                    0 => KernelEvent::DnsResolved {
                        ip: format!("198.51.100.{}", i % 255),
                        host: format!("load-{}.example.test", i),
                    },
                    1 => KernelEvent::ProcStateChanged {
                        pid: 10_000 + (i % 64),
                        kind: ProcEventKind::Exec,
                    },
                    _ => KernelEvent::FirewallState(FirewallState {
                        enabled: i % 2 == 0,
                        backend: if i % 4 == 0 {
                            FirewallBackend::Iptables
                        } else {
                            FirewallBackend::Nftables
                        },
                    }),
                };

                let _ = flood_bus.kernel_tx.try_send(event);
            }
        });

        let request_id = 0xC0FFEE_u64;
        bus.connect_tx
            .send(ConnectionAttempt {
                request_id,
                protocol: TransportProtocol::Tcp,
                src_ip: "127.0.0.1".to_string(),
                src_port: 45000,
                dst_ip: "127.0.0.1".to_string(),
                dst_port: 50051,
                dns_query: None,
                pid: std::process::id(),
                uid: 1000,
            })
            .await
            .expect("connect attempt send");

        let verdict = timeout(Duration::from_secs(2), verdict_rx.recv())
            .await
            .expect("verdict timeout")
            .expect("verdict channel closed");

        assert_eq!(verdict.request_id, request_id);
        assert!(verdict.allow);
        assert!(!verdict.reject);

        let _ = flood.await;
        daemon.shutdown().await;

        let _ = timeout(Duration::from_secs(1), connect_handle).await;
        let _ = timeout(Duration::from_secs(1), kernel_handle).await;
    }

    fn duration_percentile(sorted: &[Duration], pct: f64) -> Duration {
        if sorted.is_empty() {
            return Duration::ZERO;
        }

        let max_idx = sorted.len().saturating_sub(1);
        let idx = ((max_idx as f64) * pct).round() as usize;
        sorted[idx.min(max_idx)]
    }

    #[derive(Debug, Clone, Copy)]
    struct StressPerfBaseline {
        p95_ms: f64,
        p99_ms: f64,
        max_ms: f64,
        drop_total: u64,
    }

    fn todo_perf_path() -> String {
        std::env::var("OPENSNITCH_STRESS_TODO_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty())
            .unwrap_or_else(|| format!("{}/../../TODO.md", env!("CARGO_MANIFEST_DIR")))
    }

    fn parse_todo_f64(todo: &str, key: &str) -> Option<f64> {
        todo.lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix(key).map(str::trim))
            .and_then(|raw| raw.parse::<f64>().ok())
    }

    fn parse_todo_u64(todo: &str, key: &str) -> Option<u64> {
        todo.lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix(key).map(str::trim))
            .and_then(|raw| raw.parse::<u64>().ok())
    }

    fn load_stress_perf_baseline(todo: &str) -> StressPerfBaseline {
        let prefix = if cfg!(debug_assertions) {
            "PERF_BASELINE_RUST_DEBUG"
        } else {
            "PERF_BASELINE_RUST_RELEASE"
        };

        StressPerfBaseline {
            p95_ms: parse_todo_f64(todo, &format!("{prefix}_P95_MS="))
                .expect("missing TODO baseline key for rust p95"),
            p99_ms: parse_todo_f64(todo, &format!("{prefix}_P99_MS="))
                .expect("missing TODO baseline key for rust p99"),
            max_ms: parse_todo_f64(todo, &format!("{prefix}_MAX_MS="))
                .expect("missing TODO baseline key for rust max"),
            drop_total: parse_todo_u64(todo, &format!("{prefix}_DROP_TOTAL="))
                .expect("missing TODO baseline key for rust drop_total"),
        }
    }

    fn is_clear_regression(
        observed_ms: f64,
        baseline_ms: f64,
        factor: f64,
        min_delta_ms: f64,
    ) -> bool {
        observed_ms > baseline_ms * factor && (observed_ms - baseline_ms) > min_delta_ms
    }

    fn enforce_stress_regression_guard(
        p95: Duration,
        p99: Duration,
        max: Duration,
        drop_total: u64,
    ) {
        if std::env::var("OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK").as_deref() == Ok("1") {
            return;
        }

        let todo_path = todo_perf_path();
        let todo = fs::read_to_string(&todo_path).unwrap_or_else(|err| {
            panic!("failed to read TODO baseline file '{}': {err}", todo_path)
        });

        let baseline = load_stress_perf_baseline(&todo);
        let factor = parse_todo_f64(&todo, "PERF_CLEAR_REGRESSION_FACTOR=").unwrap_or(1.75);
        let min_delta_ms =
            parse_todo_f64(&todo, "PERF_CLEAR_REGRESSION_MIN_DELTA_MS=").unwrap_or(0.050);

        let p95_ms = p95.as_secs_f64() * 1000.0;
        let p99_ms = p99.as_secs_f64() * 1000.0;
        let max_ms = max.as_secs_f64() * 1000.0;

        let mut regressions = Vec::new();

        if is_clear_regression(p95_ms, baseline.p95_ms, factor, min_delta_ms) {
            regressions.push(format!(
                "p95_ms observed={:.3} baseline={:.3}",
                p95_ms, baseline.p95_ms
            ));
        }

        if is_clear_regression(p99_ms, baseline.p99_ms, factor, min_delta_ms) {
            regressions.push(format!(
                "p99_ms observed={:.3} baseline={:.3}",
                p99_ms, baseline.p99_ms
            ));
        }

        if is_clear_regression(max_ms, baseline.max_ms, factor, min_delta_ms) {
            regressions.push(format!(
                "max_ms observed={:.3} baseline={:.3}",
                max_ms, baseline.max_ms
            ));
        }

        if drop_total > baseline.drop_total {
            regressions.push(format!(
                "drop_total observed={} baseline={}",
                drop_total, baseline.drop_total
            ));
        }

        assert!(
            regressions.is_empty(),
            "stress-profile clear regression detected (factor={factor:.2}, min_delta_ms={min_delta_ms:.3}): {}",
            regressions.join("; ")
        );
    }

    #[tokio::test]
    #[ignore = "profiling harness; run with --ignored --nocapture"]
    async fn stress_profile_reports_connect_latency_and_pipeline_drops() {
        let rounds = std::env::var("OPENSNITCH_STRESS_ROUNDS")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(2_000);

        let (bus, rx) = build_bus(256);
        let daemon = build_test_daemon(bus.clone());

        let verdict_flow = VerdictFlow::new(
            bus.clone(),
            daemon.inner.config.clone(),
            daemon.inner.rules.clone(),
            daemon.inner.process.clone(),
            daemon.inner.dns.clone(),
            daemon.inner.stats.clone(),
        );

        let crate::bus::BusRx {
            connect_rx,
            kernel_rx,
            client_cmd_rx: _,
            mut verdict_rx,
            task_reply_rx: _,
        } = rx;

        let connect_handle =
            daemon.spawn_connect_attempt_task(verdict_flow, daemon.inner.stats.clone(), connect_rx);
        let kernel_handle = daemon.spawn_kernel_task(
            daemon.inner.process.clone(),
            daemon.inner.dns.clone(),
            daemon.inner.stats.clone(),
            kernel_rx,
        );

        let flood_shutdown = CancellationToken::new();
        let flood_token = flood_shutdown.clone();
        let flood_bus = bus.clone();
        let flood = tokio::spawn(async move {
            let mut i = 0_u32;
            while !flood_token.is_cancelled() {
                let event = match i % 3 {
                    0 => KernelEvent::DnsResolved {
                        ip: format!("203.0.113.{}", i % 255),
                        host: format!("profile-{}.example.test", i),
                    },
                    1 => KernelEvent::ProcStateChanged {
                        pid: 40_000 + (i % 64),
                        kind: ProcEventKind::Exec,
                    },
                    _ => KernelEvent::FirewallState(FirewallState {
                        enabled: i % 2 == 0,
                        backend: if i % 4 == 0 {
                            FirewallBackend::Iptables
                        } else {
                            FirewallBackend::Nftables
                        },
                    }),
                };

                let _ = flood_bus.kernel_tx.try_send(event);
                i = i.wrapping_add(1);
                tokio::task::yield_now().await;
            }
        });

        let drop_before = kernel_pipeline_drop_stats_snapshot();
        let mut latencies = Vec::with_capacity(rounds);
        let base_request_id = 0xD00D_0000_u64;

        for i in 0..rounds {
            let request_id = base_request_id + i as u64;
            let started = Instant::now();

            bus.connect_tx
                .send(ConnectionAttempt {
                    request_id,
                    protocol: TransportProtocol::Tcp,
                    src_ip: "127.0.0.1".to_string(),
                    src_port: 46000,
                    dst_ip: "127.0.0.1".to_string(),
                    dst_port: 50051,
                    dns_query: None,
                    pid: std::process::id(),
                    uid: 1000,
                })
                .await
                .expect("connect attempt send");

            let verdict = timeout(Duration::from_secs(2), verdict_rx.recv())
                .await
                .expect("verdict timeout")
                .expect("verdict channel closed");

            assert_eq!(verdict.request_id, request_id);
            assert!(verdict.allow);
            assert!(!verdict.reject);

            latencies.push(started.elapsed());
        }

        let drop_after = kernel_pipeline_drop_stats_snapshot();
        let drop_delta = drop_after.saturating_delta(drop_before);

        flood_shutdown.cancel();
        let _ = flood.await;

        daemon.shutdown().await;
        let _ = timeout(Duration::from_secs(1), connect_handle).await;
        let _ = timeout(Duration::from_secs(1), kernel_handle).await;

        latencies.sort_unstable();
        let p50 = duration_percentile(&latencies, 0.50);
        let p95 = duration_percentile(&latencies, 0.95);
        let p99 = duration_percentile(&latencies, 0.99);
        let max = latencies.last().copied().unwrap_or(Duration::ZERO);

        enforce_stress_regression_guard(p95, p99, max, drop_delta.total());

        println!(
            "stress-profile rounds={} p50_ms={:.3} p95_ms={:.3} p99_ms={:.3} max_ms={:.3} drop_dns={} drop_process={} drop_firewall={} drop_total={}",
            rounds,
            p50.as_secs_f64() * 1000.0,
            p95.as_secs_f64() * 1000.0,
            p99.as_secs_f64() * 1000.0,
            max.as_secs_f64() * 1000.0,
            drop_delta.dns,
            drop_delta.process,
            drop_delta.firewall,
            drop_delta.total(),
        );
    }
}
