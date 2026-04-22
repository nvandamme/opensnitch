use std::{
    collections::HashMap,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    bus::{Bus, BusCaps, BusRx, build_bus_with_caps},
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
        connection_service::ConnectionService,
        dns_service::DnsService,
        firewall_service::FirewallService,
        process_service::ProcessService,
        rule_service::RuleService,
        stats_service::StatsService,
        ui_session_service::UiSessionService,
        watch_service::{ProcWorkerReconfigure, WatchService, WatcherService},
    },
    tunables::RuntimeTunables,
    workers::{
        self,
        control::{
            RuntimeHandles, WorkerCommand, WorkerCommandResult, WorkerControl, WorkerJoinStatus,
            WorkerState,
        },
    },
};

const KERNEL_PIPELINE_SEND_RETRIES: usize = 8;
const KERNEL_PIPELINE_SEND_BACKOFF: Duration = Duration::from_millis(10);
const KERNEL_INGRESS_DISPATCH_BATCH: usize = 32;

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

async fn dispatch_connect_attempt_to_worker(
    worker_txs: &[tokio::sync::mpsc::Sender<ConnectionAttempt>],
    next_worker: &mut usize,
    shutdown: &CancellationToken,
    attempt: ConnectionAttempt,
) -> bool {
    if worker_txs.is_empty() {
        return false;
    }

    let worker_count = worker_txs.len();
    if worker_count == 1 {
        let tx = &worker_txs[0];
        return match tx.try_send(attempt) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(attempt)) => {
                tokio::select! {
                    _ = shutdown.cancelled() => false,
                    result = tx.send(attempt) => result.is_ok(),
                }
            }
        };
    }

    let start_idx = *next_worker % worker_count;
    let mut pending = attempt;
    let mut fallback_idx = None;
    let mut idx = start_idx;

    // Fast path: probe all workers with try_send first to avoid waiting on one full lane.
    for _ in 0..worker_count {
        match worker_txs[idx].try_send(pending) {
            Ok(()) => {
                *next_worker = (idx + 1) % worker_count;
                return true;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(attempt)) => {
                pending = attempt;
                if fallback_idx.is_none() {
                    fallback_idx = Some(idx);
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(attempt)) => {
                pending = attempt;
            }
        }

        idx += 1;
        if idx == worker_count {
            idx = 0;
        }
    }

    // Fallback: block on the first observed non-closed lane after probes fail.
    let Some(blocking_idx) = fallback_idx else {
        return false;
    };

    let tx = &worker_txs[blocking_idx];
    tokio::select! {
        _ = shutdown.cancelled() => false,
        result = tx.send(pending) => {
            if result.is_ok() {
                *next_worker = (blocking_idx + 1) % worker_count;
                true
            } else {
                false
            }
        },
    }
}

async fn dispatch_kernel_pipeline_event<T>(
    tx: &tokio::sync::mpsc::Sender<T>,
    event: T,
    shutdown: &CancellationToken,
    pipeline: KernelPipeline,
) -> bool {
    let pending = event;

    for _ in 0..KERNEL_PIPELINE_SEND_RETRIES {
        if shutdown.is_cancelled() {
            return false;
        }

        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(pending);
                return true;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
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

fn fanout_kernel_ingress_event(
    event: KernelEvent,
    dns_ingress_tx: &tokio::sync::mpsc::UnboundedSender<(String, String)>,
    process_ingress_tx: &tokio::sync::mpsc::UnboundedSender<ProcessKernelEvent>,
    firewall_ingress_tx: &tokio::sync::mpsc::UnboundedSender<
        crate::models::firewall_state::FirewallState,
    >,
) -> bool {
    match event {
        KernelEvent::DnsResolved { ip, host } => dns_ingress_tx.send((ip, host)).is_ok(),
        KernelEvent::ProcStateChanged { pid, kind } => process_ingress_tx
            .send(ProcessKernelEvent::ProcStateChanged { pid, kind })
            .is_ok(),
        KernelEvent::EbpfProcessMapHit { pid, uid, note } => process_ingress_tx
            .send(ProcessKernelEvent::EbpfProcessMapHit { pid, uid, note })
            .is_ok(),
        KernelEvent::FirewallState(state) => firewall_ingress_tx.send(state).is_ok(),
    }
}

#[derive(Clone)]
pub struct Daemon {
    inner: Arc<DaemonInner>,
}

struct DaemonInner {
    config: ConfigService,
    ui_session: UiSessionService,
    nfqueue_num: u16,
    default_action: crate::config::DefaultAction,
    audit_socket_path: std::path::PathBuf,
    proc_workers: Arc<std::sync::Mutex<ProcWorkersRuntime>>,
    bus: Bus,
    rules: RuleService,
    connections: ConnectionService,
    process: ProcessService,
    dns: DnsService,
    stats: StatsService,
    firewall: FirewallService,
    tunables: RuntimeTunables,
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
        let (bus, rx) = build_bus_with_caps(BusCaps {
            connect: 1024,
            kernel: 512,
            client_cmd: 256,
            verdict: 1024,
            task_reply: 256,
            alert: 1024,
        });
        let config = crate::config::Config::load_from_default_locations()?
            .with_client_addr_override(client_addr);
        if let Some(status) = crate::tunables::maybe_autotune_on_startup() {
            info!(status = %status, "daemon bootstrap: startup autotune");
        }
        let (tunables, tunables_source) = RuntimeTunables::load_effective();
        info!(
            addr = %config.client_addr,
            ?config.default_action,
            ?config.proc_monitor_method,
            ?config.firewall_backend,
            "daemon bootstrap: loaded config"
        );
        info!(
            source = %tunables_source,
            max_concurrent_connect_attempts = tunables.max_concurrent_connect_attempts,
            connect_worker_queue_capacity = tunables.connect_worker_queue_capacity,
            connect_dispatch_batch_size = tunables.connect_dispatch_batch_size,
            kernel_dns_queue_capacity = tunables.kernel_dns_queue_capacity,
            kernel_process_queue_capacity = tunables.kernel_process_queue_capacity,
            kernel_firewall_queue_capacity = tunables.kernel_firewall_queue_capacity,
            ebpf_map_prune_enabled = tunables.ebpf_map_prune_enabled,
            ebpf_map_prune_threshold_percent = tunables.ebpf_map_prune_threshold_percent,
            ebpf_map_prune_target_percent = tunables.ebpf_map_prune_target_percent,
            "daemon bootstrap: effective runtime tunables"
        );
        let config_service = ConfigService::new(config.clone());
        let ui_session = UiSessionService::default();
        let rules = RuleService::default();
        rules.load_path(&config.rules_path).await?;
        info!(path = %config.rules_path.display(), "daemon bootstrap: initial rules loaded");
        let firewall = FirewallService::new(&config)?;
        if let Err(err) = firewall.ensure_rules().await {
            warn!(
                backend = config.firewall_backend.as_str(),
                "firewall bootstrap skipped: {err}"
            );
        } else {
            info!(
                backend = config.firewall_backend.as_str(),
                "daemon bootstrap: firewall ensured"
            );
        }

        let process = ProcessService::default();
        let dns = DnsService::default();
        let connections = ConnectionService::new(process.clone(), dns.clone());

        let daemon = Self {
            inner: Arc::new(DaemonInner {
                config: config_service,
                ui_session,
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
                connections,
                process,
                dns,
                stats: StatsService::default(),
                firewall,
                tunables,
                shutdown: CancellationToken::new(),
            }),
        };

        daemon.inner.stats.apply_config(config.stats);

        Ok((daemon, rx))
    }

    pub async fn serve(&self, rx: BusRx) -> Result<()> {
        let config = self.inner.config.snapshot().await;
        crate::utils::systemd_notify::status("Starting daemon runtime bootstrap...");
        info!(addr = %config.client_addr, "daemon runtime: starting serve loop");
        info!(queue = self.inner.nfqueue_num, "running on netfilter queue");
        if let Err(err) = crate::logging::apply_config(&config) {
            warn!("failed to apply startup logging config: {err}");
        }
        match Client::connect_with_config(&config).await {
            Ok(mut client) => {
                if let Err(err) = self.startup_handshake(&mut client).await {
                    warn!(addr = %config.client_addr, "startup UI handshake failed, continuing without blocking runtime: {err}");
                }
            }
            Err(err) => {
                warn!(addr = %config.client_addr, "startup UI connect failed, continuing without blocking runtime: {err}");
            }
        }

        let verdict_flow = VerdictFlow::new(
            self.inner.bus.clone(),
            self.inner.config.clone(),
            self.inner.ui_session.clone(),
            self.inner.rules.clone(),
            self.inner.connections.clone(),
            self.inner.stats.clone(),
        );

        let notification_flow = NotificationFlow::new(
            self.inner.bus.clone(),
            self.inner.config.clone(),
            self.inner.ui_session.clone(),
            self.inner.rules.clone(),
            self.inner.firewall.clone(),
        );

        let mut handles = RuntimeHandles::new();
        self.spawn_workers(&mut handles).await;
        self.spawn_tasks(&mut handles, rx, verdict_flow, notification_flow);
        info!("daemon runtime: workers and tasks started");
        crate::utils::systemd_notify::ready(Some("opensnitchd-rs runtime ready"));

        self.run_signal_loop().await?;

        crate::utils::systemd_notify::stopping(Some("Daemon stopping..."));
        self.shutdown().await;
        self.stop_proc_workers().await;
        handles.join_all().await;
        info!("daemon runtime: shutdown complete");
        crate::utils::systemd_notify::status("Daemon stopped");

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

        if let Some(connected_default_action) =
            Self::parse_default_action_from_client_config(&subscribe_reply.config)
        {
            self.inner
                .ui_session
                .set_connected_default_action(connected_default_action)
                .await;
            info!(
                ?connected_default_action,
                "updated connected-mode default action from subscribe payload"
            );
        }

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

    async fn run_signal_loop(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut sig_int = signal(SignalKind::interrupt())?;
            let mut sig_term = signal(SignalKind::terminate())?;
            let mut sig_hup = signal(SignalKind::hangup())?;

            loop {
                tokio::select! {
                    _ = self.inner.shutdown.cancelled() => {
                        info!("shutdown requested");
                        crate::utils::systemd_notify::status("Shutdown requested by runtime command");
                        break;
                    }
                    signal = sig_int.recv() => {
                        if signal.is_some() {
                            info!("SIGINT received");
                            crate::utils::systemd_notify::status("SIGINT received, stopping daemon");
                        } else {
                            warn!("SIGINT stream closed");
                        }
                        break;
                    }
                    signal = sig_term.recv() => {
                        if signal.is_some() {
                            info!("SIGTERM received");
                            crate::utils::systemd_notify::status("SIGTERM received, stopping daemon");
                        } else {
                            warn!("SIGTERM stream closed");
                        }
                        break;
                    }
                    signal = sig_hup.recv() => {
                        if signal.is_none() {
                            warn!("SIGHUP stream closed");
                            continue;
                        }
                        self.reload_runtime_after_sighup().await;
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("ctrl-c received");
                }
                _ = self.inner.shutdown.cancelled() => {
                    info!("shutdown requested");
                }
            }
        }

        Ok(())
    }

    async fn reload_runtime_after_sighup(&self) {
        crate::utils::systemd_notify::reloading(Some(
            "SIGHUP received, reloading runtime config...",
        ));
        info!("SIGHUP received, reloading runtime config");

        let updated = match self.inner.config.reload().await {
            Ok(config) => config,
            Err(err) => {
                error!("failed to reload config from disk after SIGHUP: {err}");
                crate::utils::systemd_notify::status("SIGHUP reload failed while reading config");
                return;
            }
        };

        crate::ffi::nfqueue::set_default_action(updated.default_action);
        self.inner.stats.apply_config(updated.stats);

        if let Err(err) = crate::logging::apply_config(&updated) {
            error!("failed to apply logging config after SIGHUP reload: {err}");
        }

        if let Err(err) = self.inner.rules.load_path(&updated.rules_path).await {
            error!("failed to reload rules after SIGHUP: {err}");
            crate::utils::systemd_notify::status("SIGHUP reload failed while reloading rules");
            return;
        }

        if let Err(err) = self.inner.firewall.reconcile_from_config(&updated).await {
            error!("failed to reconcile firewall after SIGHUP: {err}");
            crate::utils::systemd_notify::status("SIGHUP reload failed while reconciling firewall");
            return;
        }

        if let Err(err) = self
            .reconfigure_proc_workers(Some(updated.proc_monitor_method))
            .await
        {
            error!("failed to reconfigure process monitor workers after SIGHUP: {err}");
            crate::utils::systemd_notify::status(
                "SIGHUP reload failed while reconfiguring process monitor",
            );
            return;
        }

        info!("SIGHUP reload completed");
        crate::utils::systemd_notify::ready(Some("SIGHUP reload complete"));
    }

    fn parse_default_action_from_client_config(
        raw_config_json: &str,
    ) -> Option<crate::config::DefaultAction> {
        let raw = serde_json::from_str::<serde_json::Value>(raw_config_json).ok()?;
        let action = raw
            .as_object()
            .and_then(|obj| {
                obj.iter().find_map(|(key, value)| {
                    key.eq_ignore_ascii_case("DefaultAction").then_some(value)
                })
            })
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        Some(crate::config::DefaultAction::from_name(action))
    }
    async fn spawn_workers(&self, handles: &mut RuntimeHandles) {
        info!("starting worker set");
        handles.push_worker(
            "nfqueue",
            workers::nfqueue_worker::spawn(
                self.inner.bus.clone(),
                self.inner.nfqueue_num,
                self.inner.default_action,
                self.inner.shutdown.clone(),
            ),
        );
        debug!(queue = self.inner.nfqueue_num, "nfqueue worker started");

        let initial_method = self.inner.config.snapshot().await.proc_monitor_method;
        if let Err(err) = self.reconfigure_proc_workers(Some(initial_method)).await {
            warn!(method = ?initial_method, "failed to start requested process monitor method: {err}");
            let _ = self
                .reconfigure_proc_workers(Some(ProcMonitorMethod::Proc))
                .await;
        }

        handles.push_worker_control(Box::new(workers::dns_worker::DnsWorkerControl::new(
            self.inner.bus.clone(),
            self.inner.shutdown.clone(),
        )));
        debug!("dns worker started");

        handles.push_worker(
            "firewall",
            workers::firewall_worker::spawn(
                self.inner.bus.clone(),
                self.inner.firewall.clone(),
                self.inner.shutdown.clone(),
            ),
        );
        debug!("firewall worker started");

        handles.push_worker(
            "netlink-ifaces",
            workers::netlink_addr_worker::spawn(self.inner.shutdown.clone()),
        );
        debug!("netlink local-address worker started");
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
            ProcMonitorMethod::Ebpf => {
                vec![Box::new(workers::ebpf_worker::EbpfWorkerControl::new(
                    self.inner.bus.clone(),
                    shutdown,
                    self.inner.tunables,
                ))]
            }
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

    async fn reconfigure_proc_workers(&self, method: Option<ProcMonitorMethod>) -> Result<()> {
        let previous_method = {
            let runtime = self
                .inner
                .proc_workers
                .lock()
                .expect("proc workers mutex poisoned");
            runtime.current_method
        };

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
                return Ok(());
            }

            debug!("monitor.End()");
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
            tokio::time::sleep(Duration::from_millis(100)).await;
            let running = {
                let runtime = self
                    .inner
                    .proc_workers
                    .lock()
                    .expect("proc workers mutex poisoned");
                runtime.handles.iter().any(|handle| !handle.is_finished())
            };

            if !running {
                warn!(requested = ?method, fallback = ?previous_method, "process monitor workers failed to start; rolling back");
                crate::utils::systemd_notify::status(
                    "Process monitor reconfigure failed; rolling back",
                );
                if previous_method != method {
                    let failed_handles = {
                        let mut runtime = self
                            .inner
                            .proc_workers
                            .lock()
                            .expect("proc workers mutex poisoned");
                        runtime.shutdown.cancel();
                        std::mem::take(&mut runtime.handles)
                    };

                    if !failed_handles.is_empty() {
                        let _ = tokio::task::spawn_blocking(move || {
                            for worker in failed_handles {
                                let _ = worker.join();
                            }
                        })
                        .await;
                    }

                    let mut runtime = self
                        .inner
                        .proc_workers
                        .lock()
                        .expect("proc workers mutex poisoned");
                    runtime.current_method = previous_method;
                    runtime.shutdown = CancellationToken::new();
                    runtime.handles =
                        self.spawn_proc_worker_handles(previous_method, runtime.shutdown.clone());
                }
                return Err(anyhow::anyhow!(
                    "failed to start process monitor workers for {:?}",
                    method
                ));
            }

            let method_label = match method {
                ProcMonitorMethod::Proc => "/proc",
                ProcMonitorMethod::Audit => "audit",
                ProcMonitorMethod::Ebpf => "ebpf",
            };
            info!("Process monitor method {method_label}");
            info!(method = ?method, "reconfigured process monitor workers");
            crate::utils::systemd_notify::status(&format!(
                "Process monitor reconfigured: {method_label}"
            ));
        } else {
            info!("stopped process monitor workers");
            crate::utils::systemd_notify::status("Process monitor workers stopped");
        }

        Ok(())
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
        info!("starting runtime task set");
        task_runtime::configure_alert_sender(self.inner.bus.alert_tx.clone());
        let task_reply_rx = rx.task_reply_rx;
        let alert_rx = rx.alert_rx;
        handles.push_task(
            "notifications",
            self.spawn_notification_task(notification_flow, task_reply_rx, alert_rx),
        );
        debug!("notification task started");

        handles.push_task(
            "connect-attempts",
            self.spawn_connect_attempt_task(verdict_flow, self.inner.stats.clone(), rx.connect_rx),
        );
        debug!("connect-attempt task started");

        handles.push_task(
            "kernel-events",
            self.spawn_kernel_task(
                self.inner.process.clone(),
                self.inner.dns.clone(),
                self.inner.stats.clone(),
                rx.kernel_rx,
            ),
        );
        debug!("kernel-events task started");

        handles.push_task(
            "process-cache-cleanup",
            self.inner
                .process
                .spawn_cleanup_task(self.inner.shutdown.clone()),
        );
        debug!("process-cache-cleanup task started");

        handles.push_task(
            "client-commands",
            self.spawn_client_command_task(rx.client_cmd_rx),
        );
        debug!("client-command task started");

        handles.push_task(
            "verdict-replies",
            self.spawn_verdict_rpc_task(rx.verdict_rx, self.inner.stats.clone()),
        );
        debug!("verdict-rpc task started");

        handles.push_task(
            "stats-ping",
            self.spawn_stats_ping_task(
                self.inner.config.clone(),
                self.inner.rules.clone(),
                self.inner.stats.clone(),
            ),
        );
        debug!("stats-ping task started");

        let watch_service = self.build_watch_service();
        handles.push_task("config-watch", watch_service.spawn_config_watch_task());
        handles.push_task("rules-watch", watch_service.spawn_rules_watch_task());
        handles.push_task("tasks-watch", watch_service.spawn_tasks_watch_task());
        handles.push_task("firewall-watch", watch_service.spawn_firewall_watch_task());
        debug!("watch tasks started");
    }

    fn spawn_notification_task(
        &self,
        flow: NotificationFlow,
        task_reply_rx: tokio::sync::mpsc::Receiver<opensnitch_proto::pb::NotificationReply>,
        alert_rx: tokio::sync::mpsc::Receiver<crate::models::ui_alert::UiAlert>,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();

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

    fn spawn_connect_attempt_task(
        &self,
        flow: VerdictFlow,
        stats: StatsService,
        mut connect_rx: tokio::sync::mpsc::Receiver<ConnectionAttempt>,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();
        let daemon_pid = std::process::id();
        let tunables = self.inner.tunables;

        let mut worker_handles = Vec::with_capacity(tunables.max_concurrent_connect_attempts);
        let mut worker_txs = Vec::with_capacity(tunables.max_concurrent_connect_attempts);
        for _ in 0..tunables.max_concurrent_connect_attempts {
            let worker_shutdown = shutdown.clone();
            let worker_flow = flow.clone();
            let (worker_tx, mut worker_rx) = tokio::sync::mpsc::channel::<ConnectionAttempt>(
                tunables.connect_worker_queue_capacity,
            );
            worker_txs.push(worker_tx);

            worker_handles.push(tokio::spawn(async move {
                'worker: loop {
                    let first = tokio::select! {
                        _ = worker_shutdown.cancelled() => break 'worker,
                        msg = worker_rx.recv() => {
                            match msg {
                                Some(attempt) => attempt,
                                None => break 'worker,
                            }
                        }
                    };

                    worker_flow.handle_connect_attempt(first).await;

                    // Drain a bounded burst from this lane to amortize wake-up/scheduling cost.
                    for _ in 1..tunables.connect_dispatch_batch_size {
                        if worker_shutdown.is_cancelled() {
                            break 'worker;
                        }

                        let next = match worker_rx.try_recv() {
                            Ok(attempt) => attempt,
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                break 'worker;
                            }
                        };

                        worker_flow.handle_connect_attempt(next).await;
                    }
                }
            }));
        }

        tokio::spawn(async move {
            let mut next_worker = 0usize;

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = connect_rx.recv() => {
                        match msg {
                            Some(attempt) => {
                                // Process first message.
                                if attempt.pid == daemon_pid {
                                    flow.fast_allow_with_stats(attempt.request_id, "daemon-self-dispatch")
                                        .await;
                                } else {
                                    stats.on_connect_attempt(&attempt);
                                    if !dispatch_connect_attempt_to_worker(
                                        &worker_txs,
                                        &mut next_worker,
                                        &shutdown,
                                        attempt,
                                    )
                                    .await
                                    {
                                        break;
                                    }
                                }

                                // Drain additional already-queued connect attempts without
                                // allocating a temporary batch vector.
                                for _ in 1..tunables.connect_dispatch_batch_size {
                                    let next = match connect_rx.try_recv() {
                                        Ok(next) => next,
                                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                                    };

                                    if next.pid == daemon_pid {
                                        flow.fast_allow_with_stats(next.request_id, "daemon-self-dispatch")
                                            .await;
                                    } else {
                                        stats.on_connect_attempt(&next);
                                        if !dispatch_connect_attempt_to_worker(
                                            &worker_txs,
                                            &mut next_worker,
                                            &shutdown,
                                            next,
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

            worker_txs.clear();
            for handle in worker_handles {
                let _ = handle.await;
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
        let tunables = self.inner.tunables;

        tokio::spawn(async move {
            let kernel_fanout_batch = tunables
                .max_concurrent_connect_attempts
                .saturating_mul(2)
                .clamp(8, KERNEL_INGRESS_DISPATCH_BATCH);

            let (dns_tx, mut dns_rx) =
                tokio::sync::mpsc::channel::<(String, String)>(tunables.kernel_dns_queue_capacity);
            let (process_tx, mut process_rx) = tokio::sync::mpsc::channel::<ProcessKernelEvent>(
                tunables.kernel_process_queue_capacity,
            );
            let (firewall_tx, mut firewall_rx) =
                tokio::sync::mpsc::channel::<crate::models::firewall_state::FirewallState>(
                    tunables.kernel_firewall_queue_capacity,
                );

            let (dns_ingress_tx, mut dns_ingress_rx) =
                tokio::sync::mpsc::unbounded_channel::<(String, String)>();
            let (process_ingress_tx, mut process_ingress_rx) =
                tokio::sync::mpsc::unbounded_channel::<ProcessKernelEvent>();
            let (firewall_ingress_tx, mut firewall_ingress_rx) =
                tokio::sync::mpsc::unbounded_channel::<crate::models::firewall_state::FirewallState>(
                );

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

            let dns_dispatch_shutdown = shutdown.clone();
            let dns_dispatch_tx = dns_tx.clone();
            let dns_dispatch_handle = tokio::spawn(async move {
                loop {
                    let first = tokio::select! {
                        _ = dns_dispatch_shutdown.cancelled() => break,
                        msg = dns_ingress_rx.recv() => {
                            match msg {
                                Some(event) => event,
                                None => break,
                            }
                        }
                    };

                    if !dispatch_kernel_pipeline_event(
                        &dns_dispatch_tx,
                        first,
                        &dns_dispatch_shutdown,
                        KernelPipeline::Dns,
                    )
                    .await
                    {
                        break;
                    }

                    for _ in 1..KERNEL_INGRESS_DISPATCH_BATCH {
                        if dns_dispatch_shutdown.is_cancelled() {
                            break;
                        }

                        let next = match dns_ingress_rx.try_recv() {
                            Ok(event) => event,
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                        };

                        if !dispatch_kernel_pipeline_event(
                            &dns_dispatch_tx,
                            next,
                            &dns_dispatch_shutdown,
                            KernelPipeline::Dns,
                        )
                        .await
                        {
                            break;
                        }
                    }
                }
            });

            let process_dispatch_shutdown = shutdown.clone();
            let process_dispatch_tx = process_tx.clone();
            let process_dispatch_handle = tokio::spawn(async move {
                loop {
                    let first = tokio::select! {
                        _ = process_dispatch_shutdown.cancelled() => break,
                        msg = process_ingress_rx.recv() => {
                            match msg {
                                Some(event) => event,
                                None => break,
                            }
                        }
                    };

                    if !dispatch_kernel_pipeline_event(
                        &process_dispatch_tx,
                        first,
                        &process_dispatch_shutdown,
                        KernelPipeline::Process,
                    )
                    .await
                    {
                        break;
                    }

                    for _ in 1..KERNEL_INGRESS_DISPATCH_BATCH {
                        if process_dispatch_shutdown.is_cancelled() {
                            break;
                        }

                        let next = match process_ingress_rx.try_recv() {
                            Ok(event) => event,
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                        };

                        if !dispatch_kernel_pipeline_event(
                            &process_dispatch_tx,
                            next,
                            &process_dispatch_shutdown,
                            KernelPipeline::Process,
                        )
                        .await
                        {
                            break;
                        }
                    }
                }
            });

            let firewall_dispatch_shutdown = shutdown.clone();
            let firewall_dispatch_tx = firewall_tx.clone();
            let firewall_dispatch_handle = tokio::spawn(async move {
                loop {
                    let first = tokio::select! {
                        _ = firewall_dispatch_shutdown.cancelled() => break,
                        msg = firewall_ingress_rx.recv() => {
                            match msg {
                                Some(state) => state,
                                None => break,
                            }
                        }
                    };

                    if !dispatch_kernel_pipeline_event(
                        &firewall_dispatch_tx,
                        first,
                        &firewall_dispatch_shutdown,
                        KernelPipeline::Firewall,
                    )
                    .await
                    {
                        break;
                    }

                    for _ in 1..KERNEL_INGRESS_DISPATCH_BATCH {
                        if firewall_dispatch_shutdown.is_cancelled() {
                            break;
                        }

                        let next = match firewall_ingress_rx.try_recv() {
                            Ok(state) => state,
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                        };

                        if !dispatch_kernel_pipeline_event(
                            &firewall_dispatch_tx,
                            next,
                            &firewall_dispatch_shutdown,
                            KernelPipeline::Firewall,
                        )
                        .await
                        {
                            break;
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
                                if !fanout_kernel_ingress_event(
                                    event,
                                    &dns_ingress_tx,
                                    &process_ingress_tx,
                                    &firewall_ingress_tx,
                                ) {
                                    break;
                                }

                                let mut drained = 1usize;
                                for _ in 1..kernel_fanout_batch {
                                    if shutdown.is_cancelled() {
                                        break;
                                    }

                                    let next = match kernel_rx.try_recv() {
                                        Ok(next) => next,
                                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                                    };

                                    if !fanout_kernel_ingress_event(
                                        next,
                                        &dns_ingress_tx,
                                        &process_ingress_tx,
                                        &firewall_ingress_tx,
                                    ) {
                                        break;
                                    }

                                    drained += 1;
                                }

                                // Keep burst processing, but yield after full drains to avoid
                                // starving connect-attempt handling under sustained kernel load.
                                if drained >= kernel_fanout_batch {
                                    tokio::task::yield_now().await;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            drop(dns_ingress_tx);
            drop(process_ingress_tx);
            drop(firewall_ingress_tx);

            let _ = tokio::join!(
                dns_dispatch_handle,
                process_dispatch_handle,
                firewall_dispatch_handle
            );

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
                Box::pin(async move { daemon.reconfigure_proc_workers(method).await })
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
            let (task_lifecycle_tx, mut task_lifecycle_rx) =
                tokio::sync::mpsc::channel::<task_runtime::TaskLifecycleEvent>(128);
            let shutdown_events = shutdown.clone();
            let task_lifecycle_handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_events.cancelled() => break,
                        msg = task_lifecycle_rx.recv() => {
                            match msg {
                                Some(task_runtime::TaskLifecycleEvent::Added { task_name, task_key }) => {
                                    tracing::debug!(task = %task_name, key = %task_key, "Task Added");
                                }
                                Some(task_runtime::TaskLifecycleEvent::Removed { task_name, task_key }) => {
                                    tracing::debug!(task = %task_name, key = %task_key, "Task removed");
                                }
                                Some(task_runtime::TaskLifecycleEvent::PausedAll { task_count }) => {
                                    tracing::debug!(task_count, "runtime task manager pause-all acknowledged");
                                }
                                Some(task_runtime::TaskLifecycleEvent::ResumedAll { task_count }) => {
                                    tracing::debug!(task_count, "runtime task manager resume-all acknowledged");
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
                                            tracing::debug!(task = %task.name, "TaskStart ignored for unsupported runtime task");
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
                                        let event_name = task.name.clone();
                                        let event_key = task_key.clone();
                                        task_handles.insert(task_key, (handle, token));
                                        let _ = task_lifecycle_tx
                                            .send(task_runtime::TaskLifecycleEvent::Added {
                                                task_name: event_name,
                                                task_key: event_key,
                                            })
                                            .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::StopTask(task) => {
                                        if !task_runtime::is_runtime_task_name_supported(&task.name) {
                                            tracing::debug!(task = %task.name, "TaskStop ignored for unsupported runtime task");
                                            continue;
                                        }

                                        let task_key = task_runtime::build_task_key(&task.name, &task.data);
                                        if let Some((handle, token)) = task_handles.remove(&task_key) {
                                            token.cancel();
                                            handle.abort();
                                            let _ = task_lifecycle_tx
                                                .send(task_runtime::TaskLifecycleEvent::Removed {
                                                    task_name: task.name.clone(),
                                                    task_key,
                                                })
                                                .await;
                                        } else {
                                            tracing::debug!(task = %task_key, "TaskStop requested for non-running task");
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
                                    crate::models::command_rpc::ClientCommand::PauseRuntimeTasks => {
                                        let paused = task_runtime::pause_runtime_tasks(&task_handles);
                                        let _ = task_lifecycle_tx
                                            .send(task_runtime::TaskLifecycleEvent::PausedAll {
                                                task_count: paused,
                                            })
                                            .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::ResumeRuntimeTasks => {
                                        let resumed = task_runtime::resume_runtime_tasks(&task_handles);
                                        let _ = task_lifecycle_tx
                                            .send(task_runtime::TaskLifecycleEvent::ResumedAll {
                                                task_count: resumed,
                                            })
                                            .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::StopRuntimeTasks => {
                                        for task_key in task_handles.keys().cloned().collect::<Vec<_>>() {
                                            let _ = task_lifecycle_tx
                                                .send(task_runtime::TaskLifecycleEvent::Removed {
                                                    task_name: task_key.clone(),
                                                    task_key,
                                                })
                                                .await;
                                        }
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
            drop(task_lifecycle_tx);
            let _ = task_lifecycle_handle.await;
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
                                if reply.count_stats {
                                    stats.on_verdict(reply.allow);
                                }
                                crate::ffi::nfqueue::submit_verdict(
                                    reply.request_id,
                                    reply.allow,
                                    reply.reject,
                                );
                                let decision = if reply.allow {
                                    "allow"
                                } else if reply.reject {
                                    "reject"
                                } else {
                                    "deny"
                                };
                                let source = match (reply.source, reply.rule_name.as_deref()) {
                                    (src, Some(rule_name)) if src.contains("rule") => {
                                        format!("rule:[{rule_name}]")
                                    }
                                    (src, Some(rule_name)) => format!("{src}:[{rule_name}]"),
                                    ("runtime-fast-allow", None) => "fast-allow".to_string(),
                                    ("runtime-fast-deny", None) => "fast-deny".to_string(),
                                    ("runtime-default", None) => "default".to_string(),
                                    (src, None) => src.to_string(),
                                };
                                tracing::info!(
                                    id = reply.request_id,
                                    decision,
                                    stats = reply.count_stats,
                                    source = %source,
                                    "verdict reply"
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
            let mut last_fast_allow = stats.fast_allow_count();
            let mut last_fast_deny = stats.fast_deny_count();
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

                            let fast_allow_total = stats.fast_allow_count();
                            let fast_allow_delta = fast_allow_total
                                .saturating_sub(last_fast_allow);
                            if fast_allow_delta > 0 {
                                debug!(
                                    delta = fast_allow_delta,
                                    total = fast_allow_total,
                                    "fast-allow attempts observed"
                                );
                            }

                            let fast_deny_total = stats.fast_deny_count();
                            let fast_deny_delta = fast_deny_total
                                .saturating_sub(last_fast_deny);
                            if fast_deny_delta > 0 {
                                debug!(
                                    delta = fast_deny_delta,
                                    total = fast_deny_total,
                                    "fast-deny attempts observed"
                                );
                            }

                            let snapshot = proc_workers.snapshot();
                            debug!(
                                worker = proc_workers.worker_name(),
                                state = snapshot.state.as_str(),
                                method = ?snapshot.method,
                                dns_monitor_state = crate::workers::dns_worker::dns_monitor_state_label(),
                                configured_handles = snapshot.configured_handles,
                                running_handles = snapshot.running_handles,
                                shutdown_requested = snapshot.shutdown_requested,
                                "worker state telemetry snapshot"
                            );

                            last_drop_snapshot = current;
                            last_fast_allow = fast_allow_total;
                            last_fast_deny = fast_deny_total;
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

                        let config_snapshot = config.snapshot().await;
                        let client_addr = config_snapshot.client_addr.clone();
                        let mut client = match Client::connect_with_config(&config_snapshot).await {
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
            Box::pin(async move { daemon.reconfigure_proc_workers(method).await })
        });

        WatchService::new(
            self.inner.shutdown.clone(),
            self.inner.config.clone(),
            self.inner.rules.clone(),
            self.inner.firewall.clone(),
            self.inner.stats.clone(),
            self.inner.process.clone(),
            self.inner.bus.task_reply_tx.clone(),
            self.inner.bus.alert_tx.clone(),
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
    use tracing::{info, warn};

    use super::{
        Daemon, DaemonInner, KERNEL_PIPELINE_SEND_BACKOFF, KernelPipeline, ProcWorkersRuntime,
        ProcessKernelEvent, dispatch_connect_attempt_to_worker, dispatch_kernel_pipeline_event,
        fanout_kernel_ingress_event, kernel_pipeline_drop_stats_snapshot,
    };
    use crate::{
        bus::{Bus, build_bus},
        config::Config,
        flows::verdict_flow::VerdictFlow,
        models::{
            command_rpc::{ClientCommand, TaskNotification},
            connection_state::{ConnectionAttempt, TransportProtocol},
            firewall_state::{FirewallBackend, FirewallState},
            kernel_event::{KernelEvent, ProcEventKind},
        },
        services::{
            config_service::ConfigService, connection_service::ConnectionService,
            dns_service::DnsService, firewall_service::FirewallService,
            process_service::ProcessService, rule_service::RuleService,
            stats_service::StatsService, ui_session_service::UiSessionService,
        },
        tunables::RuntimeTunables,
    };

    fn build_test_daemon_with_tunables(bus: Bus, tunables: RuntimeTunables) -> Daemon {
        let config = Config::default();
        let firewall = FirewallService::new(&config).expect("firewall service");
        let process = ProcessService::default();
        let dns = DnsService::default();
        let ui_session = UiSessionService::default();
        let connections = ConnectionService::new(process.clone(), dns.clone());

        Daemon {
            inner: Arc::new(DaemonInner {
                config: ConfigService::new(config.clone()),
                ui_session,
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
                connections,
                process,
                dns,
                stats: StatsService::default(),
                firewall,
                tunables,
                shutdown: CancellationToken::new(),
            }),
        }
    }

    fn build_test_daemon(bus: Bus) -> Daemon {
        build_test_daemon_with_tunables(bus, RuntimeTunables::default())
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

    #[test]
    fn fanout_kernel_ingress_event_routes_dns_event() {
        let (dns_tx, mut dns_rx) = mpsc::unbounded_channel::<(String, String)>();
        let (process_tx, mut process_rx) = mpsc::unbounded_channel::<ProcessKernelEvent>();
        let (firewall_tx, mut firewall_rx) = mpsc::unbounded_channel::<FirewallState>();

        let routed = fanout_kernel_ingress_event(
            KernelEvent::DnsResolved {
                ip: "203.0.113.10".to_string(),
                host: "dns.example.test".to_string(),
            },
            &dns_tx,
            &process_tx,
            &firewall_tx,
        );

        assert!(routed);
        assert_eq!(
            dns_rx.try_recv().ok(),
            Some(("203.0.113.10".to_string(), "dns.example.test".to_string()))
        );
        assert!(process_rx.try_recv().is_err());
        assert!(firewall_rx.try_recv().is_err());
    }

    #[test]
    fn fanout_kernel_ingress_event_returns_false_when_target_receiver_is_closed() {
        let (dns_tx, dns_rx) = mpsc::unbounded_channel::<(String, String)>();
        let (process_tx, _process_rx) = mpsc::unbounded_channel::<ProcessKernelEvent>();
        let (firewall_tx, _firewall_rx) = mpsc::unbounded_channel::<FirewallState>();
        drop(dns_rx);

        let routed = fanout_kernel_ingress_event(
            KernelEvent::DnsResolved {
                ip: "198.51.100.20".to_string(),
                host: "closed.example.test".to_string(),
            },
            &dns_tx,
            &process_tx,
            &firewall_tx,
        );

        assert!(!routed);
    }

    fn build_connect_attempt(request_id: u64) -> ConnectionAttempt {
        ConnectionAttempt {
            request_id,
            protocol: TransportProtocol::Tcp,
            src_ip: "127.0.0.1".to_string(),
            src_port: 46000,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 50051,
            iface_in_idx: 0,
            iface_out_idx: 0,
            dns_query: None,
            pid: std::process::id(),
            uid: 1000,
        }
    }

    #[tokio::test]
    async fn dispatch_connect_attempt_reroutes_when_primary_worker_queue_is_full() {
        let (tx0, mut rx0) = mpsc::channel::<ConnectionAttempt>(1);
        let (tx1, mut rx1) = mpsc::channel::<ConnectionAttempt>(1);

        // Saturate worker 0 queue so dispatcher should probe and route to worker 1.
        tx0.send(build_connect_attempt(10))
            .await
            .expect("prime worker 0 queue");

        let shutdown = CancellationToken::new();
        let mut next_worker = 0usize;
        let routed = timeout(
            Duration::from_millis(200),
            dispatch_connect_attempt_to_worker(
                &[tx0.clone(), tx1.clone()],
                &mut next_worker,
                &shutdown,
                build_connect_attempt(11),
            ),
        )
        .await
        .expect("dispatch timeout");

        assert!(routed);
        assert_eq!(next_worker, 0);
        assert_eq!(rx1.recv().await.expect("worker 1 recv").request_id, 11);
        assert_eq!(rx0.recv().await.expect("worker 0 recv").request_id, 10);
    }

    #[tokio::test]
    async fn dispatch_connect_attempt_returns_false_when_all_workers_are_closed() {
        let (tx0, rx0) = mpsc::channel::<ConnectionAttempt>(1);
        let (tx1, rx1) = mpsc::channel::<ConnectionAttempt>(1);
        drop(rx0);
        drop(rx1);

        let shutdown = CancellationToken::new();
        let mut next_worker = 0usize;
        let routed = dispatch_connect_attempt_to_worker(
            &[tx0, tx1],
            &mut next_worker,
            &shutdown,
            build_connect_attempt(12),
        )
        .await;

        assert!(!routed);
    }

    #[tokio::test]
    async fn runtime_task_commands_ignore_unsupported_names_without_immediate_reply() {
        let (bus, rx) = build_bus(16);
        let daemon = build_test_daemon(bus.clone());

        let crate::bus::BusRx {
            connect_rx: _,
            kernel_rx: _,
            client_cmd_rx,
            verdict_rx: _,
            mut task_reply_rx,
            alert_rx: _,
        } = rx;

        let cmd_handle = daemon.spawn_client_command_task(client_cmd_rx);

        bus.client_cmd_tx
            .send(ClientCommand::StartTask(TaskNotification {
                notification_id: 1,
                name: "unknown-task".to_string(),
                data: serde_json::json!({}),
            }))
            .await
            .expect("send start task");

        assert!(
            timeout(Duration::from_millis(80), task_reply_rx.recv())
                .await
                .is_err(),
            "unsupported task start should not emit immediate reply"
        );

        bus.client_cmd_tx
            .send(ClientCommand::StopTask(TaskNotification {
                notification_id: 2,
                name: "unknown-task".to_string(),
                data: serde_json::json!({}),
            }))
            .await
            .expect("send stop task");

        assert!(
            timeout(Duration::from_millis(80), task_reply_rx.recv())
                .await
                .is_err(),
            "unsupported task stop should not emit immediate reply"
        );

        daemon.shutdown().await;
        let _ = timeout(Duration::from_secs(1), cmd_handle).await;
    }

    #[tokio::test]
    async fn runtime_task_start_duplicate_returns_error_without_initial_started_reply() {
        let (bus, rx) = build_bus(16);
        let daemon = build_test_daemon(bus.clone());

        let crate::bus::BusRx {
            connect_rx: _,
            kernel_rx: _,
            client_cmd_rx,
            verdict_rx: _,
            mut task_reply_rx,
            alert_rx: _,
        } = rx;

        let cmd_handle = daemon.spawn_client_command_task(client_cmd_rx);
        let pid = std::process::id().to_string();

        bus.client_cmd_tx
            .send(ClientCommand::StartTask(TaskNotification {
                notification_id: 7,
                name: "pid-monitor".to_string(),
                data: serde_json::json!({
                    "pid": pid,
                    "interval": "5s",
                }),
            }))
            .await
            .expect("send initial start task");

        assert!(
            timeout(Duration::from_millis(80), task_reply_rx.recv())
                .await
                .is_err(),
            "successful start should not emit immediate started reply"
        );

        bus.client_cmd_tx
            .send(ClientCommand::StartTask(TaskNotification {
                notification_id: 8,
                name: "pid-monitor".to_string(),
                data: serde_json::json!({
                    "pid": std::process::id().to_string(),
                    "interval": "5s",
                }),
            }))
            .await
            .expect("send duplicate start task");

        let duplicate_reply = timeout(Duration::from_secs(1), task_reply_rx.recv())
            .await
            .expect("duplicate start reply timeout")
            .expect("duplicate start reply missing");

        assert_eq!(duplicate_reply.id, 8);
        assert_eq!(
            duplicate_reply.code,
            opensnitch_proto::pb::NotificationReplyCode::Error as i32
        );
        assert!(duplicate_reply.data.contains("already exists"));

        bus.client_cmd_tx
            .send(ClientCommand::StopRuntimeTasks)
            .await
            .expect("send stop runtime tasks");

        daemon.shutdown().await;
        let _ = timeout(Duration::from_secs(1), cmd_handle).await;
    }

    #[tokio::test]
    async fn connect_attempt_progresses_under_mixed_non_connect_saturation() {
        let (bus, rx) = build_bus(64);
        let (tunables, _) = RuntimeTunables::load_effective();
        let daemon = build_test_daemon_with_tunables(bus.clone(), tunables);

        let verdict_flow = VerdictFlow::new(
            bus.clone(),
            daemon.inner.config.clone(),
            daemon.inner.ui_session.clone(),
            daemon.inner.rules.clone(),
            daemon.inner.connections.clone(),
            daemon.inner.stats.clone(),
        );

        let crate::bus::BusRx {
            connect_rx,
            kernel_rx,
            client_cmd_rx: _,
            mut verdict_rx,
            task_reply_rx: _,
            alert_rx: _,
        } = rx;

        let connect_handle =
            daemon.spawn_connect_attempt_task(verdict_flow, daemon.inner.stats.clone(), connect_rx);

        // Mirror Go runtimeprofile harness shape: lightweight per-pipeline workers and
        // bounded dispatch retries, instead of full daemon service handlers.
        let (dns_tx, mut dns_rx) = tokio::sync::mpsc::channel::<()>(32);
        let (process_tx, mut process_rx) = tokio::sync::mpsc::channel::<()>(32);
        let (firewall_tx, mut firewall_rx) = tokio::sync::mpsc::channel::<()>(32);
        let kernel_shutdown = daemon.inner.shutdown.clone();

        let dns_shutdown = kernel_shutdown.clone();
        let dns_worker = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = dns_shutdown.cancelled() => break,
                    msg = dns_rx.recv() => {
                        match msg {
                            Some(()) => tokio::time::sleep(Duration::from_millis(2)).await,
                            None => break,
                        }
                    }
                }
            }
        });

        let process_shutdown = kernel_shutdown.clone();
        let process_worker = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = process_shutdown.cancelled() => break,
                    msg = process_rx.recv() => {
                        match msg {
                            Some(()) => tokio::time::sleep(Duration::from_millis(2)).await,
                            None => break,
                        }
                    }
                }
            }
        });

        let firewall_shutdown = kernel_shutdown.clone();
        let firewall_worker = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = firewall_shutdown.cancelled() => break,
                    msg = firewall_rx.recv() => {
                        match msg {
                            Some(()) => tokio::time::sleep(Duration::from_millis(2)).await,
                            None => break,
                        }
                    }
                }
            }
        });

        let router_shutdown = kernel_shutdown.clone();
        let kernel_handle = tokio::spawn(async move {
            let mut kernel_rx = kernel_rx;

            loop {
                tokio::select! {
                    _ = router_shutdown.cancelled() => break,
                    msg = kernel_rx.recv() => {
                        match msg {
                            Some(KernelEvent::DnsResolved { .. }) => {
                                if !dispatch_kernel_pipeline_event(
                                    &dns_tx,
                                    (),
                                    &router_shutdown,
                                    KernelPipeline::Dns,
                                )
                                .await
                                {
                                    break;
                                }
                            }
                            Some(KernelEvent::ProcStateChanged { .. } | KernelEvent::EbpfProcessMapHit { .. }) => {
                                if !dispatch_kernel_pipeline_event(
                                    &process_tx,
                                    (),
                                    &router_shutdown,
                                    KernelPipeline::Process,
                                )
                                .await
                                {
                                    break;
                                }
                            }
                            Some(KernelEvent::FirewallState(_)) => {
                                if !dispatch_kernel_pipeline_event(
                                    &firewall_tx,
                                    (),
                                    &router_shutdown,
                                    KernelPipeline::Firewall,
                                )
                                .await
                                {
                                    break;
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

            let _ = tokio::join!(dns_worker, process_worker, firewall_worker);
        });

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
                iface_in_idx: 0,
                iface_out_idx: 0,
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

    fn enforce_low_noise_harness_log_level(harness_name: &str) {
        crate::utils::test_support::init_test_logging();

        let raw = std::env::var("RUST_LOG").unwrap_or_default();
        let normalized = raw.to_ascii_lowercase();
        let has_warn_or_error = normalized.contains("warn") || normalized.contains("error");
        let has_debug_or_trace = normalized.contains("debug") || normalized.contains("trace");

        let allow_verbose = std::env::var("OPENSNITCH_VERBOSE")
            .ok()
            .map(|value| {
                let value = value.trim().to_ascii_lowercase();
                value == "1" || value == "true" || value == "yes" || value == "on"
            })
            .unwrap_or(false);

        if allow_verbose {
            info!(
                harness = harness_name,
                rust_log = %raw,
                "running with verbose logging for debug (OPENSNITCH_VERBOSE=1)"
            );
            return;
        }

        if !(has_warn_or_error && !has_debug_or_trace) {
            warn!(
                harness = harness_name,
                previous_rust_log = %raw,
                "requires low-noise logging; overriding RUST_LOG to 'error' for this test"
            );
            // SAFETY: Harness tests may run in dedicated test processes and need a predictable
            // log level to avoid noisy output and parser breakage.
            unsafe {
                std::env::set_var("RUST_LOG", "error");
            }
        }
    }

    fn enforce_kernel_stress_log_level() {
        enforce_low_noise_harness_log_level("kernel stress harness tests")
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
        rounds: usize,
        p95: Duration,
        p99: Duration,
        max: Duration,
        drop_total: u64,
    ) {
        crate::utils::test_support::init_test_logging();

        if std::env::var("OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK").as_deref() == Ok("1") {
            return;
        }

        if cfg!(debug_assertions) {
            warn!(
                "skipping stress regression guard in non-release profile (rerun with cargo test --release to enforce baselines)"
            );
            return;
        }

        let min_rounds = std::env::var("OPENSNITCH_STRESS_REGRESSION_MIN_ROUNDS")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(1000);
        if rounds < min_rounds {
            warn!(
                rounds,
                min_rounds,
                "skipping stress regression guard due to low sample count (set OPENSNITCH_STRESS_REGRESSION_MIN_ROUNDS to override)"
            );
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

    #[derive(Debug, Clone, Copy)]
    struct KernelPressureMetrics {
        duration_secs: u64,
        flood_tasks: usize,
        enqueue_timeout_us: u64,
        attempted_total: u64,
        enqueued_total: u64,
        enqueue_timeouts_total: u64,
        enqueue_closed_total: u64,
        forced_kernel_abort: bool,
        attempted_pps: f64,
        enqueued_pps: f64,
        enqueue_drop_ratio: f64,
        drop_delta: crate::daemon::KernelPipelineDropStats,
    }

    async fn run_kernel_pressure_profile(
        duration_secs: u64,
        flood_tasks: usize,
        enqueue_mode: &str,
        enqueue_timeout_us: u64,
    ) -> KernelPressureMetrics {
        let duration_secs = duration_secs.clamp(1, 30);
        let flood_tasks = flood_tasks.clamp(1, 32);
        let enqueue_timeout_us = enqueue_timeout_us.clamp(10, 20_000);

        let (bus, rx) = build_bus(8192);
        let daemon = build_test_daemon(bus.clone());

        let crate::bus::BusRx {
            connect_rx: _,
            kernel_rx,
            client_cmd_rx: _,
            verdict_rx: _,
            task_reply_rx: _,
            alert_rx: _,
        } = rx;

        let kernel_handle = daemon.spawn_kernel_task(
            daemon.inner.process.clone(),
            daemon.inner.dns.clone(),
            daemon.inner.stats.clone(),
            kernel_rx,
        );

        let attempted = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let enqueued = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let enqueue_timeouts = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let enqueue_closed = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let drop_before = kernel_pipeline_drop_stats_snapshot();
        let flood_shutdown = CancellationToken::new();
        let started = Instant::now();

        let mut flood_handles = Vec::with_capacity(flood_tasks);
        for worker_id in 0..flood_tasks {
            let flood_token = flood_shutdown.clone();
            let flood_bus = bus.clone();
            let attempted_ctr = attempted.clone();
            let enqueued_ctr = enqueued.clone();
            let enqueue_timeouts_ctr = enqueue_timeouts.clone();
            let enqueue_closed_ctr = enqueue_closed.clone();
            let enqueue_mode = enqueue_mode.to_string();

            flood_handles.push(tokio::spawn(async move {
                let dns_ips = (0_u16..256)
                    .map(|idx| format!("198.18.{}.{}", idx / 16, idx % 16))
                    .collect::<Vec<_>>();
                let dns_hosts = (0_u16..256)
                    .map(|idx| format!("pressure-{}.example.test", idx))
                    .collect::<Vec<_>>();
                let mut i = worker_id as u64;
                let mut burst_size = 32usize;
                let mut consecutive_saturation = 0usize;
                while !flood_token.is_cancelled() {
                    let mut batch_saturation = 0usize;
                    let mut saturation_dns_or_proc = 0usize;

                    for _ in 0..burst_size {
                        if flood_token.is_cancelled() {
                            break;
                        }

                        let lane = i % 3;
                        let event = match lane {
                            0 => {
                                let idx = (i as usize) & 0xFF;
                                KernelEvent::DnsResolved {
                                    ip: dns_ips[idx].clone(),
                                    host: dns_hosts[idx].clone(),
                                }
                            }
                            1 => KernelEvent::ProcStateChanged {
                                pid: 50_000 + ((i as u32) % 8192),
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

                        attempted_ctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let mut saturated = false;

                        if enqueue_mode == "timeout" {
                            match tokio::time::timeout(
                                Duration::from_micros(enqueue_timeout_us),
                                flood_bus.kernel_tx.send(event),
                            )
                            .await
                            {
                                Ok(Ok(())) => {
                                    enqueued_ctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                Ok(Err(_)) => {
                                    enqueue_closed_ctr
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    saturated = true;
                                }
                                Err(_) => {
                                    enqueue_timeouts_ctr
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    saturated = true;
                                }
                            }
                        } else if flood_bus.kernel_tx.try_send(event).is_ok() {
                            enqueued_ctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            saturated = true;
                        }

                        if saturated {
                            batch_saturation = batch_saturation.saturating_add(1);
                            if lane != 2 {
                                saturation_dns_or_proc = saturation_dns_or_proc.saturating_add(1);
                            }
                        }

                        i = i.wrapping_add(1);
                    }

                    if batch_saturation > 0 {
                        consecutive_saturation = consecutive_saturation.saturating_add(1);
                        burst_size = (burst_size / 2).max(4);

                        // Under DNS/process lane saturation, add a short adaptive backoff so
                        // producers do not keep overwhelming kernel pipeline queues.
                        if consecutive_saturation >= 2 {
                            let backoff_us = if saturation_dns_or_proc > (batch_saturation / 2) {
                                250
                            } else {
                                100
                            };
                            tokio::time::sleep(Duration::from_micros(backoff_us)).await;
                        }
                    } else {
                        consecutive_saturation = 0;
                        burst_size = (burst_size + 4).min(128);
                    }

                    if (i & 0x3FF) == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            }));
        }

        tokio::time::sleep(Duration::from_secs(duration_secs)).await;
        flood_shutdown.cancel();
        for mut handle in flood_handles {
            if timeout(Duration::from_secs(3), &mut handle).await.is_err() {
                handle.abort();
            }
        }

        tokio::time::sleep(Duration::from_millis(250)).await;

        let elapsed = started.elapsed();
        let attempted_total = attempted.load(std::sync::atomic::Ordering::Relaxed);
        let enqueued_total = enqueued.load(std::sync::atomic::Ordering::Relaxed);
        let enqueue_timeouts_total = enqueue_timeouts.load(std::sync::atomic::Ordering::Relaxed);
        let enqueue_closed_total = enqueue_closed.load(std::sync::atomic::Ordering::Relaxed);

        let drop_after = kernel_pipeline_drop_stats_snapshot();
        let drop_delta = drop_after.saturating_delta(drop_before);

        daemon.shutdown().await;
        let mut kernel_handle = kernel_handle;
        let forced_kernel_abort = if timeout(Duration::from_secs(10), &mut kernel_handle)
            .await
            .is_err()
        {
            kernel_handle.abort();
            true
        } else {
            false
        };

        let attempted_pps = if elapsed.as_secs_f64() > 0.0 {
            attempted_total as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let enqueued_pps = if elapsed.as_secs_f64() > 0.0 {
            enqueued_total as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let enqueue_drop_ratio = if attempted_total > 0 {
            (attempted_total.saturating_sub(enqueued_total)) as f64 / attempted_total as f64
        } else {
            0.0
        };

        KernelPressureMetrics {
            duration_secs,
            flood_tasks,
            enqueue_timeout_us,
            attempted_total,
            enqueued_total,
            enqueue_timeouts_total,
            enqueue_closed_total,
            forced_kernel_abort,
            attempted_pps,
            enqueued_pps,
            enqueue_drop_ratio,
            drop_delta,
        }
    }

    #[tokio::test]
    #[ignore = "profiling harness; run with --ignored --nocapture"]
    async fn stress_profile_reports_connect_latency_and_pipeline_drops() {
        enforce_low_noise_harness_log_level(
            "stress_profile_reports_connect_latency_and_pipeline_drops",
        );

        // Default to enabled for harnesses when env is missing; allow explicit opt-out.
        let stress_profile_enabled = std::env::var("OPENSNITCH_STRESS_PROFILE")
            .ok()
            .map(|value| {
                let value = value.trim().to_ascii_lowercase();
                !(value.is_empty() || value == "0" || value == "false")
            })
            .unwrap_or(true);

        if !stress_profile_enabled {
            info!(
                stress_profile = %std::env::var("OPENSNITCH_STRESS_PROFILE").unwrap_or_default(),
                "profiling harness disabled via OPENSNITCH_STRESS_PROFILE"
            );
            return;
        }

        let mut rounds = 2_000_usize;
        if let Ok(raw) = std::env::var("OPENSNITCH_STRESS_ROUNDS") {
            rounds = raw
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("invalid OPENSNITCH_STRESS_ROUNDS value '{}'", raw));
            assert!(
                rounds > 0,
                "invalid OPENSNITCH_STRESS_ROUNDS value '{}'",
                raw
            );
        }

        let (bus, rx) = build_bus(256);
        let daemon = build_test_daemon(bus.clone());

        let verdict_flow = VerdictFlow::new(
            bus.clone(),
            daemon.inner.config.clone(),
            daemon.inner.ui_session.clone(),
            daemon.inner.rules.clone(),
            daemon.inner.connections.clone(),
            daemon.inner.stats.clone(),
        );

        let crate::bus::BusRx {
            connect_rx,
            kernel_rx,
            client_cmd_rx: _,
            mut verdict_rx,
            task_reply_rx: _,
            alert_rx: _,
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
            let attempt = ConnectionAttempt {
                request_id,
                protocol: TransportProtocol::Tcp,
                src_ip: "127.0.0.1".to_string(),
                src_port: 46000,
                dst_ip: "127.0.0.1".to_string(),
                dst_port: 50051,
                iface_in_idx: 0,
                iface_out_idx: 0,
                dns_query: None,
                pid: std::process::id(),
                uid: 1000,
            };
            let started = Instant::now();

            bus.connect_tx
                .send(attempt)
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

        enforce_stress_regression_guard(rounds, p95, p99, max, drop_delta.total());

        info!(
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

    #[tokio::test]
    #[ignore = "profiling harness; run with --ignored --nocapture"]
    async fn stress_profile_reports_kernel_pipeline_pressure() {
        enforce_kernel_stress_log_level();

        let duration_secs = std::env::var("OPENSNITCH_KERNEL_PRESSURE_SECS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(3);
        let flood_tasks = std::env::var("OPENSNITCH_KERNEL_PRESSURE_TASKS")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(4);
        let enqueue_mode = std::env::var("OPENSNITCH_KERNEL_PRESSURE_ENQUEUE_MODE")
            .unwrap_or_else(|_| "try".to_string());
        let enqueue_timeout_us = std::env::var("OPENSNITCH_KERNEL_PRESSURE_ENQUEUE_TIMEOUT_US")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(200);

        let metrics = run_kernel_pressure_profile(
            duration_secs,
            flood_tasks,
            &enqueue_mode,
            enqueue_timeout_us,
        )
        .await;

        info!(
            "kernel-pressure mode={} enqueue_timeout_us={} secs={} flood_tasks={} attempted={} enqueued={} enqueue_timeouts={} enqueue_closed={} forced_kernel_abort={} attempted_pps={:.0} enqueued_pps={:.0} enqueue_drop_ratio={:.4} pipeline_drop_dns={} pipeline_drop_process={} pipeline_drop_firewall={} pipeline_drop_total={}",
            enqueue_mode,
            metrics.enqueue_timeout_us,
            metrics.duration_secs,
            metrics.flood_tasks,
            metrics.attempted_total,
            metrics.enqueued_total,
            metrics.enqueue_timeouts_total,
            metrics.enqueue_closed_total,
            metrics.forced_kernel_abort,
            metrics.attempted_pps,
            metrics.enqueued_pps,
            metrics.enqueue_drop_ratio,
            metrics.drop_delta.dns,
            metrics.drop_delta.process,
            metrics.drop_delta.firewall,
            metrics.drop_delta.total(),
        );

        assert!(
            metrics.enqueued_total > 0,
            "kernel pressure run did not enqueue events"
        );
    }

    #[tokio::test]
    #[ignore = "profiling harness; run with --ignored --nocapture"]
    async fn stress_profile_reports_kernel_pipeline_timeout_sweep() {
        enforce_kernel_stress_log_level();

        let duration_secs = std::env::var("OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(2);
        let flood_tasks = std::env::var("OPENSNITCH_KERNEL_PRESSURE_SWEEP_TASKS")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(4);
        let sweep_raw = std::env::var("OPENSNITCH_KERNEL_PRESSURE_SWEEP_US")
            .unwrap_or_else(|_| "50,100,200,500,1000".to_string());

        let mut timeouts = Vec::new();
        for token in sweep_raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Ok(value) = token.parse::<u64>() {
                timeouts.push(value);
            }
        }
        if timeouts.is_empty() {
            timeouts.extend([50_u64, 100, 200, 500, 1000]);
        }

        info!(
            "kernel-pressure-sweep-csv-header,timeout_us,secs,flood_tasks,attempted,enqueued,enqueue_timeouts,enqueue_closed,forced_kernel_abort,attempted_pps,enqueued_pps,enqueue_drop_ratio,pipeline_drop_dns,pipeline_drop_process,pipeline_drop_firewall,pipeline_drop_total"
        );

        let mut results = Vec::new();

        for timeout_us in timeouts {
            let metrics =
                run_kernel_pressure_profile(duration_secs, flood_tasks, "timeout", timeout_us)
                    .await;
            info!(
                "kernel-pressure-sweep timeout_us={} secs={} flood_tasks={} attempted={} enqueued={} enqueue_timeouts={} enqueue_closed={} forced_kernel_abort={} attempted_pps={:.0} enqueued_pps={:.0} enqueue_drop_ratio={:.4} pipeline_drop_total={}",
                metrics.enqueue_timeout_us,
                metrics.duration_secs,
                metrics.flood_tasks,
                metrics.attempted_total,
                metrics.enqueued_total,
                metrics.enqueue_timeouts_total,
                metrics.enqueue_closed_total,
                metrics.forced_kernel_abort,
                metrics.attempted_pps,
                metrics.enqueued_pps,
                metrics.enqueue_drop_ratio,
                metrics.drop_delta.total(),
            );

            info!(
                "kernel-pressure-sweep-csv,{},{},{},{},{},{},{},{},{:.0},{:.0},{:.4},{},{},{},{}",
                metrics.enqueue_timeout_us,
                metrics.duration_secs,
                metrics.flood_tasks,
                metrics.attempted_total,
                metrics.enqueued_total,
                metrics.enqueue_timeouts_total,
                metrics.enqueue_closed_total,
                metrics.forced_kernel_abort,
                metrics.attempted_pps,
                metrics.enqueued_pps,
                metrics.enqueue_drop_ratio,
                metrics.drop_delta.dns,
                metrics.drop_delta.process,
                metrics.drop_delta.firewall,
                metrics.drop_delta.total(),
            );

            assert!(
                metrics.enqueued_total > 0,
                "timeout_us={} did not enqueue events",
                metrics.enqueue_timeout_us
            );
            results.push(metrics);
        }

        let mut best: Option<KernelPressureMetrics> = None;
        let mut best_score = f64::NEG_INFINITY;
        let has_non_abort = results.iter().any(|m| !m.forced_kernel_abort);
        for metrics in results.iter().filter(|m| {
            if has_non_abort {
                !m.forced_kernel_abort
            } else {
                true
            }
        }) {
            let score = metrics.enqueued_pps * (1.0 - metrics.enqueue_drop_ratio);
            let replace = if score > best_score {
                true
            } else if (score - best_score).abs() < f64::EPSILON {
                if let Some(current) = best {
                    if metrics.enqueue_drop_ratio < current.enqueue_drop_ratio {
                        true
                    } else if (metrics.enqueue_drop_ratio - current.enqueue_drop_ratio).abs()
                        < f64::EPSILON
                    {
                        metrics.enqueue_timeout_us < current.enqueue_timeout_us
                    } else {
                        false
                    }
                } else {
                    true
                }
            } else {
                false
            };

            if replace {
                best_score = score;
                best = Some(*metrics);
            }
        }

        if let Some(best) = best {
            info!(
                "kernel-pressure-sweep-recommend timeout_us={} score={:.0} enqueued_pps={:.0} enqueue_drop_ratio={:.4} pipeline_drop_total={} forced_kernel_abort={}",
                best.enqueue_timeout_us,
                best_score,
                best.enqueued_pps,
                best.enqueue_drop_ratio,
                best.drop_delta.total(),
                best.forced_kernel_abort,
            );
        }
    }
}
