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
    bus::{Bus, BusCaps, BusRx, BusState},
    client::client::Client,
    commands::{command_control, rule_command, task_runtime},
    config::ProcMonitorMethod,
    flows::{notification_flow::NotificationFlow, verdict_flow::VerdictFlow},
    models::{
        connection_state::ConnectionAttempt,
        kernel_event::{KernelEvent, ProcEventKind},
        verdict_rpc::VerdictReply,
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
        watch_service::{ProcWorkerReconfigure, WatchService},
    },
    tunables::RuntimeTunables,
    utils::pid_resolver::PidResolverState,
    workers::{
        self,
        control::{
            OneShotWorker, RuntimeHandles, WorkerCommand, WorkerCommandResult, WorkerControl,
            WorkerJoinStatus, WorkerState,
        },
    },
};

const KERNEL_PIPELINE_SEND_RETRIES: usize = 8;
pub(crate) const KERNEL_PIPELINE_SEND_BACKOFF: Duration = Duration::from_millis(10);
const KERNEL_INGRESS_DISPATCH_BATCH: usize = 32;

#[repr(align(64))]
struct CacheAlignedAtomicU64(AtomicU64);

impl Default for CacheAlignedAtomicU64 {
    fn default() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl CacheAlignedAtomicU64 {
    fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    fn fetch_add(&self, value: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(value, ordering)
    }
}

#[derive(Debug)]
pub(crate) enum ProcessKernelEvent {
    ProcStateChanged { pid: u32, kind: ProcEventKind },
    EbpfProcessMapHit { pid: u32, uid: u32, note: String },
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum KernelPipeline {
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
    pub(crate) fn saturating_delta(self, previous: Self) -> Self {
        Self {
            dns: self.dns.saturating_sub(previous.dns),
            process: self.process.saturating_sub(previous.process),
            firewall: self.firewall.saturating_sub(previous.firewall),
        }
    }

    pub(crate) fn total(self) -> u64 {
        self.dns
            .saturating_add(self.process)
            .saturating_add(self.firewall)
    }
}

#[derive(Default)]
struct KernelPipelineDropCounters {
    dns: CacheAlignedAtomicU64,
    process: CacheAlignedAtomicU64,
    firewall: CacheAlignedAtomicU64,
}

static KERNEL_PIPELINE_DROP_COUNTERS: OnceLock<KernelPipelineDropCounters> = OnceLock::new();

#[derive(Clone)]
pub struct Daemon {
    pub(crate) inner: Arc<DaemonInner>,
}

pub(crate) struct DaemonInner {
    pub(crate) config: ConfigService,
    pub(crate) ui_session: UiSessionService,
    pub(crate) nfqueue_num: u16,
    pub(crate) default_action: crate::config::DefaultAction,
    pub(crate) audit_socket_path: std::path::PathBuf,
    pub(crate) proc_workers: Arc<std::sync::Mutex<ProcWorkersRuntime>>,
    pub(crate) bus: Bus,
    pub(crate) rules: RuleService,
    pub(crate) connections: ConnectionService,
    pub(crate) process: ProcessService,
    pub(crate) dns: DnsService,
    pub(crate) stats: StatsService,
    pub(crate) firewall: FirewallService,
    pub(crate) task_runtime: task_runtime::TaskRuntimeService,
    pub(crate) tunables: RuntimeTunables,
    pub(crate) shutdown: CancellationToken,
}

pub(crate) struct ProcWorkersRuntime {
    pub(crate) current_method: ProcMonitorMethod,
    pub(crate) shutdown: CancellationToken,
    pub(crate) handles: Vec<Box<dyn WorkerControl>>,
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

    fn inspect_workers(&self) -> WorkerCommandResult {
        self.daemon.control_proc_workers_sync(WorkerCommand::Probe)
    }
}

impl WorkerControl for ProcWorkersControl {
    fn worker_name(&self) -> &'static str {
        "proc-workers"
    }

    fn control(&self, command: WorkerCommand) -> WorkerCommandResult {
        match command {
            WorkerCommand::Start => self.start_workers(),
            WorkerCommand::Stop => self.stop_workers(),
            WorkerCommand::Probe => self.inspect_workers(),
        }
    }

    fn state(&self) -> WorkerState {
        self.snapshot().state
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus {
        self.stop();
        WorkerJoinStatus::Stopped
    }
}

impl OneShotWorker for ProcWorkersControl {}

impl Daemon {
    fn boxed_one_shot_worker<T>(worker: T) -> Box<dyn WorkerControl>
    where
        T: WorkerControl + OneShotWorker + 'static,
    {
        Box::new(worker)
    }

    fn kernel_pipeline_drop_counters() -> &'static KernelPipelineDropCounters {
        KERNEL_PIPELINE_DROP_COUNTERS.get_or_init(KernelPipelineDropCounters::default)
    }

    fn kernel_pipeline_drop_stats_snapshot() -> KernelPipelineDropStats {
        let counters = Self::kernel_pipeline_drop_counters();
        KernelPipelineDropStats {
            dns: counters.dns.load(Ordering::Relaxed),
            process: counters.process.load(Ordering::Relaxed),
            firewall: counters.firewall.load(Ordering::Relaxed),
        }
    }

    fn increment_kernel_pipeline_drop(pipeline: KernelPipeline) -> u64 {
        let counters = Self::kernel_pipeline_drop_counters();
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

        let start_idx = if *next_worker < worker_count {
            *next_worker
        } else {
            *next_worker % worker_count
        };
        let mut pending = attempt;
        let mut fallback_idx = None;
        let mut idx = start_idx;

        // Fast path: probe all workers with try_send first to avoid waiting on one full lane.
        for _ in 0..worker_count {
            let tx = &worker_txs[idx];
            match tx.try_send(pending) {
                Ok(()) => {
                    *next_worker = if idx + 1 == worker_count { 0 } else { idx + 1 };
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
                    *next_worker = if blocking_idx + 1 == worker_count {
                        0
                    } else {
                        blocking_idx + 1
                    };
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

        let dropped = Self::increment_kernel_pipeline_drop(pipeline);
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

    #[cfg(test)]
    pub(crate) fn probe_kernel_pipeline_drop_stats_snapshot() -> KernelPipelineDropStats {
        Self::kernel_pipeline_drop_stats_snapshot()
    }

    #[cfg(test)]
    pub(crate) async fn probe_dispatch_connect_attempt_to_worker(
        worker_txs: &[tokio::sync::mpsc::Sender<ConnectionAttempt>],
        next_worker: &mut usize,
        shutdown: &CancellationToken,
        attempt: ConnectionAttempt,
    ) -> bool {
        Self::dispatch_connect_attempt_to_worker(worker_txs, next_worker, shutdown, attempt).await
    }

    #[cfg(test)]
    pub(crate) async fn probe_dispatch_kernel_pipeline_event<T>(
        tx: &tokio::sync::mpsc::Sender<T>,
        event: T,
        shutdown: &CancellationToken,
        pipeline: KernelPipeline,
    ) -> bool {
        Self::dispatch_kernel_pipeline_event(tx, event, shutdown, pipeline).await
    }

    #[cfg(test)]
    pub(crate) fn probe_fanout_kernel_ingress_event(
        event: KernelEvent,
        dns_ingress_tx: &tokio::sync::mpsc::UnboundedSender<(String, String)>,
        process_ingress_tx: &tokio::sync::mpsc::UnboundedSender<ProcessKernelEvent>,
        firewall_ingress_tx: &tokio::sync::mpsc::UnboundedSender<
            crate::models::firewall_state::FirewallState,
        >,
    ) -> bool {
        Self::fanout_kernel_ingress_event(
            event,
            dns_ingress_tx,
            process_ingress_tx,
            firewall_ingress_tx,
        )
    }

    pub async fn run(client_addr: Option<&str>) -> Result<()> {
        let (daemon, rx) = Self::bootstrap(client_addr).await?;
        daemon.serve(rx).await
    }

    pub async fn bootstrap(client_addr: Option<&str>) -> Result<(Self, BusRx)> {
        let (bus, rx) = BusState::build_with_caps(BusCaps {
            connect: 1024,
            kernel: 512,
            client_cmd: 256,
            verdict: 1024,
            task_reply: 256,
            alert: 1024,
        });
        let config = crate::config::Config::load_from_default_locations()?
            .with_client_addr_override(client_addr);
        if let Some(status) = crate::tunables::RuntimeTunables::maybe_autotune_on_startup() {
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
            dns_lru_cache_capacity = tunables.dns_lru_cache_capacity,
            process_info_cache_capacity = tunables.process_info_cache_capacity,
            pid_inode_cache_capacity = tunables.pid_inode_cache_capacity,
            pid_inode_key_cache_capacity = tunables.pid_inode_key_cache_capacity,
            "daemon bootstrap: effective runtime tunables"
        );
        DnsService::configure_cache_capacity(tunables.dns_lru_cache_capacity);
        ProcessService::configure_cache_capacity(tunables.process_info_cache_capacity);
        PidResolverState::configure_cache_capacities(
            tunables.pid_inode_cache_capacity,
            tunables.pid_inode_key_cache_capacity,
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
                task_runtime: task_runtime::TaskRuntimeService,
                tunables,
                shutdown: CancellationToken::new(),
            }),
        };

        daemon.inner.stats.apply_config(config.stats);

        Ok((daemon, rx))
    }

    pub async fn serve(&self, rx: BusRx) -> Result<()> {
        let config = self.inner.config.snapshot_arc();
        crate::utils::systemd_notify::status("Starting daemon runtime bootstrap...");
        info!(addr = %config.client_addr, "daemon runtime: starting serve loop");
        info!(queue = self.inner.nfqueue_num, "running on netfilter queue");
        if let Err(err) = crate::logging::LoggingState::apply_config(&config) {
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
        let config = self.inner.config.snapshot_arc();
        let rules = self.inner.rules.list_proto_arc().await;
        let rules_count = rules.len() as u64;
        let firewall = self.inner.firewall.snapshot_arc();
        let subscribe_cfg = Client::build_subscribe_config_from_snapshots(
            &config,
            &rules,
            firewall.state.enabled,
            &firewall.system_firewall,
        );
        let subscribe_reply = client.subscribe(subscribe_cfg).await?;

        if let Some(connected_default_action) =
            Self::parse_default_action_from_client_config(&subscribe_reply.config)
        {
            self.inner
                .ui_session
                .set_connected_default_action(connected_default_action);
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
                stats: Some(self.inner.stats.snapshot(rules_count)),
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

        crate::ffi::nfqueue::NfqueueRuntimeState::set_default_action(updated.default_action);
        self.inner.stats.apply_config(updated.stats);

        if let Err(err) = crate::logging::LoggingState::apply_config(&updated) {
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
            workers::nfqueue_worker::NfqueueWorkerControl::spawn(
                self.inner.bus.clone(),
                self.inner.nfqueue_num,
                self.inner.default_action,
                self.inner.shutdown.clone(),
            ),
        );
        debug!(queue = self.inner.nfqueue_num, "nfqueue worker started");

        let initial_method = self.inner.config.snapshot_arc().proc_monitor_method;
        if let Err(err) = self.reconfigure_proc_workers(Some(initial_method)).await {
            warn!(method = ?initial_method, "failed to start requested process monitor method: {err}");
            let _ = self
                .reconfigure_proc_workers(Some(ProcMonitorMethod::Proc))
                .await;
        }

        handles.push_worker_control(Self::boxed_one_shot_worker(
            workers::dns_worker::DnsWorkerControl::new(
                self.inner.bus.clone(),
                self.inner.shutdown.clone(),
            ),
        ));
        debug!("dns worker started");

        handles.push_worker(
            "firewall",
            workers::firewall_worker::FirewallWorkerControl::spawn(
                self.inner.bus.clone(),
                self.inner.firewall.clone(),
                self.inner.shutdown.clone(),
            ),
        );
        debug!("firewall worker started");

        handles.push_worker(
            "netlink-ifaces",
            workers::netlink_addr_worker::NetlinkAddrWorkerControl::spawn(
                self.inner.shutdown.clone(),
            ),
        );
        debug!("netlink local-address worker started");
    }

    fn spawn_proc_worker_handles(
        &self,
        method: ProcMonitorMethod,
        shutdown: CancellationToken,
    ) -> Vec<Box<dyn WorkerControl>> {
        match method {
            ProcMonitorMethod::Proc => vec![workers::control::ThreadWorkerControl::boxed(
                "proc-netlink",
                workers::netlink_proc_worker::NetlinkProcWorkerControl::spawn(
                    self.inner.bus.clone(),
                    shutdown,
                ),
            )],
            ProcMonitorMethod::Ebpf => {
                vec![Self::boxed_one_shot_worker(
                    workers::ebpf_worker::EbpfWorkerControl::new(
                        self.inner.bus.clone(),
                        shutdown,
                        self.inner.tunables,
                    ),
                )]
            }
            ProcMonitorMethod::Audit => vec![
                workers::control::ThreadWorkerControl::boxed(
                    "proc-audit",
                    workers::audit_worker::AuditWorkerControl::spawn(
                        self.inner.bus.clone(),
                        self.inner.audit_socket_path.clone(),
                        shutdown.clone(),
                    ),
                ),
                workers::control::ThreadWorkerControl::boxed(
                    "proc-netlink",
                    workers::netlink_proc_worker::NetlinkProcWorkerControl::spawn(
                        self.inner.bus.clone(),
                        shutdown,
                    ),
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
        self.inner
            .task_runtime
            .configure_alert_sender(self.inner.bus.alert_tx.clone());
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

    pub(crate) fn spawn_connect_attempt_task(
        &self,
        flow: VerdictFlow,
        stats: StatsService,
        mut connect_rx: tokio::sync::mpsc::Receiver<ConnectionAttempt>,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();
        let daemon_pid = std::process::id();
        let tunables = self.inner.tunables;
        let verdict_tx = self.inner.bus.verdict_tx.clone();

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
                                    let verdict = VerdictReply {
                                        request_id: attempt.request_id,
                                        allow: true,
                                        reject: false,
                                        count_stats: false,
                                        source: "daemon-self-dispatch",
                                        rule_name: None,
                                    };
                                    match verdict_tx.try_send(verdict) {
                                        Ok(()) => {}
                                        Err(tokio::sync::mpsc::error::TrySendError::Full(next)) => {
                                            let _ = verdict_tx.send(next).await;
                                        }
                                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
                                    }
                                } else {
                                    stats.on_connect_attempt(&attempt);
                                    if !Self::dispatch_connect_attempt_to_worker(
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
                                        let verdict = VerdictReply {
                                            request_id: next.request_id,
                                            allow: true,
                                            reject: false,
                                            count_stats: false,
                                            source: "daemon-self-dispatch",
                                            rule_name: None,
                                        };
                                        match verdict_tx.try_send(verdict) {
                                            Ok(()) => {}
                                            Err(tokio::sync::mpsc::error::TrySendError::Full(next)) => {
                                                let _ = verdict_tx.send(next).await;
                                            }
                                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
                                        }
                                    } else {
                                        stats.on_connect_attempt(&next);
                                        if !Self::dispatch_connect_attempt_to_worker(
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

    pub(crate) fn spawn_kernel_task(
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

                    if !Self::dispatch_kernel_pipeline_event(
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

                        if !Self::dispatch_kernel_pipeline_event(
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

                    if !Self::dispatch_kernel_pipeline_event(
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

                        if !Self::dispatch_kernel_pipeline_event(
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

                    if !Self::dispatch_kernel_pipeline_event(
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

                        if !Self::dispatch_kernel_pipeline_event(
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
                                if !Self::fanout_kernel_ingress_event(
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

                                    if !Self::fanout_kernel_ingress_event(
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

    pub(crate) fn spawn_client_command_task(
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
        let task_runtime_service = self.inner.task_runtime.clone();
        let command_control_service = command_control::CommandControlService::default();
        let rule_command_service = rule_command::RuleCommandService::default();
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
                                        command_control_service
                                            .set_interception(
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
                                        command_control_service
                                            .set_firewall(
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
                                        command_control_service
                                            .reload_firewall(
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
                                        command_control_service
                                            .apply_config(
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
                                        rule_command_service
                                            .enable_rules(
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
                                        rule_command_service
                                            .disable_rules(
                                            notification_id,
                                            updated_rules,
                                            &rules,
                                            &task_reply_tx,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::StartTask(task) => {
                                        if !task_runtime_service.is_runtime_task_name_supported(&task.name) {
                                            tracing::debug!(task = %task.name, "TaskStart ignored for unsupported runtime task");
                                            continue;
                                        }

                                        if let Err(message) = task_runtime_service.validate_task_start_input(&task.name, &task.data) {
                                            task_runtime_service
                                                .send_task_reply(
                                                &task_reply_tx,
                                                task.notification_id,
                                                opensnitch_proto::pb::NotificationReplyCode::Error,
                                                message,
                                            )
                                            .await;
                                            continue;
                                        }

                                        let task_key = task_runtime_service.build_task_key(&task.name, &task.data);
                                        if task_handles.contains_key(&task_key) {
                                            task_runtime_service
                                                .send_task_reply(
                                                &task_reply_tx,
                                                task.notification_id,
                                                opensnitch_proto::pb::NotificationReplyCode::Error,
                                                format!("task with name {} already exists", task_key),
                                            )
                                            .await;
                                            continue;
                                        }

                                        let token = CancellationToken::new();
                                        let task_data_snapshot = std::sync::Arc::new(task.data);
                                        let handle = task_runtime_service.spawn_task_monitor_snapshot(
                                            &task.name,
                                            task.notification_id,
                                            task_data_snapshot,
                                            token.clone(),
                                            process.clone(),
                                            task_reply_tx.clone(),
                                        );
                                        let event_name = task.name.clone();
                                        let event_key = task_key.clone();
                                        task_handles.insert(task_key, (handle, token));
                                        let event = task_runtime::TaskLifecycleEvent::Added {
                                                task_name: event_name,
                                                task_key: event_key,
                                            };
                                        match task_lifecycle_tx.try_send(event) {
                                            Ok(()) => {}
                                            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                                                let _ = task_lifecycle_tx.send(event).await;
                                            }
                                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
                                        }
                                    }
                                    crate::models::command_rpc::ClientCommand::StopTask(task) => {
                                        if !task_runtime_service.is_runtime_task_name_supported(&task.name) {
                                            tracing::debug!(task = %task.name, "TaskStop ignored for unsupported runtime task");
                                            continue;
                                        }

                                        let task_key = task_runtime_service.build_task_key(&task.name, &task.data);
                                        if let Some((handle, token)) = task_handles.remove(&task_key) {
                                            token.cancel();
                                            handle.abort();
                                            let event = task_runtime::TaskLifecycleEvent::Removed {
                                                    task_name: task.name.clone(),
                                                    task_key,
                                                };
                                            match task_lifecycle_tx.try_send(event) {
                                                Ok(()) => {}
                                                Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                                                    let _ = task_lifecycle_tx.send(event).await;
                                                }
                                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
                                            }
                                        } else {
                                            tracing::debug!(task = %task_key, "TaskStop requested for non-running task");
                                        }
                                    }
                                    crate::models::command_rpc::ClientCommand::UpsertRules {
                                        notification_id,
                                        rules: updated_rules,
                                    } => {
                                        rule_command_service
                                            .upsert_rules(
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
                                        rule_command_service
                                            .delete_rules(
                                            notification_id,
                                            rule_names,
                                            &rules,
                                            &task_reply_tx,
                                        )
                                        .await;
                                    }
                                    crate::models::command_rpc::ClientCommand::PauseRuntimeTasks => {
                                        let paused = task_runtime_service.pause_runtime_tasks(&task_handles);
                                        let event = task_runtime::TaskLifecycleEvent::PausedAll {
                                                task_count: paused,
                                            };
                                        match task_lifecycle_tx.try_send(event) {
                                            Ok(()) => {}
                                            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                                                let _ = task_lifecycle_tx.send(event).await;
                                            }
                                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
                                        }
                                    }
                                    crate::models::command_rpc::ClientCommand::ResumeRuntimeTasks => {
                                        let resumed = task_runtime_service.resume_runtime_tasks(&task_handles);
                                        let event = task_runtime::TaskLifecycleEvent::ResumedAll {
                                                task_count: resumed,
                                            };
                                        match task_lifecycle_tx.try_send(event) {
                                            Ok(()) => {}
                                            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                                                let _ = task_lifecycle_tx.send(event).await;
                                            }
                                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
                                        }
                                    }
                                    crate::models::command_rpc::ClientCommand::StopRuntimeTasks => {
                                        for task_key in task_handles.keys() {
                                            let event = task_runtime::TaskLifecycleEvent::Removed {
                                                    task_name: task_key.clone(),
                                                    task_key: task_key.clone(),
                                                };
                                            match task_lifecycle_tx.try_send(event) {
                                                Ok(()) => {}
                                                Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                                                    let _ = task_lifecycle_tx.send(event).await;
                                                }
                                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
                                            }
                                        }
                                        let stopped = task_runtime_service.stop_runtime_tasks(&mut task_handles);
                                        tracing::info!(stopped, "stopped temporary runtime tasks after notification disconnect");
                                    }
                                    crate::models::command_rpc::ClientCommand::SetLogLevel {
                                        notification_id,
                                        level,
                                    } => {
                                        command_control_service
                                            .set_log_level(
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
                                        command_control_service
                                            .shutdown(
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

            task_runtime_service.stop_runtime_tasks(&mut task_handles);
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
                                crate::ffi::nfqueue::NfqueueRuntimeState::submit_verdict(
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
            let mut last_drop_snapshot = Self::kernel_pipeline_drop_stats_snapshot();
            let mut last_fast_allow = stats.fast_allow_count();
            let mut last_fast_deny = stats.fast_deny_count();
            let mut last_drop_log_at = tokio::time::Instant::now();

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                        if last_drop_log_at.elapsed() >= std::time::Duration::from_secs(30) {
                            let current = Self::kernel_pipeline_drop_stats_snapshot();
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
                                dns_monitor_state = crate::workers::dns_worker::DnsWorkerControl::dns_monitor_state_label(),
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

                        let rules_count = rules.rules_count() as u64;
                        let Some(snapshot) = stats.snapshot_if_pending(rules_count) else {
                            continue;
                        };

                        let req = opensnitch_proto::pb::PingRequest {
                            id: ping_id,
                            stats: Some(snapshot),
                        };

                        let config_snapshot = config.snapshot_arc();
                        let client_addr = config_snapshot.client_addr.as_str();
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
