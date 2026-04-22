use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::daemon::{Daemon, DaemonRuntime, KernelPipeline, ProcWorkersRuntime, ProcessKernelEvent};
use crate::{
    bus::{Bus, BusCaps, BusState},
    config::Config,
    flows::verdict::VerdictFlow,
    models::{
        command_rpc::{ClientCommand, TaskNotification},
        connection_state::{ConnectionAttempt, TransportProtocol},
        dns_payload::DnsPayload,
        firewall_state::{FirewallBackend, FirewallState},
        kernel_event::KernelEvent,
        proc_event::ProcEventKind,
    },
    services::{
        client::ClientService, config::ConfigService, connection::ConnectionService,
        dns::DnsService, firewall::FirewallService,
        process::ProcessService, rule::RuleService,
        stats::StatsService,
    },
    tunables::RuntimeTunables,
};

const LOCALHOST_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const KERNEL_PIPELINE_SEND_BACKOFF: Duration = Duration::from_millis(10);

fn build_test_daemon_with_tunables(bus: Bus, tunables: RuntimeTunables) -> Daemon {
    let config = Config::default();
    let firewall = FirewallService::new(&config).expect("firewall service");
    let process = ProcessService::default();
    let dns = DnsService::default();
    let client = ClientService::default();
    let connections = ConnectionService::new(process.clone(), dns.clone());

    Daemon {
        runtime: Arc::new(DaemonRuntime {
            config: ConfigService::new(config.clone()),
            client,
            nfqueue_num: config.firewall_queue_num,
            default_action: config.default_action,
            audit_socket_path: config.audit_socket_path.clone(),
            proc_workers: Arc::new(std::sync::Mutex::new(ProcWorkersRuntime {
                current_method: config.proc_monitor_method,
                shutdown: CancellationToken::new(),
                handles: Vec::new(),
            })),
            bus,
            alert_buffer: crate::services::client::AlertBuffer::default(),
            kernel_pipeline_counters: Arc::new(crate::daemon::KernelPipelineCounters::default()),
            rules: RuleService::default(),
            connections,
            process,
            dns,
            stats: StatsService::default(),
            firewall,
            subscriptions: crate::services::subscription::SubscriptionService::with_system_defaults(
            ),
            tasks: crate::services::task::TaskService::default(),
            tunables,
            shutdown: CancellationToken::new(),
            metrics_config: crate::models::metrics_config::MetricsConfig::default(),
            metrics_cli: crate::models::metrics_config::MetricsCliOverrides::default(),
            #[cfg(feature = "metrics-export")]
            metrics_server: std::sync::Mutex::new(None),
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
    let daemon = build_test_daemon(crate::bus::BusState::build_with_caps(crate::bus::BusCaps::uniform(1)).0);

    let keep_running = daemon.probe_dispatch_kernel_pipeline_event(
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
    let daemon = build_test_daemon(crate::bus::BusState::build_with_caps(crate::bus::BusCaps::uniform(1)).0);

    let before = daemon.probe_kernel_pipeline_drop_stats();
    let started = Instant::now();
    let keep_running = daemon.probe_dispatch_kernel_pipeline_event(
        &tx,
        2_u8,
        &CancellationToken::new(),
        KernelPipeline::Dns,
    )
    .await;
    let after = daemon.probe_kernel_pipeline_drop_stats();

    assert!(keep_running);
    assert!(started.elapsed() >= KERNEL_PIPELINE_SEND_BACKOFF);
    assert_eq!(rx.try_recv().ok(), Some(1_u8));
    assert!(rx.try_recv().is_err());
    assert!(after.dns >= before.dns.saturating_add(1));
}

#[test]
fn fanout_kernel_ingress_event_routes_dns_event() {
    let (dns_tx, mut dns_rx) = mpsc::channel::<DnsPayload>(16);
    let (process_tx, mut process_rx) = mpsc::channel::<ProcessKernelEvent>(16);
    let (firewall_tx, mut firewall_rx) = mpsc::channel::<FirewallState>(16);
    let counters = crate::daemon::KernelPipelineCounters::default();

    let routed = Daemon::probe_fanout_kernel_ingress_event(
        KernelEvent::DnsUpdate(DnsPayload::answer(
            "dns.example.test",
            "203.0.113.10".parse().expect("test ip should parse"),
        )),
        &dns_tx,
        &process_tx,
        &firewall_tx,
        &counters,
    );

    assert!(routed);
    assert_eq!(
        dns_rx.try_recv().ok(),
        Some(DnsPayload::answer(
            "dns.example.test",
            "203.0.113.10".parse().expect("test ip should parse"),
        ))
    );
    assert!(process_rx.try_recv().is_err());
    assert!(firewall_rx.try_recv().is_err());
}

#[test]
fn fanout_kernel_ingress_event_returns_false_when_target_receiver_is_closed() {
    let (dns_tx, dns_rx) = mpsc::channel::<DnsPayload>(16);
    let (process_tx, _process_rx) = mpsc::channel::<ProcessKernelEvent>(16);
    let (firewall_tx, _firewall_rx) = mpsc::channel::<FirewallState>(16);
    drop(dns_rx);
    let counters = crate::daemon::KernelPipelineCounters::default();

    let routed = Daemon::probe_fanout_kernel_ingress_event(
        KernelEvent::DnsUpdate(DnsPayload::answer(
            "closed.example.test",
            "198.51.100.20".parse().expect("test ip should parse"),
        )),
        &dns_tx,
        &process_tx,
        &firewall_tx,
        &counters,
    );

    assert!(!routed);
}

fn build_connect_attempt(request_id: u64) -> ConnectionAttempt {
    ConnectionAttempt {
        request_id,
        protocol: TransportProtocol::Tcp,
        src_addr: LOCALHOST_IP,
        src_port: 46000,
        dst_addr: LOCALHOST_IP,
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
        Daemon::probe_dispatch_connect_attempt_to_worker(
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
    let routed = Daemon::probe_dispatch_connect_attempt_to_worker(
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
    let started = Instant::now();
    let (bus, rx) = BusState::build_with_caps(BusCaps::uniform(16));
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

    daemon.stop().await;
    let _ = timeout(Duration::from_secs(1), cmd_handle).await;
    println!(
        "cold-profile backend=rust component=tasks elapsed_s={:.6}",
        started.elapsed().as_secs_f64()
    );
}

#[tokio::test]
async fn runtime_task_start_duplicate_returns_error_without_initial_started_reply() {
    let started = Instant::now();
    let (bus, rx) = BusState::build_with_caps(BusCaps::uniform(16));
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

    daemon.stop().await;
    let _ = timeout(Duration::from_secs(1), cmd_handle).await;
    println!(
        "cold-profile backend=rust component=tasks elapsed_s={:.6}",
        started.elapsed().as_secs_f64()
    );
}

#[tokio::test]
async fn runtime_task_pause_command_is_accepted_without_immediate_reply() {
    let (bus, rx) = BusState::build_with_caps(BusCaps::uniform(16));
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
        .send(ClientCommand::PauseRuntimeTasks)
        .await
        .expect("send pause runtime tasks");

    assert!(
        timeout(Duration::from_millis(80), task_reply_rx.recv())
            .await
            .is_err(),
        "pause runtime tasks should not emit immediate reply"
    );

    daemon.stop().await;
    let _ = timeout(Duration::from_secs(1), cmd_handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_attempt_progresses_under_mixed_non_connect_saturation() {
    let (bus, rx) = BusState::build_with_caps(BusCaps::uniform(64));
    let (tunables, _) = RuntimeTunables::load_effective();
    let daemon = build_test_daemon_with_tunables(bus.clone(), tunables);

    let verdict_flow = VerdictFlow::new(
        bus.clone(),
        daemon.runtime.alert_buffer.clone(),
        daemon.runtime.config.clone(),
        daemon.runtime.client.clone(),
        daemon.runtime.rules.clone(),
        daemon.runtime.connections.clone(),
        daemon.runtime.stats.clone(),
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
        daemon.spawn_connect_attempt_task(verdict_flow, daemon.runtime.stats.clone(), connect_rx);

    // Mirror Go runtimeprofile harness shape: lightweight per-pipeline workers and
    // bounded dispatch retries, instead of full daemon service handlers.
    let (dns_tx, mut dns_rx) = tokio::sync::mpsc::channel::<()>(32);
    let (process_tx, mut process_rx) = tokio::sync::mpsc::channel::<()>(32);
    let (firewall_tx, mut firewall_rx) = tokio::sync::mpsc::channel::<()>(32);
    let kernel_shutdown = daemon.runtime.shutdown.clone();

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
    let kernel_router_daemon = daemon.clone();
    let kernel_handle = tokio::spawn(async move {
        let mut kernel_rx = kernel_rx;

        loop {
            tokio::select! {
                _ = router_shutdown.cancelled() => break,
                msg = kernel_rx.recv() => {
                    match msg {
                        Some(KernelEvent::DnsUpdate(_)) => {
                            if !kernel_router_daemon.probe_dispatch_kernel_pipeline_event(
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
                        Some(
                            KernelEvent::ProcStateChanged { .. }
                            | KernelEvent::EbpfProcStateChanged(_)
                            | KernelEvent::EbpfProcessMapHit { .. }
                        ) => {
                            if !kernel_router_daemon.probe_dispatch_kernel_pipeline_event(
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
                            if !kernel_router_daemon.probe_dispatch_kernel_pipeline_event(
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
                0 => KernelEvent::DnsUpdate(DnsPayload::answer(
                    format!("load-{}.example.test", i),
                    format!("198.51.100.{}", i % 255)
                        .parse()
                        .expect("generated test ip should parse"),
                )),
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
    let daemon_pid = std::process::id();
    let mixed_started = Instant::now();
    bus.connect_tx
        .send(ConnectionAttempt {
            request_id,
            protocol: TransportProtocol::Tcp,
            src_addr: LOCALHOST_IP,
            src_port: 45000,
            dst_addr: LOCALHOST_IP,
            dst_port: 50051,
            iface_in_idx: 0,
            iface_out_idx: 0,
            dns_query: None,
            pid: daemon_pid,
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
    println!(
        "mixed-saturation backend=rust verdict_ms={:.3}",
        mixed_started.elapsed().as_secs_f64() * 1000.0
    );

    let _ = flood.await;
    daemon.stop().await;

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
    crate::tests::support::init_test_logging();

    let raw = std::env::var("RUST_LOG").unwrap_or_default();
    let normalized = raw.to_lowercase();
    let has_warn_or_error = normalized.contains("warn") || normalized.contains("error");
    let has_debug_or_trace = normalized.contains("debug") || normalized.contains("trace");

    let allow_verbose = std::env::var("OPENSNITCH_VERBOSE")
        .ok()
        .map(|value| {
            let value = value.trim().to_lowercase();
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

fn stress_baseline_path() -> String {
    std::env::var("OPENSNITCH_STRESS_BASELINE_PATH")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .or_else(|| {
            // Backward compatibility for older harness scripts.
            std::env::var("OPENSNITCH_STRESS_TODO_PATH")
                .ok()
                .filter(|path| !path.trim().is_empty())
        })
        .unwrap_or_else(|| format!("{}/../../PERF.md", env!("CARGO_MANIFEST_DIR")))
}

fn parse_baseline_f64(content: &str, key: &str) -> Option<f64> {
    content
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(key).map(str::trim))
        .and_then(|raw| raw.parse::<f64>().ok())
}

fn parse_baseline_u64(content: &str, key: &str) -> Option<u64> {
    content
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(key).map(str::trim))
        .and_then(|raw| raw.parse::<u64>().ok())
}

fn load_stress_perf_baseline(content: &str) -> StressPerfBaseline {
    let prefix = if cfg!(debug_assertions) {
        "PERF_BASELINE_RUST_DEBUG"
    } else {
        "PERF_BASELINE_RUST_RELEASE"
    };

    StressPerfBaseline {
        p95_ms: parse_baseline_f64(content, &format!("{prefix}_P95_MS="))
            .expect("missing baseline key for rust p95"),
        p99_ms: parse_baseline_f64(content, &format!("{prefix}_P99_MS="))
            .expect("missing baseline key for rust p99"),
        max_ms: parse_baseline_f64(content, &format!("{prefix}_MAX_MS="))
            .expect("missing baseline key for rust max"),
        drop_total: parse_baseline_u64(content, &format!("{prefix}_DROP_TOTAL="))
            .expect("missing baseline key for rust drop_total"),
    }
}

fn is_clear_regression(observed_ms: f64, baseline_ms: f64, factor: f64, min_delta_ms: f64) -> bool {
    observed_ms > baseline_ms * factor && (observed_ms - baseline_ms) > min_delta_ms
}

fn enforce_stress_regression_guard(
    rounds: usize,
    p95: Duration,
    p99: Duration,
    max: Duration,
    drop_total: u64,
) {
    crate::tests::support::init_test_logging();

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

    let baseline_path = stress_baseline_path();
    let baseline_content = fs::read_to_string(&baseline_path)
        .unwrap_or_else(|err| panic!("failed to read stress baseline file '{}': {err}", baseline_path));

    let baseline = load_stress_perf_baseline(&baseline_content);
    let factor = parse_baseline_f64(&baseline_content, "PERF_CLEAR_REGRESSION_FACTOR=").unwrap_or(1.75);
    let min_delta_ms =
        parse_baseline_f64(&baseline_content, "PERF_CLEAR_REGRESSION_MIN_DELTA_MS=").unwrap_or(0.050);

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

    let (bus, rx) = BusState::build_with_caps(BusCaps::uniform(8192));
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
        daemon.runtime.process.clone(),
        daemon.runtime.dns.clone(),
        daemon.runtime.stats.clone(),
        kernel_rx,
    );

    let attempted = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let enqueued = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let enqueue_timeouts = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let enqueue_closed = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let drop_before = daemon.probe_kernel_pipeline_drop_stats();
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
                            KernelEvent::DnsUpdate(DnsPayload::answer(
                                dns_hosts[idx].clone(),
                                dns_ips[idx]
                                    .parse()
                                    .expect("generated test ip should parse"),
                            ))
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

    let drop_after = daemon.probe_kernel_pipeline_drop_stats();
    let drop_delta = drop_after.saturating_delta(drop_before);

    daemon.stop().await;
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
            let value = value.trim().to_lowercase();
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

    let mut rounds = 1_000_usize;
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

    let (bus, rx) = BusState::build_with_caps(BusCaps::uniform(256));
    let daemon = build_test_daemon(bus.clone());

    let verdict_flow = VerdictFlow::new(
        bus.clone(),
        daemon.runtime.alert_buffer.clone(),
        daemon.runtime.config.clone(),
        daemon.runtime.client.clone(),
        daemon.runtime.rules.clone(),
        daemon.runtime.connections.clone(),
        daemon.runtime.stats.clone(),
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
        daemon.spawn_connect_attempt_task(verdict_flow, daemon.runtime.stats.clone(), connect_rx);

    // Mirror Go runtimeprofile harness shape: lightweight per-pipeline workers and
    // bounded dispatch retries, instead of full daemon service handlers.
    let (dns_tx, mut dns_rx) = tokio::sync::mpsc::channel::<()>(32);
    let (process_tx, mut process_rx) = tokio::sync::mpsc::channel::<()>(32);
    let (firewall_tx, mut firewall_rx) = tokio::sync::mpsc::channel::<()>(32);
    let kernel_shutdown = daemon.runtime.shutdown.clone();

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
    let kernel_router_daemon = daemon.clone();
    let kernel_handle = tokio::spawn(async move {
        let mut kernel_rx = kernel_rx;

        loop {
            tokio::select! {
                _ = router_shutdown.cancelled() => break,
                msg = kernel_rx.recv() => {
                    match msg {
                        Some(KernelEvent::DnsUpdate(_)) => {
                            if !kernel_router_daemon.probe_dispatch_kernel_pipeline_event(
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
                        Some(
                            KernelEvent::ProcStateChanged { .. }
                            | KernelEvent::EbpfProcStateChanged(_)
                            | KernelEvent::EbpfProcessMapHit { .. }
                        ) => {
                            if !kernel_router_daemon.probe_dispatch_kernel_pipeline_event(
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
                            if !kernel_router_daemon.probe_dispatch_kernel_pipeline_event(
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

    let flood_shutdown = CancellationToken::new();
    let flood_token = flood_shutdown.clone();
    let flood_bus = bus.clone();
    let flood = tokio::spawn(async move {
        let mut i = 0_u32;
        while !flood_token.is_cancelled() {
            let event = match i % 3 {
                0 => KernelEvent::DnsUpdate(DnsPayload::answer(
                    format!("profile-{}.example.test", i),
                    format!("203.0.113.{}", i % 255)
                        .parse()
                        .expect("generated test ip should parse"),
                )),
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

    let drop_before = daemon.probe_kernel_pipeline_drop_stats();
    let mut latencies = Vec::with_capacity(rounds);
    let base_request_id = 0xD00D_0000_u64;
    let daemon_pid = std::process::id();
    let started_all = Instant::now();

    for i in 0..rounds {
        let request_id = base_request_id + i as u64;
        let attempt = ConnectionAttempt {
            request_id,
            protocol: TransportProtocol::Tcp,
            src_addr: LOCALHOST_IP,
            src_port: 46000,
            dst_addr: LOCALHOST_IP,
            dst_port: 50051,
            iface_in_idx: 0,
            iface_out_idx: 0,
            dns_query: None,
            pid: daemon_pid,
            uid: 1000,
        };
        let started = Instant::now();

        match bus.connect_tx.try_send(attempt) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(attempt)) => {
                bus.connect_tx
                    .send(attempt)
                    .await
                    .expect("connect attempt send");
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                panic!("connect attempt channel closed")
            }
        }

        let verdict = match verdict_rx.try_recv() {
            Ok(verdict) => verdict,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                timeout(Duration::from_secs(2), verdict_rx.recv())
                    .await
                    .expect("verdict timeout")
                    .expect("verdict channel closed")
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                panic!("verdict channel closed")
            }
        };

        assert_eq!(verdict.request_id, request_id);
        assert!(verdict.allow);
        assert!(!verdict.reject);

        latencies.push(started.elapsed());
    }

    let drop_after = daemon.probe_kernel_pipeline_drop_stats();
    let drop_delta = drop_after.saturating_delta(drop_before);

    flood_shutdown.cancel();
    let _ = flood.await;

    latencies.sort_unstable();
    let p50 = duration_percentile(&latencies, 0.50);
    let p95 = duration_percentile(&latencies, 0.95);
    let p99 = duration_percentile(&latencies, 0.99);
    let max = latencies.last().copied().unwrap_or(Duration::ZERO);
    // Match Go harness timing scope: measure per-round throughput before teardown work.
    let total_elapsed = started_all.elapsed();
    let time_op_us = (total_elapsed.as_secs_f64() * 1_000_000.0) / (rounds as f64);
    let ops_s = (rounds as f64) / total_elapsed.as_secs_f64();
    let throughput_product = time_op_us * ops_s;
    assert!(
        time_op_us.is_finite()
            && ops_s.is_finite()
            && throughput_product.is_finite()
            && (throughput_product - 1_000_000.0).abs() <= 10_000.0,
        "invalid throughput conversion: time_op_us={time_op_us:.6} ops_s={ops_s:.6} product={throughput_product:.3}"
    );

    enforce_stress_regression_guard(rounds, p95, p99, max, drop_delta.total());

    daemon.stop().await;
    let _ = timeout(Duration::from_secs(1), connect_handle).await;
    let _ = timeout(Duration::from_secs(1), kernel_handle).await;

    let summary = format!(
        "stress-profile rounds={} p50_ms={:.3} p95_ms={:.3} p99_ms={:.3} max_ms={:.3} time_op_us={:.3} ops_s={:.1} backend=rust drop_dns={} drop_process={} drop_firewall={} drop_total={}",
        rounds,
        p50.as_secs_f64() * 1000.0,
        p95.as_secs_f64() * 1000.0,
        p99.as_secs_f64() * 1000.0,
        max.as_secs_f64() * 1000.0,
        time_op_us,
        ops_s,
        drop_delta.dns,
        drop_delta.process,
        drop_delta.firewall,
        drop_delta.total(),
    );
    // Keep a plain stdout line for harness parsers even when RUST_LOG=error.
    println!("{summary}");
    info!("{summary}");
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

    let summary = format!(
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
    println!("{summary}");
    info!("{summary}");

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

    let csv_header = "kernel-pressure-sweep-csv-header,timeout_us,secs,flood_tasks,attempted,enqueued,enqueue_timeouts,enqueue_closed,forced_kernel_abort,attempted_pps,enqueued_pps,enqueue_drop_ratio,pipeline_drop_dns,pipeline_drop_process,pipeline_drop_firewall,pipeline_drop_total";
    println!("{csv_header}");
    info!("{csv_header}");

    let mut results = Vec::new();

    for timeout_us in timeouts {
        let metrics =
            run_kernel_pressure_profile(duration_secs, flood_tasks, "timeout", timeout_us).await;
        let line = format!(
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
        println!("{line}");
        info!("{line}");

        let csv_line = format!(
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
        println!("{csv_line}");
        info!("{csv_line}");

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
        let line = format!(
            "kernel-pressure-sweep-recommend timeout_us={} score={:.0} enqueued_pps={:.0} enqueue_drop_ratio={:.4} pipeline_drop_total={} forced_kernel_abort={}",
            best.enqueue_timeout_us,
            best_score,
            best.enqueued_pps,
            best.enqueue_drop_ratio,
            best.drop_delta.total(),
            best.forced_kernel_abort,
        );
        println!("{line}");
        info!("{line}");
    }
}
