use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio_util::sync::CancellationToken;
use transport_wire_core::WireConnection;

use crate::{
    config::Config,
    flows::stats::{StatsFlow, WorkerTelemetrySnapshot},
    platform::ports::stats_exporter_port::StatsExporterPort,
    services::{
        client::ClientService, config::ConfigService, dns::DnsService, rule::RuleService,
        stats::StatsService,
    },
};

struct TestExporter {
    exports: Arc<AtomicUsize>,
}

impl StatsExporterPort for TestExporter {
    fn export_snapshot(&self, _snapshot: &crate::models::metrics_snapshot::MetricsSnapshot) {
        self.exports.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stats_flow_sends_stats_when_pending() {
    let exports = Arc::new(AtomicUsize::new(0));

    let mut config = Config::default();
    config.client_addr = "stub://local-ui".to_string();
    let config_service = ConfigService::new(config);

    let dns = DnsService::default();
    let rules = RuleService::default();
    let stats = StatsService::default();
    stats.on_event(WireConnection::default(), None);
    let kernel_pipeline_counters = Arc::new(crate::daemon::KernelPipelineCounters::default());

    let flow_shutdown = CancellationToken::new();
    let flow = StatsFlow::new(
        flow_shutdown.clone(),
        config_service,
        ClientService::default(),
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
        "proc-workers",
        Arc::new(|| WorkerTelemetrySnapshot {
            state: "running",
            method: crate::config::ProcMonitorMethod::Proc,
            configured_handles: 0,
            running_handles: 0,
            shutdown_requested: false,
        }),
        dns,
        crate::services::audit::AuditService::new(64),
    )
    .with_stats_exporter(Arc::new(TestExporter {
        exports: exports.clone(),
    }));

    let flow_handle = flow.spawn();

    let start = tokio::time::Instant::now();
    while exports.load(Ordering::SeqCst) == 0 {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "stats emission was not observed within deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    flow_shutdown.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(1), flow_handle)
        .await
        .expect("stats flow join timeout")
        .expect("stats flow join failed");
}
