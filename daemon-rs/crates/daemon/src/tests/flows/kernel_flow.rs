use tokio::time::{Duration, Instant, timeout};
use tokio_util::sync::CancellationToken;

use crate::{
    flows::kernel::KernelFlow,
    models::{dns_payload::DnsPayload, kernel_event::KernelEvent},
    services::{dns::DnsService, process::ProcessService, stats::StatsService},
    tunables::RuntimeTunables,
};

#[tokio::test]
async fn kernel_flow_dns_event_updates_dns_cache() {
    let shutdown = CancellationToken::new();
    let process = ProcessService::default();
    let dns = DnsService::default();
    let stats = StatsService::default();

    let (kernel_tx, kernel_rx) = tokio::sync::mpsc::channel(16);
    let flow = KernelFlow::new(
        shutdown.clone(),
        RuntimeTunables::default(),
        std::sync::Arc::new(crate::daemon::KernelPipelineCounters::default()),
    );
    let join = flow.spawn(process, dns.clone(), stats, kernel_rx);

    kernel_tx
        .send(KernelEvent::DnsUpdate(DnsPayload::answer(
            "kernel.flow.test",
            "203.0.113.10".parse().expect("test ip should parse"),
        )))
        .await
        .expect("send dns event");

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(host) = dns.lookup_ip("203.0.113.10".parse().unwrap()) {
            assert_eq!(host.as_ref(), "kernel.flow.test");
            break;
        }
        assert!(Instant::now() < deadline, "dns cache update timed out");
        tokio::task::yield_now().await;
    }

    shutdown.cancel();
    timeout(Duration::from_secs(1), join)
        .await
        .expect("kernel flow join timeout")
        .expect("kernel flow join failed");
}

#[tokio::test]
async fn kernel_flow_respects_custom_ingress_dispatch_batch_tunable() {
    let shutdown = CancellationToken::new();
    let process = ProcessService::default();
    let dns = DnsService::default();
    let stats = StatsService::default();

    let (kernel_tx, kernel_rx) = tokio::sync::mpsc::channel(16);
    let mut tunables = RuntimeTunables::default();
    tunables.kernel_ingress_dispatch_batch_size = 8;
    tunables.kernel_dns_dispatch_batch_size = 8;
    tunables.kernel_process_dispatch_batch_size = 8;
    tunables.kernel_firewall_dispatch_batch_size = 8;

    let flow = KernelFlow::new(
        shutdown.clone(),
        tunables,
        std::sync::Arc::new(crate::daemon::KernelPipelineCounters::default()),
    );
    let join = flow.spawn(process, dns.clone(), stats, kernel_rx);

    kernel_tx
        .send(KernelEvent::DnsUpdate(DnsPayload::answer(
            "kernel.flow.tunable.test",
            "203.0.113.11".parse().expect("test ip should parse"),
        )))
        .await
        .expect("send dns event");

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(host) = dns.lookup_ip("203.0.113.11".parse().unwrap()) {
            assert_eq!(host.as_ref(), "kernel.flow.tunable.test");
            break;
        }
        assert!(Instant::now() < deadline, "dns cache update timed out");
        tokio::task::yield_now().await;
    }

    shutdown.cancel();
    timeout(Duration::from_secs(1), join)
        .await
        .expect("kernel flow join timeout")
        .expect("kernel flow join failed");
}
