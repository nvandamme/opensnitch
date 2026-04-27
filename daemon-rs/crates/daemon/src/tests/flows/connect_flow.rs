use std::net::{IpAddr, Ipv4Addr};

use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

use crate::{
    bus::{BusCaps, BusState},
    config::Config,
    flows::{connect::ConnectFlow, verdict::VerdictFlow},
    models::connection::state::{ConnectionAttempt, TransportProtocol},
    services::{
        client::ClientService, config::ConfigService, connection::ConnectionService,
        dns::DnsService, process::ProcessService, rule::RuleService, stats::StatsService,
    },
    tunables::RuntimeTunables,
};

fn self_connect_attempt(request_id: u64) -> ConnectionAttempt {
    ConnectionAttempt {
        request_id,
        protocol: TransportProtocol::Tcp,
        src_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        src_port: 46000,
        dst_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        dst_port: 50051,
        iface_in_idx: 0,
        iface_out_idx: 0,
        dns_query: None,
        pid: std::process::id(),
        uid: 1000,
    }
}

#[tokio::test]
async fn connect_flow_self_connect_emits_allow_verdict() {
    let (bus, rx) = BusState::build_with_caps(BusCaps::uniform(8));
    let crate::bus::BusRx {
        connect_rx,
        mut verdict_rx,
        kernel_rx: _,
        client_cmd_rx: _,
        task_reply_rx: _,
        alert_rx: _,
    } = rx;

    let process = ProcessService::default();
    let dns = DnsService::default();
    let verdict_flow = VerdictFlow::new(
        bus.clone(),
        crate::services::client::AlertBuffer::default(),
        ConfigService::new(Config::default()),
        ClientService::default(),
        RuleService::default(),
        ConnectionService::new(process, dns),
        StatsService::default(),
        crate::services::audit::AuditService::new(32),
    );

    let shutdown = CancellationToken::new();
    let flow = ConnectFlow::new(
        shutdown.clone(),
        RuntimeTunables::default(),
        bus.verdict_tx.clone(),
        false,
    );

    let join = flow.spawn(
        verdict_flow,
        StatsService::default(),
        crate::services::audit::AuditService::new(32),
        connect_rx,
    );

    bus.connect_tx
        .send(self_connect_attempt(42))
        .await
        .expect("send connect attempt");

    let verdict = timeout(Duration::from_secs(1), verdict_rx.recv())
        .await
        .expect("verdict timeout")
        .expect("missing verdict");
    assert_eq!(verdict.request_id, 42);
    assert!(verdict.allow);
    assert!(!verdict.reject);

    shutdown.cancel();
    timeout(Duration::from_secs(1), join)
        .await
        .expect("connect flow join timeout")
        .expect("connect flow join failed");
}
