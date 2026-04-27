use anyhow::Result;
use std::{
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tonic::{Request, Response, Status};

use crate::{
    bus::{BusCaps, BusState},
    config::Config,
    flows::verdict::VerdictFlow,
    models::connection::state::{ConnectionAttempt, TransportProtocol},
    models::kernel::event::KernelEvent,
    platform::firewall::state::{FirewallBackend, FirewallState},
    services::{
        client::ClientService,
        config::ConfigService,
        connection::ConnectionService,
        dns::DnsService,
        process::ProcessService,
        rule::{RuleMatchDecision, RuleService},
        stats::StatsService,
    },
    tests::support::TestDir,
};
use proto::pb;

async fn wait_for_server_ready(addr: std::net::SocketAddr, max_wait: Duration) {
    let start = tokio::time::Instant::now();
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                return;
            }
            Err(_) if start.elapsed() < max_wait => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => {
                panic!("test ui server did not become ready at {addr}: {err}");
            }
        }
    }
}

#[derive(Default)]
struct TestUiServer {
    ask_calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl pb::ui_server::Ui for TestUiServer {
    type NotificationsStream =
        tokio_stream::wrappers::ReceiverStream<Result<pb::Notification, Status>>;

    async fn ping(
        &self,
        _request: Request<pb::PingRequest>,
    ) -> Result<Response<pb::PingReply>, Status> {
        Ok(Response::new(pb::PingReply::default()))
    }

    async fn ask_rule(
        &self,
        _request: Request<pb::Connection>,
    ) -> Result<Response<pb::Rule>, Status> {
        self.ask_calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(250)).await;
        // Keep daemon flow coverage focused on in-flight gate/default-action behavior;
        // wire/protobuf field-mapping coverage lives in transport-wire-grpc-client tests.
        Ok(Response::new(pb::Rule {
            name: "ui-allow".to_string(),
            action: "allow".to_string(),
            duration: "always".to_string(),
            enabled: true,
            ..Default::default()
        }))
    }

    async fn subscribe(
        &self,
        request: Request<pb::ClientConfig>,
    ) -> Result<Response<pb::ClientConfig>, Status> {
        Ok(Response::new(request.into_inner()))
    }

    async fn notifications(
        &self,
        _request: Request<tonic::Streaming<pb::NotificationReply>>,
    ) -> Result<Response<Self::NotificationsStream>, Status> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn post_alert(
        &self,
        _request: Request<pb::Alert>,
    ) -> Result<Response<pb::MsgResponse>, Status> {
        Ok(Response::new(pb::MsgResponse::default()))
    }
}

#[test]
fn decision_rule_summary_maps_action_names() {
    let allow = RuleMatchDecision {
        allow: true,
        reject: false,
        nolog: false,
    }
    .to_summary();
    assert_eq!(allow.action, "allow");

    let reject = RuleMatchDecision {
        allow: false,
        reject: true,
        nolog: false,
    }
    .to_summary();
    assert_eq!(reject.action, "reject");
}

#[tokio::test]
async fn handle_event_ignores_non_connection_events() -> Result<()> {
    let (bus, mut rx) = BusState::build_with_caps(BusCaps::uniform(4));
    let process = ProcessService::default();
    let dns = DnsService::default();
    let _flow = VerdictFlow::new(
        bus.clone(),
        crate::services::client::AlertBuffer::default(),
        ConfigService::new(Config::default()),
        ClientService::default(),
        RuleService::default(),
        ConnectionService::new(process, dns),
        StatsService::default(),
        crate::services::audit::AuditService::new(32),
    );

    let _ = bus
        .kernel_tx
        .try_send(KernelEvent::FirewallState(FirewallState {
            enabled: false,
            backend: FirewallBackend::Nftables,
        }));

    let no_verdict = timeout(Duration::from_millis(50), rx.verdict_rx.recv()).await;
    assert!(no_verdict.is_err());
    Ok(())
}

#[tokio::test]
async fn self_connection_is_fast_allowed() -> Result<()> {
    let (bus, mut rx) = BusState::build_with_caps(BusCaps::uniform(4));
    let process = ProcessService::default();
    let dns = DnsService::default();
    let flow = VerdictFlow::new(
        bus,
        crate::services::client::AlertBuffer::default(),
        ConfigService::new(Config::default()),
        ClientService::default(),
        RuleService::default(),
        ConnectionService::new(process, dns),
        StatsService::default(),
        crate::services::audit::AuditService::new(32),
    );

    flow.handle_connect_attempt(ConnectionAttempt {
        request_id: 42,
        protocol: TransportProtocol::Tcp,
        src_addr: "127.0.0.1".parse().expect("valid ip"),
        src_port: 50000,
        dst_addr: "127.0.0.1".parse().expect("valid ip"),
        dst_port: 8080,
        iface_in_idx: 0,
        iface_out_idx: 0,
        dns_query: None,
        pid: std::process::id(),
        uid: 1000,
    })
    .await;

    let verdict = rx.verdict_rx.recv().await.expect("verdict reply");
    assert_eq!(verdict.request_id, 42);
    assert!(verdict.allow);
    assert!(!verdict.reject);

    Ok(())
}

#[tokio::test]
async fn concurrent_ui_ask_uses_single_inflight_gate() -> Result<()> {
    let ask_calls = Arc::new(AtomicUsize::new(0));
    let ui = TestUiServer {
        ask_calls: ask_calls.clone(),
    };

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::ui_server::UiServer::new(ui))
            .serve_with_shutdown(addr, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve test ui server");
    });

    wait_for_server_ready(addr, Duration::from_secs(2)).await;

    let (bus, mut rx) = BusState::build_with_caps(BusCaps::uniform(16));
    let mut config = Config::default();
    config.client_addr = format!("http://{addr}");
    config.default_action = crate::config::DefaultAction::Deny;
    let process = ProcessService::default();
    let dns = DnsService::default();
    let stats = StatsService::default();
    let rules = RuleService::default();
    let rules_dir = TestDir::new("verdict-flow-ui-ask");
    rules.load_path(&rules_dir.path).await?;
    let flow = VerdictFlow::new(
        bus,
        crate::services::client::AlertBuffer::default(),
        ConfigService::new(config),
        ClientService::default(),
        rules,
        ConnectionService::new(process, dns),
        stats.clone(),
        crate::services::audit::AuditService::new(32),
    );

    let a1 = ConnectionAttempt {
        request_id: 1001,
        protocol: TransportProtocol::Tcp,
        src_addr: "127.0.0.1".parse().expect("valid ip"),
        src_port: 50001,
        dst_addr: "203.0.113.11".parse().expect("valid ip"),
        dst_port: 443,
        iface_in_idx: 0,
        iface_out_idx: 0,
        dns_query: None,
        pid: 1,
        uid: 1000,
    };
    let a2 = ConnectionAttempt {
        request_id: 1002,
        src_port: 50002,
        ..a1.clone()
    };

    let f1 = flow.clone();
    let f2 = flow.clone();
    let j1 = tokio::spawn(async move { f1.handle_connect_attempt(a1).await });
    let j2 = tokio::spawn(async move { f2.handle_connect_attempt(a2).await });
    let _ = tokio::join!(j1, j2);

    let v1 = timeout(Duration::from_secs(3), rx.verdict_rx.recv())
        .await?
        .expect("first verdict");
    let v2 = timeout(Duration::from_secs(3), rx.verdict_rx.recv())
        .await?
        .expect("second verdict");

    let allow_count = usize::from(v1.allow) + usize::from(v2.allow);
    let deny_count = usize::from(!v1.allow) + usize::from(!v2.allow);
    assert_eq!(allow_count, 1);
    assert_eq!(deny_count, 1);
    let stats_counted = usize::from(v1.count_stats) + usize::from(v2.count_stats);
    assert_eq!(stats_counted, 1);
    assert_eq!(ask_calls.load(Ordering::SeqCst), 1);

    let snapshot = stats.snapshot(0);
    assert_eq!(snapshot.stats.rule_hits, 1);
    assert_eq!(snapshot.stats.rule_misses, 1);

    let _ = shutdown_tx.send(());
    let _ = timeout(Duration::from_secs(1), server_handle).await;
    Ok(())
}
