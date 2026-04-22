use anyhow::Result;
use std::{
    net::TcpListener,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::time::{Duration, timeout};
use tonic::{Request, Response, Status};

use crate::{
    bus::build_bus,
    config::Config,
    flows::verdict_flow::{VerdictFlow, decision_rule_summary},
    models::{
        connection_state::{ConnectionAttempt, TransportProtocol},
        firewall_state::{FirewallBackend, FirewallState},
        kernel_event::KernelEvent,
    },
    services::{
        config_service::ConfigService,
        connection_service::ConnectionService,
        dns_service::DnsService,
        process_service::ProcessService,
        rule_service::{RuleMatchDecision, RuleService},
        stats_service::StatsService,
        ui_session_service::UiSessionService,
    },
};
use opensnitch_proto::pb;

fn test_rules_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "opensnitchd-rs-{name}-{}-{nanos}",
        std::process::id()
    ))
}

#[derive(Default)]
struct TestUiServer {
    ask_calls: Arc<AtomicUsize>,
}

#[tonic::async_trait]
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
        Ok(Response::new(pb::Rule {
            name: "ui-allow".to_string(),
            action: "allow".to_string(),
            duration: "always".to_string(),
            enabled: true,
            operator: Some(pb::Operator {
                r#type: "simple".to_string(),
                operand: "true".to_string(),
                data: String::new(),
                sensitive: false,
                list: Vec::new(),
            }),
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
    let allow = decision_rule_summary(RuleMatchDecision {
        allow: true,
        reject: false,
        nolog: false,
    });
    assert_eq!(allow.action, "allow");

    let reject = decision_rule_summary(RuleMatchDecision {
        allow: false,
        reject: true,
        nolog: false,
    });
    assert_eq!(reject.action, "reject");
}

#[tokio::test]
async fn handle_event_ignores_non_connection_events() -> Result<()> {
    let (bus, _rx) = build_bus(4);
    let process = ProcessService::default();
    let dns = DnsService::default();
    let flow = VerdictFlow::new(
        bus,
        ConfigService::new(Config::default()),
        UiSessionService::default(),
        RuleService::default(),
        ConnectionService::new(process, dns),
        StatsService::default(),
    );

    flow.handle_event(KernelEvent::FirewallState(FirewallState {
        enabled: false,
        backend: FirewallBackend::Nftables,
    }))
    .await?;

    Ok(())
}

#[tokio::test]
async fn self_connection_is_fast_allowed() -> Result<()> {
    let (bus, mut rx) = build_bus(4);
    let process = ProcessService::default();
    let dns = DnsService::default();
    let flow = VerdictFlow::new(
        bus,
        ConfigService::new(Config::default()),
        UiSessionService::default(),
        RuleService::default(),
        ConnectionService::new(process, dns),
        StatsService::default(),
    );

    flow.handle_connect_attempt(ConnectionAttempt {
        request_id: 42,
        protocol: TransportProtocol::Tcp,
        src_ip: "127.0.0.1".to_string(),
        src_port: 50000,
        dst_ip: "127.0.0.1".to_string(),
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

    let (bus, mut rx) = build_bus(16);
    let mut config = Config::default();
    config.client_addr = format!("http://{addr}");
    config.default_action = crate::config::DefaultAction::Deny;
    let process = ProcessService::default();
    let dns = DnsService::default();
    let stats = StatsService::default();
    let rules = RuleService::default();
    let rules_dir = test_rules_dir("verdict-flow-ui-ask");
    tokio::fs::create_dir_all(&rules_dir).await?;
    rules.load_path(&rules_dir).await?;
    let flow = VerdictFlow::new(
        bus,
        ConfigService::new(config),
        UiSessionService::default(),
        rules,
        ConnectionService::new(process, dns),
        stats.clone(),
    );

    let a1 = ConnectionAttempt {
        request_id: 1001,
        protocol: TransportProtocol::Tcp,
        src_ip: "127.0.0.1".to_string(),
        src_port: 50001,
        dst_ip: "203.0.113.11".to_string(),
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
    assert_eq!(snapshot.rule_hits, 1);
    assert_eq!(snapshot.rule_misses, 1);

    let _ = shutdown_tx.send(());
    let _ = timeout(Duration::from_secs(1), server_handle).await;
    let _ = tokio::fs::remove_dir_all(&rules_dir).await;
    Ok(())
}
