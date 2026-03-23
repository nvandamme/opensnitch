use std::{
    net::TcpListener,
    sync::Mutex,
    time::{Duration as StdDuration, Instant},
};

use opensnitch_proto::pb;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{
    bus::{BusCaps, BusState},
    commands::{
        client::client::{parse_log_level_data, parse_task_notification_data},
    },
    config::{ClientAuthType, Config},
    flows::notification::NotificationFlow,
    services::client::{Client, NotificationStream, UiSessionService},
    services::config::ConfigService,
    services::firewall::FirewallService,
    services::rule::RuleService,
};

#[cfg(feature = "subscriptions")]
use crate::models::subscription_wire::SubscriptionReplyWire;
#[cfg(feature = "subscriptions")]
use crate::commands::subscription::SubscriptionCommandService;
#[cfg(feature = "subscriptions")]
use crate::services::stats::StatsService;
#[cfg(feature = "subscriptions")]
use crate::services::subscription::SubscriptionService;
#[cfg(feature = "subscriptions")]
use crate::services::subscription::storage::SubscriptionStorage;
#[cfg(feature = "subscriptions")]
use crate::tests::support::TestDir;

#[derive(Default)]
struct TestUiServer {
    open_tx: Mutex<Option<oneshot::Sender<()>>>,
    hello_tx: Mutex<Option<oneshot::Sender<pb::NotificationReply>>>,
}

async fn recv_oneshot_with_deadline<T>(
    rx: &mut oneshot::Receiver<T>,
    max_wait: StdDuration,
) -> Result<T, &'static str> {
    let start = Instant::now();
    loop {
        match rx.try_recv() {
            Ok(value) => return Ok(value),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                if start.elapsed() >= max_wait {
                    return Err("timeout");
                }
                tokio::task::yield_now().await;
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                return Err("closed");
            }
        }
    }
}

async fn wait_join_with_deadline<T>(
    handle: &mut tokio::task::JoinHandle<T>,
    max_wait: StdDuration,
) -> Result<T, &'static str> {
    let start = Instant::now();
    loop {
        if handle.is_finished() {
            return handle.await.map_err(|_| "join-error");
        }
        if start.elapsed() >= max_wait {
            return Err("timeout");
        }
        tokio::task::yield_now().await;
    }
}

async fn yield_for(duration: StdDuration) {
    let start = Instant::now();
    while start.elapsed() < duration {
        tokio::task::yield_now().await;
    }
}

async fn wait_for_server_ready(addr: std::net::SocketAddr, max_wait: StdDuration) {
    let start = Instant::now();
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                return;
            }
            Err(_) if start.elapsed() < max_wait => {
                tokio::time::sleep(StdDuration::from_millis(25)).await;
            }
            Err(err) => {
                panic!("test ui server did not become ready at {addr}: {err}");
            }
        }
    }
}

#[tonic::async_trait]
impl pb::ui_server::Ui for TestUiServer {
    type NotificationsStream = ReceiverStream<Result<pb::Notification, Status>>;

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
        Ok(Response::new(pb::Rule::default()))
    }

    async fn subscribe(
        &self,
        request: Request<pb::ClientConfig>,
    ) -> Result<Response<pb::ClientConfig>, Status> {
        eprintln!("[notification_flow_test] server=subscribe");
        Ok(Response::new(request.into_inner()))
    }

    async fn notifications(
        &self,
        request: Request<tonic::Streaming<pb::NotificationReply>>,
    ) -> Result<Response<Self::NotificationsStream>, Status> {
        eprintln!("[notification_flow_test] server=notifications-open");
        if let Some(open_tx) = self.open_tx.lock().expect("lock open sender").take() {
            let _ = open_tx.send(());
        }
        let mut outbound = request.into_inner();
        let hello_tx = self.hello_tx.lock().expect("lock hello sender").take();
        let (notification_tx, notification_rx) = mpsc::channel(1);

        tokio::spawn(async move {
            if let Ok(Some(reply)) = outbound.message().await
                && let Some(hello_tx) = hello_tx
            {
                eprintln!("[notification_flow_test] server=notifications-hello-received");
                let _ = hello_tx.send(reply);
            }

            yield_for(StdDuration::from_millis(200)).await;
            drop(notification_tx);
        });

        Ok(Response::new(ReceiverStream::new(notification_rx)))
    }

    async fn post_alert(
        &self,
        _request: Request<pb::Alert>,
    ) -> Result<Response<pb::MsgResponse>, Status> {
        Ok(Response::new(pb::MsgResponse::default()))
    }
}

#[test]
fn notification_hello_reply_matches_go_stream_handshake() {
    let reply = NotificationFlow::notification_hello_reply();
    assert_eq!(reply.id, 0);
    assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);
    assert!(reply.data.is_empty());
}

#[test]
fn stream_close_notification_recognizes_action_none_and_lower_values() {
    assert!(NotificationFlow::is_stream_close_notification(
        pb::Action::None as i32
    ));
    assert!(NotificationFlow::is_stream_close_notification(-1));
    assert!(!NotificationFlow::is_stream_close_notification(
        pb::Action::EnableInterception as i32
    ));
}

#[cfg(feature = "subscriptions")]
async fn handle_subscription_notification(
    subscriptions: &SubscriptionService,
    stats: &StatsService,
    id: u64,
    request_json: &str,
) -> pb::NotificationReply {
    SubscriptionCommandService::default()
        .handle_notification(id, request_json, subscriptions, stats)
        .await
}

#[cfg(feature = "subscriptions")]
fn sample_subscription_request(url: &str) -> pb::SubscriptionRequest {
    pb::SubscriptionRequest {
        operation: pb::SubscriptionOperation::Apply as i32,
        subscriptions: vec![pb::Subscription {
            name: "fixture".to_string(),
            url: url.to_string(),
            enabled: true,
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[cfg(feature = "subscriptions")]
fn encode_subscription_request(request: pb::SubscriptionRequest) -> String {
    serde_json::to_string(&serde_json::json!({
        "operation": request.operation,
        "subscriptions": request
            .subscriptions
            .into_iter()
            .map(|s| serde_json::json!({
                "id": s.id,
                "name": s.name,
                "url": s.url,
                "filename": s.filename,
                "groups": s.groups,
                "enabled": s.enabled,
                "format": s.format,
                "interval_seconds": s.interval_seconds,
                "timeout_seconds": s.timeout_seconds,
                "max_bytes": s.max_bytes,
                "node": s.node,
                "status": s.status,
                "last_updated": s.last_updated,
                "last_error": s.last_error,
            }))
            .collect::<Vec<_>>(),
        "targets": request.targets,
        "force": request.force,
    }))
    .expect("serialize subscription request payload")
}

#[cfg(feature = "subscriptions")]
fn decode_subscription_reply(raw_data: &str) -> pb::SubscriptionReply {
    serde_json::from_str::<SubscriptionReplyWire>(raw_data)
        .expect("invalid subscription reply payload")
        .into_proto()
}

#[cfg(feature = "subscriptions")]
#[tokio::test]
async fn subscription_notification_requires_typed_request() {
    let dir = TestDir::new("notification-flow-subscription-missing");
    let stats = StatsService::default();
    let subscriptions = SubscriptionService::new(
        SubscriptionStorage::new(dir.path.join("subscriptions.json"))
            .expect("create test subscription store"),
        dir.path.join("lists"),
    );
    let reply = handle_subscription_notification(&subscriptions, &stats, 41, "").await;
    assert_eq!(reply.code, pb::NotificationReplyCode::Error as i32);
    assert!(reply.data.contains("invalid subscription request payload"));

    let snapshot = stats.snapshot(0);
    assert_eq!(snapshot.subscription_total, 0);
    assert_eq!(snapshot.subscription_ready, 0);
    assert_eq!(snapshot.subscription_error, 0);
}

#[cfg(feature = "subscriptions")]
#[tokio::test]
async fn subscription_notification_updates_stats_after_apply_and_list() {
    let dir = TestDir::new("notification-flow-subscription-refresh");
    let stats = StatsService::default();
    let subscriptions = SubscriptionService::new(
        SubscriptionStorage::new(dir.path.join("subscriptions.json"))
            .expect("create test subscription store"),
        dir.path.join("lists"),
    );
    let apply_reply = handle_subscription_notification(
        &subscriptions,
        &stats,
        7,
        &encode_subscription_request(sample_subscription_request(
            "https://example.test/list.txt",
        )),
    )
    .await;
    assert_eq!(apply_reply.code, pb::NotificationReplyCode::Ok as i32);
    let apply = decode_subscription_reply(&apply_reply.data);
    assert!(apply.accepted);
    assert_eq!(apply.subscriptions.len(), 1);
    let apply_snapshot = stats.snapshot(0);
    assert_eq!(apply_snapshot.subscription_total, 1);
    assert_eq!(apply_snapshot.subscription_ready, 0);
    assert_eq!(apply_snapshot.subscription_error, 0);

    let list_reply = handle_subscription_notification(
        &subscriptions,
        &stats,
        8,
        &encode_subscription_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionOperation::List as i32,
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(list_reply.code, pb::NotificationReplyCode::Ok as i32);
    let listed = decode_subscription_reply(&list_reply.data);
    assert!(listed.accepted);
    assert_eq!(listed.subscriptions.len(), 1);

    let list_snapshot = stats.snapshot(0);
    assert_eq!(list_snapshot.subscription_total, 1);
    assert_eq!(list_snapshot.subscription_ready, 0);
    assert_eq!(list_snapshot.subscription_error, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_flow_runs_ui_poller_path_against_live_server() {
    crate::tests::support::init_test_logging();
    eprintln!("[notification_flow_test] stage=begin");

    let (open_tx, open_rx) = oneshot::channel();
    let (hello_tx, hello_rx) = oneshot::channel();
    let ui = TestUiServer {
        open_tx: Mutex::new(Some(open_tx)),
        hello_tx: Mutex::new(Some(hello_tx)),
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test ui server");
    let addr = listener.local_addr().expect("resolve test ui addr");
    drop(listener);
    eprintln!("[notification_flow_test] stage=server-bind addr={addr}");

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::ui_server::UiServer::new(ui))
            .serve_with_shutdown(addr, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve test ui server");
    });

    wait_for_server_ready(addr, StdDuration::from_secs(2)).await;
    eprintln!("[notification_flow_test] stage=server-ready");

    let (bus, _bus_rx) = BusState::build_with_caps(BusCaps::uniform(8));
    let mut config = Config::default();
    config.client_addr = format!("http://{addr}");
    config.client_auth.auth_type = ClientAuthType::Simple;
    let rules = RuleService::default();
    rules
        .load_path(&config.rules_path)
        .await
        .expect("load rules");
    eprintln!("[notification_flow_test] stage=rules-loaded");
    let firewall = FirewallService::new(&config).expect("build firewall service");
    let _flow = NotificationFlow::new(
        bus,
        ConfigService::new(config.clone()),
        UiSessionService::default(),
        rules.clone(),
        firewall.clone(),
        crate::services::stats::StatsService::default(),
        crate::services::subscription::SubscriptionService::with_system_defaults(),
    );

    eprintln!("[notification_flow_test] stage=client-connect");
    let mut subscribe_client = Client::connect_with_config(&config)
        .await
        .expect("client connect should succeed");

    let rules_snapshot = rules.get_proto_snapshot();
    let firewall_state = firewall.get_snapshot();
    let subscribe_cfg = Client::build_subscribe_config_from_snapshots(
        &config,
        &rules_snapshot,
        firewall_state.state.enabled,
        &firewall_state.system_firewall,
    );
    subscribe_client
        .subscribe(subscribe_cfg)
        .await
        .expect("subscribe should succeed");
    eprintln!("[notification_flow_test] stage=subscribe-ok");

    let mut stream_client = Client::connect_with_config(&config)
        .await
        .expect("stream client connect should succeed");
    let stream = NotificationStream::open(&mut stream_client)
        .await
        .expect("notifications stream open should succeed");
    eprintln!("[notification_flow_test] stage=stream-opened");

    assert!(
        stream
            .reply_tx
            .send(NotificationFlow::notification_hello_reply())
            .await
            .is_ok(),
        "hello send should succeed"
    );
    eprintln!("[notification_flow_test] stage=hello-sent");

    let mut failure: Option<String> = None;

    let mut open_rx = open_rx;
    if recv_oneshot_with_deadline(&mut open_rx, StdDuration::from_secs(10))
        .await
        .is_err()
    {
        failure = Some("notifications rpc open timeout".to_string());
    }
    eprintln!(
        "[notification_flow_test] stage=open-wait-finished failure={:?}",
        failure
    );

    // Wait for the hello handshake to be captured by the test server.
    if failure.is_none() {
        let mut hello_rx = hello_rx;
        match recv_oneshot_with_deadline(&mut hello_rx, StdDuration::from_secs(10)).await {
            Ok(hello) => {
                eprintln!("[notification_flow_test] stage=hello-received");
                if hello.id != 0 || hello.code != pb::NotificationReplyCode::Ok as i32 {
                    failure = Some("unexpected hello reply payload".to_string());
                }
            }
            Err("closed") => {
                failure = Some("hello channel closed before reply".to_string());
            }
            Err(_) => {
                failure = Some("hello reply timeout".to_string());
            }
        }
    }

    yield_for(StdDuration::from_millis(250)).await;
    let _ = shutdown_tx.send(());
    eprintln!("[notification_flow_test] stage=shutdown-sent");

    match wait_join_with_deadline(&mut server_handle, StdDuration::from_secs(1)).await {
        Ok(_) => {}
        Err(_) => {
            server_handle.abort();
            let _ = wait_join_with_deadline(&mut server_handle, StdDuration::from_secs(1)).await;
            if failure.is_none() {
                failure = Some("test server did not stop within timeout".to_string());
            }
        }
    }
    eprintln!("[notification_flow_test] stage=server-joined");

    if let Some(reason) = failure {
        panic!("{reason}");
    }
}

#[test]
fn parse_task_notification_accepts_valid_payload() {
    let parsed = parse_task_notification_data(
        10,
        r#"{"Name":"pid-monitor","Data":{"pid":1234}}"#,
    )
    .expect("task payload");
    assert_eq!(parsed.notification_id, 10);
    assert_eq!(parsed.name, "pid-monitor");
}

#[test]
fn parse_task_notification_accepts_lowercase_payload_fields() {
    let parsed = parse_task_notification_data(
        12,
        r#"{"name":"sockets-monitor","data":{}}"#,
    )
    .expect("task payload");
    assert_eq!(parsed.notification_id, 12);
    assert_eq!(parsed.name, "sockets-monitor");
}

#[test]
fn parse_task_notification_accepts_uppercase_payload_fields() {
    let parsed = parse_task_notification_data(
        13,
        r#"{"NAME":"pid-monitor","DATA":{"pid":4321}}"#,
    )
    .expect("task payload");
    assert_eq!(parsed.notification_id, 13);
    assert_eq!(parsed.name, "pid-monitor");
}

#[test]
fn parse_task_notification_rejects_invalid_payload() {
    assert!(parse_task_notification_data(11, "not-json").is_err());
}

#[test]
fn parse_log_level_notification_supports_number_and_object() {
    assert_eq!(parse_log_level_data("3"), Some(3));
    assert_eq!(
        parse_log_level_data(r#"{"log_level":7}"#),
        Some(7)
    );
    assert_eq!(
        parse_log_level_data(r#"{"Log_Level":"9"}"#),
        Some(9)
    );
    assert_eq!(
        parse_log_level_data(r#"{"LEVEL":5}"#),
        Some(5)
    );
}
