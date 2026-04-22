use std::{net::TcpListener, sync::Mutex};

use opensnitch_proto::pb;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, timeout};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{
    bus::build_bus,
    config::Config,
    flows::notification_flow::{
        NotificationFlow, is_stream_close_notification, notification_hello_reply,
        parse_log_level_notification, parse_task_notification,
    },
    services::config_service::ConfigService,
    services::firewall_service::FirewallService,
    services::rule_service::RuleService,
    services::ui_session_service::UiSessionService,
    utils::test_support::init_test_logging,
};

#[derive(Default)]
struct TestUiServer {
    hello_tx: Mutex<Option<oneshot::Sender<pb::NotificationReply>>>,
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
        Ok(Response::new(request.into_inner()))
    }

    async fn notifications(
        &self,
        request: Request<tonic::Streaming<pb::NotificationReply>>,
    ) -> Result<Response<Self::NotificationsStream>, Status> {
        let mut outbound = request.into_inner();
        let hello_tx = self.hello_tx.lock().expect("lock hello sender").take();
        let (notification_tx, notification_rx) = mpsc::channel(1);

        tokio::spawn(async move {
            if let Ok(Some(reply)) = outbound.message().await
                && let Some(hello_tx) = hello_tx
            {
                let _ = hello_tx.send(reply);
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
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
fn parse_task_notification_accepts_valid_payload() {
    let notification = pb::Notification {
        id: 10,
        data: r#"{"Name":"pid-monitor","Data":{"pid":1234}}"#.to_string(),
        ..Default::default()
    };

    let parsed = parse_task_notification(&notification).expect("task payload");
    assert_eq!(parsed.notification_id, 10);
    assert_eq!(parsed.name, "pid-monitor");
}

#[test]
fn parse_task_notification_accepts_lowercase_payload_fields() {
    let notification = pb::Notification {
        id: 12,
        data: r#"{"name":"sockets-monitor","data":{}}"#.to_string(),
        ..Default::default()
    };

    let parsed = parse_task_notification(&notification).expect("task payload");
    assert_eq!(parsed.notification_id, 12);
    assert_eq!(parsed.name, "sockets-monitor");
}

#[test]
fn parse_task_notification_accepts_uppercase_payload_fields() {
    let notification = pb::Notification {
        id: 13,
        data: r#"{"NAME":"pid-monitor","DATA":{"pid":4321}}"#.to_string(),
        ..Default::default()
    };

    let parsed = parse_task_notification(&notification).expect("task payload");
    assert_eq!(parsed.notification_id, 13);
    assert_eq!(parsed.name, "pid-monitor");
}

#[test]
fn parse_task_notification_rejects_invalid_payload() {
    let notification = pb::Notification {
        id: 11,
        data: "not-json".to_string(),
        ..Default::default()
    };

    assert!(parse_task_notification(&notification).is_err());
}

#[test]
fn parse_log_level_notification_supports_number_and_object() {
    let number = pb::Notification {
        data: "3".to_string(),
        ..Default::default()
    };
    assert_eq!(parse_log_level_notification(&number), Some(3));

    let object = pb::Notification {
        data: r#"{"log_level":7}"#.to_string(),
        ..Default::default()
    };
    assert_eq!(parse_log_level_notification(&object), Some(7));

    let mixed_case_object = pb::Notification {
        data: r#"{"Log_Level":"9"}"#.to_string(),
        ..Default::default()
    };
    assert_eq!(parse_log_level_notification(&mixed_case_object), Some(9));

    let upper_case_level = pb::Notification {
        data: r#"{"LEVEL":5}"#.to_string(),
        ..Default::default()
    };
    assert_eq!(parse_log_level_notification(&upper_case_level), Some(5));
}

#[test]
fn notification_hello_reply_matches_go_stream_handshake() {
    let reply = notification_hello_reply();
    assert_eq!(reply.id, 0);
    assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);
    assert!(reply.data.is_empty());
}

#[test]
fn stream_close_notification_recognizes_action_none_and_lower_values() {
    assert!(is_stream_close_notification(pb::Action::None as i32));
    assert!(is_stream_close_notification(-1));
    assert!(!is_stream_close_notification(
        pb::Action::EnableInterception as i32
    ));
}

#[tokio::test]
async fn notification_flow_runs_ui_poller_path_against_live_server() {
    init_test_logging();

    let (hello_tx, hello_rx) = oneshot::channel();
    let ui = TestUiServer {
        hello_tx: Mutex::new(Some(hello_tx)),
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test ui server");
    let addr = listener.local_addr().expect("resolve test ui addr");
    drop(listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::ui_server::UiServer::new(ui))
            .serve_with_shutdown(addr, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve test ui server");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let (bus, _bus_rx) = build_bus(8);
    let mut config = Config::default();
    config.client_addr = format!("http://{addr}");
    let rules = RuleService::default();
    rules
        .load_path(&config.rules_path)
        .await
        .expect("load rules");
    let firewall = FirewallService::new(&config).expect("build firewall service");
    let flow = NotificationFlow::new(
        bus,
        ConfigService::new(config),
        UiSessionService::default(),
        rules,
        firewall,
    );

    // Keep task_reply_tx alive so the inner loop doesn't exit via None immediately;
    // the server stream closes after 200ms which triggers client.disconnect().
    let (task_reply_tx, task_reply_rx) = mpsc::channel(1);
    let (_alert_tx, alert_rx) = mpsc::channel(1);
    let flow_handle = tokio::spawn(flow.run(task_reply_rx, alert_rx));

    // Wait for the hello handshake to be captured by the test server.
    let hello = timeout(Duration::from_secs(2), hello_rx)
        .await
        .expect("hello reply timeout")
        .expect("hello reply should be captured");
    assert_eq!(hello.id, 0);
    assert_eq!(hello.code, pb::NotificationReplyCode::Ok as i32);

    // Server stream closes after 200ms; wait for client.disconnect() to be logged.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Shut down the server then drop task_reply_tx; the flow will see a failed
    // reconnect with a closed receiver and exit via uiClient exit.
    let _ = shutdown_tx.send(());
    drop(task_reply_tx);

    timeout(Duration::from_secs(5), flow_handle)
        .await
        .expect("notification flow should exit cleanly")
        .expect("flow join")
        .expect("flow result");

    let _ = timeout(Duration::from_secs(1), server_handle).await;
}
