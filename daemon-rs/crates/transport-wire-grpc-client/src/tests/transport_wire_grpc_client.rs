use std::{
    net::TcpListener,
    sync::Mutex,
    time::{Duration, Instant},
};

use opensnitch_proto::pb;
use opensnitch_transport_wire_core::{
    WireConnection, WireNotificationReply, WireNotificationReplyCode, WireSubscribeConfig,
};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Endpoint;
use tonic::{Request, Response, Status};

use crate::{HTTP2_KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT, TCP_KEEPALIVE, ui_client_from_channel};

#[test]
fn keepalive_constants_are_non_zero() {
    assert!(!HTTP2_KEEPALIVE_INTERVAL.is_zero());
    assert!(!KEEPALIVE_TIMEOUT.is_zero());
    assert!(!TCP_KEEPALIVE.is_zero());
}

#[tokio::test]
async fn ui_client_can_be_constructed_from_channel() {
    let channel = Endpoint::from_static("http://127.0.0.1:50051").connect_lazy();
    let _client = ui_client_from_channel(channel);
}

#[cfg(feature = "subscriptions")]
#[tokio::test]
async fn subscriptions_client_can_be_constructed() {
    let channel = Endpoint::from_static("http://127.0.0.1:50051").connect_lazy();
    let _client = crate::subscriptions_client_from_channel(channel);
}

#[derive(Default)]
struct TestUiServer {
    open_tx: Mutex<Option<oneshot::Sender<()>>>,
    hello_tx: Mutex<Option<oneshot::Sender<pb::NotificationReply>>>,
}

async fn recv_oneshot_with_deadline<T>(
    rx: &mut oneshot::Receiver<T>,
    max_wait: Duration,
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
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => return Err("closed"),
        }
    }
}

async fn wait_for_server_ready(addr: std::net::SocketAddr, max_wait: Duration) {
    let start = Instant::now();
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

struct AskRuleUiServer;

#[tonic::async_trait]
impl pb::ui_server::Ui for AskRuleUiServer {
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
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn post_alert(
        &self,
        _request: Request<pb::Alert>,
    ) -> Result<Response<pb::MsgResponse>, Status> {
        Ok(Response::new(pb::MsgResponse::default()))
    }
}

#[tokio::test]
async fn grpc_client_supports_subscribe_and_notification_hello_handshake() {
    let (open_tx, mut open_rx) = oneshot::channel();
    let (hello_tx, mut hello_rx) = oneshot::channel();
    let ui = TestUiServer {
        open_tx: Mutex::new(Some(open_tx)),
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

    wait_for_server_ready(addr, Duration::from_secs(2)).await;

    let endpoint =
        crate::wire_endpoint_with_keepalive(&format!("http://{addr}")).expect("build endpoint");
    let session = endpoint.connect().await.expect("connect grpc session");
    let mut client = crate::WireClient::from_session(session);

    let subscribe = client
        .subscribe(WireSubscribeConfig {
            id: 1,
            name: "test-ui".to_string(),
            version: "test".to_string(),
            ..Default::default()
        })
        .await
        .expect("subscribe should succeed");
    assert_eq!(subscribe.id, 1);
    assert_eq!(subscribe.name, "test-ui");

    let stream = client
        .open_notifications()
        .await
        .expect("notifications stream open should succeed");
    let _inbound = stream.0;
    stream
        .1
        .send(WireNotificationReply {
            id: 0,
            code: WireNotificationReplyCode::Ok as i32,
            data: String::new(),
        })
        .await
        .expect("send hello reply");

    recv_oneshot_with_deadline(&mut open_rx, Duration::from_secs(3))
        .await
        .expect("notifications rpc open");
    let hello = recv_oneshot_with_deadline(&mut hello_rx, Duration::from_secs(3))
        .await
        .expect("hello reply");
    assert_eq!(hello.id, 0);
    assert_eq!(hello.code, WireNotificationReplyCode::Ok as i32);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(1), server_handle).await;
}

#[tokio::test]
async fn grpc_client_maps_ask_rule_response_to_wire_rule() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test ui server");
    let addr = listener.local_addr().expect("resolve test ui addr");
    drop(listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::ui_server::UiServer::new(AskRuleUiServer))
            .serve_with_shutdown(addr, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve test ui server");
    });

    wait_for_server_ready(addr, Duration::from_secs(2)).await;

    let endpoint =
        crate::wire_endpoint_with_keepalive(&format!("http://{addr}")).expect("build endpoint");
    let session = endpoint.connect().await.expect("connect grpc session");
    let mut client = crate::WireClient::from_session(session);

    let rule = client
        .ask_rule(WireConnection::default())
        .await
        .expect("ask_rule should succeed");

    assert_eq!(rule.name, "ui-allow");
    assert_eq!(rule.action, "allow");
    assert_eq!(rule.duration, "always");
    let operator = rule.operator.expect("operator should be mapped");
    assert_eq!(operator.type_name, "simple");
    assert_eq!(operator.operand, "true");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(1), server_handle).await;
}
