use std::{
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration as StdDuration, Instant},
};

use opensnitch_proto::pb;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

use crate::{
    config::Config,
    flows::stats::{StatsFlow, WorkerTelemetrySnapshot},
    services::{config::ConfigService, rule::RuleService, stats::StatsService},
};

#[derive(Default)]
struct TestUiServer {
    ping_calls: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl pb::ui_server::Ui for TestUiServer {
    type NotificationsStream =
        tokio_stream::wrappers::ReceiverStream<Result<pb::Notification, Status>>;

    async fn ping(
        &self,
        _request: Request<pb::PingRequest>,
    ) -> Result<Response<pb::PingReply>, Status> {
        self.ping_calls.fetch_add(1, Ordering::SeqCst);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stats_flow_sends_stats_when_pending() {
    let ping_calls = Arc::new(AtomicUsize::new(0));
    let ui = TestUiServer {
        ping_calls: ping_calls.clone(),
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test ui server");
    let addr = listener.local_addr().expect("resolve test ui addr");
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

    wait_for_server_ready(addr, StdDuration::from_secs(2)).await;

    let mut config = Config::default();
    config.client_addr = format!("http://{addr}");
    let config_service = ConfigService::new(config);

    let rules = RuleService::default();
    let stats = StatsService::default();
    stats.on_event(pb::Connection::default(), None);

    let flow_shutdown = CancellationToken::new();
    let flow = StatsFlow::new(
        flow_shutdown.clone(),
        config_service,
        rules,
        stats,
        Arc::new(crate::daemon::Daemon::probe_kernel_pipeline_ingress_stats),
        Arc::new(crate::daemon::Daemon::probe_kernel_pipeline_drop_stats),
        "proc-workers",
        Arc::new(|| WorkerTelemetrySnapshot {
            state: "running",
            method: crate::config::ProcMonitorMethod::Proc,
            configured_handles: 0,
            running_handles: 0,
            shutdown_requested: false,
        }),
    );

    let flow_handle = flow.spawn();

    let start = Instant::now();
    while ping_calls.load(Ordering::SeqCst) == 0 {
        assert!(
            start.elapsed() < StdDuration::from_secs(3),
            "stats emission was not observed within deadline"
        );
        tokio::task::yield_now().await;
    }

    flow_shutdown.cancel();
    tokio::time::timeout(StdDuration::from_secs(1), flow_handle)
        .await
        .expect("stats flow join timeout")
        .expect("stats flow join failed");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(StdDuration::from_secs(1), server_handle).await;
}
