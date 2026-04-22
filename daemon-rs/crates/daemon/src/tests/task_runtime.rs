use crate::commands::task_runtime::{
    build_task_key, is_runtime_task_name_supported, send_task_reply, spawn_task_monitor,
    stop_runtime_tasks, validate_task_start_input,
};
use opensnitch_proto::pb;
use serde_json::json;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

#[test]
fn build_task_key_normalizes_aliases_and_uses_identity_keys() {
    assert_eq!(
        build_task_key("pidmonitor", &json!({ "pid": "4242" })),
        "pid-monitor:4242"
    );
    assert_eq!(
        build_task_key("nodemonitor", &json!({ "node": "alpha" })),
        "node-monitor:alpha"
    );
    assert_eq!(
        build_task_key("socketsmonitor", &json!({})),
        "sockets-monitor"
    );
}

#[test]
fn build_task_key_defaults_node_monitor_key_when_node_missing() {
    assert_eq!(
        build_task_key("node-monitor", &json!({})),
        "node-monitor:default"
    );
}

#[test]
fn build_task_key_uses_instance_suffix_when_data_is_missing() {
    assert_eq!(
        build_task_key("pid-monitor-4242", &json!({})),
        "pid-monitor:4242"
    );
    assert_eq!(
        build_task_key("node-monitor-main", &json!({})),
        "node-monitor:main"
    );
    assert_eq!(
        build_task_key("pidmonitor-555", &json!({})),
        "pid-monitor:555"
    );
    assert_eq!(
        build_task_key("nodemonitor-edge", &json!({})),
        "node-monitor:edge"
    );
}

#[test]
fn validate_task_start_input_checks_pid_monitor_inputs() {
    assert!(validate_task_start_input("node-monitor", &json!({ "node": "main" })).is_ok());

    let invalid = validate_task_start_input("pid-monitor", &json!({"pid": "abc"}));
    assert!(invalid.is_err());

    let invalid_interval = validate_task_start_input(
        "pid-monitor",
        &json!({"pid": std::process::id().to_string(), "interval": "bogus"}),
    );
    assert!(invalid_interval.is_err());

    let running_pid = std::process::id().to_string();
    let from_data = validate_task_start_input("pid-monitor", &json!({"pid": running_pid}));
    assert!(from_data.is_ok());

    let from_suffix =
        validate_task_start_input(&format!("pid-monitor-{}", std::process::id()), &json!({}));
    assert!(from_suffix.is_ok());

    let node_missing = validate_task_start_input("node-monitor", &json!({}));
    assert!(node_missing.is_err());

    let sockets_missing =
        validate_task_start_input("sockets-monitor", &json!({"family": 2, "proto": 6}));
    assert!(sockets_missing.is_err());

    let sockets_ok = validate_task_start_input(
        "sockets-monitor",
        &json!({"family": 2, "proto": 6, "state": 1}),
    );
    assert!(sockets_ok.is_ok());
}

#[test]
fn is_runtime_task_name_supported_accepts_known_aliases_only() {
    assert!(is_runtime_task_name_supported("pidmonitor"));
    assert!(is_runtime_task_name_supported("node-monitor-main"));
    assert!(is_runtime_task_name_supported("socketsmonitor"));
    assert!(!is_runtime_task_name_supported("downloader-list-a"));
    assert!(!is_runtime_task_name_supported("unknown-task"));
}

#[tokio::test]
async fn stop_runtime_tasks_cancels_all_handles() {
    let first = CancellationToken::new();
    let second = CancellationToken::new();
    let first_child = first.clone();
    let second_child = second.clone();

    let mut handles = std::collections::HashMap::from([
        (
            "pid-monitor:1".to_string(),
            (
                tokio::spawn(async move {
                    first_child.cancelled().await;
                }),
                first,
            ),
        ),
        (
            "node-monitor:alpha".to_string(),
            (
                tokio::spawn(async move {
                    second_child.cancelled().await;
                }),
                second,
            ),
        ),
    ]);

    assert_eq!(stop_runtime_tasks(&mut handles), 2);
    assert!(handles.is_empty());
}

#[tokio::test]
async fn send_task_reply_keeps_zero_notification_id_for_disk_tasks() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<pb::NotificationReply>(1);

    send_task_reply(
        &tx,
        0,
        pb::NotificationReplyCode::Ok,
        "disk payload".to_string(),
    )
    .await;

    let reply = rx.recv().await.expect("reply should be sent");
    assert_eq!(reply.id, 0);
    assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);
    assert_eq!(reply.data, "disk payload");
}

#[tokio::test]
async fn send_task_reply_keeps_existing_notification_id() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<pb::NotificationReply>(1);

    send_task_reply(
        &tx,
        77,
        pb::NotificationReplyCode::Error,
        "oops".to_string(),
    )
    .await;

    let reply = rx.recv().await.expect("reply should be sent");
    assert_eq!(reply.id, 77);
    assert_eq!(reply.code, pb::NotificationReplyCode::Error as i32);
    assert_eq!(reply.data, "oops");
}

#[tokio::test]
async fn spawn_task_monitor_emits_adding_task_log() {
    use crate::{
        services::process_service::ProcessService, utils::test_support::init_test_logging,
    };

    init_test_logging();
    let (tx, _rx) = tokio::sync::mpsc::channel::<pb::NotificationReply>(1);
    let token = CancellationToken::new();
    let handle = spawn_task_monitor(
        "basic-task",
        1,
        &json!({}),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    token.cancel();
    let _ = handle.await;
}

#[tokio::test]
async fn pid_monitor_emits_first_sample_without_waiting_full_interval() {
    use crate::services::process_service::ProcessService;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<pb::NotificationReply>(4);
    let token = CancellationToken::new();
    let handle = spawn_task_monitor(
        "pid-monitor",
        11_001,
        &json!({
            "pid": "999999",
            "interval": "5s"
        }),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    let reply = timeout(Duration::from_millis(900), rx.recv())
        .await
        .expect("pid monitor first sample timeout")
        .expect("pid monitor reply missing");
    assert_eq!(reply.id, 11_001);
    assert_eq!(reply.code, pb::NotificationReplyCode::Error as i32);

    token.cancel();
    let _ = timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn node_monitor_emits_first_sample_without_waiting_full_interval() {
    use crate::services::process_service::ProcessService;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<pb::NotificationReply>(4);
    let token = CancellationToken::new();
    let handle = spawn_task_monitor(
        "node-monitor",
        12_001,
        &json!({
            "node": "main",
            "interval": "5s"
        }),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    let reply = timeout(Duration::from_millis(900), rx.recv())
        .await
        .expect("node monitor first sample timeout")
        .expect("node monitor reply missing");
    assert_eq!(reply.id, 12_001);
    assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);

    token.cancel();
    let _ = timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn looper_reply_payload_matches_go_interval_string() {
    use crate::services::process_service::ProcessService;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<pb::NotificationReply>(4);
    let token = CancellationToken::new();
    let handle = spawn_task_monitor(
        "looper",
        13_001,
        &json!({"interval": "100ms"}),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    let reply = timeout(Duration::from_millis(900), rx.recv())
        .await
        .expect("looper first sample timeout")
        .expect("looper reply missing");
    assert_eq!(reply.id, 13_001);
    assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);
    assert_eq!(reply.data, "100ms");

    token.cancel();
    let _ = timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn ioc_scanner_without_schedule_emits_no_periodic_results() {
    use crate::services::process_service::ProcessService;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<pb::NotificationReply>(4);
    let token = CancellationToken::new();
    let handle = spawn_task_monitor(
        "ioc-scanner",
        14_001,
        &json!({
            "interval": "100ms",
            "tools": [],
            "schedule": []
        }),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    assert!(
        timeout(Duration::from_millis(450), rx.recv())
            .await
            .is_err(),
        "ioc-scanner without schedule should not emit periodic replies"
    );

    token.cancel();
    let _ = timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn downloader_notify_payload_matches_go_success_message_shape() {
    use crate::services::process_service::ProcessService;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<pb::NotificationReply>(4);
    let token = CancellationToken::new();
    let handle = spawn_task_monitor(
        "downloader",
        15_001,
        &json!({
            "interval": "100ms",
            "notify": {"enabled": true},
            "urls": []
        }),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    let reply = timeout(Duration::from_millis(900), rx.recv())
        .await
        .expect("downloader first sample timeout")
        .expect("downloader reply missing");
    assert_eq!(reply.id, 15_001);
    assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);
    assert_eq!(reply.data, "[blocklists] lists updated");

    token.cancel();
    let _ = timeout(Duration::from_secs(1), handle).await;
}
