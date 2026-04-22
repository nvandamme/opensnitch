use crate::services::{
    lifecycle::ServiceLifecycle,
    task::{
        TaskRuntime, TaskService, TaskStorageRuntime, naming as task_runtime_naming,
        validation as task_runtime_validation,
    },
};
use serde_json::json;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;
use transport_wire_core::{WireNotificationReply, WireNotificationReplyCode};

#[test]
fn build_task_key_normalizes_aliases_and_uses_identity_keys() {
    assert_eq!(
        task_runtime_naming::build_task_key(
            "pidmonitor",
            &crate::services::task::TaskRuntimePayload::from_task_data(
                "pidmonitor",
                json!({ "pid": "4242" }),
            ),
        ),
        "pid-monitor:4242"
    );
    assert_eq!(
        task_runtime_naming::build_task_key(
            "nodemonitor",
            &crate::services::task::TaskRuntimePayload::from_task_data(
                "nodemonitor",
                json!({ "node": "alpha" }),
            ),
        ),
        "node-monitor:alpha"
    );
    assert_eq!(
        task_runtime_naming::build_task_key(
            "socketsmonitor",
            &crate::services::task::TaskRuntimePayload::from_task_data(
                "socketsmonitor",
                json!({}),
            ),
        ),
        "sockets-monitor"
    );
}

#[test]
fn build_task_key_defaults_node_monitor_key_when_node_missing() {
    assert_eq!(
        task_runtime_naming::build_task_key(
            "node-monitor",
            &crate::services::task::TaskRuntimePayload::from_task_data("node-monitor", json!({})),
        ),
        "node-monitor:default"
    );
}

#[test]
fn build_task_key_uses_instance_suffix_when_data_is_missing() {
    assert_eq!(
        task_runtime_naming::build_task_key(
            "pid-monitor-4242",
            &crate::services::task::TaskRuntimePayload::from_task_data("pid-monitor-4242", json!({})),
        ),
        "pid-monitor:4242"
    );
    assert_eq!(
        task_runtime_naming::build_task_key(
            "node-monitor-main",
            &crate::services::task::TaskRuntimePayload::from_task_data("node-monitor-main", json!({})),
        ),
        "node-monitor:main"
    );
    assert_eq!(
        task_runtime_naming::build_task_key(
            "pidmonitor-555",
            &crate::services::task::TaskRuntimePayload::from_task_data("pidmonitor-555", json!({})),
        ),
        "pid-monitor:555"
    );
    assert_eq!(
        task_runtime_naming::build_task_key(
            "nodemonitor-edge",
            &crate::services::task::TaskRuntimePayload::from_task_data("nodemonitor-edge", json!({})),
        ),
        "node-monitor:edge"
    );
}

#[test]
fn validate_task_start_input_checks_pid_monitor_inputs() {
    assert!(
        task_runtime_validation::validate_task_start_input(
            "node-monitor",
            &crate::services::task::TaskRuntimePayload::from_task_data(
                "node-monitor",
                json!({ "node": "main" }),
            ),
        )
        .is_ok()
    );

    let invalid = task_runtime_validation::validate_task_start_input(
        "pid-monitor",
        &crate::services::task::TaskRuntimePayload::from_task_data(
            "pid-monitor",
            json!({"pid": "abc"}),
        ),
    );
    assert!(invalid.is_err());

    let invalid_interval = task_runtime_validation::validate_task_start_input(
        "pid-monitor",
        &crate::services::task::TaskRuntimePayload::from_task_data(
            "pid-monitor",
            json!({"pid": std::process::id().to_string(), "interval": "bogus"}),
        ),
    );
    assert!(invalid_interval.is_err());

    let running_pid = std::process::id().to_string();
    let from_data = task_runtime_validation::validate_task_start_input(
        "pid-monitor",
        &crate::services::task::TaskRuntimePayload::from_task_data(
            "pid-monitor",
            json!({"pid": running_pid}),
        ),
    );
    assert!(from_data.is_ok());

    let from_suffix = task_runtime_validation::validate_task_start_input(
        &format!("pid-monitor-{}", std::process::id()),
        &crate::services::task::TaskRuntimePayload::from_task_data(
            &format!("pid-monitor-{}", std::process::id()),
            json!({}),
        ),
    );
    assert!(from_suffix.is_ok());

    let node_missing = task_runtime_validation::validate_task_start_input(
        "node-monitor",
        &crate::services::task::TaskRuntimePayload::from_task_data("node-monitor", json!({})),
    );
    assert!(node_missing.is_err());

    let sockets_missing = task_runtime_validation::validate_task_start_input(
        "sockets-monitor",
        &crate::services::task::TaskRuntimePayload::from_task_data(
            "sockets-monitor",
            json!({"family": 2, "proto": 6}),
        ),
    );
    assert!(sockets_missing.is_err());

    let sockets_ok = task_runtime_validation::validate_task_start_input(
        "sockets-monitor",
        &crate::services::task::TaskRuntimePayload::from_task_data(
            "sockets-monitor",
            json!({"family": 2, "proto": 6, "state": 1}),
        ),
    );
    assert!(sockets_ok.is_ok());
}

#[test]
fn is_runtime_task_name_supported_accepts_known_aliases_only() {
    assert!(task_runtime_validation::is_runtime_task_name_supported(
        "pidmonitor"
    ));
    assert!(task_runtime_validation::is_runtime_task_name_supported(
        "node-monitor-main"
    ));
    assert!(task_runtime_validation::is_runtime_task_name_supported(
        "socketsmonitor"
    ));
    assert!(!task_runtime_validation::is_runtime_task_name_supported(
        "downloader-list-a"
    ));
    assert!(!task_runtime_validation::is_runtime_task_name_supported(
        "unknown-task"
    ));
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
            TaskStorageRuntime::runtime(
                tokio::spawn(async move {
                    first_child.cancelled().await;
                }),
                first,
            ),
        ),
        (
            "node-monitor:alpha".to_string(),
            TaskStorageRuntime::runtime(
                tokio::spawn(async move {
                    second_child.cancelled().await;
                }),
                second,
            ),
        ),
    ]);

    assert_eq!(TaskService::stop_runtime_tasks(&mut handles), 2);
    assert!(handles.is_empty());
}

#[tokio::test]
async fn lifecycle_subscriptions_increment_and_decrement_monitor_counters() {
    use crate::services::process::ProcessService;

    let (task_reply_tx, _task_reply_rx) = tokio::sync::mpsc::channel::<WireNotificationReply>(8);
    let shutdown = CancellationToken::new();
    let runtime = TaskRuntime::new(
        TaskService,
        ProcessService::default(),
        task_reply_tx,
        shutdown,
    );

    let stats = ServiceLifecycle::monitor_stats(&runtime);
    assert_eq!(stats.status_subscribers, 0);
    assert_eq!(stats.event_subscribers, 0);

    let status_sub = ServiceLifecycle::subscribe_status(&runtime).expect("subscribe status");
    let event_sub = ServiceLifecycle::subscribe_events(&runtime).expect("subscribe events");

    let stats = ServiceLifecycle::monitor_stats(&runtime);
    assert_eq!(stats.status_subscribers, 1);
    assert_eq!(stats.event_subscribers, 1);

    drop(status_sub);
    let stats = ServiceLifecycle::monitor_stats(&runtime);
    assert_eq!(stats.status_subscribers, 0);
    assert_eq!(stats.event_subscribers, 1);

    drop(event_sub);
    let stats = ServiceLifecycle::monitor_stats(&runtime);
    assert_eq!(stats.status_subscribers, 0);
    assert_eq!(stats.event_subscribers, 0);
}

#[tokio::test]
async fn send_task_reply_keeps_zero_notification_id_for_disk_tasks() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<WireNotificationReply>(1);

    let _ = crate::utils::notification_reply::send_notification_reply(
        &tx,
        0,
        WireNotificationReplyCode::Ok,
        "disk payload".to_string(),
        "task notification",
    )
    .await;

    let reply = rx.recv().await.expect("reply should be sent");
    assert_eq!(reply.id, 0);
    assert_eq!(reply.code, WireNotificationReplyCode::Ok as i32);
    assert_eq!(reply.data, "disk payload");
}

#[tokio::test]
async fn send_task_reply_keeps_existing_notification_id() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<WireNotificationReply>(1);

    let _ = crate::utils::notification_reply::send_notification_reply(
        &tx,
        77,
        WireNotificationReplyCode::Error,
        "oops".to_string(),
        "task notification",
    )
    .await;

    let reply = rx.recv().await.expect("reply should be sent");
    assert_eq!(reply.id, 77);
    assert_eq!(reply.code, WireNotificationReplyCode::Error as i32);
    assert_eq!(reply.data, "oops");
}

#[tokio::test]
async fn spawn_task_monitor_emits_adding_task_log() {
    use crate::services::process::ProcessService;

    crate::tests::support::init_test_logging();
    let (tx, _rx) = tokio::sync::mpsc::channel::<WireNotificationReply>(1);
    let token = CancellationToken::new();
    let handle = TaskService.spawn_task_monitor_snapshot(
        "basic-task",
        1,
        crate::services::task::TaskRuntimePayload::from_task_data("basic-task", json!({})),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    token.cancel();
    let _ = handle.await;
}

#[tokio::test]
async fn pid_monitor_emits_first_sample_without_waiting_full_interval() {
    use crate::services::process::ProcessService;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<WireNotificationReply>(4);
    let token = CancellationToken::new();
    let handle = TaskService.spawn_task_monitor_snapshot(
        "pid-monitor",
        11_001,
        crate::services::task::TaskRuntimePayload::from_task_data("pid-monitor", json!({
            "pid": "999999",
            "interval": "5s"
        })),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    let reply = timeout(Duration::from_millis(900), rx.recv())
        .await
        .expect("pid monitor first sample timeout")
        .expect("pid monitor reply missing");
    assert_eq!(reply.id, 11_001);
    assert_eq!(reply.code, WireNotificationReplyCode::Error as i32);

    token.cancel();
    let _ = timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn node_monitor_emits_first_sample_without_waiting_full_interval() {
    use crate::services::process::ProcessService;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<WireNotificationReply>(4);
    let token = CancellationToken::new();
    let handle = TaskService.spawn_task_monitor_snapshot(
        "node-monitor",
        12_001,
        crate::services::task::TaskRuntimePayload::from_task_data("node-monitor", json!({
            "node": "main",
            "interval": "5s"
        })),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    let reply = timeout(Duration::from_millis(900), rx.recv())
        .await
        .expect("node monitor first sample timeout")
        .expect("node monitor reply missing");
    assert_eq!(reply.id, 12_001);
    assert_eq!(reply.code, WireNotificationReplyCode::Ok as i32);

    token.cancel();
    let _ = timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn looper_reply_payload_matches_go_interval_string() {
    use crate::services::process::ProcessService;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<WireNotificationReply>(4);
    let token = CancellationToken::new();
    let handle = TaskService.spawn_task_monitor_snapshot(
        "looper",
        13_001,
        crate::services::task::TaskRuntimePayload::from_task_data("looper", json!({"interval": "100ms"})),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    let reply = timeout(Duration::from_millis(900), rx.recv())
        .await
        .expect("looper first sample timeout")
        .expect("looper reply missing");
    assert_eq!(reply.id, 13_001);
    assert_eq!(reply.code, WireNotificationReplyCode::Ok as i32);
    assert_eq!(reply.data, "100ms");

    token.cancel();
    let _ = timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn ioc_scanner_without_schedule_emits_no_periodic_results() {
    use crate::services::process::ProcessService;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<WireNotificationReply>(4);
    let token = CancellationToken::new();
    let handle = TaskService.spawn_task_monitor_snapshot(
        "ioc-scanner",
        14_001,
        crate::services::task::TaskRuntimePayload::from_task_data("ioc-scanner", json!({
            "interval": "100ms",
            "tools": [],
            "schedule": []
        })),
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
    use crate::services::process::ProcessService;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<WireNotificationReply>(4);
    let token = CancellationToken::new();
    let handle = TaskService.spawn_task_monitor_snapshot(
        "downloader",
        15_001,
        crate::services::task::TaskRuntimePayload::from_task_data("downloader", json!({
            "interval": "100ms",
            "notify": {"enabled": true},
            "urls": []
        })),
        token.clone(),
        ProcessService::default(),
        tx,
    );

    let reply = timeout(Duration::from_millis(900), rx.recv())
        .await
        .expect("downloader first sample timeout")
        .expect("downloader reply missing");
    assert_eq!(reply.id, 15_001);
    assert_eq!(reply.code, WireNotificationReplyCode::Ok as i32);
    assert_eq!(reply.data, "[blocklists] lists updated");

    token.cancel();
    let _ = timeout(Duration::from_secs(1), handle).await;
}

#[test]
fn normalize_task_name_accepts_legacy_aliases() {
    assert_eq!(
        task_runtime_naming::normalized_task_name("pidmonitor"),
        "pid-monitor"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("nodemonitor"),
        "node-monitor"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("socketsmonitor"),
        "sockets-monitor"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("iocscanner"),
        "ioc-scanner"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("looptask"),
        "looper"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("  PID-MONITOR  "),
        "pid-monitor"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("pid-monitor-123"),
        "pid-monitor"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("node-monitor-main"),
        "node-monitor"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("socketsmonitor-debug"),
        "sockets-monitor"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("netstat"),
        "sockets-monitor"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("netstat-main"),
        "sockets-monitor"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("iocscanner-weekly"),
        "ioc-scanner"
    );
    assert_eq!(
        task_runtime_naming::normalized_task_name("downloader-list-a"),
        "downloader"
    );
}

#[test]
fn parse_task_interval_parses_supported_units() {
    assert_eq!(
        crate::utils::duration_parse::parse_human_duration(
            "250ms",
            crate::utils::duration_parse::TASK_INTERVAL_OPTIONS,
        ),
        Some(std::time::Duration::from_millis(250))
    );
    assert_eq!(
        crate::utils::duration_parse::parse_human_duration(
            "5s",
            crate::utils::duration_parse::TASK_INTERVAL_OPTIONS,
        ),
        Some(std::time::Duration::from_secs(5))
    );
    assert_eq!(
        crate::utils::duration_parse::parse_human_duration(
            "2m",
            crate::utils::duration_parse::TASK_INTERVAL_OPTIONS,
        ),
        Some(std::time::Duration::from_secs(120))
    );
    assert_eq!(
        crate::utils::duration_parse::parse_human_duration(
            "1h",
            crate::utils::duration_parse::TASK_INTERVAL_OPTIONS,
        ),
        Some(std::time::Duration::from_secs(3600))
    );
    assert!(
        crate::utils::duration_parse::parse_human_duration(
            "oops",
            crate::utils::duration_parse::TASK_INTERVAL_OPTIONS,
        )
        .is_none()
    );
}

#[test]
fn ioc_schedule_time_matches_hh_mm_and_hh_mm_ss() {
    assert!(crate::utils::time_spec::matches_hms_spec("09:15", 9, 15, 0));
    assert!(crate::utils::time_spec::matches_hms_spec(
        "09:15:30", 9, 15, 30
    ));
    assert!(!crate::utils::time_spec::matches_hms_spec(
        "09:15", 9, 15, 31
    ));
    assert!(!crate::utils::time_spec::matches_hms_spec("bad", 9, 15, 0));
}

#[test]
fn ioc_schedule_matches_now_from_time_entry() {
    let data = crate::services::task::TaskRuntimePayload::from_task_data(
        "ioc-scanner",
        json!({
            "schedule": [
                {
                    "weekday": [1],
                    "time": ["11:22:33"]
                }
            ]
        }),
    );

    let now = time::Date::from_calendar_date(2026, time::Month::April, 6)
        .expect("valid date")
        .with_hms(11, 22, 33)
        .expect("valid time")
        .assume_utc();
    assert!(TaskService.ioc_schedule_matches_now(&data, now));
}

#[test]
fn ioc_schedule_matches_now_from_hour_minute_second_arrays() {
    let data = crate::services::task::TaskRuntimePayload::from_task_data(
        "ioc-scanner",
        json!({
            "schedule": [
                {
                    "weekday": [2],
                    "hour": [14],
                    "minute": [9],
                    "second": [7]
                }
            ]
        }),
    );

    let now = time::Date::from_calendar_date(2026, time::Month::April, 7)
        .expect("valid date")
        .with_hms(14, 9, 7)
        .expect("valid time")
        .assume_utc();
    assert!(TaskService.ioc_schedule_matches_now(&data, now));
}

#[test]
fn is_disk_task_name_supported_accepts_known_aliases_only() {
    assert!(task_runtime_validation::storage_task_name_supported(
        "downloader-list-a"
    ));
    assert!(task_runtime_validation::storage_task_name_supported(
        "looptask"
    ));
    assert!(task_runtime_validation::storage_task_name_supported(
        "iocscanner-weekly"
    ));
    assert!(!task_runtime_validation::storage_task_name_supported(
        "pid-monitor-123"
    ));
}

#[test]
fn validate_task_start_input_reuses_storage_task_interval_classification() {
    let invalid_interval = task_runtime_validation::validate_task_start_input(
        "downloader-list-a",
        &crate::services::task::TaskRuntimePayload::from_task_data(
            "downloader-list-a",
            json!({"interval": "bogus"}),
        ),
    );
    assert_eq!(
        invalid_interval,
        Err("invalid interval for downloader".to_string())
    );

    let looper_ok = task_runtime_validation::validate_task_start_input(
        "looptask",
        &crate::services::task::TaskRuntimePayload::from_task_data(
            "looptask",
            json!({"interval": "1s"}),
        ),
    );
    assert!(looper_ok.is_ok());
}

#[test]
fn legacy_downloader_task_result_matches_go_taskresults_shape() {
    let payload = crate::services::task::reply::build_legacy_downloader_task_result(
        "[blocklists] lists updated",
    );
    let parsed: serde_json::Value =
        transport_wire_core::decode_json_notification_payload(&payload).expect("valid JSON");
    assert_eq!(parsed["Type"], 9999);
    assert_eq!(parsed["Data"], "[blocklists] lists updated");
}

#[tokio::test]
async fn stop_disk_tasks_cancels_all_handles() {
    let token = CancellationToken::new();
    let token_child = token.clone();
    let mut handles = std::collections::HashMap::from([(
        "disk-task:downloader".to_string(),
        TaskStorageRuntime {
            handle: tokio::spawn(async move {
                token_child.cancelled().await;
            }),
            token,
            fingerprint: "abc123".to_string(),
        },
    )]);

    assert_eq!(TaskService::stop_runtime_tasks(&mut handles), 1);
    assert!(handles.is_empty());
}
