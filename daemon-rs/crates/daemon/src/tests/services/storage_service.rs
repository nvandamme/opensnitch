use crate::services::storage::{StorageFormat, StorageOperation, StorageService};
use crate::tests::support::{
    TestDir, assert_storage_event, assert_storage_event_async, assert_storage_event_empty,
    ensure_dir, read_text, write_text,
};
use crate::{
    models::audit::{AuditEventKind, StorageAction},
    services::audit::AuditService,
};
use serde::Deserialize;
use tokio::time::{Duration, timeout};

fn test_dir(label: &str) -> TestDir {
    TestDir::new(&format!("opensnitch-storage-{label}"))
}

#[test]
fn local_service_broadcasts_storage_events() {
    let service = StorageService::new();
    let mut subscription = service.subscribe_events();
    let dir = test_dir("local-event");
    let path = dir.path.join("config.json");
    let temp_path = dir.path.join("config.json.tmp");

    service
        .write_bytes_atomic_sync_and_notify("config", &temp_path, &path, br#"{"ok":true}"#)
        .expect("emit write event through io path");

    assert_storage_event(
        &mut subscription,
        "storage event",
        "config",
        StorageOperation::Write,
        &path,
    );
}

#[tokio::test]
async fn async_io_helpers_emit_completed_events() {
    let service = StorageService::new();
    let mut subscription = service.subscribe_events();
    let dir = test_dir("async-io");
    let path = dir.path.join("config.json");

    write_text(&path, "hello");

    let contents = service
        .read_to_string_and_notify("config", &path)
        .await
        .expect("read file");
    assert_eq!(contents, "hello");
    assert_storage_event_async(
        &mut subscription,
        "read event",
        "config",
        StorageOperation::Read,
        &path,
    )
    .await;

    let deleted = service
        .remove_file_if_exists_and_notify("config", &path)
        .await
        .expect("delete file");
    assert!(deleted);
    assert_storage_event_async(
        &mut subscription,
        "delete event",
        "config",
        StorageOperation::Delete,
        &path,
    )
    .await;
}

#[test]
fn sync_atomic_write_helper_emits_write_event() {
    let service = StorageService::new();
    let mut subscription = service.subscribe_events();
    let dir = test_dir("sync-write");
    let path = dir.path.join("subscriptions.json");
    let temp_path = dir.path.join("subscriptions.json.tmp");

    service
        .write_bytes_atomic_sync_and_notify("subscription", &temp_path, &path, br#"{"ok":true}"#)
        .expect("write file");

    assert_eq!(read_text(&path), r#"{"ok":true}"#);
    assert_storage_event(
        &mut subscription,
        "write event",
        "subscription",
        StorageOperation::Write,
        &path,
    );
}

#[test]
fn path_exists_sync_and_notify_have_explicit_event_semantics() {
    let service = StorageService::new();
    let mut subscription = service.subscribe_events();
    let dir = test_dir("path-exists-sync-semantics");
    let file_path = dir.path.join("payload.txt");
    write_text(&file_path, "hello");

    let exists = service
        .path_exists_sync("rule", &file_path)
        .expect("path exists sync");
    assert!(exists);
    assert_storage_event_empty(&mut subscription);

    let exists = service
        .path_exists_sync_and_notify("rule", &file_path)
        .expect("path exists sync notify");
    assert!(exists);
    assert_storage_event(
        &mut subscription,
        "read event",
        "rule",
        StorageOperation::Read,
        &file_path,
    );
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct DemoJson {
    ok: bool,
}

#[tokio::test]
async fn json_helpers_parse_and_emit_read_event() {
    let service = StorageService::new();
    let mut subscription = service.subscribe_events();
    let dir = test_dir("json-read");
    let path = dir.path.join("payload.json");
    write_text(&path, r#"{"ok":true}"#);

    let parsed: DemoJson = service
        .read_and_parse_with_storage_format_and_notify("rule", &path)
        .await
        .expect("read json");
    assert_eq!(parsed, DemoJson { ok: true });
    assert_storage_event_async(
        &mut subscription,
        "read event",
        "rule",
        StorageOperation::Read,
        &path,
    )
    .await;
}

#[tokio::test]
async fn storage_helpers_fallback_to_json_when_extension_is_unknown() {
    let service = StorageService::new();
    let dir = test_dir("json-fallback");
    let path = dir.path.join("payload.unknown");
    write_text(&path, r#"{"ok":true}"#);

    let parsed: DemoJson = service
        .read_and_parse_with_storage_format("rule", &path)
        .await
        .expect("parse unknown extension as default json");
    assert_eq!(parsed, DemoJson { ok: true });
}

#[tokio::test]
async fn storage_helpers_honor_explicit_main_storage_format_override() {
    #[cfg(feature = "storage-format-json")]
    let (format, dir_tag, file_name, payload) = (
        StorageFormat::Json,
        "json-main-format",
        "payload.yaml",
        r#"{"ok":true}"#,
    );

    #[cfg(all(not(feature = "storage-format-json"), feature = "storage-format-yaml"))]
    let (format, dir_tag, file_name, payload) = (
        StorageFormat::Yaml,
        "yaml-main-format",
        "payload.json",
        "ok: true\n",
    );

    #[cfg(all(
        not(feature = "storage-format-json"),
        not(feature = "storage-format-yaml"),
        feature = "storage-format-toml"
    ))]
    let (format, dir_tag, file_name, payload) = (
        StorageFormat::Toml,
        "toml-main-format",
        "payload.json",
        "ok = true\n",
    );

    let service = StorageService::new().with_main_storage_format(Some(format));
    let dir = test_dir(dir_tag);
    let path = dir.path.join(file_name);
    write_text(&path, payload);

    let parsed: DemoJson = service
        .read_and_parse_with_storage_format("rule", &path)
        .await
        .expect("parse using explicit main storage format override");
    assert_eq!(parsed, DemoJson { ok: true });
}

#[test]
fn path_subscription_receives_only_exact_path_events() {
    let service = StorageService::new();
    let dir = test_dir("path-filter");
    let observed = dir.path.join("observed.json");
    let other = dir.path.join("other.json");
    let observed_tmp = dir.path.join("observed.json.tmp");
    let other_tmp = dir.path.join("other.json.tmp");

    let mut filtered = service.subscribe_events_for_path(&observed);

    service
        .write_bytes_atomic_sync_and_notify("rule", &other_tmp, &other, br#"{"ok":false}"#)
        .expect("write other path");
    assert_storage_event_empty(&mut filtered);

    service
        .write_bytes_atomic_sync_and_notify("rule", &observed_tmp, &observed, br#"{"ok":true}"#)
        .expect("write observed path");

    assert_storage_event(
        &mut filtered,
        "observed event",
        "rule",
        StorageOperation::Write,
        &observed,
    );
}

#[test]
fn prefix_subscription_receives_events_under_observed_path() {
    let service = StorageService::new();
    let dir = test_dir("prefix-filter");
    let observed_dir = dir.path.join("lists");
    let nested_dir = observed_dir.join("nested");
    let outside_dir = dir.path.join("other");
    let observed_path = nested_dir.join("domains.txt");
    let outside_path = outside_dir.join("outside.txt");
    let observed_tmp = nested_dir.join("domains.txt.tmp");
    let outside_tmp = outside_dir.join("outside.txt.tmp");

    ensure_dir(&nested_dir);
    ensure_dir(&outside_dir);

    let mut filtered = service.subscribe_events_for_prefix(&observed_dir);

    service
        .write_bytes_atomic_sync_and_notify("rule", &outside_tmp, &outside_path, br#"{"ok":false}"#)
        .expect("write outside path");
    assert_storage_event_empty(&mut filtered);

    service
        .write_bytes_atomic_sync_and_notify(
            "rule",
            &observed_tmp,
            &observed_path,
            br#"{"ok":true}"#,
        )
        .expect("write observed prefix path");

    assert_storage_event(
        &mut filtered,
        "observed prefix event",
        "rule",
        StorageOperation::Write,
        &observed_path,
    );
}

#[tokio::test]
async fn list_dir_with_metadata_reports_file_state() {
    let service = StorageService::new();
    let mut subscription = service.subscribe_events();
    let dir = test_dir("dir-metadata-no-emit");
    let nested_dir = dir.path.join("nested");
    let file_path = dir.path.join("payload.txt");

    ensure_dir(&nested_dir);
    write_text(&file_path, "hello");

    let entries = service
        .list_dir_with_metadata("rule", &dir.path)
        .await
        .expect("list directory with metadata");

    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|entry| { entry.path == file_path && entry.is_file && entry.modified.is_some() })
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.path == nested_dir && !entry.is_file)
    );
    assert_storage_event_empty(&mut subscription);
}

#[tokio::test]
async fn list_dir_with_metadata_and_notify_emits_scan_and_reports_file_state() {
    let service = StorageService::new();
    let mut subscription = service.subscribe_events();
    let dir = test_dir("dir-metadata-emit");
    let nested_dir = dir.path.join("nested");
    let file_path = dir.path.join("payload.txt");

    ensure_dir(&nested_dir);
    write_text(&file_path, "hello");

    let entries = service
        .list_dir_with_metadata_and_notify("rule", &dir.path)
        .await
        .expect("list directory with metadata");

    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|entry| { entry.path == file_path && entry.is_file && entry.modified.is_some() })
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.path == nested_dir && !entry.is_file)
    );
    assert_storage_event_async(
        &mut subscription,
        "scan event",
        "rule",
        StorageOperation::Scan,
        &dir.path,
    )
    .await;
}

#[tokio::test]
async fn list_dir_returns_entries_without_scan_event() {
    let service = StorageService::new();
    let mut subscription = service.subscribe_events();
    let dir = test_dir("dir-list-no-emit");
    let nested_dir = dir.path.join("nested");
    let file_path = dir.path.join("payload.txt");

    ensure_dir(&nested_dir);
    write_text(&file_path, "hello");

    let entries = service
        .list_dir("rule", &dir.path)
        .await
        .expect("list directory");

    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|entry| entry == &file_path));
    assert!(entries.iter().any(|entry| entry == &nested_dir));
    assert_storage_event_empty(&mut subscription);
}

#[tokio::test]
async fn path_exists_and_notify_have_explicit_event_semantics() {
    let service = StorageService::new();
    let mut subscription = service.subscribe_events();
    let dir = test_dir("path-exists-semantics");
    let file_path = dir.path.join("payload.txt");
    write_text(&file_path, "hello");

    let exists = service
        .path_exists("rule", &file_path)
        .await
        .expect("path exists no emit");
    assert!(exists);
    assert_storage_event_empty(&mut subscription);

    let exists = service
        .path_exists_and_notify("rule", &file_path)
        .await
        .expect("path exists emit");
    assert!(exists);
    assert_storage_event_async(
        &mut subscription,
        "read event",
        "rule",
        StorageOperation::Read,
        &file_path,
    )
    .await;
}

#[tokio::test]
async fn read_failure_emits_storage_audit_event_when_audit_is_injected() {
    let audit = AuditService::new(32);
    let service = StorageService::new().with_audit(audit.clone());
    let mut audit_rx = audit.subscribe();
    let dir = test_dir("audit-read-failure");
    let missing_path = dir.path.join("missing.json");

    let read_result = service
        .read_to_string_and_notify("config", &missing_path)
        .await;
    assert!(read_result.is_err());

    let event = timeout(Duration::from_secs(1), audit_rx.recv())
        .await
        .expect("audit recv timeout")
        .expect("audit event");

    match &event.kind {
        AuditEventKind::StorageAction(StorageAction::FileReadFailed { path, reason }) => {
            assert_eq!(path.as_ref(), missing_path.display().to_string());
            assert_eq!(*reason, "not-found");
        }
        other => panic!("unexpected audit kind: {other:?}"),
    }
}

#[tokio::test]
async fn write_failure_emits_storage_audit_event_when_audit_is_injected() {
    let audit = AuditService::new(32);
    let service = StorageService::new().with_audit(audit.clone());
    let mut audit_rx = audit.subscribe();
    let dir = test_dir("audit-write-failure");
    let missing_parent = dir.path.join("missing-parent");
    let path = missing_parent.join("payload.json");
    let temp_path = missing_parent.join("payload.json.tmp");

    let write_result = service
        .write_bytes_atomic_and_notify("config", &temp_path, &path, br#"{"ok":true}"#)
        .await;
    assert!(write_result.is_err());

    let event = timeout(Duration::from_secs(1), audit_rx.recv())
        .await
        .expect("audit recv timeout")
        .expect("audit event");

    match &event.kind {
        AuditEventKind::StorageAction(StorageAction::FileWriteFailed { path: got, reason }) => {
            assert_eq!(got.as_ref(), path.display().to_string());
            assert_eq!(*reason, "not-found");
        }
        other => panic!("unexpected audit kind: {other:?}"),
    }
}
