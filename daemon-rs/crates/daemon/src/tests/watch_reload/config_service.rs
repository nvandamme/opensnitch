use std::fs;

use crate::config::Config;
use crate::services::config::ConfigService;
use crate::tests::support::TestDir;

async fn apply_raw_json_via_disk(
    service: &ConfigService,
    raw_json: &str,
) -> anyhow::Result<Config> {
    let updated = service.parse_raw_json(raw_json).await?;
    service.persist_raw_json(raw_json).await?;
    service.set_snapshot(updated.clone()).await;
    Ok(updated)
}

#[tokio::test]
async fn apply_raw_json_updates_runtime_snapshot() {
    let dir = TestDir::new("opensnitch-config-service-test");
    let config_path = dir.path.join("default-config.json");
    fs::write(&config_path, "{}").expect("write initial config");

    let mut base = Config::default();
    base.config_path = config_path.clone();
    let service = ConfigService::new(base);

    let updated = apply_raw_json_via_disk(
        &service,
        r#"{"LogLevel":7,"Server":{"Address":"http://127.0.0.1:50052"}}"#,
    )
    .await
    .expect("apply raw json");

    assert_eq!(updated.log_level, 7);
    assert_eq!(updated.client_addr, "http://127.0.0.1:50052");

    let snapshot = service.get_snapshot();
    assert_eq!(snapshot.log_level, 7);
    assert_eq!(snapshot.client_addr, "http://127.0.0.1:50052");
}

#[tokio::test]
async fn apply_raw_json_invalid_proc_monitor_falls_back_to_proc() {
    let dir = TestDir::new("opensnitch-config-service-proc-fallback");
    let config_path = dir.path.join("default-config.json");
    fs::write(&config_path, "{}").expect("write initial config");

    let mut base = Config::default();
    base.config_path = config_path.clone();
    let service = ConfigService::new(base);

    let updated = apply_raw_json_via_disk(
        &service,
        r#"{"LogLevel":2,"ProcMonitorMethod":"invalid-monitor","Server":{"Address":"http://127.0.0.1:50053"}}"#,
    )
        .await
        .expect("apply raw json");

    assert!(matches!(
        updated.proc_monitor_method,
        crate::config::ProcMonitorMethod::Proc
    ));
    let snapshot = service.get_snapshot();
    assert!(matches!(
        snapshot.proc_monitor_method,
        crate::config::ProcMonitorMethod::Proc
    ));
    assert_eq!(snapshot.client_addr, "http://127.0.0.1:50053");
}

#[tokio::test]
async fn apply_raw_json_invalid_payload_does_not_mutate_snapshot() {
    let dir = TestDir::new("opensnitch-config-service-invalid-json");
    let config_path = dir.path.join("default-config.json");
    fs::write(&config_path, "{}").expect("write initial config");

    let mut base = Config::default();
    base.config_path = config_path.clone();
    let base_addr = base.client_addr.clone();
    let service = ConfigService::new(base);

    let err = service
        .parse_raw_json(r#"{"Server":{"Address":"http://127.0.0.1:50054"}"#)
        .await
        .expect_err("invalid payload should fail");
    assert!(!err.to_string().is_empty());

    let snapshot = service.get_snapshot();
    assert_eq!(snapshot.client_addr, base_addr);
}

#[tokio::test]
async fn apply_raw_json_preserves_log_level_when_payload_omits_log_level() {
    let dir = TestDir::new("opensnitch-config-service-preserve-loglevel");
    let config_path = dir.path.join("default-config.json");
    fs::write(&config_path, "{}").expect("write initial config");

    let mut base = Config::default();
    base.config_path = config_path;
    base.log_level = 4;
    let service = ConfigService::new(base);

    let updated = apply_raw_json_via_disk(
        &service,
        r#"{"Server":{"Address":"http://127.0.0.1:50099"}}"#,
    )
    .await
    .expect("apply raw json");

    assert_eq!(updated.log_level, 4);
    let snapshot = service.get_snapshot();
    assert_eq!(snapshot.log_level, 4);
}

#[tokio::test]
async fn apply_raw_json_accepts_case_insensitive_log_level_key() {
    let dir = TestDir::new("opensnitch-config-service-case-insensitive-loglevel");
    let config_path = dir.path.join("default-config.json");
    fs::write(&config_path, "{}").expect("write initial config");

    let mut base = Config::default();
    base.config_path = config_path;
    base.log_level = 2;
    let service = ConfigService::new(base);

    let updated = apply_raw_json_via_disk(
        &service,
        r#"{"loglevel":8,"server":{"address":"http://127.0.0.1:50101"}}"#,
    )
    .await
    .expect("apply raw json");

    assert_eq!(updated.log_level, 8);
    assert_eq!(updated.client_addr, "http://127.0.0.1:50101");
    let snapshot = service.get_snapshot();
    assert_eq!(snapshot.log_level, 8);
}
