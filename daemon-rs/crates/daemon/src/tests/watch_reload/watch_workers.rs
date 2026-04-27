use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use storage_format_core::StorageFormatCodec;
use storage_format_json::JsonStorageFormat;

use crate::{
    config::{Config, DefaultAction, ProcMonitorMethod},
    models::rule::storage::{RuleFile, RuleFileOperator},
    models::{
        connection::state::{ConnectionAttempt, TransportProtocol},
        process::state::ProcessInfo,
    },
    services::{
        config::ConfigService, firewall::FirewallService, rule::RuleService, stats::StatsService,
    },
    tests::support::{TestDir, path_string, remove_file_async},
    workers::{
        firewall::watch_worker as firewall_watch_worker, runtime::control::WorkerControl,
        runtime::watch,
    },
};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const WATCH_POLLER_ARM_DELAY: Duration = Duration::from_millis(2600);

fn into_join_handle(
    shutdown: CancellationToken,
    worker: Box<dyn WorkerControl>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        shutdown.cancelled().await;
        let _ = tokio::task::spawn_blocking(move || {
            let _ = worker.join();
        })
        .await;
    })
}

fn raw_config(
    address: &str,
    default_action: &str,
    proc_monitor: &str,
    firewall_config_path: &std::path::Path,
    rules_path: &std::path::Path,
    tasks_config_path: &std::path::Path,
) -> String {
    format!(
        r#"{{
  "Server": {{ "Address": "{address}" }},
  "DefaultAction": "{default_action}",
  "ProcMonitorMethod": "{proc_monitor}",
  "Firewall": "nftables",
  "FwOptions": {{ "ConfigPath": "{fw_path}", "QueueNum": 0, "QueueBypass": true }},
  "Rules": {{ "Path": "{rules_path}" }},
  "TasksOptions": {{ "ConfigPath": "{tasks_path}" }},
  "Audit": {{ "AudispSocketPath": "" }},
  "Stats": {{ "MaxEvents": 150, "MaxStats": 25, "Workers": 6 }}
}}"#,
        address = address,
        default_action = default_action,
        proc_monitor = proc_monitor,
        fw_path = firewall_config_path.display(),
        rules_path = rules_path.display(),
        tasks_path = tasks_config_path.display(),
    )
}

fn write_default_raw_config(
    config_path: &Path,
    firewall_path: &Path,
    rules_path: &Path,
    tasks_path: &Path,
) {
    let raw = raw_config(
        "http://127.0.0.1:50051",
        "allow",
        "proc",
        firewall_path,
        rules_path,
        tasks_path,
    );
    fs::write(config_path, &raw).expect("write config");
}

fn prepare_runtime_watch_fixture(rules_path: &Path, firewall_path: &Path, tasks_path: &Path) {
    fs::create_dir_all(rules_path).expect("create rules dir");
    fs::write(firewall_path, "{}").expect("write firewall config");
    fs::write(tasks_path, r#"{"tasks":[]}"#).expect("write tasks config");
}

async fn write_rule_file(rules_dir: &Path, name: &str, action: &str) {
    let rule = make_test_rule(name, action);
    tokio::fs::write(
        rules_dir.join(format!("{name}.json")),
        JsonStorageFormat
            .convert_to_storage(&rule)
            .expect("serialize test rule"),
    )
    .await
    .expect("write test rule");
}

/// Sync variant for use in timed sections — matches Go's synchronous Copy().
fn write_rule_file_sync(rules_dir: &Path, name: &str, action: &str) {
    let rule = make_test_rule(name, action);
    std::fs::write(
        rules_dir.join(format!("{name}.json")),
        JsonStorageFormat
            .convert_to_storage(&rule)
            .expect("serialize test rule"),
    )
    .expect("write test rule (sync)");
}

fn make_test_rule(name: &str, action: &str) -> RuleFile {
    RuleFile {
        created: String::new(),
        updated: String::new(),
        name: name.to_string(),
        description: String::new(),
        action: action.to_string(),
        duration: "always".to_string(),
        enabled: true,
        precedence: false,
        nolog: false,
        operator: RuleFileOperator {
            r#type: String::new(),
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    }
}

async fn write_lists_rule_file(rules_dir: &Path, name: &str, operand: &str, list_path: &Path) {
    let rule = RuleFile {
        created: String::new(),
        updated: String::new(),
        name: name.to_string(),
        description: String::new(),
        action: "deny".to_string(),
        duration: "always".to_string(),
        enabled: true,
        precedence: false,
        nolog: false,
        operator: RuleFileOperator {
            r#type: "lists".to_string(),
            operand: operand.to_string(),
            data: path_string(list_path),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    };

    tokio::fs::write(
        rules_dir.join(format!("{name}.json")),
        JsonStorageFormat
            .convert_to_storage(&rule)
            .expect("serialize lists test rule"),
    )
    .await
    .expect("write lists test rule");
}

async fn write_nested_lists_rule_file(rules_dir: &Path, name: &str, list_path: &Path) {
    let rule = RuleFile {
        created: String::new(),
        updated: String::new(),
        name: name.to_string(),
        description: String::new(),
        action: "deny".to_string(),
        duration: "always".to_string(),
        enabled: true,
        precedence: false,
        nolog: false,
        operator: RuleFileOperator {
            r#type: "list".to_string(),
            operand: "list".to_string(),
            data: String::new(),
            sensitive: false,
            scope: None,
            list: vec![
                RuleFileOperator {
                    r#type: "simple".to_string(),
                    operand: "user.id".to_string(),
                    data: "1000".to_string(),
                    sensitive: false,
                    scope: None,
                    list: Vec::new(),
                },
                RuleFileOperator {
                    r#type: "lists".to_string(),
                    operand: "lists.domains".to_string(),
                    data: path_string(list_path),
                    sensitive: false,
                    scope: None,
                    list: Vec::new(),
                },
            ],
        },
    };

    tokio::fs::write(
        rules_dir.join(format!("{name}.json")),
        JsonStorageFormat
            .convert_to_storage(&rule)
            .expect("serialize nested lists test rule"),
    )
    .await
    .expect("write nested lists test rule");
}

async fn load_rules_service(rules_path: &Path) -> RuleService {
    let rules_service = RuleService::default();
    rules_service
        .load_path(rules_path)
        .await
        .expect("load initial rules");
    rules_service
}

async fn start_rules_watch_task(
    rules_service: &RuleService,
) -> (CancellationToken, tokio::task::JoinHandle<()>) {
    let shutdown = CancellationToken::new();
    let watch_handle = into_join_handle(
        shutdown.clone(),
        rules_service.spawn_watch_task(shutdown.clone()),
    );
    tokio::time::sleep(WATCH_POLLER_ARM_DELAY).await;
    (shutdown, watch_handle)
}

async fn wait_until_host_no_match(
    rules_service: &RuleService,
    attempt: &ConnectionAttempt,
    process: &ProcessInfo,
    host: &str,
    timeout_secs: u64,
    poll_ms: u64,
    refresh_context: &str,
    timeout_context: &str,
) {
    timeout(Duration::from_secs(timeout_secs), async {
        loop {
            let decision = rules_service
                .match_attempt(attempt, process, Some(host))
                .await
                .expect(refresh_context);
            if decision.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(poll_ms)).await;
        }
    })
    .await
    .expect(timeout_context);
}

async fn assert_host_match_present(
    rules_service: &RuleService,
    attempt: &ConnectionAttempt,
    process: &ProcessInfo,
    host: &str,
    match_context: &str,
    assert_context: &str,
) {
    let initial = rules_service
        .match_attempt(attempt, process, Some(host))
        .await
        .expect(match_context);
    assert!(initial.is_some(), "{assert_context}");
}

async fn wait_until_rule_count(
    rules_service: &RuleService,
    expected: usize,
    timeout_secs: u64,
    poll_ms: u64,
    timeout_context: &str,
) {
    timeout(Duration::from_secs(timeout_secs), async {
        loop {
            let rules = rules_service.list_wire().await;
            if rules.len() == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(poll_ms)).await;
        }
    })
    .await
    .expect(timeout_context);
}

async fn stop_watch_task(shutdown: CancellationToken, watch_handle: tokio::task::JoinHandle<()>) {
    shutdown.cancel();
    let _ = timeout(Duration::from_secs(1), watch_handle).await;
}

fn probe_attempt() -> ConnectionAttempt {
    ConnectionAttempt {
        request_id: 7,
        protocol: TransportProtocol::Tcp,
        src_addr: "127.0.0.1".parse().expect("valid ip"),
        src_port: 12345,
        dst_addr: "10.0.0.2".parse().expect("valid ip"),
        dst_port: 443,
        iface_in_idx: 0,
        iface_out_idx: 0,
        dns_query: None,
        pid: 4242,
        uid: 1000,
    }
}

fn probe_process() -> ProcessInfo {
    ProcessInfo {
        pid: 4242,
        path: "/usr/bin/curl".to_string(),
        args: vec!["curl".to_string()],
        cwd: None,
        env_preview: Vec::new(),
        env_map: std::collections::HashMap::new(),
        process_hash: Some("hash-value".to_string()),
        process_hash_md5: Some("hash-value".to_string()),
        process_hash_sha1: Some("hash-value".to_string()),
        parent_chain: Vec::new(),
    }
}

fn read_rules_dir_state(path: &std::path::Path) -> Option<(u64, Option<std::time::SystemTime>)> {
    let mut count = 0_u64;
    let mut latest: Option<std::time::SystemTime> = None;

    let entries = std::fs::read_dir(path).ok()?;
    for entry in entries.flatten() {
        let file_path = entry.path();
        if file_path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        count = count.saturating_add(1);
        if let Ok(meta) = entry.metadata()
            && let Ok(modified) = meta.modified()
        {
            latest = Some(match latest {
                Some(prev) if prev > modified => prev,
                _ => modified,
            });
        }
    }

    Some((count, latest))
}

#[tokio::test]
async fn config_watch_task_reloads_runtime_snapshot_after_file_change() {
    crate::tests::support::init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-reload-parity");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");

    prepare_runtime_watch_fixture(&rules_path, &firewall_path, &tasks_path);

    let initial = raw_config(
        "http://127.0.0.1:50051",
        "allow",
        "proc",
        &firewall_path,
        &rules_path,
        &tasks_path,
    );
    fs::write(&config_path, &initial).expect("write initial config");

    let config = Config::from_raw_json(&config_path, initial).expect("parse initial config");
    let config_service = ConfigService::new(config.clone());
    let rules_service = RuleService::default();
    rules_service
        .load_path(&config.rules_path)
        .await
        .expect("load initial rules path");
    let firewall_service = FirewallService::new(&config).expect("build firewall service");

    let (alert_tx, _alert_rx) = tokio::sync::mpsc::channel(4);
    let seen_proc_reconfigure: Arc<Mutex<Vec<ProcMonitorMethod>>> = Arc::new(Mutex::new(vec![]));
    let seen_proc_reconfigure_cb = Arc::clone(&seen_proc_reconfigure);

    let shutdown = CancellationToken::new();
    let reconfigure_proc_workers: crate::services::config::ProcWorkerReconfigure =
        Arc::new(move |next_method| {
            let seen = Arc::clone(&seen_proc_reconfigure_cb);
            Box::pin(async move {
                if let Some(method) = next_method {
                    seen.lock().expect("lock reconfigure methods").push(method);
                }
                Ok(())
            })
        });
    let watch_handle = into_join_handle(
        shutdown.clone(),
        config_service.spawn_watch_task(
            shutdown.clone(),
            rules_service,
            firewall_service,
            StatsService::default(),
            crate::services::client::AlertBuffer::default(),
            alert_tx,
            reconfigure_proc_workers,
        ),
    );

    // Give the watch task one poll cycle plus scheduling slack to arm before
    // measuring reload latency.
    tokio::time::sleep(WATCH_POLLER_ARM_DELAY).await;

    let updated_addr = "http://127.0.0.1:59999";
    let updated = raw_config(
        updated_addr,
        "deny",
        "audit",
        &firewall_path,
        &rules_path,
        &tasks_path,
    );
    let reload_started = Instant::now();
    fs::write(&config_path, &updated).expect("write updated config");

    timeout(Duration::from_secs(6), async {
        loop {
            let snapshot = config_service.get_snapshot();
            let saw_audit_reconfigure = seen_proc_reconfigure
                .lock()
                .expect("lock reconfigure methods")
                .iter()
                .any(|method| matches!(method, ProcMonitorMethod::Audit));

            if snapshot.client_addr == updated_addr
                && matches!(snapshot.default_action, DefaultAction::Deny)
                && matches!(snapshot.proc_monitor_method, ProcMonitorMethod::Audit)
                && saw_audit_reconfigure
            {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("config watch should reload runtime snapshot after file change");

    let snapshot = config_service.get_snapshot();
    assert_eq!(snapshot.client_addr, updated_addr);
    assert!(matches!(snapshot.default_action, DefaultAction::Deny));
    assert!(matches!(
        snapshot.proc_monitor_method,
        ProcMonitorMethod::Audit
    ));

    let methods = seen_proc_reconfigure
        .lock()
        .expect("lock reconfigure methods")
        .clone();
    assert!(
        methods
            .iter()
            .any(|method| matches!(method, ProcMonitorMethod::Audit)),
        "expected proc worker reconfigure callback to receive audit method"
    );

    // Keep cold-path parity timing aligned with the Go UI reload test, which
    // enforces a minimum 4s measurement window before emitting elapsed_s.
    let elapsed = reload_started.elapsed();
    if elapsed < Duration::from_secs(4) {
        tokio::time::sleep(Duration::from_secs(4) - elapsed).await;
    }

    stop_watch_task(shutdown, watch_handle).await;
    println!(
        "cold-profile backend=rust component=ui elapsed_s={:.3}",
        reload_started.elapsed().as_secs_f64()
    );
}

#[tokio::test]
async fn rules_watch_task_emits_live_reload_delete_sequence() {
    crate::tests::support::init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-parity");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");

    prepare_runtime_watch_fixture(&rules_path, &firewall_path, &tasks_path);

    write_rule_file(&rules_path, "test-live-reload-delete", "deny").await;
    write_rule_file(&rules_path, "test-live-reload-remove", "deny").await;

    write_default_raw_config(&config_path, &firewall_path, &rules_path, &tasks_path);

    let rules_service = load_rules_service(&rules_path).await;

    let (shutdown, watch_handle) = start_rules_watch_task(&rules_service).await;

    remove_file_async(
        &rules_path.join("test-live-reload-remove.json"),
        "delete rule file test-live-reload-remove.json",
    )
    .await;
    remove_file_async(
        &rules_path.join("test-live-reload-delete.json"),
        "delete rule file test-live-reload-delete.json",
    )
    .await;

    wait_until_rule_count(
        &rules_service,
        0,
        5,
        100,
        "rules watch should reload after live deletion of both rules",
    )
    .await;

    let remaining_rules = rules_service.list_wire().await;
    assert!(
        remaining_rules.is_empty(),
        "all live-reload rules should be deleted"
    );

    stop_watch_task(shutdown, watch_handle).await;
}

#[tokio::test]
async fn rules_watch_task_matches_go_live_reload_add_then_delete_flow() {
    crate::tests::support::init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-go-live-reload");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");

    prepare_runtime_watch_fixture(&rules_path, &firewall_path, &tasks_path);

    write_rule_file(&rules_path, "000-allow-chrome", "allow").await;
    write_rule_file(&rules_path, "001-deny-chrome", "deny").await;

    write_default_raw_config(&config_path, &firewall_path, &rules_path, &tasks_path);

    let rules_service = load_rules_service(&rules_path).await;

    let shutdown = CancellationToken::new();
    let watch_handle = into_join_handle(
        shutdown.clone(),
        rules_service.spawn_watch_task(shutdown.clone()),
    );
    // Match Go parity fixture startup delay before measuring reload latency.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let reload_started = Instant::now();

    // Use sync writes to match Go's synchronous Copy() — avoids measuring
    // spawn_blocking overhead from tokio::fs in the timed section.
    write_rule_file_sync(&rules_path, "test-live-reload-remove", "deny");
    write_rule_file_sync(&rules_path, "test-live-reload-delete", "deny");

    // Poll at 5ms: epoll now delivers events near-instantly so a 50ms poll
    // would dominate the measured latency with noise.  5ms ≈ Go's synchronous
    // fsnotify handler overhead, giving a comparable measurement window.
    wait_until_rule_count(
        &rules_service,
        4,
        3,
        5,
        "rules watch should reload after adding two rules",
    )
    .await;

    // Sync remove to match Go's os.Remove().
    std::fs::remove_file(rules_path.join("test-live-reload-remove.json"))
        .expect("delete rule file test-live-reload-remove.json");
    rules_service
        .delete_by_name("test-live-reload-delete")
        .await
        .expect("delete rule by name test-live-reload-delete");

    wait_until_rule_count(
        &rules_service,
        2,
        3,
        5,
        "rules watch should converge back to two rules after delete/remove",
    )
    .await;

    let remaining = rules_service.list_wire().await;
    assert_eq!(remaining.len(), 2);
    assert!(remaining.iter().any(|rule| rule.name == "000-allow-chrome"));
    assert!(remaining.iter().any(|rule| rule.name == "001-deny-chrome"));

    stop_watch_task(shutdown, watch_handle).await;
    println!(
        "cold-profile backend=rust component=rule elapsed_s={:.3}",
        reload_started.elapsed().as_secs_f64()
    );
}

#[tokio::test]
async fn rules_watch_task_survives_churn_like_go_race_scenario() {
    crate::tests::support::init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-churn");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");

    prepare_runtime_watch_fixture(&rules_path, &firewall_path, &tasks_path);

    write_rule_file(&rules_path, "000-base", "allow").await;

    write_default_raw_config(&config_path, &firewall_path, &rules_path, &tasks_path);

    let rules_service = load_rules_service(&rules_path).await;

    let (shutdown, watch_handle) = start_rules_watch_task(&rules_service).await;

    let churn_path = rules_path.clone();
    let churn_writer = tokio::spawn(async move {
        for i in 0..40 {
            let name = format!("z-churn-{i:03}");
            write_rule_file(&churn_path, &name, "deny").await;
            if i % 2 == 0 {
                let _ = tokio::fs::remove_file(churn_path.join(format!("{name}.json"))).await;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });

    let churn_reader_rules = rules_service.clone();
    let churn_reader = tokio::spawn(async move {
        for _ in 0..120 {
            let _ = churn_reader_rules.list_wire().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let _ = timeout(Duration::from_secs(8), churn_writer)
        .await
        .expect("writer task timeout")
        .expect("writer task failed");
    let _ = timeout(Duration::from_secs(8), churn_reader)
        .await
        .expect("reader task timeout")
        .expect("reader task failed");

    tokio::time::sleep(Duration::from_secs(3)).await;

    let final_rules = rules_service.list_wire().await;
    assert!(
        final_rules.iter().any(|rule| rule.name == "000-base"),
        "base rule should remain after churn"
    );

    stop_watch_task(shutdown, watch_handle).await;
}

#[tokio::test]
async fn rules_watch_task_reloads_on_domains_list_content_change() {
    crate::tests::support::init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-domains-list");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");
    let list_path = temp_dir.path.join("blocklists/domains");

    fs::create_dir_all(&list_path).expect("create list dir");
    prepare_runtime_watch_fixture(&rules_path, &firewall_path, &tasks_path);
    fs::write(list_path.join("domains.txt"), "0.0.0.0 example.org\n").expect("write domains list");

    write_lists_rule_file(&rules_path, "domains-live", "lists.domains", &list_path).await;

    write_default_raw_config(&config_path, &firewall_path, &rules_path, &tasks_path);

    let rules_service = load_rules_service(&rules_path).await;

    let (shutdown, watch_handle) = start_rules_watch_task(&rules_service).await;

    let attempt = probe_attempt();
    let process = probe_process();
    assert_host_match_present(
        &rules_service,
        &attempt,
        &process,
        "example.org",
        "initial list match",
        "expected deny match before list update",
    )
    .await;

    fs::write(list_path.join("domains.txt"), "0.0.0.0 blocked.example\n")
        .expect("rewrite domains list");

    wait_until_host_no_match(
        &rules_service,
        &attempt,
        &process,
        "example.org",
        6,
        120,
        "refresh list match",
        "rules watch should reload after domains list update",
    )
    .await;

    stop_watch_task(shutdown, watch_handle).await;
}

#[tokio::test]
async fn rules_watch_task_reloads_on_domains_regexp_list_content_change() {
    crate::tests::support::init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-regexp-list");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");
    let list_path = temp_dir.path.join("blocklists/regexp");

    fs::create_dir_all(&list_path).expect("create list dir");
    prepare_runtime_watch_fixture(&rules_path, &firewall_path, &tasks_path);
    fs::write(list_path.join("regexp.txt"), "^example\\.org$\n").expect("write regexp list");

    write_lists_rule_file(
        &rules_path,
        "regexp-live",
        "lists.domains_regexp",
        &list_path,
    )
    .await;

    write_default_raw_config(&config_path, &firewall_path, &rules_path, &tasks_path);

    let rules_service = load_rules_service(&rules_path).await;

    let (shutdown, watch_handle) = start_rules_watch_task(&rules_service).await;

    let attempt = probe_attempt();
    let process = probe_process();
    assert_host_match_present(
        &rules_service,
        &attempt,
        &process,
        "example.org",
        "initial regexp list match",
        "expected deny match before regexp list update",
    )
    .await;

    fs::write(list_path.join("regexp.txt"), "^blocked\\.example$\n").expect("rewrite regexp list");

    wait_until_host_no_match(
        &rules_service,
        &attempt,
        &process,
        "example.org",
        6,
        120,
        "refresh regexp list match",
        "rules watch should reload after regexp list update",
    )
    .await;

    stop_watch_task(shutdown, watch_handle).await;
}

#[tokio::test]
async fn rules_watch_task_reloads_on_nested_list_subrule_list_change() {
    crate::tests::support::init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-nested-list-subrule");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");
    let list_path = temp_dir.path.join("blocklists/nested-domains");

    fs::create_dir_all(&list_path).expect("create nested list dir");
    prepare_runtime_watch_fixture(&rules_path, &firewall_path, &tasks_path);
    fs::write(list_path.join("domains.txt"), "0.0.0.0 nested.example\n")
        .expect("write nested domains list");

    write_nested_lists_rule_file(&rules_path, "nested-lists-live", &list_path).await;

    write_default_raw_config(&config_path, &firewall_path, &rules_path, &tasks_path);

    let rules_service = load_rules_service(&rules_path).await;

    let (shutdown, watch_handle) = start_rules_watch_task(&rules_service).await;

    let attempt = probe_attempt();
    let process = probe_process();
    assert_host_match_present(
        &rules_service,
        &attempt,
        &process,
        "nested.example",
        "initial nested list match",
        "expected deny match before nested list update",
    )
    .await;

    fs::write(
        list_path.join("domains.txt"),
        "0.0.0.0 blocked-nested.example\n",
    )
    .expect("rewrite nested domains list");

    wait_until_host_no_match(
        &rules_service,
        &attempt,
        &process,
        "nested.example",
        6,
        120,
        "refresh nested list match",
        "rules watch should reload after nested list file update",
    )
    .await;

    stop_watch_task(shutdown, watch_handle).await;
}

use std::time::SystemTime;

#[test]
fn parse_firewall_monitor_interval_supports_common_units() {
    assert_eq!(
        firewall_watch_worker::parse_firewall_monitor_interval("250ms").as_millis(),
        250
    );
    assert_eq!(
        firewall_watch_worker::parse_firewall_monitor_interval("5s").as_secs(),
        5
    );
    assert_eq!(
        firewall_watch_worker::parse_firewall_monitor_interval("2m").as_secs(),
        120
    );
    assert_eq!(
        firewall_watch_worker::parse_firewall_monitor_interval("1h").as_secs(),
        3600
    );
}

#[test]
fn parse_firewall_monitor_interval_defaults_or_disables_as_expected() {
    assert_eq!(
        firewall_watch_worker::parse_firewall_monitor_interval(""),
        Duration::from_secs(10)
    );
    assert_eq!(
        firewall_watch_worker::parse_firewall_monitor_interval("garbage"),
        Duration::from_secs(10)
    );
    assert_eq!(
        firewall_watch_worker::parse_firewall_monitor_interval("0"),
        Duration::ZERO
    );
}

#[test]
fn config_file_changed_only_triggers_on_newer_timestamp() {
    let prev = SystemTime::UNIX_EPOCH + Duration::from_secs(5);
    let newer = SystemTime::UNIX_EPOCH + Duration::from_secs(6);

    assert!(!watch::is_newer_mtime(Some(newer), None));
    assert!(!watch::is_newer_mtime(Some(prev), Some(prev)));
    assert!(watch::is_newer_mtime(Some(newer), Some(prev)));
}

#[test]
fn read_rules_dir_state_counts_json_files_only() {
    let temp_dir = TestDir::new("opensnitch-watch-service");
    fs::write(temp_dir.path.join("one.json"), "{}").expect("write json rule");
    fs::write(temp_dir.path.join("two.txt"), "ignored").expect("write txt file");

    let state = read_rules_dir_state(&temp_dir.path).expect("rules dir state");
    assert_eq!(state.0, 1);
    assert!(state.1.is_some());
}

#[test]
fn inotify_mask_filter_accepts_change_events() {
    assert!(watch::should_forward_inotify_mask(nix::libc::IN_MODIFY));
    assert!(watch::should_forward_inotify_mask(
        nix::libc::IN_CLOSE_WRITE
    ));
    assert!(!watch::should_forward_inotify_mask(nix::libc::IN_ACCESS));
}

#[test]
fn inotify_name_filter_ignores_transient_temp_artifacts() {
    assert!(watch::is_transient_watch_event_name("rule.json.tmp"));
    assert!(watch::is_transient_watch_event_name("config.json.tmp-123"));
    assert!(watch::is_transient_watch_event_name("domains.txt.download"));
    assert!(watch::is_transient_watch_event_name(".domains.txt.swp"));

    assert!(!watch::is_transient_watch_event_name("rule.json"));
    assert!(!watch::is_transient_watch_event_name("domains.txt"));
}
