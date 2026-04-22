use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    config::{Config, DefaultAction, ProcMonitorMethod},
    models::rule_storage::{RuleFile, RuleFileOperator},
    models::{
        connection_state::{ConnectionAttempt, TransportProtocol},
        process_state::ProcessInfo,
    },
    services::{
        config_service::ConfigService,
        firewall_service::FirewallService,
        process_service::ProcessService,
        rule_service::RuleService,
        stats_service::StatsService,
        watch_service::{WatchService, WatcherService},
    },
    utils::test_support::{TestDir, init_test_logging},
};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

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

async fn write_rule_file(rules_dir: &Path, name: &str, action: &str) {
    let rule = RuleFile {
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
            list: Vec::new(),
        },
    };

    tokio::fs::write(
        rules_dir.join(format!("{name}.json")),
        serde_json::to_string(&rule).expect("serialize test rule"),
    )
    .await
    .expect("write test rule");
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
            data: list_path.display().to_string(),
            sensitive: false,
            list: Vec::new(),
        },
    };

    tokio::fs::write(
        rules_dir.join(format!("{name}.json")),
        serde_json::to_string(&rule).expect("serialize lists test rule"),
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
            list: vec![
                RuleFileOperator {
                    r#type: "simple".to_string(),
                    operand: "user.id".to_string(),
                    data: "1000".to_string(),
                    sensitive: false,
                    list: Vec::new(),
                },
                RuleFileOperator {
                    r#type: "lists".to_string(),
                    operand: "lists.domains".to_string(),
                    data: list_path.display().to_string(),
                    sensitive: false,
                    list: Vec::new(),
                },
            ],
        },
    };

    tokio::fs::write(
        rules_dir.join(format!("{name}.json")),
        serde_json::to_string(&rule).expect("serialize nested lists test rule"),
    )
    .await
    .expect("write nested lists test rule");
}

fn test_attempt() -> ConnectionAttempt {
    ConnectionAttempt {
        request_id: 7,
        protocol: TransportProtocol::Tcp,
        src_ip: "127.0.0.1".to_string(),
        src_port: 12345,
        dst_ip: "10.0.0.2".to_string(),
        dst_port: 443,
        iface_in_idx: 0,
        iface_out_idx: 0,
        dns_query: None,
        pid: 4242,
        uid: 1000,
    }
}

fn test_process() -> ProcessInfo {
    ProcessInfo {
        pid: 4242,
        path: "/usr/bin/curl".to_string(),
        args: vec!["curl".to_string()],
        cwd: None,
        env_preview: Vec::new(),
        process_hash: Some("hash-value".to_string()),
        process_hash_md5: Some("hash-value".to_string()),
        process_hash_sha1: Some("hash-value".to_string()),
        parent_chain: Vec::new(),
    }
}

#[tokio::test]
async fn config_watch_task_reloads_runtime_snapshot_after_file_change() {
    init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-reload-parity");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");

    fs::create_dir_all(&rules_path).expect("create rules dir");
    fs::write(&firewall_path, "{}").expect("write firewall config");
    fs::write(&tasks_path, r#"{"tasks":[]}"#).expect("write tasks config");

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

    let (task_reply_tx, _task_reply_rx) = tokio::sync::mpsc::channel(4);
    let (alert_tx, _alert_rx) = tokio::sync::mpsc::channel(4);
    let seen_proc_reconfigure: Arc<Mutex<Vec<ProcMonitorMethod>>> = Arc::new(Mutex::new(vec![]));
    let seen_proc_reconfigure_cb = Arc::clone(&seen_proc_reconfigure);

    let shutdown = CancellationToken::new();
    let watch_service = WatchService::new(
        shutdown.clone(),
        config_service.clone(),
        rules_service,
        firewall_service,
        StatsService::default(),
        ProcessService::default(),
        task_reply_tx,
        alert_tx,
        Arc::new(move |next_method| {
            let seen = Arc::clone(&seen_proc_reconfigure_cb);
            Box::pin(async move {
                if let Some(method) = next_method {
                    seen.lock().expect("lock reconfigure methods").push(method);
                }
                Ok(())
            })
        }),
    );

    let watch_handle = watch_service.spawn_config_watch_task();

    tokio::time::sleep(Duration::from_millis(2200)).await;

    let updated_addr = "http://127.0.0.1:59999";
    let updated = raw_config(
        updated_addr,
        "deny",
        "audit",
        &firewall_path,
        &rules_path,
        &tasks_path,
    );
    fs::write(&config_path, &updated).expect("write updated config");

    tokio::time::sleep(Duration::from_secs(10)).await;

    let snapshot = config_service.snapshot().await;
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

    shutdown.cancel();
    let _ = timeout(Duration::from_secs(1), watch_handle).await;
}

#[tokio::test]
async fn rules_watch_task_emits_live_reload_delete_sequence() {
    init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-parity");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");

    fs::create_dir_all(&rules_path).expect("create rules dir");
    fs::write(&firewall_path, "{}").expect("write firewall config");
    fs::write(&tasks_path, r#"{"tasks":[]}"#).expect("write tasks config");

    write_rule_file(&rules_path, "test-live-reload-delete", "deny").await;
    write_rule_file(&rules_path, "test-live-reload-remove", "deny").await;

    let raw = raw_config(
        "http://127.0.0.1:50051",
        "allow",
        "proc",
        &firewall_path,
        &rules_path,
        &tasks_path,
    );
    fs::write(&config_path, &raw).expect("write config");

    let config = Config::from_raw_json(&config_path, raw).expect("parse config");
    let config_service = ConfigService::new(config.clone());
    let rules_service = RuleService::default();
    rules_service
        .load_path(&rules_path)
        .await
        .expect("load initial rules");
    let firewall_service = FirewallService::new(&config).expect("build firewall service");

    let (task_reply_tx, _task_reply_rx) = tokio::sync::mpsc::channel(4);
    let (alert_tx, _alert_rx) = tokio::sync::mpsc::channel(4);
    let shutdown = CancellationToken::new();
    let watch_service = WatchService::new(
        shutdown.clone(),
        config_service,
        rules_service.clone(),
        firewall_service,
        StatsService::default(),
        ProcessService::default(),
        task_reply_tx,
        alert_tx,
        Arc::new(|_| Box::pin(async { Ok(()) })),
    );

    let watch_handle = watch_service.spawn_rules_watch_task();

    tokio::time::sleep(Duration::from_millis(2200)).await;

    tokio::fs::remove_file(rules_path.join("test-live-reload-remove.json"))
        .await
        .expect("delete rule file test-live-reload-remove.json");
    tokio::fs::remove_file(rules_path.join("test-live-reload-delete.json"))
        .await
        .expect("delete rule file test-live-reload-delete.json");

    timeout(Duration::from_secs(5), async {
        loop {
            let rules = rules_service.list_proto().await;
            if rules.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("rules watch should reload after live deletion of both rules");

    let remaining_rules = rules_service.list_proto().await;
    assert!(
        remaining_rules.is_empty(),
        "all live-reload rules should be deleted"
    );

    shutdown.cancel();
    let _ = timeout(Duration::from_secs(1), watch_handle).await;
}

#[tokio::test]
async fn rules_watch_task_matches_go_live_reload_add_then_delete_flow() {
    init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-go-live-reload");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");

    fs::create_dir_all(&rules_path).expect("create rules dir");
    fs::write(&firewall_path, "{}").expect("write firewall config");
    fs::write(&tasks_path, r#"{"tasks":[]}"#).expect("write tasks config");

    write_rule_file(&rules_path, "000-allow-chrome", "allow").await;
    write_rule_file(&rules_path, "001-deny-chrome", "deny").await;

    let raw = raw_config(
        "http://127.0.0.1:50051",
        "allow",
        "proc",
        &firewall_path,
        &rules_path,
        &tasks_path,
    );
    fs::write(&config_path, &raw).expect("write config");

    let config = Config::from_raw_json(&config_path, raw).expect("parse config");
    let config_service = ConfigService::new(config.clone());
    let rules_service = RuleService::default();
    rules_service
        .load_path(&rules_path)
        .await
        .expect("load initial rules");
    let firewall_service = FirewallService::new(&config).expect("build firewall service");

    let (task_reply_tx, _task_reply_rx) = tokio::sync::mpsc::channel(4);
    let (alert_tx, _alert_rx) = tokio::sync::mpsc::channel(4);
    let shutdown = CancellationToken::new();
    let watch_service = WatchService::new(
        shutdown.clone(),
        config_service,
        rules_service.clone(),
        firewall_service,
        StatsService::default(),
        ProcessService::default(),
        task_reply_tx,
        alert_tx,
        Arc::new(|_| Box::pin(async { Ok(()) })),
    );

    let watch_handle = watch_service.spawn_rules_watch_task();
    tokio::time::sleep(Duration::from_millis(2200)).await;

    write_rule_file(&rules_path, "test-live-reload-remove", "deny").await;
    write_rule_file(&rules_path, "test-live-reload-delete", "deny").await;

    timeout(Duration::from_secs(6), async {
        loop {
            let rules = rules_service.list_proto().await;
            if rules.len() == 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("rules watch should reload after adding two rules");

    tokio::fs::remove_file(rules_path.join("test-live-reload-remove.json"))
        .await
        .expect("delete rule file test-live-reload-remove.json");
    rules_service
        .delete_by_name("test-live-reload-delete")
        .await
        .expect("delete rule by name test-live-reload-delete");

    timeout(Duration::from_secs(6), async {
        loop {
            let rules = rules_service.list_proto().await;
            if rules.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("rules watch should converge back to two rules after delete/remove");

    let remaining = rules_service.list_proto().await;
    assert_eq!(remaining.len(), 2);
    assert!(remaining.iter().any(|rule| rule.name == "000-allow-chrome"));
    assert!(remaining.iter().any(|rule| rule.name == "001-deny-chrome"));

    shutdown.cancel();
    let _ = timeout(Duration::from_secs(1), watch_handle).await;
}

#[tokio::test]
async fn rules_watch_task_survives_churn_like_go_race_scenario() {
    init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-churn");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");

    fs::create_dir_all(&rules_path).expect("create rules dir");
    fs::write(&firewall_path, "{}").expect("write firewall config");
    fs::write(&tasks_path, r#"{"tasks":[]}"#).expect("write tasks config");

    write_rule_file(&rules_path, "000-base", "allow").await;

    let raw = raw_config(
        "http://127.0.0.1:50051",
        "allow",
        "proc",
        &firewall_path,
        &rules_path,
        &tasks_path,
    );
    fs::write(&config_path, &raw).expect("write config");

    let config = Config::from_raw_json(&config_path, raw).expect("parse config");
    let config_service = ConfigService::new(config.clone());
    let rules_service = RuleService::default();
    rules_service
        .load_path(&rules_path)
        .await
        .expect("load initial rules");
    let firewall_service = FirewallService::new(&config).expect("build firewall service");

    let (task_reply_tx, _task_reply_rx) = tokio::sync::mpsc::channel(4);
    let (alert_tx, _alert_rx) = tokio::sync::mpsc::channel(4);
    let shutdown = CancellationToken::new();
    let watch_service = WatchService::new(
        shutdown.clone(),
        config_service,
        rules_service.clone(),
        firewall_service,
        StatsService::default(),
        ProcessService::default(),
        task_reply_tx,
        alert_tx,
        Arc::new(|_| Box::pin(async { Ok(()) })),
    );

    let watch_handle = watch_service.spawn_rules_watch_task();
    tokio::time::sleep(Duration::from_millis(2200)).await;

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
            let _ = churn_reader_rules.list_proto().await;
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
    let final_rules = rules_service.list_proto().await;
    assert!(
        final_rules.iter().any(|rule| rule.name == "000-base"),
        "base rule should remain after churn"
    );

    shutdown.cancel();
    let _ = timeout(Duration::from_secs(1), watch_handle).await;
}

#[tokio::test]
async fn rules_watch_task_reloads_on_domains_list_content_change() {
    init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-domains-list");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");
    let list_path = temp_dir.path.join("blocklists/domains");

    fs::create_dir_all(&rules_path).expect("create rules dir");
    fs::create_dir_all(&list_path).expect("create list dir");
    fs::write(&firewall_path, "{}").expect("write firewall config");
    fs::write(&tasks_path, r#"{"tasks":[]}"#).expect("write tasks config");
    fs::write(list_path.join("domains.txt"), "0.0.0.0 example.org\n").expect("write domains list");

    write_lists_rule_file(&rules_path, "domains-live", "lists.domains", &list_path).await;

    let raw = raw_config(
        "http://127.0.0.1:50051",
        "allow",
        "proc",
        &firewall_path,
        &rules_path,
        &tasks_path,
    );
    fs::write(&config_path, &raw).expect("write config");

    let config = Config::from_raw_json(&config_path, raw).expect("parse config");
    let config_service = ConfigService::new(config.clone());
    let rules_service = RuleService::default();
    rules_service
        .load_path(&rules_path)
        .await
        .expect("load initial rules");
    let firewall_service = FirewallService::new(&config).expect("build firewall service");

    let (task_reply_tx, _task_reply_rx) = tokio::sync::mpsc::channel(4);
    let (alert_tx, _alert_rx) = tokio::sync::mpsc::channel(4);
    let shutdown = CancellationToken::new();
    let watch_service = WatchService::new(
        shutdown.clone(),
        config_service,
        rules_service.clone(),
        firewall_service,
        StatsService::default(),
        ProcessService::default(),
        task_reply_tx,
        alert_tx,
        Arc::new(|_| Box::pin(async { Ok(()) })),
    );

    let attempt = test_attempt();
    let process = test_process();
    let initial = rules_service
        .match_attempt(&attempt, &process, Some("example.org"))
        .await
        .expect("initial list match");
    assert!(initial.is_some(), "expected deny match before list update");

    let watch_handle = watch_service.spawn_rules_watch_task();
    tokio::time::sleep(Duration::from_millis(2200)).await;

    fs::write(list_path.join("domains.txt"), "0.0.0.0 blocked.example\n")
        .expect("rewrite domains list");

    timeout(Duration::from_secs(6), async {
        loop {
            let decision = rules_service
                .match_attempt(&attempt, &process, Some("example.org"))
                .await
                .expect("refresh list match");
            if decision.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    })
    .await
    .expect("rules watch should reload after domains list update");

    shutdown.cancel();
    let _ = timeout(Duration::from_secs(1), watch_handle).await;
}

#[tokio::test]
async fn rules_watch_task_reloads_on_domains_regexp_list_content_change() {
    init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-regexp-list");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");
    let list_path = temp_dir.path.join("blocklists/regexp");

    fs::create_dir_all(&rules_path).expect("create rules dir");
    fs::create_dir_all(&list_path).expect("create list dir");
    fs::write(&firewall_path, "{}").expect("write firewall config");
    fs::write(&tasks_path, r#"{"tasks":[]}"#).expect("write tasks config");
    fs::write(list_path.join("regexp.txt"), "^example\\.org$\n").expect("write regexp list");

    write_lists_rule_file(
        &rules_path,
        "regexp-live",
        "lists.domains_regexp",
        &list_path,
    )
    .await;

    let raw = raw_config(
        "http://127.0.0.1:50051",
        "allow",
        "proc",
        &firewall_path,
        &rules_path,
        &tasks_path,
    );
    fs::write(&config_path, &raw).expect("write config");

    let config = Config::from_raw_json(&config_path, raw).expect("parse config");
    let config_service = ConfigService::new(config.clone());
    let rules_service = RuleService::default();
    rules_service
        .load_path(&rules_path)
        .await
        .expect("load initial rules");
    let firewall_service = FirewallService::new(&config).expect("build firewall service");

    let (task_reply_tx, _task_reply_rx) = tokio::sync::mpsc::channel(4);
    let (alert_tx, _alert_rx) = tokio::sync::mpsc::channel(4);
    let shutdown = CancellationToken::new();
    let watch_service = WatchService::new(
        shutdown.clone(),
        config_service,
        rules_service.clone(),
        firewall_service,
        StatsService::default(),
        ProcessService::default(),
        task_reply_tx,
        alert_tx,
        Arc::new(|_| Box::pin(async { Ok(()) })),
    );

    let attempt = test_attempt();
    let process = test_process();
    let initial = rules_service
        .match_attempt(&attempt, &process, Some("example.org"))
        .await
        .expect("initial regexp list match");
    assert!(
        initial.is_some(),
        "expected deny match before regexp list update"
    );

    let watch_handle = watch_service.spawn_rules_watch_task();
    tokio::time::sleep(Duration::from_millis(2200)).await;

    fs::write(list_path.join("regexp.txt"), "^blocked\\.example$\n").expect("rewrite regexp list");

    timeout(Duration::from_secs(6), async {
        loop {
            let decision = rules_service
                .match_attempt(&attempt, &process, Some("example.org"))
                .await
                .expect("refresh regexp list match");
            if decision.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    })
    .await
    .expect("rules watch should reload after regexp list update");

    shutdown.cancel();
    let _ = timeout(Duration::from_secs(1), watch_handle).await;
}

#[tokio::test]
async fn rules_watch_task_reloads_on_nested_list_subrule_list_change() {
    init_test_logging();

    let temp_dir = TestDir::new("opensnitch-watch-rules-nested-list-subrule");
    let config_path = temp_dir.path.join("default-config.json");
    let firewall_path = temp_dir.path.join("system-fw.json");
    let rules_path = temp_dir.path.join("rules");
    let tasks_path = temp_dir.path.join("tasks.json");
    let list_path = temp_dir.path.join("blocklists/nested-domains");

    fs::create_dir_all(&rules_path).expect("create rules dir");
    fs::create_dir_all(&list_path).expect("create nested list dir");
    fs::write(&firewall_path, "{}").expect("write firewall config");
    fs::write(&tasks_path, r#"{"tasks":[]}"#).expect("write tasks config");
    fs::write(list_path.join("domains.txt"), "0.0.0.0 nested.example\n")
        .expect("write nested domains list");

    write_nested_lists_rule_file(&rules_path, "nested-lists-live", &list_path).await;

    let raw = raw_config(
        "http://127.0.0.1:50051",
        "allow",
        "proc",
        &firewall_path,
        &rules_path,
        &tasks_path,
    );
    fs::write(&config_path, &raw).expect("write config");

    let config = Config::from_raw_json(&config_path, raw).expect("parse config");
    let config_service = ConfigService::new(config.clone());
    let rules_service = RuleService::default();
    rules_service
        .load_path(&rules_path)
        .await
        .expect("load initial rules");
    let firewall_service = FirewallService::new(&config).expect("build firewall service");

    let (task_reply_tx, _task_reply_rx) = tokio::sync::mpsc::channel(4);
    let (alert_tx, _alert_rx) = tokio::sync::mpsc::channel(4);
    let shutdown = CancellationToken::new();
    let watch_service = WatchService::new(
        shutdown.clone(),
        config_service,
        rules_service.clone(),
        firewall_service,
        StatsService::default(),
        ProcessService::default(),
        task_reply_tx,
        alert_tx,
        Arc::new(|_| Box::pin(async { Ok(()) })),
    );

    let attempt = test_attempt();
    let process = test_process();
    let initial = rules_service
        .match_attempt(&attempt, &process, Some("nested.example"))
        .await
        .expect("initial nested list match");
    assert!(
        initial.is_some(),
        "expected deny match before nested list update"
    );

    let watch_handle = watch_service.spawn_rules_watch_task();
    tokio::time::sleep(Duration::from_millis(2200)).await;

    fs::write(
        list_path.join("domains.txt"),
        "0.0.0.0 blocked-nested.example\n",
    )
    .expect("rewrite nested domains list");

    timeout(Duration::from_secs(6), async {
        loop {
            let decision = rules_service
                .match_attempt(&attempt, &process, Some("nested.example"))
                .await
                .expect("refresh nested list match");
            if decision.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    })
    .await
    .expect("rules watch should reload after nested list file update");

    shutdown.cancel();
    let _ = timeout(Duration::from_secs(1), watch_handle).await;
}
