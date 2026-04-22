use std::fs;

use crate::config::{ClientAuthType, Config, DefaultAction, ProcMonitorMethod};
use crate::{models::firewall_state::FirewallBackend, tests::support::TestDir};

#[test]
fn from_raw_json_parses_expected_config_values() {
    let dir = TestDir::new("opensnitch-config-parse");
    let config_path = dir.path.join("default-config.json");
    let fw_path = dir.path.join("system-fw.json");
    let rules_path = dir.path.join("rules");
    let tasks_path = dir.path.join("tasks.json");

    fs::create_dir_all(&rules_path).expect("create rules dir");
    fs::write(&fw_path, "{}").expect("create firewall file");
    fs::write(&tasks_path, "[]").expect("create tasks file");

    let raw = format!(
        r#"{{
"Server": {{
    "Address": "http://127.0.0.1:50051",
    "Authentication": {{
        "Type": "tls-mutual",
        "TLSOptions": {{
            "CACert": "/tmp/ca.pem",
            "ServerCert": "/tmp/server.pem",
            "ServerKey": "/tmp/server.key",
            "ClientCert": "/tmp/client.pem",
            "ClientKey": "/tmp/client.key",
            "ClientAuthType": "req-and-verify-cert",
            "SkipVerify": true
        }}
    }},
    "LogFile": "{log_file}",
    "Loggers": [
        {{"Name": "syslog", "Format": "json", "Protocol": "udp", "Server": "127.0.0.1:514", "Workers": 2}}
    ]
}},
"LogLevel": 4,
"LogUTC": false,
"LogMicro": true,
"DefaultAction": "allow",
"ProcMonitorMethod": "proc",
"Firewall": "nftables",
"FwOptions": {{
"MonitorInterval": "7s",
"ConfigPath": "{fw}",
"QueueNum": 7,
"QueueBypass": false
}},
"Rules": {{"Path": "{rules}"}},
"TasksOptions": {{"ConfigPath": "{tasks}"}},
"Audit": {{"AudispSocketPath": "/tmp/audisp.sock"}},
"Stats": {{"MaxEvents": 111, "MaxStats": 33, "Workers": 4}}
}}"#,
        fw = fw_path.display(),
        rules = rules_path.display(),
        tasks = tasks_path.display(),
        log_file = dir.path.join("opensnitchd.log").display()
    );

    let cfg = Config::from_raw_json(&config_path, raw.clone()).expect("parse config");

    assert_eq!(cfg.client_addr, "http://127.0.0.1:50051");
    assert_eq!(cfg.log_level, 4);
    assert!(!cfg.log_utc);
    assert!(cfg.log_micro);
    assert!(
        cfg.log_file
            .as_ref()
            .is_some_and(|path| path.ends_with("opensnitchd.log"))
    );
    assert_eq!(cfg.loggers.len(), 1);
    assert_eq!(cfg.loggers[0].name, "syslog");
    assert_eq!(cfg.loggers[0].protocol, "udp");
    assert!(matches!(
        cfg.client_auth.auth_type,
        ClientAuthType::TlsMutual
    ));
    assert_eq!(cfg.client_auth.tls_options.ca_cert, "/tmp/ca.pem");
    assert_eq!(cfg.client_auth.tls_options.server_cert, "/tmp/server.pem");
    assert_eq!(cfg.client_auth.tls_options.server_key, "/tmp/server.key");
    assert_eq!(cfg.client_auth.tls_options.client_cert, "/tmp/client.pem");
    assert_eq!(cfg.client_auth.tls_options.client_key, "/tmp/client.key");
    assert_eq!(
        cfg.client_auth.tls_options.client_auth_type,
        "req-and-verify-cert"
    );
    assert!(cfg.client_auth.tls_options.skip_verify);
    assert!(!cfg.rules_enable_checksums);
    assert!(matches!(cfg.default_action, DefaultAction::Allow));
    assert!(matches!(cfg.proc_monitor_method, ProcMonitorMethod::Proc));
    assert!(matches!(cfg.firewall_backend, FirewallBackend::Nftables));
    assert_eq!(cfg.firewall_monitor_interval, "7s");
    assert_eq!(cfg.firewall_queue_num, 7);
    assert!(!cfg.firewall_queue_bypass);
    assert_eq!(cfg.firewall_config_path, fw_path);
    assert_eq!(cfg.rules_path, rules_path);
    assert_eq!(cfg.tasks_config_path, tasks_path);
    assert_eq!(cfg.audit_socket_path.to_string_lossy(), "/tmp/audisp.sock");
    assert_eq!(cfg.stats.max_events, 111);
    assert_eq!(cfg.stats.max_stats, 33);
    assert_eq!(cfg.stats.workers, 4);
    assert_eq!(cfg.raw_json, raw);
}

#[test]
fn from_raw_json_invalid_proc_monitor_falls_back_to_proc() {
    let dir = TestDir::new("opensnitch-config-proc-fallback");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {"Address": "http://127.0.0.1:50051"},
"ProcMonitorMethod": "invalid-monitor",
"Firewall": "nftables"
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(cfg.proc_monitor_method, ProcMonitorMethod::Proc));
}

#[test]
fn from_raw_json_ignores_unknown_fields_including_legacy_gc_percent() {
    let dir = TestDir::new("opensnitch-config-unknown-fields");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {
    "Address": "http://127.0.0.1:50051",
    "UnexpectedServerField": "ignored"
},
"Internal": {
    "GCPercent": 50,
    "FlushConnsOnStart": false,
    "AnotherUnknownInternal": true
},
"TopLevelUnknown": {"foo": "bar"}
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert_eq!(cfg.client_addr, "http://127.0.0.1:50051");
    assert!(!cfg.flush_conns_on_start);
}

#[test]
fn from_raw_json_accepts_legacy_tasks_key_alias() {
    let dir = TestDir::new("opensnitch-config-tasks-alias");
    let config_path = dir.path.join("default-config.json");
    let tasks_path = dir.path.join("tasks-alias.json");
    fs::write(&tasks_path, "[]").expect("create tasks alias file");

    let raw = format!(
        r#"{{
"Server": {{"Address": "http://127.0.0.1:50051"}},
"Tasks": {{"ConfigPath": "{}"}}
}}"#,
        tasks_path.display()
    );

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert_eq!(cfg.tasks_config_path, tasks_path);
}

#[test]
fn from_raw_json_accepts_case_insensitive_config_keys_like_go() {
    let dir = TestDir::new("opensnitch-config-case-insensitive-keys");
    let config_path = dir.path.join("default-config.json");
    let fw_path = dir.path.join("system-fw.json");
    let rules_path = dir.path.join("rules");
    let tasks_path = dir.path.join("tasks.json");

    fs::create_dir_all(&rules_path).expect("create rules dir");
    fs::write(&fw_path, "{}").expect("create firewall file");
    fs::write(&tasks_path, "[]").expect("create tasks file");

    let raw = format!(
        r#"{{
"server": {{
    "address": "http://127.0.0.1:50100"
}},
"loglevel": 6,
"firewall": "nftables",
"fwoptions": {{
    "configpath": "{fw}"
}},
"rules": {{"path": "{rules}"}},
"tasksoptions": {{"configpath": "{tasks}"}}
}}"#,
        fw = fw_path.display(),
        rules = rules_path.display(),
        tasks = tasks_path.display()
    );

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert_eq!(cfg.client_addr, "http://127.0.0.1:50100");
    assert_eq!(cfg.log_level, 6);
    assert_eq!(cfg.firewall_config_path, fw_path);
    assert_eq!(cfg.rules_path, rules_path);
    assert_eq!(cfg.tasks_config_path, tasks_path);
}
