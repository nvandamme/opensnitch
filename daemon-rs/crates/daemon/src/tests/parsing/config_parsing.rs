use std::fs;

use nix::unistd::{Uid, User};

use crate::config::{
    AskFallbackPolicy, AuthMode, ClientAuthType, Config, DefaultAction, FirewallPersistenceMode,
    ProcMonitorMethod,
};
use crate::{
    models::{audit::AuditSeverity, firewall_state::FirewallBackend},
    tests::support::TestDir,
};

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
"QueueBypass": false,
"PersistenceMode": "live-only"
}},
"Rules": {{"Path": "{rules}"}},
"TasksOptions": {{"ConfigPath": "{tasks}"}},
"Audit": {{
    "AudispSocketPath": "/tmp/audisp.sock",
    "VerboseHotPath": true,
    "MinSeverity": "warning"
}},
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
    assert!(matches!(
        cfg.firewall_persistence_mode,
        FirewallPersistenceMode::LiveOnly
    ));
    assert_eq!(cfg.firewall_config_path, fw_path);
    assert_eq!(cfg.rules_path, rules_path);
    assert_eq!(cfg.tasks_config_path, tasks_path);
    assert_eq!(cfg.audit_socket_path.to_string_lossy(), "/tmp/audisp.sock");
    assert!(cfg.audit_sinks.verbose_hot_path);
    assert_eq!(cfg.audit_sinks.min_severity, AuditSeverity::Warning);
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

#[cfg(feature = "openwrt")]
#[test]
fn from_raw_json_parses_openwrt_firewall_backend() {
    let dir = TestDir::new("opensnitch-config-openwrt-firewall-backend");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {"Address": "http://127.0.0.1:50051"},
"Firewall": "openwrt-uci"
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(cfg.firewall_backend, FirewallBackend::OpenWrtUci));
}

#[cfg(not(feature = "openwrt"))]
#[test]
fn from_raw_json_openwrt_firewall_backend_falls_back_to_nftables_without_feature() {
    let dir = TestDir::new("opensnitch-config-openwrt-firewall-backend-no-feature");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {"Address": "http://127.0.0.1:50051"},
"Firewall": "openwrt-uci"
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(cfg.firewall_backend, FirewallBackend::Nftables));
}

#[test]
fn from_raw_json_accepts_drop_alias_for_default_action() {
    let dir = TestDir::new("opensnitch-config-default-action-drop-alias");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {"Address": "http://127.0.0.1:50051"},
"DefaultAction": "drop"
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(cfg.default_action, DefaultAction::Deny));
}

#[test]
fn from_raw_json_parses_ask_timeout_policy_values() {
    let dir = TestDir::new("opensnitch-config-ask-timeout-policy");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {"Address": "http://127.0.0.1:50051"},
"AskTimeoutPolicy": "drop"
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(cfg.ask_timeout_policy, AskFallbackPolicy::Drop));
}

#[test]
fn from_raw_json_parses_ask_timeout_policy_default_keyword() {
    let dir = TestDir::new("opensnitch-config-ask-timeout-policy-default-keyword");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {"Address": "http://127.0.0.1:50051"},
"AskTimeoutPolicy": "default"
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(
        cfg.ask_timeout_policy,
        AskFallbackPolicy::DefaultAction
    ));
}

#[test]
fn from_raw_json_ask_timeout_policy_defaults_to_default_action() {
    let dir = TestDir::new("opensnitch-config-ask-timeout-policy-default");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {"Address": "http://127.0.0.1:50051"}
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(
        cfg.ask_timeout_policy,
        AskFallbackPolicy::DefaultAction
    ));
}

#[test]
fn from_raw_json_ask_timeout_policy_null_defaults_to_default_action() {
    let dir = TestDir::new("opensnitch-config-ask-timeout-policy-null");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {"Address": "http://127.0.0.1:50051"},
"AskTimeoutPolicy": null
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(
        cfg.ask_timeout_policy,
        AskFallbackPolicy::DefaultAction
    ));
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

#[test]
fn from_raw_json_local_principal_allowlist_missing_preserves_legacy_unrestricted_behavior() {
    let dir = TestDir::new("opensnitch-config-local-allowlist-missing");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {"Address": "http://127.0.0.1:50051"}
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(cfg.local_control_allowed_principals.is_none());
}

#[test]
fn from_raw_json_local_principal_allowlist_null_preserves_legacy_unrestricted_behavior() {
    let dir = TestDir::new("opensnitch-config-local-allowlist-null");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {
    "Address": "http://127.0.0.1:50051",
    "Authentication": {
        "AllowedPrincipals": null,
        "AllowedUsers": null
    }
}
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(cfg.local_control_allowed_principals.is_none());
}

#[test]
fn from_raw_json_parses_local_principal_allowlist_uid_gid_pairs() {
    let dir = TestDir::new("opensnitch-config-local-allowlist-uid-gid");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {
    "Address": "http://127.0.0.1:50051",
    "Authentication": {
        "AllowedPrincipals": [
            {"UID": 1000, "GID": 1000},
            {"UID": 0, "GID": 0}
        ]
    }
}
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    let principals = cfg
        .local_control_allowed_principals
        .expect("allowlist should be set");

    assert_eq!(principals.len(), 2);
    assert!(principals.iter().any(|p| p.uid == 0 && p.gid == 0));
    assert!(principals.iter().any(|p| p.uid == 1000 && p.gid == 1000));
}

#[test]
fn from_raw_json_parses_local_principal_allowlist_usernames() {
    let dir = TestDir::new("opensnitch-config-local-allowlist-users");
    let config_path = dir.path.join("default-config.json");

    let current_user = User::from_uid(Uid::current())
        .expect("lookup current uid")
        .expect("current uid must exist in passwd database");
    let current_username = current_user.name;

    let raw = format!(
        r#"{{
"Server": {{
    "Address": "http://127.0.0.1:50051",
    "Authentication": {{
        "AllowedUsers": ["{current_username}"]
    }}
}}
}}"#
    );

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    let principals = cfg
        .local_control_allowed_principals
        .expect("allowlist should be set");

    assert!(
        principals
            .iter()
            .any(|p| { p.uid == current_user.uid.as_raw() && p.gid == current_user.gid.as_raw() })
    );
}

#[test]
fn from_raw_json_parses_remote_principal_bindings() {
    let dir = TestDir::new("opensnitch-config-remote-principal-bindings");
    let config_path = dir.path.join("default-config.json");

    let current_user = User::from_uid(Uid::current())
        .expect("lookup current uid")
        .expect("current uid must exist in passwd database");
    let current_username = current_user.name.clone();

    let raw = format!(
        r#"{{
"server": {{
    "address": "http://127.0.0.1:50051",
    "authentication": {{
        "mode": "local+remote",
        "remoteprincipalbindings": [
            {{
                "name": "primary-admin",
                "certfingerprint": "SHA256:AA:BB",
                "certsubject": "CN=Primary Admin",
                "certsan": "spiffe://opensnitch/admin",
                "localuser": "{current_username}",
                "capabilities": ["Firewall.Global.Write", "rules.owner.write", "firewall.global.write"]
            }},
            {{
                "name": "owner-only",
                "certfingerprint": "sha256:cc:dd",
                "localprincipal": {{"uid": 1001, "gid": 1002}},
                "capabilities": ["rules.owner.write"]
            }}
        ]
    }}
}}
}}"#
    );

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    let bindings = cfg
        .remote_principal_bindings
        .expect("remote bindings should be set");

    assert_eq!(bindings.len(), 2);
    assert_eq!(bindings[0].name, "primary-admin");
    assert_eq!(
        bindings[0].cert_fingerprint.as_deref(),
        Some("sha256:aa:bb")
    );
    assert_eq!(
        bindings[0].cert_subject.as_deref(),
        Some("CN=Primary Admin")
    );
    assert_eq!(
        bindings[0].cert_san.as_deref(),
        Some("spiffe://opensnitch/admin")
    );
    assert_eq!(bindings[0].local_principal.uid, current_user.uid.as_raw());
    assert_eq!(bindings[0].local_principal.gid, current_user.gid.as_raw());
    assert_eq!(
        bindings[0].capabilities,
        vec!["firewall.global.write", "rules.owner.write"]
    );
    assert_eq!(bindings[1].name, "owner-only");
    assert_eq!(bindings[1].local_principal.uid, 1001);
    assert_eq!(bindings[1].local_principal.gid, 1002);
}

#[test]
fn from_raw_json_filters_invalid_remote_principal_bindings() {
    let dir = TestDir::new("opensnitch-config-remote-principal-bindings-invalid");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {
    "Address": "http://127.0.0.1:50051",
    "Authentication": {
        "RemotePrincipalBindings": [
            {"Name": "missing-selector", "LocalPrincipal": {"UID": 1000, "GID": 1000}},
            {"Name": "missing-local-principal", "CertFingerprint": "sha256:11:22"}
        ]
    }
}
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert_eq!(cfg.remote_principal_bindings, Some(Vec::new()));
}

#[test]
fn from_raw_json_auth_mode_defaults_to_legacy() {
    let dir = TestDir::new("opensnitch-config-auth-mode-default");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {"Address": "http://127.0.0.1:50051"}
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(cfg.auth_mode, AuthMode::Legacy));
}

#[test]
fn from_raw_json_parses_auth_mode_local_only() {
    let dir = TestDir::new("opensnitch-config-auth-mode-local-only");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"Server": {
    "Address": "http://127.0.0.1:50051",
    "Authentication": {
        "Mode": "local-only"
    }
}
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(cfg.auth_mode, AuthMode::LocalOnly));
}

#[test]
fn from_raw_json_parses_auth_mode_case_insensitive_local_remote() {
    let dir = TestDir::new("opensnitch-config-auth-mode-local-remote");
    let config_path = dir.path.join("default-config.json");

    let raw = r#"{
"server": {
    "address": "http://127.0.0.1:50051",
    "authentication": {
        "mode": "LOCAL+REMOTE"
    }
}
}"#
    .to_string();

    let cfg = Config::from_raw_json(&config_path, raw).expect("parse config");
    assert!(matches!(cfg.auth_mode, AuthMode::LocalRemoteCapabilities));
}

#[test]
fn with_auth_mode_override_applies_cli_mode() {
    let cfg = Config::default().with_auth_mode_override(Some("local-only"));
    assert!(matches!(cfg.auth_mode, AuthMode::LocalOnly));

    let cfg = cfg.with_auth_mode_override(Some("legacy"));
    assert!(matches!(cfg.auth_mode, AuthMode::Legacy));
}

#[test]
fn with_auth_mode_override_ignores_invalid_values() {
    let cfg = Config::default().with_auth_mode_override(Some("local-only"));
    let cfg = cfg.with_auth_mode_override(Some("unsupported-mode"));
    assert!(matches!(cfg.auth_mode, AuthMode::LocalOnly));
}

#[test]
fn with_firewall_persistence_mode_override_applies_cli_mode() {
    let cfg = Config::default().with_firewall_persistence_mode_override(Some("live-only"));
    assert!(matches!(
        cfg.firewall_persistence_mode,
        FirewallPersistenceMode::LiveOnly
    ));

    let cfg = cfg.with_firewall_persistence_mode_override(Some("durable"));
    assert!(matches!(
        cfg.firewall_persistence_mode,
        FirewallPersistenceMode::Durable
    ));
}

#[test]
fn with_firewall_persistence_mode_override_ignores_invalid_values() {
    let cfg = Config::default().with_firewall_persistence_mode_override(Some("live-only"));
    let cfg = cfg.with_firewall_persistence_mode_override(Some("unsupported-mode"));
    assert!(matches!(
        cfg.firewall_persistence_mode,
        FirewallPersistenceMode::LiveOnly
    ));
}
