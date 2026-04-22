use std::{fs, path::PathBuf};

use crate::config::Config;
use crate::models::firewall_config::{
    FirewallChain, FirewallConfig, FirewallExpression, FirewallRule, FirewallStatement,
    FirewallStatementValue,
};
use crate::models::firewall_state::FirewallBackend;
use crate::services::firewall::FirewallService;
use crate::tests::support::TestDir;

fn make_sysfw(version: u32, uuid: &str, table: &str, target: &str) -> FirewallConfig {
    FirewallConfig {
        enabled: true,
        version,
        rules: vec![FirewallRule {
            table: table.to_string(),
            chain: "OUTPUT".to_string(),
            uuid: uuid.to_string(),
            enabled: true,
            position: 1,
            description: format!("{uuid} rule"),
            parameters: "".to_string(),
            expressions: Vec::new(),
            target: target.to_string(),
            target_parameters: "".to_string(),
        }],
        chains: Vec::new(),
    }
}

#[tokio::test]
async fn reload_from_config_updates_runtime_backend_and_system_firewall() {
    crate::tests::support::init_test_logging();

    let dir = TestDir::new("opensnitch-firewall-reload");
    let nft_path = dir.path.join("system-fw-nft.json");
    let ipt_path = dir.path.join("system-fw-ipt.json");

    let mut nft_cfg = Config::default();
    nft_cfg.firewall_backend = FirewallBackend::Nftables;
    nft_cfg.firewall_queue_num = 0;
    nft_cfg.firewall_queue_bypass = true;
    nft_cfg.firewall_config_path = nft_path;
    nft_cfg.rules_path = PathBuf::from(&dir.path);
    nft_cfg.tasks_config_path = dir.path.join("tasks.json");

    let mut ipt_cfg = nft_cfg.clone();
    ipt_cfg.firewall_backend = FirewallBackend::Iptables;
    ipt_cfg.firewall_queue_num = 23;
    ipt_cfg.firewall_queue_bypass = false;
    ipt_cfg.firewall_config_path = ipt_path;

    let prep_service = FirewallService::new(&nft_cfg).expect("prep firewall service");
    prep_service
        .replace_system_firewall(
            Some(make_sysfw(1, "nft-uuid", "filter", "ACCEPT")),
            &nft_cfg,
        )
        .await
        .expect("persist nft system firewall");
    prep_service
        .replace_system_firewall(
            Some(make_sysfw(2, "ipt-uuid", "mangle", "NFQUEUE")),
            &ipt_cfg,
        )
        .await
        .expect("persist iptables system firewall");

    let service = FirewallService::new(&nft_cfg).expect("firewall service");
    let initial_state = service.snapshot();
    assert!(matches!(
        initial_state.state.backend,
        FirewallBackend::Nftables
    ));

    let initial_sysfw = service.system_firewall();
    let initial_sysfw = initial_sysfw
        .as_ref()
        .as_ref()
        .expect("initial system firewall must exist");
    assert_eq!(initial_sysfw.version, 1);

    service
        .reload_from_config(&ipt_cfg)
        .await
        .expect("reload from config");

    let reloaded_state = service.snapshot();
    assert!(matches!(
        reloaded_state.state.backend,
        FirewallBackend::Iptables
    ));

    let reloaded_sysfw = service.system_firewall();
    let reloaded_sysfw = reloaded_sysfw
        .as_ref()
        .as_ref()
        .expect("reloaded system firewall must exist");
    assert_eq!(reloaded_sysfw.version, 2);
    assert_eq!(
        reloaded_sysfw.rules.first().map(|r| r.uuid.as_str()),
        Some("ipt-uuid")
    );
}

#[tokio::test]
async fn new_with_missing_config_path_starts_without_system_firewall() {
    let dir = TestDir::new("opensnitch-firewall-missing-config");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_config_path = dir.path.join("does-not-exist.json");
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    let service = FirewallService::new(&cfg).expect("firewall service");
    assert!(service.system_firewall().is_none());
}

#[tokio::test]
async fn reload_from_config_missing_file_clears_runtime_system_firewall() {
    let dir = TestDir::new("opensnitch-firewall-clear-runtime");
    let existing_path = dir.path.join("system-fw-existing.json");
    let missing_path = dir.path.join("system-fw-missing.json");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_queue_num = 0;
    cfg.firewall_queue_bypass = true;
    cfg.firewall_config_path = existing_path;
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    let service = FirewallService::new(&cfg).expect("firewall service");
    service
        .replace_system_firewall(
            Some(make_sysfw(3, "present-uuid", "filter", "ACCEPT")),
            &cfg,
        )
        .await
        .expect("persist system firewall");
    assert!(service.system_firewall().is_some());

    let mut reloaded_cfg = cfg.clone();
    reloaded_cfg.firewall_backend = FirewallBackend::Iptables;
    reloaded_cfg.firewall_config_path = missing_path;

    service
        .reload_from_config(&reloaded_cfg)
        .await
        .expect("reload from missing config path");

    let state = service.snapshot();
    assert!(matches!(state.state.backend, FirewallBackend::Iptables));
    assert!(service.system_firewall().is_none());
}

#[tokio::test]
async fn reload_from_config_with_invalid_json_returns_error() {
    let dir = TestDir::new("opensnitch-firewall-invalid-reload");
    let valid_path = dir.path.join("system-fw-valid.json");
    let invalid_path = dir.path.join("system-fw-invalid.json");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_config_path = valid_path;
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    let service = FirewallService::new(&cfg).expect("firewall service");
    service
        .replace_system_firewall(Some(make_sysfw(5, "valid-uuid", "filter", "ACCEPT")), &cfg)
        .await
        .expect("persist valid system firewall");

    tokio::fs::write(&invalid_path, "{not-json")
        .await
        .expect("write invalid json");

    let mut bad_cfg = cfg.clone();
    bad_cfg.firewall_config_path = invalid_path;
    bad_cfg.firewall_backend = FirewallBackend::Iptables;

    let result = service.reload_from_config(&bad_cfg).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn new_loads_existing_system_firewall_from_disk() {
    let dir = TestDir::new("opensnitch-firewall-new-loads-existing");
    let path = dir.path.join("system-fw-existing.json");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_config_path = path;
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    let prep_service = FirewallService::new(&cfg).expect("prep service");
    prep_service
        .replace_system_firewall(
            Some(make_sysfw(8, "existing-uuid", "filter", "ACCEPT")),
            &cfg,
        )
        .await
        .expect("persist system firewall");

    let service = FirewallService::new(&cfg).expect("new service");
    let loaded = service.system_firewall();
    let loaded = loaded.as_ref().as_ref().expect("system firewall loaded");
    assert_eq!(loaded.version, 8);
    assert_eq!(
        loaded.rules.first().map(|r| r.uuid.as_str()),
        Some("existing-uuid")
    );
}

#[tokio::test]
async fn reload_from_config_error_keeps_previous_runtime_state() {
    let dir = TestDir::new("opensnitch-firewall-reload-error-preserves-state");
    let valid_path = dir.path.join("system-fw-valid.json");
    let invalid_path = dir.path.join("system-fw-invalid.json");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_config_path = valid_path;
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    let service = FirewallService::new(&cfg).expect("firewall service");
    service
        .replace_system_firewall(
            Some(make_sysfw(11, "stable-uuid", "filter", "ACCEPT")),
            &cfg,
        )
        .await
        .expect("persist baseline system firewall");

    tokio::fs::write(&invalid_path, "{invalid-json")
        .await
        .expect("write invalid json");

    let mut bad_cfg = cfg.clone();
    bad_cfg.firewall_backend = FirewallBackend::Iptables;
    bad_cfg.firewall_config_path = invalid_path;

    assert!(service.reload_from_config(&bad_cfg).await.is_err());

    let state = service.snapshot();
    assert!(matches!(state.state.backend, FirewallBackend::Nftables));

    let fw = service.system_firewall();
    let fw = fw
        .as_ref()
        .as_ref()
        .expect("previous system firewall should be retained");
    assert_eq!(fw.version, 11);
    assert_eq!(
        fw.rules.first().map(|r| r.uuid.as_str()),
        Some("stable-uuid")
    );
}

#[test]
fn save_and_load_system_firewall_round_trip() {
    let dir = TestDir::new("opensnitch-firewall-service-test");
    let path = dir.path.join("system-fw.json");

    let fw = FirewallConfig {
        enabled: true,
        version: 1,
        rules: vec![FirewallRule {
            table: "filter".to_string(),
            chain: "OUTPUT".to_string(),
            uuid: "uuid-1".to_string(),
            enabled: true,
            position: 1,
            description: "allow-dns".to_string(),
            parameters: "-p udp --dport 53".to_string(),
            expressions: Vec::new(),
            target: "ACCEPT".to_string(),
            target_parameters: "".to_string(),
        }],
        chains: Vec::new(),
    };

    FirewallService::probe_save_system_firewall(&path, &fw).expect("save fw");
    let loaded = FirewallService::probe_load_system_firewall(&path)
        .expect("load fw")
        .expect("present fw");

    assert!(loaded.enabled);
    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.rules.len(), 1);
    assert_eq!(
        loaded.rules.first().map(|r| r.uuid.as_str()),
        Some("uuid-1")
    );
}

#[test]
fn load_system_firewall_missing_file_returns_none() {
    let dir = TestDir::new("opensnitch-firewall-service-missing-load");
    let path = dir.path.join("missing-system-fw.json");

    let loaded =
        FirewallService::probe_load_system_firewall(&path).expect("missing path should not fail");
    assert!(loaded.is_none());
}

#[test]
fn load_system_firewall_invalid_json_returns_error() {
    let dir = TestDir::new("opensnitch-firewall-service-invalid-json");
    let path = dir.path.join("invalid-system-fw.json");
    fs::write(&path, "{not-json").expect("write invalid json");

    let err =
        FirewallService::probe_load_system_firewall(&path).expect_err("invalid json must error");
    assert!(format!("{err:#}").contains("failed to parse firewall config"));
}

#[test]
fn save_and_load_preserves_nested_chain_expressions() {
    let dir = TestDir::new("opensnitch-firewall-service-nested-roundtrip");
    let path = dir.path.join("nested-system-fw.json");

    let fw = FirewallConfig {
        enabled: true,
        version: 7,
        rules: Vec::new(),
        chains: vec![FirewallChain {
            name: "mangle_output".to_string(),
            table: "opensnitch".to_string(),
            family: "inet".to_string(),
            priority: "mangle".to_string(),
            r#type: "filter".to_string(),
            hook: "output".to_string(),
            policy: "accept".to_string(),
            rules: vec![FirewallRule {
                table: "opensnitch".to_string(),
                chain: "mangle_output".to_string(),
                uuid: "uuid-nested-1".to_string(),
                enabled: true,
                position: 11,
                description: "nested expression".to_string(),
                parameters: "".to_string(),
                expressions: vec![FirewallExpression {
                    statement: Some(FirewallStatement {
                        op: "==".to_string(),
                        name: "meta".to_string(),
                        values: vec![FirewallStatementValue {
                            key: "l4proto".to_string(),
                            value: "tcp".to_string(),
                        }],
                    }),
                }],
                target: "queue".to_string(),
                target_parameters: "num 0 bypass".to_string(),
            }],
        }],
    };

    FirewallService::probe_save_system_firewall(&path, &fw).expect("save nested fw");
    let loaded = FirewallService::probe_load_system_firewall(&path)
        .expect("load nested fw")
        .expect("nested fw should exist");

    assert_eq!(loaded.version, 7);
    let chain = &loaded.chains[0];
    assert_eq!(chain.name, "mangle_output");
    assert_eq!(chain.rules.len(), 1);
    let expr = &chain.rules[0].expressions[0];
    let statement = expr.statement.as_ref().expect("statement present");
    assert_eq!(statement.name, "meta");
    assert_eq!(statement.values[0].key, "l4proto");
    assert_eq!(statement.values[0].value, "tcp");
}

#[test]
fn load_system_firewall_minimal_json_uses_defaults() {
    let dir = TestDir::new("opensnitch-firewall-service-minimal-json");
    let path = dir.path.join("minimal-system-fw.json");
    fs::write(&path, "{}").expect("write minimal json");

    let loaded = FirewallService::probe_load_system_firewall(&path)
        .expect("load minimal fw")
        .expect("minimal fw should deserialize");

    assert!(!loaded.enabled);
    assert_eq!(loaded.version, 0);
    assert!(loaded.rules.is_empty());
    assert!(loaded.chains.is_empty());
}

#[test]
fn load_system_firewall_supports_top_level_rule_only() {
    let dir = TestDir::new("opensnitch-firewall-service-top-rule");
    let path = dir.path.join("top-rule-system-fw.json");
    fs::write(
        &path,
        r#"{
    "Enabled": true,
    "Version": 2,
    "SystemRules": [
        {
            "Rule": {
                "Table": "filter",
                "Chain": "OUTPUT",
                "UUID": "rule-only-uuid",
                "Enabled": true,
                "Position": 9,
                "Description": "top-level-rule",
                "Parameters": "-p udp --dport 53",
                "Expressions": [],
                "Target": "ACCEPT",
                "TargetParameters": ""
            },
            "Chains": []
        }
    ]
}"#,
    )
    .expect("write top-level rule json");

    let loaded = FirewallService::probe_load_system_firewall(&path)
        .expect("load top-level rule fw")
        .expect("top-level rule fw should deserialize");

    assert!(loaded.enabled);
    assert_eq!(loaded.version, 2);
    assert_eq!(loaded.rules.len(), 1);
    let rule = &loaded.rules[0];
    assert_eq!(rule.uuid, "rule-only-uuid");
    assert_eq!(rule.position, 9);
    assert_eq!(rule.target, "ACCEPT");
}

#[test]
fn load_system_firewall_parses_position_from_string_or_invalid_to_zero() {
    let dir = TestDir::new("opensnitch-firewall-service-position-string");
    let path = dir.path.join("position-system-fw.json");
    fs::write(
        &path,
        r#"{
    "Enabled": true,
    "Version": 3,
    "SystemRules": [
        {
            "Rule": {
                "UUID": "pos-string",
                "Enabled": true,
                "Position": "13",
                "Target": "ACCEPT"
            },
            "Chains": []
        },
        {
            "Rule": {
                "UUID": "pos-invalid",
                "Enabled": true,
                "Position": "not-a-number",
                "Target": "DROP"
            },
            "Chains": []
        }
    ]
}"#,
    )
    .expect("write position parsing json");

    let loaded = FirewallService::probe_load_system_firewall(&path)
        .expect("load position parsing fw")
        .expect("position parsing fw should deserialize");

    let first = &loaded.rules[0];
    let second = &loaded.rules[1];

    assert_eq!(first.position, 13);
    assert_eq!(second.position, 0);
}

#[test]
fn load_system_firewall_inherits_table_and_chain_from_parent_chain() {
    // Mirrors the Go daemon's legacy file format (daemon/data/system-fw.json):
    // nested Rules inside a FwChain don't carry Table/Chain; they inherit from
    // the parent chain's Table and Name fields.
    let dir = TestDir::new("opensnitch-firewall-chain-inheritance");
    let path = dir.path.join("chain-inherit-system-fw.json");
    fs::write(
        &path,
        r#"{
    "Enabled": true,
    "Version": 1,
    "SystemRules": [
        {
            "Chains": [
                {
                    "Name": "mangle_output",
                    "Table": "opensnitch",
                    "Family": "inet",
                    "Priority": "",
                    "Type": "mangle",
                    "Hook": "output",
                    "Policy": "accept",
                    "Rules": [
                        {
                            "UUID": "inherit-uuid",
                            "Enabled": true,
                            "Position": "0",
                            "Description": "no table/chain in source",
                            "Expressions": [],
                            "Target": "accept",
                            "TargetParameters": ""
                        }
                    ]
                }
            ]
        }
    ]
}"#,
    )
    .expect("write chain-inheritance json");

    let loaded = FirewallService::probe_load_system_firewall(&path)
        .expect("load chain-inheritance fw")
        .expect("should deserialize");

    assert_eq!(loaded.chains.len(), 1);
    let chain = &loaded.chains[0];
    assert_eq!(chain.name, "mangle_output");
    assert_eq!(chain.table, "opensnitch");
    assert_eq!(chain.rules.len(), 1);

    let rule = &chain.rules[0];
    assert_eq!(rule.uuid, "inherit-uuid");
    // Table and Chain must be inherited from the parent chain, not left empty.
    assert_eq!(rule.table, "opensnitch");
    assert_eq!(rule.chain, "mangle_output");
}
