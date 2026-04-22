use std::path::PathBuf;

use opensnitch_proto::pb;

use crate::config::Config;
use crate::models::firewall_state::FirewallBackend;
use crate::services::firewall_service::FirewallService;
use crate::utils::test_support::{TestDir, init_test_logging};

fn make_sysfw(version: u32, uuid: &str, table: &str, target: &str) -> pb::SysFirewall {
    pb::SysFirewall {
        enabled: true,
        version,
        system_rules: vec![pb::FwChains {
            rule: Some(pb::FwRule {
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
            }),
            chains: Vec::new(),
        }],
    }
}

#[tokio::test]
async fn reload_from_config_updates_runtime_backend_and_system_firewall() {
    init_test_logging();

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
    let initial_state = service.snapshot().await;
    assert!(matches!(initial_state.backend, FirewallBackend::Nftables));

    let initial_sysfw = service
        .system_firewall()
        .await
        .expect("initial system firewall must exist");
    assert_eq!(initial_sysfw.version, 1);

    service
        .reload_from_config(&ipt_cfg)
        .await
        .expect("reload from config");

    let reloaded_state = service.snapshot().await;
    assert!(matches!(reloaded_state.backend, FirewallBackend::Iptables));

    let reloaded_sysfw = service
        .system_firewall()
        .await
        .expect("reloaded system firewall must exist");
    assert_eq!(reloaded_sysfw.version, 2);
    assert_eq!(
        reloaded_sysfw.system_rules[0]
            .rule
            .as_ref()
            .map(|r| r.uuid.as_str()),
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
    assert!(service.system_firewall().await.is_none());
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
    assert!(service.system_firewall().await.is_some());

    let mut reloaded_cfg = cfg.clone();
    reloaded_cfg.firewall_backend = FirewallBackend::Iptables;
    reloaded_cfg.firewall_config_path = missing_path;

    service
        .reload_from_config(&reloaded_cfg)
        .await
        .expect("reload from missing config path");

    let state = service.snapshot().await;
    assert!(matches!(state.backend, FirewallBackend::Iptables));
    assert!(service.system_firewall().await.is_none());
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
    let loaded = service
        .system_firewall()
        .await
        .expect("system firewall loaded");
    assert_eq!(loaded.version, 8);
    assert_eq!(
        loaded.system_rules[0]
            .rule
            .as_ref()
            .map(|r| r.uuid.as_str()),
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

    let state = service.snapshot().await;
    assert!(matches!(state.backend, FirewallBackend::Nftables));

    let sysfw = service
        .system_firewall()
        .await
        .expect("previous system firewall should be retained");
    assert_eq!(sysfw.version, 11);
    assert_eq!(
        sysfw.system_rules[0].rule.as_ref().map(|r| r.uuid.as_str()),
        Some("stable-uuid")
    );
}
