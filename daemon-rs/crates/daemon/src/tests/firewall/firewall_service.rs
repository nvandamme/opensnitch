use std::os::unix::fs::PermissionsExt;
use std::{fs, path::PathBuf};

use crate::config::Config;
use crate::models::config_runtime::FirewallPersistenceMode;
use crate::models::firewall_config::{
    FirewallChain, FirewallConfig, FirewallExpression, FirewallRule, FirewallStatement,
    FirewallStatementValue,
};
use crate::models::firewall_state::FirewallBackend;
#[cfg(feature = "openwrt")]
use crate::platform::firewall::openwrt_uci::OpenWrtUciFirewallAdapter;
use crate::services::firewall::FirewallService;
use crate::tests::support::TestDir;

#[cfg(feature = "openwrt")]
fn openwrt_env_lock() -> &'static std::sync::Mutex<()> {
    firewall_manager_env_lock()
}

fn firewall_manager_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

fn firewall_backend_fixture_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/fixtures/firewall")
        .join(file)
}

#[cfg(feature = "openwrt")]
#[test]
fn runtime_backend_resolution_keeps_openwrt_explicit() {
    let resolved = FirewallService::probe_runtime_backend_for_target(FirewallBackend::OpenWrtUci);
    assert!(matches!(resolved, FirewallBackend::OpenWrtUci));
}

#[cfg(feature = "openwrt")]
#[test]
fn introspection_backend_order_is_netlink_first_with_openwrt_fallback() {
    let order = FirewallService::probe_firewall_introspection_sources(FirewallBackend::OpenWrtUci);
    assert!(!order.is_empty());
    assert_eq!(order[0], "netlink");
    assert_eq!(order, vec!["netlink", "openwrt-uci"]);
}

#[cfg(not(feature = "openwrt"))]
#[test]
fn runtime_backend_resolution_routes_openwrt_to_generic_linux_path() {
    let resolved = FirewallService::probe_runtime_backend_for_target(FirewallBackend::OpenWrtUci);
    assert!(!matches!(resolved, FirewallBackend::OpenWrtUci));
}

#[cfg(not(feature = "openwrt"))]
#[test]
fn introspection_backend_order_is_netlink_first_with_generic_linux_fallback() {
    let order = FirewallService::probe_firewall_introspection_sources(FirewallBackend::Iptables);
    assert!(!order.is_empty());
    assert_eq!(order[0], "netlink");
    assert_eq!(order, vec!["netlink", "nftables", "iptables"]);
}

fn copy_firewall_backend_fixture(file: &str, dst: &std::path::Path) {
    let raw =
        fs::read_to_string(firewall_backend_fixture_path(file)).expect("read firewall fixture");
    fs::write(dst, raw).expect("write firewall fixture copy");
}

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
        zones: Vec::new(),
    }
}

fn make_zone_service_sysfw(
    version: u32,
    zone_name: &str,
    uuid: &str,
    service_name: &str,
) -> FirewallConfig {
    FirewallConfig {
        enabled: true,
        version,
        rules: Vec::new(),
        chains: Vec::new(),
        zones: vec![crate::models::firewall_config::FirewallZone {
            name: zone_name.to_string(),
            chains: vec![FirewallChain {
                name: format!("zone_{zone_name}_input"),
                table: "filter".to_string(),
                family: "inet".to_string(),
                hook: "input".to_string(),
                policy: "accept".to_string(),
                r#type: "filter".to_string(),
                rules: vec![FirewallRule {
                    table: "filter".to_string(),
                    chain: format!("zone_{zone_name}_input"),
                    uuid: uuid.to_string(),
                    enabled: true,
                    position: 1,
                    description: format!("zone {zone_name} service {service_name}"),
                    parameters: "-s 192.0.2.0/24".to_string(),
                    expressions: vec![FirewallExpression {
                        statement: Some(FirewallStatement {
                            op: "".to_string(),
                            name: "service".to_string(),
                            values: vec![FirewallStatementValue {
                                key: "service".to_string(),
                                value: service_name.to_string(),
                            }],
                        }),
                    }],
                    target: "ACCEPT".to_string(),
                    target_parameters: "".to_string(),
                }],
                ..Default::default()
            }],
        }],
    }
}

fn make_ufw_app_profile_sysfw(version: u32, uuid: &str, profile_name: &str) -> FirewallConfig {
    FirewallConfig {
        enabled: true,
        version,
        rules: vec![FirewallRule {
            table: "filter".to_string(),
            chain: "INPUT".to_string(),
            uuid: uuid.to_string(),
            enabled: true,
            position: 1,
            description: format!("allow profile {profile_name}"),
            parameters: "-s 198.51.100.10".to_string(),
            expressions: vec![FirewallExpression {
                statement: Some(FirewallStatement {
                    op: "".to_string(),
                    name: "profile".to_string(),
                    values: vec![FirewallStatementValue {
                        key: "profile".to_string(),
                        value: profile_name.to_string(),
                    }],
                }),
            }],
            target: "ALLOW".to_string(),
            target_parameters: "".to_string(),
        }],
        chains: Vec::new(),
        zones: Vec::new(),
    }
}

fn make_empty_zone_sysfw(version: u32, zone_name: &str) -> FirewallConfig {
    FirewallConfig {
        enabled: true,
        version,
        rules: Vec::new(),
        chains: Vec::new(),
        zones: vec![crate::models::firewall_config::FirewallZone {
            name: zone_name.to_string(),
            chains: Vec::new(),
        }],
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
async fn replace_system_firewall_live_only_updates_runtime_without_persisting_to_disk() {
    let dir = TestDir::new("opensnitch-firewall-live-only");
    let path = dir.path.join("system-fw-live-only.json");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_persistence_mode = FirewallPersistenceMode::LiveOnly;
    cfg.firewall_config_path = path.clone();
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    let service = FirewallService::new(&cfg).expect("firewall service");
    service
        .replace_system_firewall(
            Some(make_sysfw(9, "live-only-uuid", "filter", "ACCEPT")),
            &cfg,
        )
        .await
        .expect("apply runtime-only system firewall");

    let runtime_snapshot = service.system_firewall();
    let runtime_sysfw = runtime_snapshot
        .as_ref()
        .as_ref()
        .expect("runtime system firewall should be set");
    assert_eq!(runtime_sysfw.version, 9);
    assert_eq!(runtime_sysfw.rules[0].uuid, "live-only-uuid");

    assert!(
        !path.exists(),
        "live-only mode must not create durable firewall config files"
    );
}

#[tokio::test]
async fn replace_system_firewall_durable_uses_firewalld_manager_when_active() {
    let _guard = firewall_manager_env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let dir = TestDir::new("opensnitch-firewall-durable-firewalld-manager");
    let bin_dir = dir.path.join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let log_path = dir.path.join("firewall-cmd.log");

    let fake_firewall_cmd = bin_dir.join("firewall-cmd");
    fs::write(
        &fake_firewall_cmd,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$OPENSNITCH_TEST_FIREWALL_CMD_LOG\"\nif [ \"${1:-}\" = \"--state\" ]; then\n  echo running\n  exit 0\nfi\nif [ \"${1:-}\" = \"--direct\" ] && [ \"${2:-}\" = \"--get-all-rules\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--permanent\" ] && [ \"${2:-}\" = \"--direct\" ] && [ \"${3:-}\" = \"--get-all-rules\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--reload\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--direct\" ] && [ \"${2:-}\" = \"--add-rule\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--permanent\" ] && [ \"${2:-}\" = \"--direct\" ] && [ \"${3:-}\" = \"--add-rule\" ]; then\n  exit 0\nfi\nexit 0\n",
    )
    .expect("write fake firewall-cmd script");
    let mut perms = fs::metadata(&fake_firewall_cmd)
        .expect("stat fake firewall-cmd")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake_firewall_cmd, perms).expect("chmod fake firewall-cmd");

    let old_path = std::env::var_os("PATH");
    let mut new_path_entries = vec![bin_dir.clone()];
    if let Some(old_path) = &old_path {
        new_path_entries.extend(std::env::split_paths(old_path));
    }
    let new_path = std::env::join_paths(new_path_entries).expect("join PATH entries");

    // SAFETY: this test serializes process-environment mutation behind a global mutex.
    unsafe {
        std::env::set_var("PATH", &new_path);
        std::env::set_var("OPENSNITCH_TEST_FIREWALL_CMD_LOG", &log_path);
    }

    let path = dir.path.join("system-fw-durable.json");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_persistence_mode = FirewallPersistenceMode::Durable;
    cfg.firewall_config_path = path.clone();
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    // Authority is injected on the instance — no process-global env var needed.
    let service = FirewallService::new(&cfg)
        .expect("firewall service")
        .with_test_manager("firewalld");
    let result = service
        .replace_system_firewall(
            Some(make_sysfw(10, "durable-uuid", "filter", "ACCEPT")),
            &cfg,
        )
        .await;

    // SAFETY: this test serializes process-environment mutation behind a global mutex.
    unsafe {
        if let Some(old_path) = old_path {
            std::env::set_var("PATH", old_path);
        } else {
            std::env::remove_var("PATH");
        }
        std::env::remove_var("OPENSNITCH_TEST_FIREWALL_CMD_LOG");
    }

    result.expect("durable persistence should use firewalld manager path");
    let log = fs::read_to_string(&log_path).expect("read fake firewall-cmd log");
    assert!(log.contains("--direct --add-rule"));
    assert!(log.contains("--permanent --direct --add-rule"));
    assert!(log.contains("--reload"));
    assert!(
        !path.exists(),
        "manager-based durable path should not write direct backend config files"
    );
}

#[tokio::test]
async fn replace_system_firewall_durable_uses_firewalld_zone_rich_rules_when_zone_present() {
    let _guard = firewall_manager_env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let dir = TestDir::new("opensnitch-firewall-durable-firewalld-zone-rich-rule");
    let bin_dir = dir.path.join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let log_path = dir.path.join("firewall-cmd.log");

    let fake_firewall_cmd = bin_dir.join("firewall-cmd");
    fs::write(
        &fake_firewall_cmd,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$OPENSNITCH_TEST_FIREWALL_CMD_LOG\"\nif [ \"${1:-}\" = \"--state\" ]; then\n  echo running\n  exit 0\nfi\nif [ \"${1:-}\" = \"--get-zones\" ]; then\n  echo public home\n  exit 0\nfi\nif [ \"${1:-}\" = \"--zone=work\" ] && [ \"${2:-}\" = \"--list-rich-rules\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--permanent\" ] && [ \"${2:-}\" = \"--zone=work\" ] && [ \"${3:-}\" = \"--list-rich-rules\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--permanent\" ] && [ \"${2:-}\" = \"--new-zone=work\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--direct\" ] && [ \"${2:-}\" = \"--get-all-rules\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--permanent\" ] && [ \"${2:-}\" = \"--direct\" ] && [ \"${3:-}\" = \"--get-all-rules\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--zone=work\" ] && [ \"${2:-}\" = \"--add-rich-rule\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--permanent\" ] && [ \"${2:-}\" = \"--zone=work\" ] && [ \"${3:-}\" = \"--add-rich-rule\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--reload\" ]; then\n  exit 0\nfi\nexit 0\n",
    )
    .expect("write fake firewall-cmd script");
    let mut perms = fs::metadata(&fake_firewall_cmd)
        .expect("stat fake firewall-cmd")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake_firewall_cmd, perms).expect("chmod fake firewall-cmd");

    let old_path = std::env::var_os("PATH");
    let mut new_path_entries = vec![bin_dir.clone()];
    if let Some(old_path) = &old_path {
        new_path_entries.extend(std::env::split_paths(old_path));
    }
    let new_path = std::env::join_paths(new_path_entries).expect("join PATH entries");

    unsafe {
        std::env::set_var("PATH", &new_path);
        std::env::set_var("OPENSNITCH_TEST_FIREWALL_CMD_LOG", &log_path);
    }

    let path = dir.path.join("system-fw-durable.json");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_persistence_mode = FirewallPersistenceMode::Durable;
    cfg.firewall_config_path = path.clone();
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    // Authority is injected on the instance — no process-global env var needed.
    let service = FirewallService::new(&cfg)
        .expect("firewall service")
        .with_test_manager("firewalld");
    let result = service
        .replace_system_firewall(
            Some(make_zone_service_sysfw(
                13,
                "work",
                "zone-service-uuid",
                "ssh",
            )),
            &cfg,
        )
        .await;

    unsafe {
        if let Some(old_path) = old_path {
            std::env::set_var("PATH", old_path);
        } else {
            std::env::remove_var("PATH");
        }
        std::env::remove_var("OPENSNITCH_TEST_FIREWALL_CMD_LOG");
    }

    result.expect("zone-backed firewalld persistence should use rich rules");
    let log = fs::read_to_string(&log_path).expect("read fake firewall-cmd log");
    assert!(log.contains("--get-zones"));
    assert!(log.contains("--permanent --new-zone=work"));
    assert!(log.contains("--zone=work --add-rich-rule rule family=\"ipv4\" source address=\"192.0.2.0/24\" service name=\"ssh\" accept"));
    assert!(log.contains("--permanent --zone=work --add-rich-rule rule family=\"ipv4\" source address=\"192.0.2.0/24\" service name=\"ssh\" accept"));
    assert!(!log.contains("--direct --add-rule"));
    assert!(log.contains("--reload"));
    assert!(
        !path.exists(),
        "manager-based durable path should not write direct backend config files"
    );
}

#[tokio::test]
async fn replace_system_firewall_durable_removes_stale_firewalld_zone_rich_rules() {
    let _guard = firewall_manager_env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let dir = TestDir::new("opensnitch-firewall-durable-firewalld-zone-rich-remove");
    let bin_dir = dir.path.join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let log_path = dir.path.join("firewall-cmd.log");

    let fake_firewall_cmd = bin_dir.join("firewall-cmd");
    fs::write(
        &fake_firewall_cmd,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$OPENSNITCH_TEST_FIREWALL_CMD_LOG\"\nif [ \"${1:-}\" = \"--state\" ]; then\n  echo running\n  exit 0\nfi\nif [ \"${1:-}\" = \"--get-zones\" ]; then\n  echo public home work\n  exit 0\nfi\nif [ \"${1:-}\" = \"--direct\" ] && [ \"${2:-}\" = \"--get-all-rules\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--permanent\" ] && [ \"${2:-}\" = \"--direct\" ] && [ \"${3:-}\" = \"--get-all-rules\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--zone=work\" ] && [ \"${2:-}\" = \"--add-rich-rule\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--permanent\" ] && [ \"${2:-}\" = \"--zone=work\" ] && [ \"${3:-}\" = \"--add-rich-rule\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--zone=work\" ] && [ \"${2:-}\" = \"--remove-rich-rule\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--permanent\" ] && [ \"${2:-}\" = \"--zone=work\" ] && [ \"${3:-}\" = \"--remove-rich-rule\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--reload\" ]; then\n  exit 0\nfi\nexit 0\n",
    )
    .expect("write fake firewall-cmd script");
    let mut perms = fs::metadata(&fake_firewall_cmd)
        .expect("stat fake firewall-cmd")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake_firewall_cmd, perms).expect("chmod fake firewall-cmd");

    let old_path = std::env::var_os("PATH");
    let mut new_path_entries = vec![bin_dir.clone()];
    if let Some(old_path) = &old_path {
        new_path_entries.extend(std::env::split_paths(old_path));
    }
    let new_path = std::env::join_paths(new_path_entries).expect("join PATH entries");

    unsafe {
        std::env::set_var("PATH", &new_path);
        std::env::set_var("OPENSNITCH_TEST_FIREWALL_CMD_LOG", &log_path);
    }

    let path = dir.path.join("system-fw-durable.json");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_persistence_mode = FirewallPersistenceMode::Durable;
    cfg.firewall_config_path = path.clone();
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    let service = FirewallService::new(&cfg)
        .expect("firewall service")
        .with_test_manager("firewalld");
    service
        .replace_system_firewall(
            Some(make_zone_service_sysfw(
                15,
                "work",
                "zone-service-uuid-1",
                "ssh",
            )),
            &cfg,
        )
        .await
        .expect("first persist should add zone rich rule");
    service
        .replace_system_firewall(Some(make_empty_zone_sysfw(16, "work")), &cfg)
        .await
        .expect("second persist should remove stale zone rich rule");

    unsafe {
        if let Some(old_path) = old_path {
            std::env::set_var("PATH", old_path);
        } else {
            std::env::remove_var("PATH");
        }
        std::env::remove_var("OPENSNITCH_TEST_FIREWALL_CMD_LOG");
    }

    let log = fs::read_to_string(&log_path).expect("read fake firewall-cmd log");
    assert!(log.contains("--zone=work --add-rich-rule rule family=\"ipv4\" source address=\"192.0.2.0/24\" service name=\"ssh\" accept"));
    assert!(log.contains("--zone=work --remove-rich-rule rule family=\"ipv4\" source address=\"192.0.2.0/24\" service name=\"ssh\" accept"));
    assert!(log.contains("--permanent --zone=work --remove-rich-rule rule family=\"ipv4\" source address=\"192.0.2.0/24\" service name=\"ssh\" accept"));
}

#[tokio::test]
async fn replace_system_firewall_durable_uses_ufw_manager_when_active() {
    let _guard = firewall_manager_env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let dir = TestDir::new("opensnitch-firewall-durable-ufw-manager");
    let bin_dir = dir.path.join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let log_path = dir.path.join("ufw.log");

    let fake_ufw = bin_dir.join("ufw");
    fs::write(
        &fake_ufw,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$OPENSNITCH_TEST_UFW_LOG\"\nif [ \"${1:-}\" = \"status\" ] && [ \"${2:-}\" = \"numbered\" ]; then\n  echo 'Status: active'\n  exit 0\nfi\nif [ \"${1:-}\" = \"status\" ]; then\n  echo 'Status: active'\n  exit 0\nfi\nif [ \"${1:-}\" = \"reload\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--force\" ]; then\n  exit 0\nfi\nexit 0\n",
    )
    .expect("write fake ufw script");
    let mut perms = fs::metadata(&fake_ufw)
        .expect("stat fake ufw")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake_ufw, perms).expect("chmod fake ufw");

    let old_path = std::env::var_os("PATH");
    let mut new_path_entries = vec![bin_dir.clone()];
    if let Some(old_path) = &old_path {
        new_path_entries.extend(std::env::split_paths(old_path));
    }
    let new_path = std::env::join_paths(new_path_entries).expect("join PATH entries");

    // SAFETY: this test serializes process-environment mutation behind a global mutex.
    unsafe {
        std::env::set_var("PATH", &new_path);
        std::env::set_var("OPENSNITCH_TEST_UFW_LOG", &log_path);
    }

    let path = dir.path.join("system-fw-durable.json");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_persistence_mode = FirewallPersistenceMode::Durable;
    cfg.firewall_config_path = path.clone();
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    // Authority is injected on the instance — no process-global env var needed.
    let service = FirewallService::new(&cfg)
        .expect("firewall service")
        .with_test_manager("ufw");
    let result = service
        .replace_system_firewall(Some(make_sysfw(12, "ufw-uuid", "filter", "ACCEPT")), &cfg)
        .await;

    // SAFETY: this test serializes process-environment mutation behind a global mutex.
    unsafe {
        if let Some(old_path) = old_path {
            std::env::set_var("PATH", old_path);
        } else {
            std::env::remove_var("PATH");
        }
        std::env::remove_var("OPENSNITCH_TEST_UFW_LOG");
    }

    result.expect("durable persistence should use ufw manager path");
    let log = fs::read_to_string(&log_path).expect("read fake ufw log");
    assert!(log.contains("status numbered"));
    assert!(log.contains("--force allow"));
    assert!(log.contains("reload"));
    assert!(
        !path.exists(),
        "manager-based durable path should not write direct backend config files"
    );
}

#[tokio::test]
async fn replace_system_firewall_durable_uses_ufw_app_profile_when_rule_has_profile_hint() {
    let _guard = firewall_manager_env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let dir = TestDir::new("opensnitch-firewall-durable-ufw-app-profile");
    let bin_dir = dir.path.join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let log_path = dir.path.join("ufw.log");

    let fake_ufw = bin_dir.join("ufw");
    fs::write(
        &fake_ufw,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$OPENSNITCH_TEST_UFW_LOG\"\nif [ \"${1:-}\" = \"status\" ] && [ \"${2:-}\" = \"numbered\" ]; then\n  echo 'Status: active'\n  exit 0\nfi\nif [ \"${1:-}\" = \"status\" ]; then\n  echo 'Status: active'\n  exit 0\nfi\nif [ \"${1:-}\" = \"reload\" ]; then\n  exit 0\nfi\nif [ \"${1:-}\" = \"--force\" ]; then\n  exit 0\nfi\nexit 0\n",
    )
    .expect("write fake ufw script");
    let mut perms = fs::metadata(&fake_ufw)
        .expect("stat fake ufw")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake_ufw, perms).expect("chmod fake ufw");

    let old_path = std::env::var_os("PATH");
    let mut new_path_entries = vec![bin_dir.clone()];
    if let Some(old_path) = &old_path {
        new_path_entries.extend(std::env::split_paths(old_path));
    }
    let new_path = std::env::join_paths(new_path_entries).expect("join PATH entries");

    unsafe {
        std::env::set_var("PATH", &new_path);
        std::env::set_var("OPENSNITCH_TEST_UFW_LOG", &log_path);
    }

    let path = dir.path.join("system-fw-durable.json");

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::Nftables;
    cfg.firewall_persistence_mode = FirewallPersistenceMode::Durable;
    cfg.firewall_config_path = path.clone();
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    // Authority is injected on the instance — no process-global env var needed.
    let service = FirewallService::new(&cfg)
        .expect("firewall service")
        .with_test_manager("ufw");
    let result = service
        .replace_system_firewall(
            Some(make_ufw_app_profile_sysfw(
                14,
                "ufw-profile-uuid",
                "OpenSSH",
            )),
            &cfg,
        )
        .await;

    unsafe {
        if let Some(old_path) = old_path {
            std::env::set_var("PATH", old_path);
        } else {
            std::env::remove_var("PATH");
        }
        std::env::remove_var("OPENSNITCH_TEST_UFW_LOG");
    }

    result.expect("ufw profile-backed persistence should use app syntax");
    let log = fs::read_to_string(&log_path).expect("read fake ufw log");
    assert!(log.contains("status numbered"));
    assert!(log.contains("--force allow in from 198.51.100.10 to any app OpenSSH comment opensnitch-sysfw:ufw-profile-uuid"));
    assert!(log.contains("reload"));
    assert!(
        !path.exists(),
        "manager-based durable path should not write direct backend config files"
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

#[cfg(feature = "openwrt")]
#[test]
fn load_openwrt_uci_firewall_from_extensionless_path() {
    let dir = TestDir::new("opensnitch-firewall-openwrt-load");
    let path = dir.path.join("firewall");
    let fw = make_sysfw(14, "openwrt-load-uuid", "filter", "queue");
    let raw = OpenWrtUciFirewallAdapter::render_firewall_config_to_uci_text(&fw);
    fs::write(&path, raw).expect("write OpenWrt UCI firewall fixture");

    let loaded =
        FirewallService::probe_load_system_firewall_for_backend(&path, FirewallBackend::OpenWrtUci)
            .expect("load OpenWrt firewall from extensionless path")
            .expect("OpenWrt firewall should exist");

    assert_eq!(loaded.version, 14);
    assert_eq!(loaded.rules.len(), 1);
    assert_eq!(loaded.rules[0].uuid, "openwrt_load_uuid");
}

#[cfg(feature = "openwrt")]
#[tokio::test]
async fn replace_system_firewall_runs_openwrt_apply_after_commit() {
    let _guard = openwrt_env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = TestDir::new("opensnitch-firewall-openwrt-apply");
    let bin_dir = dir.path.join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");

    let log_path = dir.path.join("uci.log");
    let firewall_path = dir.path.join("firewall");

    let fake_uci_path = bin_dir.join("uci");
    fs::write(
        &fake_uci_path,
        "#!/bin/sh\nset -eu\nprintf 'uci %s\\n' \"$*\" >> \"$OPENSNITCH_TEST_UCI_LOG\"\nif [ \"${1:-}\" = commit ] && [ \"${2:-}\" = firewall ]; then\n  printf '%s' \"$OPENSNITCH_TEST_UCI_COMMIT_OUTPUT\" > \"$OPENSNITCH_TEST_UCI_OUTPUT_PATH\"\nfi\n",
    )
    .expect("write fake uci script");

    let fake_fw4_path = bin_dir.join("fw4");
    fs::write(
        &fake_fw4_path,
        "#!/bin/sh\nset -eu\nprintf 'fw4 %s\\n' \"$*\" >> \"$OPENSNITCH_TEST_UCI_LOG\"\n",
    )
    .expect("write fake fw4 script");

    for path in [&fake_uci_path, &fake_fw4_path] {
        let mut perms = fs::metadata(path).expect("stat fake script").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod fake script");
    }

    let old_path = std::env::var_os("PATH");
    let mut new_path_entries = vec![bin_dir.clone()];
    if let Some(old_path) = &old_path {
        new_path_entries.extend(std::env::split_paths(old_path));
    }
    let new_path = std::env::join_paths(new_path_entries).expect("join PATH entries");

    let fw = make_sysfw(22, "openwrt-apply-uuid", "filter", "queue");
    let expected_uci = OpenWrtUciFirewallAdapter::render_firewall_config_to_uci_text(&fw);

    // SAFETY: this test serializes process-environment mutation behind a global mutex.
    unsafe {
        std::env::set_var("PATH", &new_path);
        std::env::set_var("OPENSNITCH_TEST_UCI_LOG", &log_path);
        std::env::set_var("OPENSNITCH_TEST_UCI_OUTPUT_PATH", &firewall_path);
        std::env::set_var("OPENSNITCH_TEST_UCI_COMMIT_OUTPUT", &expected_uci);
    }

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::OpenWrtUci;
    cfg.firewall_config_path = firewall_path;
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    let service = FirewallService::new(&cfg).expect("firewall service");
    let result = service.replace_system_firewall(Some(fw), &cfg).await;

    // SAFETY: this test serializes process-environment mutation behind a global mutex.
    unsafe {
        if let Some(old_path) = old_path {
            std::env::set_var("PATH", old_path);
        } else {
            std::env::remove_var("PATH");
        }
        std::env::remove_var("OPENSNITCH_TEST_UCI_LOG");
        std::env::remove_var("OPENSNITCH_TEST_UCI_OUTPUT_PATH");
        std::env::remove_var("OPENSNITCH_TEST_UCI_COMMIT_OUTPUT");
    }

    result.expect("persist firewall and apply runtime");

    let log = fs::read_to_string(&log_path).expect("read fake command log");
    assert!(log.contains("uci commit firewall"));
    assert!(log.contains("fw4 reload"));
}

#[cfg(feature = "openwrt")]
#[tokio::test]
async fn replace_system_firewall_openwrt_removes_stale_managed_sections() {
    let _guard = openwrt_env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = TestDir::new("opensnitch-firewall-openwrt-reconcile-remove");
    let bin_dir = dir.path.join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");

    let log_path = dir.path.join("uci.log");
    let firewall_path = dir.path.join("firewall");

    let fake_uci_path = bin_dir.join("uci");
    fs::write(
        &fake_uci_path,
        "#!/bin/sh\nset -eu\nprintf 'uci %s\\n' \"$*\" >> \"$OPENSNITCH_TEST_UCI_LOG\"\nif [ \"${1:-}\" = commit ] && [ \"${2:-}\" = firewall ]; then\n  printf '%s' \"$OPENSNITCH_TEST_UCI_COMMIT_OUTPUT\" > \"$OPENSNITCH_TEST_UCI_OUTPUT_PATH\"\nfi\n",
    )
    .expect("write fake uci script");

    let fake_fw4_path = bin_dir.join("fw4");
    fs::write(
        &fake_fw4_path,
        "#!/bin/sh\nset -eu\nprintf 'fw4 %s\\n' \"$*\" >> \"$OPENSNITCH_TEST_UCI_LOG\"\n",
    )
    .expect("write fake fw4 script");

    for path in [&fake_uci_path, &fake_fw4_path] {
        let mut perms = fs::metadata(path).expect("stat fake script").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod fake script");
    }

    let old_path = std::env::var_os("PATH");
    let mut new_path_entries = vec![bin_dir.clone()];
    if let Some(old_path) = &old_path {
        new_path_entries.extend(std::env::split_paths(old_path));
    }
    let new_path = std::env::join_paths(new_path_entries).expect("join PATH entries");

    let initial_fw = make_sysfw(23, "openwrt-remove-uuid", "filter", "queue");
    let updated_fw = FirewallConfig {
        enabled: true,
        version: 24,
        rules: Vec::new(),
        chains: Vec::new(),
        zones: Vec::new(),
    };
    let initial_uci = OpenWrtUciFirewallAdapter::render_firewall_config_to_uci_text(&initial_fw);
    let updated_uci = OpenWrtUciFirewallAdapter::render_firewall_config_to_uci_text(&updated_fw);

    unsafe {
        std::env::set_var("PATH", &new_path);
        std::env::set_var("OPENSNITCH_TEST_UCI_LOG", &log_path);
        std::env::set_var("OPENSNITCH_TEST_UCI_OUTPUT_PATH", &firewall_path);
        std::env::set_var("OPENSNITCH_TEST_UCI_COMMIT_OUTPUT", &initial_uci);
    }

    let mut cfg = Config::default();
    cfg.firewall_backend = FirewallBackend::OpenWrtUci;
    cfg.firewall_config_path = firewall_path.clone();
    cfg.rules_path = PathBuf::from(&dir.path);
    cfg.tasks_config_path = dir.path.join("tasks.json");

    let service = FirewallService::new(&cfg).expect("firewall service");
    service
        .replace_system_firewall(Some(initial_fw), &cfg)
        .await
        .expect("persist initial OpenWrt firewall state");

    unsafe {
        std::env::set_var("OPENSNITCH_TEST_UCI_COMMIT_OUTPUT", &updated_uci);
    }

    service
        .replace_system_firewall(Some(updated_fw), &cfg)
        .await
        .expect("reconcile OpenWrt firewall state after rule removal");

    unsafe {
        if let Some(old_path) = old_path {
            std::env::set_var("PATH", old_path);
        } else {
            std::env::remove_var("PATH");
        }
        std::env::remove_var("OPENSNITCH_TEST_UCI_LOG");
        std::env::remove_var("OPENSNITCH_TEST_UCI_OUTPUT_PATH");
        std::env::remove_var("OPENSNITCH_TEST_UCI_COMMIT_OUTPUT");
    }

    let log = fs::read_to_string(&log_path).expect("read fake command log");
    assert!(
        log.contains("uci delete firewall.opensnitch_openwrt_remove_uuid"),
        "expected stale managed rule section to be deleted before recreation"
    );
    assert!(log.matches("fw4 reload").count() >= 2);

    let persisted = fs::read_to_string(&firewall_path).expect("read reconciled firewall file");
    assert!(!persisted.contains("openwrt-remove-uuid"));
    assert!(persisted.contains("option version '24'"));
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
        zones: Vec::new(),
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
        zones: Vec::new(),
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
fn save_and_load_preserves_zone_chains() {
    let dir = TestDir::new("opensnitch-firewall-service-zone-roundtrip");
    let path = dir.path.join("zone-system-fw.json");

    let fw = FirewallConfig {
        enabled: true,
        version: 9,
        rules: Vec::new(),
        chains: Vec::new(),
        zones: vec![crate::models::firewall_config::FirewallZone {
            name: "lan".to_string(),
            chains: vec![FirewallChain {
                name: "zone_lan_output".to_string(),
                table: "opensnitch".to_string(),
                family: "inet".to_string(),
                priority: "0".to_string(),
                r#type: "filter".to_string(),
                hook: "output".to_string(),
                policy: "accept".to_string(),
                rules: vec![FirewallRule {
                    table: "opensnitch".to_string(),
                    chain: "zone_lan_output".to_string(),
                    uuid: "zone-lan-rule-1".to_string(),
                    enabled: true,
                    position: 1,
                    description: "zone allow".to_string(),
                    parameters: "ip protocol tcp".to_string(),
                    expressions: Vec::new(),
                    target: "accept".to_string(),
                    target_parameters: "".to_string(),
                }],
            }],
        }],
    };

    FirewallService::probe_save_system_firewall(&path, &fw).expect("save zone fw");
    let loaded = FirewallService::probe_load_system_firewall(&path)
        .expect("load zone fw")
        .expect("zone fw should exist");

    assert_eq!(loaded.version, 9);
    assert_eq!(loaded.zones.len(), 1);
    let zone = &loaded.zones[0];
    assert_eq!(zone.name, "lan");
    assert_eq!(zone.chains.len(), 1);
    assert_eq!(zone.chains[0].name, "zone_lan_output");
    assert_eq!(zone.chains[0].rules.len(), 1);
    assert_eq!(zone.chains[0].rules[0].uuid, "zone-lan-rule-1");
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
    assert!(loaded.zones.is_empty());
}

#[test]
fn load_system_firewall_supports_top_level_rule_only() {
    let dir = TestDir::new("opensnitch-firewall-service-top-rule");
    let path = dir.path.join("top-rule-system-fw.json");
    copy_firewall_backend_fixture("top-rule-system-fw.example.json", &path);

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
    copy_firewall_backend_fixture("position-parsing-system-fw.example.json", &path);

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
    copy_firewall_backend_fixture("chain-inherit-system-fw.example.json", &path);

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
