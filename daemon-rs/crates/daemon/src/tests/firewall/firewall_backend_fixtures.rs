use std::{fs, path::PathBuf};

use crate::services::firewall::FirewallService;
use crate::tests::support::TestDir;

fn workspace_data_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(rel)
}

#[test]
fn runtime_backend_json_fixture_loads_with_semantic_shape() {
    let src = workspace_data_path("data/fixtures/firewall/openwrt-firewall-runtime.example.json");
    let raw = fs::read_to_string(&src).expect("read runtime firewall fixture");

    let dir = TestDir::new("opensnitch-firewall-runtime-fixture");
    let dst = dir.path.join("system-fw-runtime.json");
    fs::write(&dst, raw).expect("write fixture copy");

    let loaded = FirewallService::probe_load_system_firewall(&dst)
        .expect("load runtime semantics fixture")
        .expect("runtime fixture should deserialize");

    assert!(loaded.enabled);
    assert_eq!(loaded.version, 1);
    assert!(
        !loaded.chains.is_empty(),
        "expected chain semantics fixture"
    );

    let has_chain_rules = loaded.chains.iter().any(|c| !c.rules.is_empty());
    assert!(has_chain_rules, "expected nested chain rules");

    let has_queue_rule = loaded
        .chains
        .iter()
        .flat_map(|c| c.rules.iter())
        .any(|r| r.target.eq_ignore_ascii_case("queue") && r.target_parameters.contains("num"));
    assert!(
        has_queue_rule,
        "expected queue target rule from backend fixture"
    );
}

#[test]
fn uci_syntax_fixture_is_not_a_firewall_backend_loader_input() {
    let src = workspace_data_path("data/system-fw.example.uci");
    let raw = fs::read_to_string(&src).expect("read uci syntax fixture");

    let dir = TestDir::new("opensnitch-firewall-uci-not-backend");
    // Keep the extension as .json to ensure rejection is content-based,
    // not filename-based.
    let dst = dir.path.join("system-fw-from-uci.json");
    fs::write(&dst, raw).expect("write uci fixture copy");

    let err = FirewallService::probe_load_system_firewall(&dst)
        .expect_err("UCI syntax fixture must not be parsed as backend JSON");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("failed to parse firewall config"),
        "unexpected error message: {msg}"
    );
}

#[test]
fn uci_cli_show_fixture_is_not_a_firewall_backend_loader_input() {
    let src = workspace_data_path("data/system-fw.cli-show.example.txt");
    let raw = fs::read_to_string(&src).expect("read uci cli show fixture");

    let dir = TestDir::new("opensnitch-firewall-uci-cli-not-backend");
    // Keep the extension as .json to ensure rejection is content-based,
    // not filename-based.
    let dst = dir.path.join("system-fw-from-uci-cli-show.json");
    fs::write(&dst, raw).expect("write uci cli fixture copy");

    let err = FirewallService::probe_load_system_firewall(&dst)
        .expect_err("UCI CLI show fixture must not be parsed as backend JSON");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("failed to parse firewall config"),
        "unexpected error message: {msg}"
    );
}

#[test]
fn uci_cli_export_fixture_is_not_a_firewall_backend_loader_input() {
    let src = workspace_data_path("data/system-fw.cli-export.example.uci");
    let raw = fs::read_to_string(&src).expect("read uci cli export fixture");

    let dir = TestDir::new("opensnitch-firewall-uci-cli-export-not-backend");
    // Keep the extension as .json to ensure rejection is content-based,
    // not filename-based.
    let dst = dir.path.join("system-fw-from-uci-cli-export.json");
    fs::write(&dst, raw).expect("write uci cli export fixture copy");

    let err = FirewallService::probe_load_system_firewall(&dst)
        .expect_err("UCI CLI export fixture must not be parsed as backend JSON");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("failed to parse firewall config"),
        "unexpected error message: {msg}"
    );
}

#[test]
fn firewall_backend_fixture_directory_uses_json_only() {
    let dir = workspace_data_path("data/fixtures/firewall");
    let entries = fs::read_dir(&dir).expect("read firewall fixture directory");

    for entry in entries {
        let path = entry.expect("read fixture entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("fixture filename");

        if name.eq_ignore_ascii_case("README.md") {
            continue;
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        assert_eq!(ext, "json", "firewall fixtures must be .json (got: {name})");
    }
}

#[test]
fn all_firewall_backend_json_fixtures_are_loadable() {
    let dir = workspace_data_path("data/fixtures/firewall");
    let entries = fs::read_dir(&dir).expect("read firewall fixture directory");

    for entry in entries {
        let path = entry.expect("read fixture entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("fixture filename");

        // This test targets runtime system-firewall JSON object fixtures only.
        // Other JSON fixtures (for example expression arrays) are validated in
        // their owning test modules.
        let is_system_fw_fixture = name.contains("system-fw")
            || name.eq_ignore_ascii_case("openwrt-firewall-runtime.example.json")
            || name.eq_ignore_ascii_case("nftables-test-sysfw.example.json");
        if !is_system_fw_fixture {
            continue;
        }

        let raw = fs::read_to_string(&path).expect("read backend fixture json");
        let tmp = TestDir::new("opensnitch-firewall-fixture-load");
        let dst = tmp.path.join("fixture.json");
        fs::write(&dst, raw).expect("write backend fixture copy");

        let loaded = FirewallService::probe_load_system_firewall(&dst)
            .expect("load backend fixture")
            .expect("backend fixture should deserialize");
        assert!(
            loaded.enabled || !loaded.chains.is_empty() || !loaded.rules.is_empty(),
            "backend fixture should not decode into empty default-only payload: {}",
            path.display()
        );
    }
}

#[test]
fn nftables_fixture_preserves_expected_chain_and_rule_shapes() {
    let src = workspace_data_path("data/fixtures/firewall/nftables-test-sysfw.example.json");
    let raw = fs::read_to_string(&src).expect("read nftables fixture");

    let dir = TestDir::new("opensnitch-firewall-nftables-fixture");
    let dst = dir.path.join("nftables-system-fw.json");
    fs::write(&dst, raw).expect("write nftables fixture copy");

    let loaded = FirewallService::probe_load_system_firewall(&dst)
        .expect("load nftables fixture")
        .expect("nftables fixture should deserialize");

    let chain_names: Vec<_> = loaded.chains.iter().map(|c| c.name.as_str()).collect();
    assert!(
        chain_names.contains(&"filter_input"),
        "expected filter_input chain"
    );
    assert!(
        chain_names.contains(&"mangle_output"),
        "expected mangle_output chain"
    );
    assert!(
        chain_names.contains(&"mangle_forward"),
        "expected mangle_forward chain"
    );

    let has_queue_rule =
        loaded.chains.iter().flat_map(|c| c.rules.iter()).any(|r| {
            r.target.eq_ignore_ascii_case("queue") && r.target_parameters.contains("num 0")
        });
    assert!(
        has_queue_rule,
        "expected forwarded-connection queue rule in nftables fixture"
    );

    let has_icmp_echo = loaded
        .chains
        .iter()
        .flat_map(|c| c.rules.iter())
        .flat_map(|r| r.expressions.iter())
        .filter_map(|e| e.statement.as_ref())
        .any(|s| {
            s.name.eq_ignore_ascii_case("icmp")
                && s.values
                    .iter()
                    .any(|v| v.key == "type" && v.value == "echo-request")
        });
    assert!(
        has_icmp_echo,
        "expected ICMP echo-request expression in nftables fixture"
    );
}
