#![cfg(feature = "openwrt")]

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::models::firewall_config::{
    FirewallChain, FirewallConfig, FirewallExpression, FirewallRule, FirewallStatement,
    FirewallStatementValue, FirewallZone,
};
use crate::platform::firewall::openwrt_uci::{FirewallUciCommandRunner, OpenWrtUciFirewallAdapter};

struct RecordingRunner {
    commands: Mutex<Vec<String>>,
}

impl RecordingRunner {
    fn new() -> Self {
        Self {
            commands: Mutex::new(Vec::new()),
        }
    }

    fn take(&self) -> Vec<String> {
        self.commands.lock().expect("lock commands").clone()
    }
}

impl FirewallUciCommandRunner for RecordingRunner {
    fn run_uci_cli_command(&self, command: &str) -> anyhow::Result<()> {
        self.commands
            .lock()
            .expect("lock commands")
            .push(command.to_string());
        Ok(())
    }
}

fn export_fixture() -> &'static str {
    "package firewall\n\
\n\
config rule\n\
\toption name 'Allow-DNS'\n\
\toption target 'ACCEPT'\n\
\tlist expression_statement 'udp dport 53'\n"
}

fn luci_visible_rule_fixture() -> &'static str {
    "package firewall\n\
\n\
config rule\n\
	option name 'Allow-SSH'\n\
	option src 'wan'\n\
	option dest_port '22'\n\
	option proto 'tcp'\n\
	option target 'ACCEPT'\n"
}

fn named_rule_fixture() -> &'static str {
    "package firewall\n\
\n\
config rule 'opensnitch_ssh'\n\
    option name 'Allow-SSH'\n\
    option src 'wan'\n\
    option dest_port '22'\n\
    option proto 'tcp'\n\
    option target 'ACCEPT'\n"
}

fn passthrough_rule_fixture() -> &'static str {
    "package firewall\n\
\n\
config rule\n\
    option name 'Allow-HTTPS'\n\
    option src 'wan'\n\
    option dest 'lan'\n\
    option family 'ipv4'\n\
    option proto 'tcp'\n\
    option src_ip '198.51.100.10'\n\
    option dest_ip '192.0.2.25'\n\
    option src_port '1024-65535'\n\
    option dest_port '443'\n\
    option target 'ACCEPT'\n\
    option enabled '1'\n\
    list device 'wan'\n\
    list device 'wan6'\n"
}

fn canonical_firewall_fixture() -> FirewallConfig {
    FirewallConfig {
        enabled: true,
        version: 7,
        rules: vec![FirewallRule {
            table: "filter".to_string(),
            chain: "INPUT".to_string(),
            uuid: "allow_dns".to_string(),
            enabled: true,
            position: 1,
            description: "Allow DNS".to_string(),
            parameters: "-p udp --dport 53".to_string(),
            expressions: vec![FirewallExpression {
                statement: Some(FirewallStatement {
                    op: "raw".to_string(),
                    name: "expression_statement".to_string(),
                    values: vec![FirewallStatementValue {
                        key: "raw".to_string(),
                        value: "udp dport 53".to_string(),
                    }],
                }),
            }],
            target: "queue".to_string(),
            target_parameters: "num 0 bypass".to_string(),
        }],
        chains: vec![FirewallChain {
            name: "filter_output".to_string(),
            table: "filter".to_string(),
            family: "inet".to_string(),
            priority: "0".to_string(),
            r#type: "filter".to_string(),
            hook: "output".to_string(),
            policy: "accept".to_string(),
            rules: vec![FirewallRule {
                table: "filter".to_string(),
                chain: "filter_output".to_string(),
                uuid: "allow_https".to_string(),
                enabled: true,
                position: 2,
                description: "Allow HTTPS".to_string(),
                parameters: String::new(),
                expressions: vec![FirewallExpression {
                    statement: Some(FirewallStatement {
                        op: "==".to_string(),
                        name: "tcp".to_string(),
                        values: vec![FirewallStatementValue {
                            key: "dport".to_string(),
                            value: "443".to_string(),
                        }],
                    }),
                }],
                target: "accept".to_string(),
                target_parameters: String::new(),
            }],
        }],
        zones: vec![FirewallZone {
            name: "lan".to_string(),
            chains: vec![FirewallChain {
                name: "zone_lan_output".to_string(),
                table: "filter".to_string(),
                family: "inet".to_string(),
                priority: "0".to_string(),
                r#type: "filter".to_string(),
                hook: "output".to_string(),
                policy: "accept".to_string(),
                rules: vec![FirewallRule {
                    table: "filter".to_string(),
                    chain: "zone_lan_output".to_string(),
                    uuid: "allow_lan_dns".to_string(),
                    enabled: true,
                    position: 3,
                    description: "Allow LAN DNS".to_string(),
                    parameters: String::new(),
                    expressions: vec![FirewallExpression {
                        statement: Some(FirewallStatement {
                            op: "raw".to_string(),
                            name: "expression_statement".to_string(),
                            values: vec![FirewallStatementValue {
                                key: "raw".to_string(),
                                value: "udp dport 53".to_string(),
                            }],
                        }),
                    }],
                    target: "accept".to_string(),
                    target_parameters: String::new(),
                }],
            }],
        }],
    }
}

#[test]
fn builds_firewall_persistence_plan_from_uci_text() {
    let commands = OpenWrtUciFirewallAdapter::build_firewall_persistence_plan(export_fixture())
        .expect("build cli plan");

    assert!(commands.iter().any(|c| c == "uci add firewall rule"));
    assert!(
        commands
            .iter()
            .any(|c| c.starts_with("uci set firewall.@rule[-1].name="))
    );
    assert_eq!(
        commands.last().map(String::as_str),
        Some("uci commit firewall")
    );
}

#[test]
fn executes_firewall_persistence_plan_via_runner() {
    let runner = RecordingRunner::new();

    OpenWrtUciFirewallAdapter::persist_firewall_from_uci_text(export_fixture(), &runner)
        .expect("persist via runner");

    let commands = runner.take();
    assert!(!commands.is_empty(), "expected executed command list");
    assert_eq!(
        commands.last().map(String::as_str),
        Some("uci commit firewall")
    );
}

#[test]
fn builds_expected_luci_visible_rule_cli_sequence() {
    let commands =
        OpenWrtUciFirewallAdapter::build_firewall_persistence_plan(luci_visible_rule_fixture())
            .expect("build cli plan");

    assert_eq!(
        commands,
        vec![
            "uci add firewall rule".to_string(),
            "uci set firewall.@rule[-1].name='Allow-SSH'".to_string(),
            "uci set firewall.@rule[-1].src='wan'".to_string(),
            "uci set firewall.@rule[-1].dest_port='22'".to_string(),
            "uci set firewall.@rule[-1].proto='tcp'".to_string(),
            "uci set firewall.@rule[-1].target='ACCEPT'".to_string(),
            "uci commit firewall".to_string(),
        ]
    );
}

#[test]
fn persists_luci_visible_rule_via_uci_cli_runner() {
    let runner = RecordingRunner::new();

    OpenWrtUciFirewallAdapter::persist_firewall_from_uci_text(luci_visible_rule_fixture(), &runner)
        .expect("persist luci-visible rule via runner");

    assert_eq!(
        runner.take(),
        vec![
            "uci add firewall rule".to_string(),
            "uci set firewall.@rule[-1].name='Allow-SSH'".to_string(),
            "uci set firewall.@rule[-1].src='wan'".to_string(),
            "uci set firewall.@rule[-1].dest_port='22'".to_string(),
            "uci set firewall.@rule[-1].proto='tcp'".to_string(),
            "uci set firewall.@rule[-1].target='ACCEPT'".to_string(),
            "uci commit firewall".to_string(),
        ]
    );
}

#[test]
fn reconcile_plan_keeps_unknown_fields_on_existing_managed_sections() {
    let existing = "package firewall\n\
\n\
config rule 'opensnitch_allow_ssh'\n\
    option name 'Allow-SSH'\n\
    option src 'wan'\n\
    option dest_port '22'\n\
    option proto 'tcp'\n\
    option target 'ACCEPT'\n\
    option limit '10/sec'\n";

    let desired = "package firewall\n\
\n\
config rule 'opensnitch_allow_ssh'\n\
    option name 'Allow-SSH'\n\
    option src 'wan'\n\
    option dest_port '22'\n\
    option proto 'tcp'\n\
    option target 'DROP'\n";

    let commands = OpenWrtUciFirewallAdapter::build_reconcile_cli_plan_for_test(existing, desired)
        .expect("build reconcile plan preserving unknown fields");

    assert!(
        !commands
            .iter()
            .any(|cmd| cmd == "uci delete firewall.opensnitch_allow_ssh"),
        "existing managed section should be updated in place"
    );
    assert!(
        commands
            .iter()
            .any(|cmd| cmd == "uci set firewall.opensnitch_allow_ssh.target='DROP'"),
        "known OpenSnitch-owned fields should be updated from desired state"
    );
    assert!(
        commands
            .iter()
            .any(|cmd| cmd == "uci set firewall.opensnitch_allow_ssh.limit='10/sec'"),
        "unknown/non-OpenSnitch option fields should be preserved"
    );
}

#[test]
fn reconcile_plan_matches_rule_by_sidecar_map_when_section_name_is_renamed() {
    let existing = "package firewall\n\
\n\
config rule 'manual_ssh_rule'\n\
    option name 'Allow-SSH'\n\
    option src 'wan'\n\
    option dest_port '22'\n\
    option proto 'tcp'\n\
    option target 'ACCEPT'\n";

    let desired = "package firewall\n\
\n\
config rule 'opensnitch_allow_ssh'\n\
    option name 'Allow-SSH'\n\
    option src 'wan'\n\
    option dest_port '22'\n\
    option proto 'tcp'\n\
    option target 'DROP'\n";

    let mut rule_map = std::collections::HashMap::new();
    rule_map.insert("allow_ssh".to_string(), "manual_ssh_rule".to_string());

    let commands = OpenWrtUciFirewallAdapter::build_reconcile_cli_plan_with_rule_map_for_test(
        existing, desired, &rule_map,
    )
    .expect("build reconcile plan for renamed section");

    assert!(
        !commands
            .iter()
            .any(|cmd| cmd == "uci delete firewall.manual_ssh_rule"),
        "renamed section with sidecar identity should be updated in place"
    );
    assert!(
        commands
            .iter()
            .any(|cmd| cmd == "uci set firewall.manual_ssh_rule.target='DROP'"),
        "target section should remain the user-renamed section name"
    );
}

#[test]
fn preserves_explicit_named_rule_section_when_present() {
    let commands = OpenWrtUciFirewallAdapter::build_firewall_persistence_plan(named_rule_fixture())
        .expect("build named cli plan");

    assert_eq!(
        commands,
        vec![
            "uci set firewall.opensnitch_ssh='rule'".to_string(),
            "uci set firewall.opensnitch_ssh.name='Allow-SSH'".to_string(),
            "uci set firewall.opensnitch_ssh.src='wan'".to_string(),
            "uci set firewall.opensnitch_ssh.dest_port='22'".to_string(),
            "uci set firewall.opensnitch_ssh.proto='tcp'".to_string(),
            "uci set firewall.opensnitch_ssh.target='ACCEPT'".to_string(),
            "uci commit firewall".to_string(),
        ]
    );
}

#[test]
fn passes_through_firewall_rule_fields_to_uci_mapped_fields() {
    let commands =
        OpenWrtUciFirewallAdapter::build_firewall_persistence_plan(passthrough_rule_fixture())
            .expect("build passthrough cli plan");

    assert_eq!(
        commands,
        vec![
            "uci add firewall rule".to_string(),
            "uci set firewall.@rule[-1].name='Allow-HTTPS'".to_string(),
            "uci set firewall.@rule[-1].src='wan'".to_string(),
            "uci set firewall.@rule[-1].dest='lan'".to_string(),
            "uci set firewall.@rule[-1].family='ipv4'".to_string(),
            "uci set firewall.@rule[-1].proto='tcp'".to_string(),
            "uci set firewall.@rule[-1].src_ip='198.51.100.10'".to_string(),
            "uci set firewall.@rule[-1].dest_ip='192.0.2.25'".to_string(),
            "uci set firewall.@rule[-1].src_port='1024-65535'".to_string(),
            "uci set firewall.@rule[-1].dest_port='443'".to_string(),
            "uci set firewall.@rule[-1].target='ACCEPT'".to_string(),
            "uci set firewall.@rule[-1].enabled='1'".to_string(),
            "uci add_list firewall.@rule[-1].device='wan'".to_string(),
            "uci add_list firewall.@rule[-1].device='wan6'".to_string(),
            "uci commit firewall".to_string(),
        ]
    );
}

#[test]
fn renders_canonical_firewall_config_into_uci_cli_plan() {
    let commands =
        OpenWrtUciFirewallAdapter::build_firewall_config_cli_plan(&canonical_firewall_fixture())
            .expect("build cli plan from canonical firewall config");

    assert!(
        commands
            .iter()
            .any(|command| command == "uci set firewall.opensnitch_system_fw='system_fw'")
    );
    assert!(
        commands
            .iter()
            .any(|command| command == "uci set firewall.opensnitch_allow_dns.name='Allow DNS'")
    );
    assert!(commands.iter().any(|command| command
        == "uci add_list firewall.opensnitch_allow_dns.expression_statement='udp dport 53'"));
    assert!(
        commands
            .iter()
            .any(|command| command == "uci set firewall.opensnitch_zone_lan_output.zone='lan'")
    );
    assert_eq!(
        commands.last().map(String::as_str),
        Some("uci commit firewall")
    );
}

#[test]
fn parses_rendered_canonical_firewall_config_back_from_uci_text() {
    let expected = canonical_firewall_fixture();
    let raw = OpenWrtUciFirewallAdapter::render_firewall_config_to_uci_text(&expected);

    let parsed = OpenWrtUciFirewallAdapter::load_firewall_from_uci_text(&raw)
        .expect("parse rendered UCI text into firewall config");

    assert!(parsed.enabled);
    assert_eq!(parsed.version, expected.version);
    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(parsed.rules[0].uuid, "allow_dns");
    assert_eq!(parsed.rules[0].target, "queue");
    assert_eq!(parsed.chains.len(), 1);
    assert_eq!(parsed.chains[0].name, "filter_output");
    assert_eq!(parsed.chains[0].rules.len(), 1);
    assert_eq!(parsed.chains[0].rules[0].uuid, "allow_https");
    assert_eq!(parsed.zones.len(), 1);
    assert_eq!(parsed.zones[0].name, "lan");
    assert_eq!(parsed.zones[0].chains.len(), 1);
    assert_eq!(parsed.zones[0].chains[0].name, "zone_lan_output");
    assert_eq!(parsed.zones[0].chains[0].rules.len(), 1);
    assert_eq!(parsed.zones[0].chains[0].rules[0].uuid, "allow_lan_dns");
}

#[test]
fn parses_uci_show_firewall_fixture_into_firewall_model() {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/system-fw.cli-show.example.txt");
    let raw = fs::read_to_string(&fixture_path).expect("read uci show firewall fixture");

    let parsed = OpenWrtUciFirewallAdapter::load_firewall_from_uci_show_text(&raw)
        .expect("parse uci show firewall output");

    assert_eq!(parsed.rules.len(), 1);
    let rule = &parsed.rules[0];
    assert_eq!(rule.description, "Allow-DNS");
    assert!(rule.enabled);
    assert_eq!(rule.target, "ACCEPT");

    assert_eq!(rule.parameters, "-p udp --dport 53");
}

#[test]
fn parses_uci_show_repeated_option_as_list_values() {
    let raw = "firewall.@rule[0]=rule
firewall.@rule[0].name='Allow-DNS'
firewall.@rule[0].expression_statement='udp dport 53'
firewall.@rule[0].expression_statement='udp dport 5353'";

    let parsed = OpenWrtUciFirewallAdapter::load_firewall_from_uci_show_text(raw)
        .expect("parse repeated uci show list-like output");

    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(parsed.rules[0].expressions.len(), 2);
    assert_eq!(
        parsed.rules[0].expressions[0]
            .statement
            .as_ref()
            .expect("first expression statement")
            .values[0]
            .value,
        "udp dport 53"
    );
    assert_eq!(
        parsed.rules[0].expressions[1]
            .statement
            .as_ref()
            .expect("second expression statement")
            .values[0]
            .value,
        "udp dport 5353"
    );
}

#[test]
fn parses_realistic_uci_show_syntax_with_inline_multi_values() {
    let raw = "firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan' 'lan2'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[1].network='wan' 'wan6'
firewall.dot_fwd=rule
firewall.dot_fwd.name='Deny-DoT'
firewall.dot_fwd.src='lan'
firewall.dot_fwd.dest='wan'
firewall.dot_fwd.dest_port='853'
firewall.dot_fwd.proto='tcp' 'udp'
firewall.dot_fwd.target='REJECT'";

    let parsed = OpenWrtUciFirewallAdapter::load_firewall_from_uci_show_text(raw)
        .expect("parse realistic uci show firewall snippet");

    assert_eq!(parsed.zones.len(), 2);
    assert!(parsed.zones.iter().any(|zone| zone.name == "lan"));
    assert!(parsed.zones.iter().any(|zone| zone.name == "wan"));
    assert_eq!(parsed.rules.len(), 1);
    let rule = &parsed.rules[0];
    assert_eq!(rule.description, "Deny-DoT");
    assert_eq!(rule.target, "REJECT");

    assert_eq!(rule.parameters, "-p tcp udp -i lan -o wan --dport 853");
}

#[test]
fn parses_uci_show_with_redirect_nat_and_dense_icmp_lists() {
    let raw = "firewall.@defaults[0]=defaults
firewall.@defaults[0].input='DROP'
firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan' 'lan2'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[1].network='wan' 'wan6'
firewall.@rule[5]=rule
firewall.@rule[5].name='Allow-ICMPv6-Input'
firewall.@rule[5].src='wan'
firewall.@rule[5].proto='icmp'
firewall.@rule[5].icmp_type='echo-request' 'echo-reply' 'destination-unreachable' 'packet-too-big'
firewall.@rule[5].limit='1000/sec'
firewall.@rule[5].family='ipv6'
firewall.@rule[5].target='ACCEPT'
firewall.@rule[6]=rule
firewall.@rule[6].name='Allow-ICMPv6-Forward'
firewall.@rule[6].src='wan'
firewall.@rule[6].dest='*'
firewall.@rule[6].proto='icmp'
firewall.@rule[6].icmp_type='echo-request' 'echo-reply' 'destination-unreachable' 'packet-too-big'
firewall.@rule[6].limit='1000/sec'
firewall.@rule[6].family='ipv6'
firewall.@rule[6].target='ACCEPT'
firewall.@redirect[1]=redirect
firewall.@redirect[1].dest='lan'
firewall.@redirect[1].target='DNAT'
firewall.@redirect[1].name='Tailscale-IPv4'
firewall.@redirect[1].src='wan'
firewall.@redirect[1].src_dport='41641'
firewall.@redirect[1].dest_ip='10.1.1.4'
firewall.@redirect[1].dest_port='41641'
firewall.nat6=nat
firewall.nat6.family='ipv6'
firewall.nat6.src='wan'
firewall.nat6.src_ip='fd10::/48'
firewall.nat6.target='MASQUERADE'
firewall.nat6.proto='all'";

    let parsed = OpenWrtUciFirewallAdapter::load_firewall_from_uci_show_text(raw)
        .expect("parse uci show firewall snippet with redirect/nat + icmp lists");

    assert_eq!(parsed.zones.len(), 2);
    assert_eq!(parsed.rules.len(), 2);

    let input_rule = parsed
        .rules
        .iter()
        .find(|rule| rule.description == "Allow-ICMPv6-Input")
        .expect("input icmpv6 rule present");
    assert_eq!(input_rule.target, "ACCEPT");

    let forward_rule = parsed
        .rules
        .iter()
        .find(|rule| rule.description == "Allow-ICMPv6-Forward")
        .expect("forward icmpv6 rule present");
    assert_eq!(forward_rule.target, "ACCEPT");

    {
        assert_eq!(input_rule.parameters, "-p icmp -i wan");
        assert_eq!(forward_rule.parameters, "-p icmp -i wan -o *");
    }
}
#[test]
fn native_field_mapping_projects_parameters_into_openwrt_rule_fields() {
    let mut fw = canonical_firewall_fixture();
    fw.rules[0].parameters =
        "-p tcp -s 198.51.100.10 -d 192.0.2.25 --sport 12000 --dport 443".to_string();

    let commands = OpenWrtUciFirewallAdapter::build_firewall_config_cli_plan(&fw)
        .expect("build cli plan with native field projection");

    assert!(
        commands
            .iter()
            .any(|command| command == "uci set firewall.opensnitch_allow_dns.proto='tcp'")
    );
    assert!(commands.iter().any(|command| {
        command == "uci set firewall.opensnitch_allow_dns.src_ip='198.51.100.10'"
    }));
    assert!(commands.iter().any(|command| {
        command == "uci set firewall.opensnitch_allow_dns.dest_ip='192.0.2.25'"
    }));
    assert!(
        commands
            .iter()
            .any(|command| command == "uci set firewall.opensnitch_allow_dns.src_port='12000'")
    );
    assert!(
        commands
            .iter()
            .any(|command| command == "uci set firewall.opensnitch_allow_dns.dest_port='443'")
    );
}
#[test]
fn native_field_mapping_reconstructs_parameters_when_legacy_field_is_missing() {
    let raw = "package firewall

config rule 'allow_https'
    option table 'filter'
    option chain 'INPUT'
    option enabled '1'
    option proto 'tcp'
    option src_ip '198.51.100.10'
    option dest_ip '192.0.2.25'
    option src_port '12000'
    option dest_port '443'
    option target 'ACCEPT'
";

    let parsed = OpenWrtUciFirewallAdapter::load_firewall_from_uci_text(raw)
        .expect("parse native-field rule without legacy parameters");

    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(
        parsed.rules[0].parameters,
        "-p tcp -s 198.51.100.10 -d 192.0.2.25 --sport 12000 --dport 443"
    );
}
