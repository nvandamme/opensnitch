use crate::models::firewall_config::{FirewallChain, FirewallRule};
use crate::platform::firewall::iptables::FirewallIptablesAdapter;

#[test]
fn chain_policy_args_builds_expected_iptables_policy_command() {
    let chain = FirewallChain {
        r#type: "mangle".to_string(),
        hook: "output".to_string(),
        policy: "drop".to_string(),
        ..Default::default()
    };

    let args =
        FirewallIptablesAdapter::probe_chain_policy_args(&chain).expect("policy args expected");
    assert_eq!(args, vec!["-w", "-t", "mangle", "-P", "OUTPUT", "DROP"]);
}

#[test]
fn chain_policy_args_returns_none_when_hook_or_table_missing() {
    let missing_hook = FirewallChain {
        r#type: "filter".to_string(),
        ..Default::default()
    };
    assert!(FirewallIptablesAdapter::probe_chain_policy_args(&missing_hook).is_none());

    let missing_type = FirewallChain {
        hook: "output".to_string(),
        ..Default::default()
    };
    assert!(FirewallIptablesAdapter::probe_chain_policy_args(&missing_type).is_none());
}

#[test]
fn iptables_args_render_expected_system_rule() {
    let rule = FirewallRule {
        table: "mangle".to_string(),
        chain: "OUTPUT".to_string(),
        parameters: "-p tcp --dport 443 -m comment --comment opensnitch".to_string(),
        target: "ACCEPT".to_string(),
        target_parameters: String::new(),
        ..Default::default()
    };

    let args = FirewallIptablesAdapter::probe_iptables_args(&rule);
    assert_eq!(
        args,
        vec![
            "-t",
            "mangle",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-m",
            "comment",
            "--comment",
            "opensnitch",
            "-j",
            "ACCEPT"
        ]
    );
}

#[test]
fn iptables_args_use_defaults_when_table_chain_missing() {
    let rule = FirewallRule {
        parameters: "-p udp --sport 53".to_string(),
        target: "NFQUEUE".to_string(),
        target_parameters: "--queue-num 0 --queue-bypass".to_string(),
        ..Default::default()
    };

    let args = FirewallIptablesAdapter::probe_iptables_args(&rule);
    assert_eq!(
        args,
        vec![
            "-t",
            "filter",
            "OUTPUT",
            "-p",
            "udp",
            "--sport",
            "53",
            "-j",
            "NFQUEUE",
            "--queue-num",
            "0",
            "--queue-bypass"
        ]
    );
}

#[test]
fn nfqueue_rules_include_bypass_flag_when_enabled() {
    let (conn, dns) = FirewallIptablesAdapter::probe_nfqueue_rules("23", true);
    assert!(conn.contains(&"--queue-bypass".to_string()));
    assert!(dns.contains(&"--queue-bypass".to_string()));
    assert!(conn.windows(2).any(|w| w == ["--queue-num", "23"]));
    assert!(dns.windows(2).any(|w| w == ["--queue-num", "23"]));
}

#[test]
fn nfqueue_rules_omit_bypass_flag_when_disabled() {
    let (conn, dns) = FirewallIptablesAdapter::probe_nfqueue_rules("0", false);
    assert!(!conn.contains(&"--queue-bypass".to_string()));
    assert!(!dns.contains(&"--queue-bypass".to_string()));
}

#[test]
fn parse_iptables_save_dump_extracts_chains_rules_and_zone_grouping() {
    let dump = r#"
*filter
:INPUT ACCEPT [0:0]
:zone_wan_input DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A zone_wan_input -s 198.51.100.0/24 -j DROP
COMMIT
"#;

    let parsed = FirewallIptablesAdapter::probe_parse_iptables_save_dump(dump, "ip");
    assert!(parsed.enabled);
    assert_eq!(parsed.chains.len(), 1);
    assert_eq!(parsed.zones.len(), 1);

    let input = &parsed.chains[0];
    assert_eq!(input.name, "INPUT");
    assert_eq!(input.table, "filter");
    assert_eq!(input.family, "ip");
    assert_eq!(input.policy, "accept");
    assert_eq!(input.rules.len(), 1);
    assert_eq!(input.rules[0].parameters, "-p tcp --dport 22");
    assert_eq!(input.rules[0].target, "ACCEPT");

    let zone = &parsed.zones[0];
    assert_eq!(zone.name, "wan");
    assert_eq!(zone.chains.len(), 1);
    assert_eq!(zone.chains[0].name, "zone_wan_input");
    assert_eq!(zone.chains[0].rules.len(), 1);
    assert_eq!(zone.chains[0].rules[0].target, "DROP");
}
