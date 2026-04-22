use crate::models::firewall_config::{FirewallChain, FirewallRule};
use crate::platform::adapters::firewall_iptables::FirewallIptablesAdapter;

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
