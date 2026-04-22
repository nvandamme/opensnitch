use crate::adapters::firewall_iptables::FirewallIptablesAdapter;
use opensnitch_proto::pb;

#[test]
fn chain_policy_args_builds_expected_iptables_policy_command() {
    let chain = pb::FwChain {
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
    let missing_hook = pb::FwChain {
        r#type: "filter".to_string(),
        ..Default::default()
    };
    assert!(FirewallIptablesAdapter::probe_chain_policy_args(&missing_hook).is_none());

    let missing_type = pb::FwChain {
        hook: "output".to_string(),
        ..Default::default()
    };
    assert!(FirewallIptablesAdapter::probe_chain_policy_args(&missing_type).is_none());
}
