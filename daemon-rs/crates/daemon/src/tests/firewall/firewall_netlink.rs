use std::{fs, path::PathBuf};

use crate::models::firewall_config::{FirewallChain, FirewallConfig, FirewallRule};
use crate::platform::adapters::firewall_netlink::{
    FirewallNetlinkAdapter, FirewallNetlinkOperation, NetfilterRuleChain,
};
use crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter;

fn backend_fixture_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/fixtures/firewall")
        .join(file)
}

#[test]
fn ensure_plan_contains_expected_interception_rules() {
    let ops = FirewallNetlinkAdapter::probe_plan_ensure(7, true);

    assert_eq!(ops.len(), 4);
    assert_eq!(
        ops[0],
        FirewallNetlinkOperation::EnsureBaseChains {
            queue_num: 7,
            queue_bypass: true,
        }
    );

    assert!(matches!(
        &ops[1],
        FirewallNetlinkOperation::EnsureInterceptionRule {
            chain: NetfilterRuleChain::FilterInput,
            expression,
            tag,
        } if expression.contains("queue num 7 bypass")
            && expression.contains("opensnitch-queue-dns")
            && tag == "opensnitch-queue-dns"
    ));

    assert!(matches!(
        &ops[2],
        FirewallNetlinkOperation::EnsureInterceptionRule {
            chain: NetfilterRuleChain::MangleOutput,
            expression,
            tag,
        } if expression.contains("opensnitch-queue-connections-non-tcp")
            && tag == "opensnitch-queue-connections-non-tcp"
    ));

    assert!(matches!(
        &ops[3],
        FirewallNetlinkOperation::EnsureInterceptionRule {
            chain: NetfilterRuleChain::MangleOutput,
            expression,
            tag,
        } if expression.contains("opensnitch-queue-connections-tcp-syn")
            && tag == "opensnitch-queue-connections-tcp-syn"
    ));
}

#[test]
fn apply_system_firewall_plan_skips_disabled_and_empty_rules() {
    let chain = FirewallChain {
        family: "inet".to_string(),
        table: "opensnitch".to_string(),
        name: "mangle_output".to_string(),
        rules: vec![
            FirewallRule {
                enabled: false,
                uuid: "disabled".to_string(),
                parameters: "ip protocol tcp".to_string(),
                ..Default::default()
            },
            FirewallRule {
                enabled: true,
                uuid: "enabled-1".to_string(),
                parameters: "ip protocol tcp".to_string(),
                target: "accept".to_string(),
                ..Default::default()
            },
            FirewallRule {
                enabled: true,
                uuid: "empty".to_string(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let sysfw = FirewallConfig {
        enabled: true,
        version: 0,
        rules: Vec::new(),
        chains: vec![chain],
        ..Default::default()
    };

    let ops = FirewallNetlinkAdapter::probe_plan_apply_system_firewall(&sysfw, 0);

    assert_eq!(ops.len(), 2);
    assert!(matches!(
        &ops[0],
        FirewallNetlinkOperation::EnsureSystemChain {
            family,
            table,
            name,
            hook,
            priority,
            policy,
            chain_type,
        } if family == "inet" && table == "opensnitch" && name == "mangle_output"
            && hook == "output"
            && priority == "0"
            && policy == "accept"
            && chain_type == "filter"
    ));

    assert!(matches!(
        &ops[1],
        FirewallNetlinkOperation::ApplySystemRule {
            family,
            table,
            chain,
            expression,
            tag,
        } if family == "inet"
            && table == "opensnitch"
            && chain == "mangle_output"
            && expression == "ip protocol tcp accept"
            && tag == "opensnitch-sysfw:enabled-1"
    ));
}

#[test]
fn clear_system_firewall_plan_targets_each_chain() {
    let sysfw = FirewallConfig {
        enabled: true,
        version: 0,
        rules: Vec::new(),
        chains: vec![
            FirewallChain {
                family: "inet".to_string(),
                table: "opensnitch".to_string(),
                name: "mangle_output".to_string(),
                ..Default::default()
            },
            FirewallChain {
                family: "ip".to_string(),
                table: "filter".to_string(),
                name: "output".to_string(),
                ..Default::default()
            },
        ],
        zones: vec![crate::models::firewall_config::FirewallZone {
            name: "lan".to_string(),
            chains: vec![FirewallChain {
                family: "inet".to_string(),
                table: "opensnitch".to_string(),
                name: "zone_lan_output".to_string(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let ops = FirewallNetlinkAdapter::probe_plan_clear_system_firewall(&sysfw);
    assert_eq!(ops.len(), 3);

    assert!(matches!(
        &ops[0],
        FirewallNetlinkOperation::ClearTaggedSystemRules {
            family,
            table,
            chain,
        } if family == "inet" && table == "opensnitch" && chain == "mangle_output"
    ));
    assert!(matches!(
        &ops[1],
        FirewallNetlinkOperation::ClearTaggedSystemRules {
            family,
            table,
            chain,
        } if family == "ip" && table == "filter" && chain == "output"
    ));
    assert!(matches!(
        &ops[2],
        FirewallNetlinkOperation::ClearTaggedSystemRules {
            family,
            table,
            chain,
        } if family == "inet" && table == "opensnitch" && chain == "zone_lan_output"
    ));
}

#[test]
fn apply_system_firewall_plan_includes_zone_chains() {
    let sysfw = FirewallConfig {
        enabled: true,
        version: 0,
        rules: Vec::new(),
        chains: Vec::new(),
        zones: vec![crate::models::firewall_config::FirewallZone {
            name: "wan".to_string(),
            chains: vec![FirewallChain {
                family: "inet".to_string(),
                table: "opensnitch".to_string(),
                name: "zone_wan_input".to_string(),
                hook: "input".to_string(),
                policy: "accept".to_string(),
                r#type: "filter".to_string(),
                rules: vec![FirewallRule {
                    enabled: true,
                    uuid: "zone-rule-1".to_string(),
                    parameters: "ip protocol tcp".to_string(),
                    target: "accept".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }],
    };

    let ops = FirewallNetlinkAdapter::probe_plan_apply_system_firewall(&sysfw, 0);
    assert_eq!(ops.len(), 2);
    assert!(matches!(
        &ops[0],
        FirewallNetlinkOperation::EnsureSystemChain {
            family,
            table,
            name,
            ..
        } if family == "inet" && table == "opensnitch" && name == "zone_wan_input"
    ));
    assert!(matches!(
        &ops[1],
        FirewallNetlinkOperation::ApplySystemRule {
            family,
            table,
            chain,
            expression,
            ..
        } if family == "inet" && table == "opensnitch" && chain == "zone_wan_input" && expression == "ip protocol tcp accept"
    ));
}

#[test]
fn system_rule_expression_supports_safe_netlink_subset() {
    let supported = [
        "meta l4proto != tcp drop",
        "meta l4proto { tcp, udp } th dport 88 accept",
        "ip protocol udp accept",
        "ip6 nexthdr == tcp accept",
        "meta mark 0x10 drop",
        "ip saddr 192.168.1.10 accept",
        "ip saddr 192.168.1.0/24 accept",
        "ip daddr 127.0.0.0-127.255.255.255 accept",
        "ip daddr == 10.0.0.1 drop",
        "ip6 saddr 2001:db8::1 accept",
        "ip6 daddr 2001:db8::1-2001:db8::ffff accept",
        "ip6 daddr 2001:db8::/64 accept",
        "ip6 daddr != 2001:db8::2 drop",
        "ct state new,related accept",
        "ct state established,related accept",
        "ct state new queue num 0",
        "tcp flags & (fin|syn|rst|ack) == syn accept",
        "th dport 443 accept",
        "udp dport 51820 accept",
        "icmp type { echo-request, echo-reply } accept",
        "icmpv6 type echo-request accept",
        "queue num 3 bypass",
    ];

    for expression in supported {
        assert!(
            FirewallNetlinkAdapter::probe_is_system_rule_expression_supported(expression),
            "expected expression to be supported: {expression}"
        );
    }
}

#[test]
fn system_rule_expression_supports_shipped_system_firewall_shapes() {
    // Keep this list aligned with real shapes from daemon/data/system-fw.json.
    let shipped = [
        "tcp dport 22 accept",
        "ip daddr 127.0.0.0-127.255.255.255 accept",
        "icmp type { echo-request, echo-reply, destination-unreachable } accept",
        "icmpv6 type { echo-request, echo-reply, destination-unreachable } accept",
        "udp dport 51820 accept",
        "ct state new queue num 0",
    ];

    for expression in shipped {
        assert!(
            FirewallNetlinkAdapter::probe_is_system_rule_expression_supported(expression),
            "expected shipped system-fw expression to be supported: {expression}"
        );
    }
}

#[test]
fn system_rule_expression_supports_nftables_testdata_shapes() {
    // Keep aligned with daemon/firewall/nftables/testdata/test-sysfw-conf.json
    // so parity against the Go-side rule shapes remains explicit.
    let fixture = backend_fixture_path("nftables-supported-expressions.example.json");
    let raw = fs::read_to_string(&fixture).expect("read nftables expression fixture");
    let go_testdata: Vec<String> = crate::services::storage::StorageService::
        parse_with_storage_format_for_path(&fixture, &raw)
        .expect("decode nftables expression fixture as JSON string array");

    assert!(
        !go_testdata.is_empty(),
        "expression fixture must not be empty"
    );

    for expression in go_testdata {
        assert!(
            FirewallNetlinkAdapter::probe_is_system_rule_expression_supported(&expression),
            "expected Go testdata expression to be supported: {expression}"
        );
    }
}

#[test]
fn apply_plan_generated_expressions_are_netlink_supported() {
    let sysfw = FirewallConfig {
        enabled: true,
        version: 0,
        rules: Vec::new(),
        chains: vec![
            FirewallChain {
                family: "inet".to_string(),
                table: "opensnitch".to_string(),
                name: "filter_input".to_string(),
                hook: "input".to_string(),
                policy: "accept".to_string(),
                r#type: "filter".to_string(),
                rules: vec![
                    FirewallRule {
                        enabled: true,
                        uuid: "ssh-allow".to_string(),
                        parameters: "tcp dport 22".to_string(),
                        target: "accept".to_string(),
                        ..Default::default()
                    },
                    FirewallRule {
                        enabled: true,
                        uuid: "icmp-allow".to_string(),
                        parameters:
                            "icmp type { echo-request, echo-reply, destination-unreachable }"
                                .to_string(),
                        target: "accept".to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            FirewallChain {
                family: "inet".to_string(),
                table: "opensnitch".to_string(),
                name: "mangle_output".to_string(),
                hook: "output".to_string(),
                policy: "accept".to_string(),
                r#type: "mangle".to_string(),
                rules: vec![
                    FirewallRule {
                        enabled: true,
                        uuid: "localhost-allow".to_string(),
                        parameters: "ip daddr 127.0.0.0-127.255.255.255".to_string(),
                        target: "accept".to_string(),
                        ..Default::default()
                    },
                    FirewallRule {
                        enabled: true,
                        uuid: "icmpv6-allow".to_string(),
                        parameters:
                            "icmpv6 type { echo-request, echo-reply, destination-unreachable }"
                                .to_string(),
                        target: "accept".to_string(),
                        ..Default::default()
                    },
                    FirewallRule {
                        enabled: true,
                        uuid: "queue-forward-like".to_string(),
                        parameters: "ct state new".to_string(),
                        target: "queue".to_string(),
                        target_parameters: "num 0".to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let ops = FirewallNetlinkAdapter::probe_plan_apply_system_firewall(&sysfw, 0);
    let expressions: Vec<&str> = ops
        .iter()
        .filter_map(|op| match op {
            FirewallNetlinkOperation::ApplySystemRule { expression, .. } => {
                Some(expression.as_str())
            }
            _ => None,
        })
        .collect();

    assert!(
        !expressions.is_empty(),
        "expected at least one planned ApplySystemRule expression"
    );

    for expression in expressions {
        assert!(
            FirewallNetlinkAdapter::probe_is_system_rule_expression_supported(expression),
            "planned ApplySystemRule expression is not netlink-supported: {expression}"
        );
    }
}

#[test]
fn native_dump_composition_reflects_chains_rules_and_zones() {
    let cfg = FirewallNetlinkAdapter::probe_compose_dumped_config();

    assert!(cfg.enabled);
    assert_eq!(cfg.chains.len(), 1);
    assert_eq!(cfg.zones.len(), 1);

    let chain = &cfg.chains[0];
    assert_eq!(chain.name, "filter_input");
    assert_eq!(chain.rules.len(), 1);
    assert_eq!(chain.rules[0].uuid, "ssh");
    assert_eq!(chain.rules[0].parameters, "meta l4proto tcp");

    let zone = &cfg.zones[0];
    assert_eq!(zone.name, "wan");
    assert_eq!(zone.chains.len(), 1);
    assert_eq!(zone.chains[0].name, "zone_wan_input");
    assert_eq!(zone.chains[0].rules.len(), 1);
}

#[test]
fn apply_plan_keeps_unsupported_expression_for_fallback_path() {
    let unsupported_expr = "meta nfproto ipv4";
    let sysfw = FirewallConfig {
        enabled: true,
        version: 0,
        rules: Vec::new(),
        chains: vec![FirewallChain {
            family: "inet".to_string(),
            table: "opensnitch".to_string(),
            name: "mangle_output".to_string(),
            hook: "output".to_string(),
            policy: "accept".to_string(),
            r#type: "mangle".to_string(),
            rules: vec![FirewallRule {
                enabled: true,
                uuid: "unsupported-cidr".to_string(),
                parameters: unsupported_expr.to_string(),
                target: "accept".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let ops = FirewallNetlinkAdapter::probe_plan_apply_system_firewall(&sysfw, 0);
    let planned_expression = ops.iter().find_map(|op| match op {
        FirewallNetlinkOperation::ApplySystemRule { expression, .. } => Some(expression.as_str()),
        _ => None,
    });

    let planned_expression =
        planned_expression.expect("expected planned ApplySystemRule expression");
    assert_eq!(planned_expression, "meta nfproto ipv4 accept");
    assert!(
        !FirewallNetlinkAdapter::probe_is_system_rule_expression_supported(planned_expression),
        "expected unsupported expression to remain unsupported for netlink execution"
    );
}

#[test]
fn cli_normalized_expression_support_matrix_stays_explicit() {
    let cases = [
        (
            FirewallRule {
                parameters: "meta dport == 443".to_string(),
                target: "accept".to_string(),
                ..Default::default()
            },
            true,
        ),
        (
            FirewallRule {
                parameters: "icmp type echo-request,echo-reply,destination-unreachable".to_string(),
                target: "accept".to_string(),
                ..Default::default()
            },
            true,
        ),
        (
            FirewallRule {
                parameters: "ct state new".to_string(),
                target: "queue".to_string(),
                target_parameters: "num 0".to_string(),
                ..Default::default()
            },
            true,
        ),
        (
            FirewallRule {
                parameters: "ip saddr 192.168.1.0/24".to_string(),
                target: "accept".to_string(),
                ..Default::default()
            },
            true,
        ),
        (
            FirewallRule {
                parameters: "ip6 daddr 2001:db8::/64".to_string(),
                target: "accept".to_string(),
                ..Default::default()
            },
            true,
        ),
        (
            FirewallRule {
                parameters: "meta nfproto ipv4".to_string(),
                target: "accept".to_string(),
                ..Default::default()
            },
            false,
        ),
    ];

    for (rule, expected_supported) in cases {
        let expression = FirewallNftablesAdapter::probe_nft_expression(&rule, 0);
        let supported =
            FirewallNetlinkAdapter::probe_is_system_rule_expression_supported(&expression);
        assert_eq!(
            supported, expected_supported,
            "unexpected support state for CLI-normalized expression: {expression}"
        );
    }
}

#[test]
fn system_rule_expression_shipped_coverage_audit_report() {
    // Non-gating audit: keep this list close to shipped/normalized rule shapes and
    // print coverage so incremental parser work can be measured without breaking CI.
    let shipped_like = [
        "tcp dport 22 accept",
        "ip daddr 127.0.0.0-127.255.255.255 accept",
        "ip saddr 192.168.1.0/24 accept",
        "icmp type { echo-request, echo-reply, destination-unreachable } accept",
        "icmpv6 type { echo-request, echo-reply, destination-unreachable } accept",
        "udp dport 51820 accept",
        "ct state new queue num 0",
        "ip6 daddr 2001:db8::/64 accept",
    ];

    let mut supported = 0usize;
    let mut unsupported = Vec::new();
    for expression in shipped_like {
        if FirewallNetlinkAdapter::probe_is_system_rule_expression_supported(expression) {
            supported += 1;
        } else {
            unsupported.push(expression);
        }
    }

    let total = shipped_like.len();
    let supported_pct = (supported as f64 * 100.0) / (total as f64);
    eprintln!(
        "nft-netlink coverage audit: supported={supported}/{total} ({supported_pct:.1}%), unsupported={unsupported:?}"
    );
    assert_eq!(supported + unsupported.len(), total);

    if let Ok(raw_threshold) = std::env::var("OPENSNITCH_NFT_NETLINK_MIN_AUDIT_COVERAGE") {
        let threshold = raw_threshold
            .trim()
            .parse::<f64>()
            .expect("OPENSNITCH_NFT_NETLINK_MIN_AUDIT_COVERAGE must be a number between 0 and 100");
        assert!(
            (0.0..=100.0).contains(&threshold),
            "OPENSNITCH_NFT_NETLINK_MIN_AUDIT_COVERAGE must be in [0, 100], got {threshold}"
        );
        assert!(
            supported_pct >= threshold,
            "nft-netlink coverage {supported_pct:.1}% is below enforced threshold {threshold:.1}%"
        );
    }
}

#[test]
fn unsupported_expression_family_classifier_is_stable() {
    let cases = [
        ("meta nfproto ipv4 accept", "nfproto"),
        ("ip saddr 192.168.1.0/24 accept", "cidr"),
        ("ip6 daddr 2001:db8::/129 accept", "cidr"),
        ("ct state bogus accept", "ct_state"),
        ("queue bogus 3", "queue"),
        (
            "icmp type { echo-request, echo-reply } accept",
            "set_or_list",
        ),
        ("meta mark 0x10 accept", "meta"),
        ("tcp dport 22 accept", "transport"),
        ("ip protocol 250 accept", "ip_addr_or_proto"),
    ];

    for (expression, expected_family) in cases {
        let family = FirewallNetlinkAdapter::probe_unsupported_expression_family(expression);
        assert_eq!(
            family, expected_family,
            "unexpected classifier family for expression: {expression}"
        );
    }
}

#[test]
fn unsupported_summary_shape_is_stable() {
    let ops = vec![
        FirewallNetlinkOperation::EnsureSystemChain {
            family: "inet".to_string(),
            table: "opensnitch".to_string(),
            name: "mangle_output".to_string(),
            hook: "output".to_string(),
            priority: "0".to_string(),
            policy: "accept".to_string(),
            chain_type: "route".to_string(),
        },
        FirewallNetlinkOperation::ApplySystemRule {
            family: "inet".to_string(),
            table: "opensnitch".to_string(),
            chain: "mangle_output".to_string(),
            expression: "meta nfproto ipv4 accept".to_string(),
            tag: "opensnitch-sysfw:nfproto".to_string(),
        },
        FirewallNetlinkOperation::ApplySystemRule {
            family: "inet".to_string(),
            table: "opensnitch".to_string(),
            chain: "mangle_output".to_string(),
            expression: "ip6 daddr 2001:db8::/64 accept".to_string(),
            tag: "opensnitch-sysfw:cidr".to_string(),
        },
        FirewallNetlinkOperation::EnsureInterceptionRule {
            chain: NetfilterRuleChain::MangleOutput,
            expression: "queue bogus 3".to_string(),
            tag: "opensnitch-queue-connections".to_string(),
        },
    ];

    let (unsupported_ops, unsupported_expression_families) =
        FirewallNetlinkAdapter::probe_unsupported_summary_for_ops(&ops);

    assert_eq!(
        unsupported_ops,
        vec![
            "ensure_system_chain",
            "apply_system_rule",
            "apply_system_rule",
            "ensure_interception_rule",
        ]
    );
    assert_eq!(
        unsupported_expression_families,
        vec![("cidr", 1), ("nfproto", 1), ("queue", 1)]
    );
}

#[test]
fn system_rule_expression_rejects_unsupported_forms() {
    let unsupported = [
        "meta nfproto ipv4 accept",
        "ip6 daddr 2001:db8::/129 drop",
        "ct state bogus accept",
        "queue bogus 3",
    ];

    for expression in unsupported {
        assert!(
            !FirewallNetlinkAdapter::probe_is_system_rule_expression_supported(expression),
            "expected expression to be unsupported: {expression}"
        );
    }
}
