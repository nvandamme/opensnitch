use std::{fs, path::PathBuf};

use crate::platform::firewall::config::{
    FirewallChain, FirewallConfig, FirewallExpression, FirewallRule, FirewallStatement,
    FirewallStatementValue,
};
use crate::platform::firewall::netlink::{
    FirewallNetlinkAdapter, FirewallNetlinkOperation, NftChain, NftRule, NftTable,
};
use crate::platform::firewall::nftables::FirewallNftablesAdapter;

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
            chain,
            expression,
            tag,
        } if chain == &NftChain::interception_filter_input()
            && expression.contains("queue num 7 bypass")
            && expression.contains("opensnitch-queue-dns")
            && tag == "opensnitch-queue-dns"
    ));

    assert!(matches!(
        &ops[2],
        FirewallNetlinkOperation::EnsureInterceptionRule {
            chain,
            expression,
            tag,
        } if chain == &NftChain::interception_mangle_output()
            && expression.contains("opensnitch-queue-connections-non-tcp")
            && tag == "opensnitch-queue-connections-non-tcp"
    ));

    assert!(matches!(
        &ops[3],
        FirewallNetlinkOperation::EnsureInterceptionRule {
            chain,
            expression,
            tag,
        } if chain == &NftChain::interception_mangle_output()
            && expression.contains("opensnitch-queue-connections-tcp-syn")
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
        FirewallNetlinkOperation::ApplySystemRule { rule }
            if rule.table().family() == "inet"
                && rule.table().name() == "opensnitch"
                && rule.chain() == "mangle_output"
                && rule.expression_count() > 0
                && rule.tag() == "opensnitch-sysfw:enabled-1"
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
        zones: vec![crate::platform::firewall::config::FirewallZone {
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
        zones: vec![crate::platform::firewall::config::FirewallZone {
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
        FirewallNetlinkOperation::ApplySystemRule { rule }
            if rule.table().family() == "inet"
                && rule.table().name() == "opensnitch"
                && rule.chain() == "zone_wan_input"
                && rule.expression_count() > 0
    ));
}

#[test]
fn system_rule_expression_supports_safe_netlink_subset() {
    let supported = [
        "meta l4proto != tcp drop",
        "meta l4proto { tcp, udp } th dport 88 accept",
        "meta nfproto ipv4 accept",
        "ip protocol udp accept",
        "ip protocol > 100 drop",
        "ip6 nexthdr == tcp accept",
        "meta mark 0x10 drop",
        "meta mark >= 16 drop",
        "meta skuid 1000 accept",
        "meta skgid >= 100 drop",
        "meta iif 2 accept",
        "meta oif >= 3 drop",
        "meta iiftype 1 accept",
        "meta iiftype { 1, 772 } accept",
        "meta oiftype >= 772 drop",
        "meta oiftype { 1, 772 } drop",
        "meta iifname lo accept",
        "meta iifname { lo, eth0 } accept",
        "meta oifname != eth0 drop",
        "meta oifname != { eth0, wlan0 } drop",
        "meta bri_iifname br0 accept",
        "meta bri_iifname { br0, br-lan } accept",
        "meta bri_oifname != br-lan drop",
        "meta bri_oifname != { br-lan, br0 } drop",
        "meta secmark 1 accept",
        "meta priority >= 10 drop",
        "meta len > 60 accept",
        "meta rtclassid 0x100 accept",
        "meta cpu 0 accept",
        "meta iifgroup 10 accept",
        "meta oifgroup >= 20 drop",
        "meta nftrace 1 accept",
        "meta cgroup 1 accept",
        "meta prandom >= 100 accept",
        "meta secpath 1 accept",
        "meta pkttype 2 accept",
        "meta sdif 2 accept",
        "meta sdif { 2, 3 } accept",
        "meta sdifname != lo drop",
        "meta sdifname != { lo, eth0 } drop",
        "meta iifkind vlan accept",
        "meta iifkind { vlan, bridge } accept",
        "meta oifkind != bridge drop",
        "meta oifkind != { bridge, vlan } drop",
        "meta time ns >= 1 accept",
        "meta time ns { 1, 2 } accept",
        "meta time day 3 accept",
        "meta time day { 1, 7 } accept",
        "meta time hour <= 12 drop",
        "meta time hour { 8, 12 } drop",
        "meta protocol 0x0800 accept",
        "meta protocol { 0x0800, 0x86dd } accept",
        "meta bri_iifpvid 1 accept",
        "meta bri_iifpvid { 1, 100 } accept",
        "meta bri_iifvproto 0x8100 accept",
        "meta bri_iifvproto { 0x8100, 0x88a8 } accept",
        "meta bri_broute 1 drop",
        "meta bri_broute { 0, 1 } drop",
        "socket transparent 1 accept",
        "socket wildcard false drop",
        "socket mark 0x10 accept",
        "socket cgroupv2 level 1 12345 accept",
        "fib saddr . iif oif != 0 accept",
        "fib saddr . mark oif >= 2 accept",
        "fib daddr . oif type 1 accept",
        "fib saddr . iif oifname != eth0 accept",
        "fib saddr . iif oif { 1, 2 } accept",
        "fib daddr . oif oifname { wan0, eth0 } accept",
        "fib daddr . iif type 1 accept",
        "numgen random mod 10 < 3 accept",
        "numgen inc mod 100 offset 7 >= 50 drop",
        "numgen random mod 10 { 1, 3 } accept",
        "numgen inc mod 100 offset 7 != { 50, 51 } drop",
        "log accept",
        "log prefix opensnitch accept",
        "log level warning flags tcpseq,uid group 5 snaplen 64 qthreshold 10 accept",
        "ip saddr 192.168.1.10 accept",
        "ip ttl 64 accept",
        "ip saddr {192.168.1.10,192.168.1.11} accept",
        "ip saddr 192.168.1.0/24 accept",
        "ip daddr 127.0.0.0-127.255.255.255 accept",
        "ip daddr {10.0.0.1,10.0.0.2} accept",
        "ip daddr == 10.0.0.1 drop",
        "ip6 saddr 2001:db8::1 accept",
        "ip6 hoplimit 64 accept",
        "ip6 saddr {2001:db8::1,2001:db8::2} accept",
        "ip6 daddr 2001:db8::1-2001:db8::ffff accept",
        "ip6 daddr 2001:db8::/64 accept",
        "ip6 daddr {2001:db8::10,2001:db8::11} accept",
        "ip6 daddr != 2001:db8::2 drop",
        "ct state new,related accept",
        "ct state established,related accept",
        "ct state { established, related } accept",
        "ct status dnat accept",
        "ct status { seen-reply, assured } accept",
        "ct direction original accept",
        "ct direction != reply drop",
        "ct mark 0x10 accept",
        "ct mark >= 16 drop",
        "ct secmark 7 accept",
        "ct expiration > 100 accept",
        "ct l3protocol ipv4 accept",
        "ct protocol tcp accept",
        "ct proto-src { 53, 5353 } accept",
        "ct proto-dst <= 443 drop",
        "ct zone 10 accept",
        "ct helper ftp accept",
        "ct src 0x01020304 accept",
        "ct dst 0x05060708 drop",
        "ct src-ip 192.168.1.10 accept",
        "ct dst-ip { 10.0.0.1, 10.0.0.2 } accept",
        "ct src-ip6 2001:db8::10 accept",
        "ct dst-ip6 { 2001:db8::20, 2001:db8::21 } drop",
        "ct pkts >= 1 accept",
        "ct bytes > 1024 accept",
        "ct avgpkt 64 accept",
        "ct eventmask 0x1 accept",
        "ct id 12345 accept",
        "ip saddr @allowed_v4 accept",
        "ip saddr != @allowed_v4 accept",
        "ip6 daddr @allowed_v6 accept",
        "ip6 daddr != @allowed_v6 accept",
        "th dport @allowed_ports accept",
        "th dport != @allowed_ports accept",
        "tcp dport @allowed_tcp_ports accept",
        "tcp dport != @allowed_tcp_ports accept",
        "ip saddr vmap @policy_v4",
        "ip6 daddr vmap @policy_v6",
        "th dport vmap @policy_ports",
        "tcp dport vmap @policy_tcp",
        "tcp dport 25 reject",
        "tcp dport 25 reject with tcp reset",
        "udp dport 53 reject with icmpx type port-unreachable",
        "ct state new queue num 0",
        "ct state new notrack accept",
        "tcp dport 53 masquerade",
        "udp dport 5353 masq",
        "tcp dport 53 masquerade to :8080 random",
        "udp dport 5353 masq to :5353 fully-random persistent",
        "tcp dport 53 masquerade to :8080",
        "udp dport 5353 masq to :1024-2048",
        "tcp dport 53 snat to 10.0.0.10",
        "udp dport 5353 dnat to 2001:db8::10",
        "tcp dport 53 snat to 10.0.0.10:8080",
        "udp dport 5353 dnat to [2001:db8::10]:5353",
        "tcp dport 53 snat to 10.0.0.10:1024-2048",
        "tcp dport 53 snat to 10.0.0.10:8080 random",
        "udp dport 5353 dnat to [2001:db8::10]:5353 persistent fully-random",
        "tcp dport 53 snat to 10.0.0.10-10.0.0.20",
        "udp dport 5353 dnat to 2001:db8::10-2001:db8::20",
        "tcp dport 53 redirect",
        "udp dport 5353 redir to :5353",
        "tcp dport 53 redirect to :1024-2048 random",
        "udp dport 5353 redir to :5353 fully-random persistent",
        "tcp dport 443 tproxy to :12345",
        "udp dport 53 tproxy to 127.0.0.1:5300",
        "udp dport 53 tproxy to [2001:db8::1]:5300",
        "tcp flags & (fin|syn|rst|ack) == syn accept",
        "th dport 443 accept",
        "th dport > 1024 accept",
        "th dport { 80, 443 } accept",
        "tcp dport == 88 accept",
        "tcp dport <= 443 accept",
        "tcp dport {80,443} accept",
        "udp dport != 5353 drop",
        "udp length >= 32 accept",
        "udp sport < 1024 drop",
        "udp sport {53,5353} drop",
        "udp dport 51820 accept",
        "counter accept",
        "counter name opensnitch accept",
        "tcp dport 22 counter packets bytes accept",
        "tcp dport 22 counter accept",
        "quota 64 kbytes accept",
        "quota over 1 mbytes drop",
        "limit rate over 1 mbytes/second drop",
        "tcp dport 22 return",
        "tcp dport 22 continue",
        "tcp dport 22 break",
        "tcp dport 22 jump custom_chain",
        "tcp dport 22 goto custom_chain",
        "icmp type { echo-request, echo-reply } accept",
        "icmp code 3 accept",
        "icmpv6 type echo-request accept",
        "icmpv6 checksum 1234 accept",
        "queue num 3 bypass",
        // exthdr (tcp option)
        "tcp option maxseg size 1460 accept",
        "tcp option maxseg exists accept",
        "tcp option window size 7 accept",
        "tcp option timestamp size 12345 accept",
        "tcp option sack-perm exists accept",
        // exthdr (ipv6 extension headers)
        "ip6 exthdr hbh exists accept",
        "ip6 exthdr rt exists accept",
        "ip6 exthdr frag exists drop",
        "ip6 exthdr dst exists accept",
        "ip6 exthdr mh exists accept",
        "ip6 exthdr ah exists accept",
        // connlimit (ct count)
        "ct count 20 accept",
        "ct count over 20 drop",
        // hash (jhash/symhash)
        "jhash ip saddr mod 10 seed 0xdeadbeef < 3 accept",
        "symhash mod 10 < 5 accept",
        "jhash ip daddr mod 100 < 50 drop",
        "jhash ip6 saddr mod 16 seed 42 offset 5 < 8 accept",
        "symhash mod 256 offset 10 < 128 accept",
        // rt
        "rt classid 100 accept",
        "rt mtu < 1500 accept",
        "rt nexthop 192.168.1.1 accept",
        "rt nexthop 2001:db8::1 accept",
        "rt ipsec exists accept",
        // dynset (add/update @set)
        "add @blacklist { ip saddr } accept",
        "update @myset { ip saddr } accept",
        "update @myset { ip daddr } drop",
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
    let go_testdata: Vec<String> =
        crate::services::storage::StorageService::parse_with_storage_format_for_path(
            &fixture, &raw,
        )
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
    let apply_rules: Vec<&NftRule> = ops
        .iter()
        .filter_map(|op| match op {
            FirewallNetlinkOperation::ApplySystemRule { rule } => Some(rule),
            _ => None,
        })
        .collect();

    assert!(
        !apply_rules.is_empty(),
        "expected at least one planned ApplySystemRule expression"
    );

    for rule in apply_rules {
        assert!(
            rule.expression_count() > 0,
            "planned ApplySystemRule must carry parsed expressions"
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
fn apply_plan_drops_unsupported_expression_from_netlink_ir_path() {
    let unsupported_expr = "meta unknownkey 1";
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
    let has_apply_rule = ops
        .iter()
        .any(|op| matches!(op, FirewallNetlinkOperation::ApplySystemRule { .. }));

    assert!(
        !has_apply_rule,
        "unsupported expressions should not be carried into parsed netlink ApplySystemRule IR"
    );

    assert_eq!(
        FirewallNetlinkAdapter::probe_count_dropped_system_fw_rules(&sysfw, 0),
        1,
        "unsupported dropped rules must be counted so apply() can trigger compatibility fallback"
    );
}

#[test]
fn structured_json_expression_binding_is_preferred_over_legacy_parameters() {
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
                uuid: "structured-json".to_string(),
                // Invalid legacy text must not drive netlink binding when structured
                // JSON expressions are present.
                parameters: "meta unknownkey 1".to_string(),
                expressions: vec![FirewallExpression {
                    statement: Some(FirewallStatement {
                        op: "==".to_string(),
                        name: "meta".to_string(),
                        values: vec![FirewallStatementValue {
                            key: "nfproto".to_string(),
                            value: "ipv4".to_string(),
                        }],
                    }),
                }],
                target: "accept".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let ops = FirewallNetlinkAdapter::probe_plan_apply_system_firewall(&sysfw, 0);
    assert!(
        ops.iter()
            .any(|op| matches!(op, FirewallNetlinkOperation::ApplySystemRule { .. })),
        "structured JSON expressions must produce netlink ApplySystemRule operations even when legacy text is invalid"
    );
    assert_eq!(
        FirewallNetlinkAdapter::probe_count_dropped_system_fw_rules(&sysfw, 0),
        0,
        "structured JSON expression binding should not be dropped due to legacy textual parameters"
    );
}

#[test]
fn structured_json_statement_values_allow_complex_token_sequences() {
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
                uuid: "structured-complex".to_string(),
                parameters: String::new(),
                expressions: vec![FirewallExpression {
                    statement: Some(FirewallStatement {
                        op: String::new(),
                        name: "tcp".to_string(),
                        values: vec![FirewallStatementValue {
                            key: "flags".to_string(),
                            value: "& (fin|syn|rst|ack) == syn".to_string(),
                        }],
                    }),
                }],
                target: "accept".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let ops = FirewallNetlinkAdapter::probe_plan_apply_system_firewall(&sysfw, 0);
    assert!(
        ops.iter()
            .any(|op| matches!(op, FirewallNetlinkOperation::ApplySystemRule { .. })),
        "complex token sequences in structured statement values must be parsed through token parsing and produce netlink apply rules"
    );
}

#[test]
fn structured_json_quota_statement_follows_system_rules_shape() {
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
                uuid: "structured-quota".to_string(),
                expressions: vec![FirewallExpression {
                    statement: Some(FirewallStatement {
                        op: String::new(),
                        name: "quota".to_string(),
                        values: vec![
                            FirewallStatementValue {
                                key: "over".to_string(),
                                value: String::new(),
                            },
                            FirewallStatementValue {
                                key: "gbytes".to_string(),
                                value: "1".to_string(),
                            },
                        ],
                    }),
                }],
                target: "drop".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let ops = FirewallNetlinkAdapter::probe_plan_apply_system_firewall(&sysfw, 0);
    assert!(
        ops.iter()
            .any(|op| matches!(op, FirewallNetlinkOperation::ApplySystemRule { .. })),
        "quota statements encoded in OpenSnitch system-rules JSON shape must parse through netlink statement binding"
    );
}

#[test]
fn structured_json_limit_statement_follows_system_rules_shape() {
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
                uuid: "structured-limit".to_string(),
                expressions: vec![FirewallExpression {
                    statement: Some(FirewallStatement {
                        op: String::new(),
                        name: "limit".to_string(),
                        values: vec![
                            FirewallStatementValue {
                                key: "over".to_string(),
                                value: String::new(),
                            },
                            FirewallStatementValue {
                                key: "units".to_string(),
                                value: "1".to_string(),
                            },
                            FirewallStatementValue {
                                key: "rate-units".to_string(),
                                value: "mbytes".to_string(),
                            },
                            FirewallStatementValue {
                                key: "time-units".to_string(),
                                value: "second".to_string(),
                            },
                        ],
                    }),
                }],
                target: "drop".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let ops = FirewallNetlinkAdapter::probe_plan_apply_system_firewall(&sysfw, 0);
    assert!(
        ops.iter()
            .any(|op| matches!(op, FirewallNetlinkOperation::ApplySystemRule { .. })),
        "limit statements encoded in OpenSnitch system-rules JSON shape must parse through netlink statement binding"
    );
}

#[test]
fn structured_json_socket_statement_follows_system_rules_shape() {
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
                uuid: "structured-socket".to_string(),
                expressions: vec![FirewallExpression {
                    statement: Some(FirewallStatement {
                        op: "==".to_string(),
                        name: "socket".to_string(),
                        values: vec![FirewallStatementValue {
                            key: "mark".to_string(),
                            value: "16".to_string(),
                        }],
                    }),
                }],
                target: "accept".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let ops = FirewallNetlinkAdapter::probe_plan_apply_system_firewall(&sysfw, 0);
    assert!(
        ops.iter()
            .any(|op| matches!(op, FirewallNetlinkOperation::ApplySystemRule { .. })),
        "socket statements encoded in OpenSnitch system-rules JSON shape must parse through netlink statement binding"
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
            true,
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
        "ip ttl 32 accept",
        "icmp type { echo-request, echo-reply, destination-unreachable } accept",
        "icmpv6 type { echo-request, echo-reply, destination-unreachable } accept",
        "udp dport 51820 accept",
        "ct state new queue num 0",
        "ct status dnat accept",
        "ct direction original accept",
        "ct secmark 7 accept",
        "ct protocol tcp accept",
        "ct helper ftp accept",
        "ct src-ip 192.168.1.10 accept",
        "ct pkts >= 1 accept",
        "ct bytes > 1024 accept",
        "tcp dport 25 reject",
        "meta len > 60 accept",
        "meta secpath 1 accept",
        "meta iiftype 1 accept",
        "meta sdifname lo accept",
        "meta iifkind vlan accept",
        "meta oifkind bridge accept",
        "meta iifname { lo, eth0 } accept",
        "meta sdifname != { lo, eth0 } accept",
        "meta time ns >= 1 accept",
        "meta time day 3 accept",
        "meta time hour <= 12 accept",
        "meta protocol 0x0800 accept",
        "meta bri_iifpvid 1 accept",
        "meta bri_iifvproto 0x8100 accept",
        "meta bri_broute 1 accept",
        "meta time day { 1, 7 } accept",
        "meta protocol { 0x0800, 0x86dd } accept",
        "meta bri_broute { 0, 1 } accept",
        "fib saddr . iif oif != 0 accept",
        "fib saddr . iif oifname != eth0 accept",
        "numgen random mod 10 < 3 accept",
        "log level info prefix opensnitch accept",
        "numgen inc mod 100 offset 7 != { 50, 51 } accept",
        "tcp dport @allowed_tcp_ports accept",
        "tcp dport vmap @policy_tcp",
        "ip6 daddr 2001:db8::/64 accept",
        "ip6 hoplimit 64 accept",
        "ip saddr != @allowed_v4 accept",
        "tcp dport != @allowed_tcp_ports accept",
        "tcp dport 53 masquerade",
        "quota 128 kbytes accept",
        "limit rate 10/second accept",
        "udp length 128 accept",
        "ip6 exthdr hbh exists accept",
        "ip6 exthdr frag exists drop",
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
        ("meta nfproto ipv4 accept", "meta"),
        ("meta unknownkey 1 accept", "meta"),
        ("ip saddr 192.168.1.0/24 accept", "cidr"),
        ("ip6 daddr 2001:db8::/129 accept", "cidr"),
        ("ct state bogus accept", "ct_state"),
        ("ct status bogus accept", "ct_state"),
        ("ct direction bogus accept", "ct_state"),
        ("ct mark bogus accept", "ct_state"),
        ("ct secmark bogus accept", "ct_state"),
        ("ct expiration bogus accept", "ct_state"),
        ("ct l3protocol bogus accept", "ct_state"),
        ("ct protocol bogus accept", "ct_state"),
        ("ct proto-src bogus accept", "ct_state"),
        ("ct proto-dst bogus accept", "ct_state"),
        ("ct zone bogus accept", "ct_state"),
        ("ct helper bad*helper accept", "ct_state"),
        ("ct src bogus accept", "ct_state"),
        ("ct dst bogus accept", "ct_state"),
        ("ct src-ip bogus accept", "ct_state"),
        ("ct dst-ip bogus accept", "ct_state"),
        ("ct src-ip6 bogus accept", "ct_state"),
        ("ct dst-ip6 bogus accept", "ct_state"),
        ("ct pkts bogus accept", "ct_state"),
        ("ct bytes bogus accept", "ct_state"),
        ("ct avgpkt bogus accept", "ct_state"),
        ("ct eventmask bogus accept", "ct_state"),
        ("ct id bogus accept", "ct_state"),
        ("tcp dport 25 reject with icmpx type bogus", "reject"),
        ("ip saddr @ accept", "lookup"),
        ("ip saddr > @allowed_v4 accept", "lookup"),
        ("ip saddr vmap @", "lookup"),
        ("tcp dport 53 masquerade to 1024", "nat"),
        ("tcp dport 53 snat to 10.0.0.10:bad", "nat"),
        ("tcp dport 53 snat to 10.0.0.10 randomx", "nat"),
        ("tcp dport 53 snat to 10.0.0.10-2001:db8::10", "nat"),
        ("tcp dport 53 redirect to 5353", "nat"),
        ("tcp dport 53 redirect random", "nat"),
        ("tcp dport 53 redirect to :5353 random fully-random", "nat"),
        ("tcp dport 53 redirect randomx", "nat"),
        ("tcp dport 53 tproxy", "nat"),
        ("tcp dport 53 tproxy to 127.0.0.1", "nat"),
        ("tcp dport 53 tproxy to :bad", "nat"),
        ("tcp dport 53 tproxy to :12345 random", "nat"),
        ("counter name accept", "objref"),
        ("counter name bad*counter accept", "objref"),
        ("quota bogus accept", "quota"),
        ("limit rate bogus/second accept", "limit"),
        ("notrack", "notrack"),
        ("queue bogus 3", "queue"),
        ("queue num 3 bypass extra", "queue"),
        (
            "icmp type { echo-request, echo-reply } accept",
            "set_or_list",
        ),
        ("meta mark 0x10 accept", "meta"),
        ("meta skuid bogus accept", "meta"),
        ("meta skgid bogus accept", "meta"),
        ("meta iif bogus accept", "meta"),
        ("meta oif bogus accept", "meta"),
        ("meta iiftype bogus accept", "meta"),
        ("meta oiftype bogus accept", "meta"),
        ("meta iifname bad*iface accept", "meta"),
        ("meta iifname { bad*iface, lo } accept", "set_or_list"),
        ("meta oifname > eth0 accept", "meta"),
        ("meta oifname > { eth0, wlan0 } accept", "set_or_list"),
        ("meta bri_iifname bad*iface accept", "meta"),
        ("meta bri_iifname { bad*iface, br0 } accept", "set_or_list"),
        ("meta bri_oifname > br0 accept", "meta"),
        ("meta bri_oifname > { br0, br-lan } accept", "set_or_list"),
        ("meta secmark bogus accept", "meta"),
        ("meta priority bogus accept", "meta"),
        ("meta len bogus accept", "meta"),
        ("meta rtclassid bogus accept", "meta"),
        ("meta cpu bogus accept", "meta"),
        ("meta iifgroup bogus accept", "meta"),
        ("meta oifgroup bogus accept", "meta"),
        ("meta nftrace bogus accept", "meta"),
        ("meta cgroup bogus accept", "meta"),
        ("meta prandom bogus accept", "meta"),
        ("meta secpath bogus accept", "meta"),
        ("meta pkttype bogus accept", "meta"),
        ("meta sdif bogus accept", "meta"),
        ("meta sdifname > lo accept", "meta"),
        ("meta sdifname > { lo, eth0 } accept", "set_or_list"),
        ("meta iifkind bad*kind accept", "meta"),
        ("meta iifkind { bad*kind, vlan } accept", "set_or_list"),
        ("meta oifkind > bridge accept", "meta"),
        ("meta oifkind > { bridge, vlan } accept", "set_or_list"),
        ("meta time ns bogus accept", "meta"),
        ("meta time day bogus accept", "meta"),
        ("meta time hour bogus accept", "meta"),
        ("meta protocol bogus accept", "meta"),
        ("meta iiftype { 1, bogus } accept", "set_or_list"),
        ("meta oiftype { 1, bogus } accept", "set_or_list"),
        ("meta sdif { 2, bogus } accept", "set_or_list"),
        ("meta time day { 1, bogus } accept", "set_or_list"),
        ("meta time hour { 8, bogus } accept", "set_or_list"),
        ("meta protocol { 0x0800, bogus } accept", "set_or_list"),
        ("meta bri_iifpvid bogus accept", "meta"),
        ("meta bri_iifpvid { 1, bogus } accept", "set_or_list"),
        ("meta bri_iifvproto bogus accept", "meta"),
        ("meta bri_iifvproto { 0x8100, bogus } accept", "set_or_list"),
        ("meta bri_broute 999 accept", "meta"),
        ("meta bri_broute { 0, 999 } accept", "set_or_list"),
        ("log level bogus accept", "log"),
        ("log flags bogus accept", "log"),
        ("log group bogus accept", "log"),
        ("log snaplen bogus accept", "log"),
        ("log qthreshold bogus accept", "log"),
        ("log prefix bad*prefix accept", "log"),
        ("fib saddr . iif bogus 1 accept", "fib"),
        ("fib saddr . bogus oif 1 accept", "fib"),
        ("fib saddr . iif oifname bad*iface accept", "fib"),
        ("fib saddr . iif oifname > eth0 accept", "fib"),
        ("fib saddr . iif oifname { bad*iface, eth0 } accept", "fib"),
        ("numgen random mod 0 < 1 accept", "numgen"),
        ("numgen random mod 10 { bogus, 1 } accept", "numgen"),
        ("ip ttl bogus accept", "ip_addr_or_proto"),
        ("ip6 hoplimit bogus accept", "ip_addr_or_proto"),
        ("udp length bogus accept", "transport"),
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
            rule: NftRule::new(
                NftTable::new("inet", "opensnitch"),
                "mangle_output",
                "opensnitch-sysfw:nfproto",
            ),
        },
        FirewallNetlinkOperation::ApplySystemRule {
            rule: NftRule::new(
                NftTable::new("inet", "opensnitch"),
                "mangle_output",
                "opensnitch-sysfw:cidr",
            ),
        },
        FirewallNetlinkOperation::EnsureInterceptionRule {
            chain: NftChain::interception_mangle_output(),
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
    assert_eq!(unsupported_expression_families, vec![("queue", 1)]);
}

#[test]
fn nft_rule_metadata_fields_are_exposed() {
    let rule = NftRule::new(
        NftTable::new("inet", "opensnitch"),
        "mangle_output",
        "opensnitch-sysfw:meta-test",
    )
    .with_handle(42)
    .with_position(7)
    .with_userdata(vec![0xAA, 0xBB])
    .with_id(9);

    assert_eq!(rule.handle(), Some(42));
    assert_eq!(rule.position(), Some(7));
    assert_eq!(rule.userdata(), Some(&[0xAA, 0xBB][..]));
    assert_eq!(rule.encoded_userdata(), &[0xAA, 0xBB]);
    assert_eq!(rule.id(), Some(9));
}

#[test]
fn system_rule_expression_rejects_unsupported_forms() {
    let unsupported = [
        "meta unknownkey 1 accept",
        "ip6 daddr 2001:db8::/129 drop",
        "ct state bogus accept",
        "ct status bogus accept",
        "ct direction bogus accept",
        "ct mark bogus accept",
        "ct secmark bogus accept",
        "ct expiration bogus accept",
        "ct l3protocol bogus accept",
        "ct protocol bogus accept",
        "ct proto-src bogus accept",
        "ct proto-dst bogus accept",
        "ct zone bogus accept",
        "ct helper bad*helper accept",
        "ct src bogus accept",
        "ct dst bogus accept",
        "ct src-ip bogus accept",
        "ct dst-ip bogus accept",
        "ct src-ip6 bogus accept",
        "ct dst-ip6 bogus accept",
        "ct pkts bogus accept",
        "ct bytes bogus accept",
        "ct avgpkt bogus accept",
        "ct eventmask bogus accept",
        "ct id bogus accept",
        "meta skuid bogus accept",
        "meta skgid bogus accept",
        "meta iif bogus accept",
        "meta oif bogus accept",
        "meta iiftype bogus accept",
        "meta oiftype bogus accept",
        "meta iifname bad*iface accept",
        "meta iifname { bad*iface, lo } accept",
        "meta oifname > eth0 accept",
        "meta oifname > { eth0, wlan0 } accept",
        "meta bri_iifname bad*iface accept",
        "meta bri_iifname { bad*iface, br0 } accept",
        "meta bri_oifname > br0 accept",
        "meta bri_oifname > { br0, br-lan } accept",
        "meta secmark bogus accept",
        "meta priority bogus accept",
        "meta len bogus accept",
        "meta rtclassid bogus accept",
        "meta cpu bogus accept",
        "meta iifgroup bogus accept",
        "meta oifgroup bogus accept",
        "meta nftrace bogus accept",
        "meta cgroup bogus accept",
        "meta prandom bogus accept",
        "meta secpath bogus accept",
        "meta pkttype bogus accept",
        "meta sdif bogus accept",
        "meta sdifname > lo accept",
        "meta sdifname > { lo, eth0 } accept",
        "meta iifkind bad*kind accept",
        "meta iifkind { bad*kind, vlan } accept",
        "meta oifkind > bridge accept",
        "meta oifkind > { bridge, vlan } accept",
        "meta time ns bogus accept",
        "meta time day bogus accept",
        "meta time hour bogus accept",
        "meta protocol bogus accept",
        "meta iiftype { 1, bogus } accept",
        "meta oiftype { 1, bogus } accept",
        "meta sdif { 2, bogus } accept",
        "meta time day { 1, bogus } accept",
        "meta time hour { 8, bogus } accept",
        "meta protocol { 0x0800, bogus } accept",
        "meta bri_iifpvid bogus accept",
        "meta bri_iifpvid { 1, bogus } accept",
        "meta bri_iifvproto bogus accept",
        "meta bri_iifvproto { 0x8100, bogus } accept",
        "meta bri_broute 999 accept",
        "meta bri_broute { 0, 999 } accept",
        "log level bogus accept",
        "log flags bogus accept",
        "log group bogus accept",
        "log snaplen bogus accept",
        "log qthreshold bogus accept",
        "log prefix bad*prefix accept",
        "fib saddr . iif bogus 1 accept",
        "fib saddr . bogus oif 1 accept",
        "fib saddr . iif oifname bad*iface accept",
        "fib saddr . iif oifname > eth0 accept",
        "fib saddr . iif oifname { bad*iface, eth0 } accept",
        "numgen random mod 0 < 1 accept",
        "numgen random mod 10 { bogus, 1 } accept",
        "ip ttl bogus accept",
        "ip6 hoplimit bogus accept",
        "udp length bogus accept",
        "tcp dport 25 reject with tcp",
        "tcp dport 25 reject with icmpx type bogus",
        "ip saddr @ accept",
        "ip saddr > @allowed_v4 accept",
        "ip saddr vmap @",
        "tcp dport 53 masquerade to 1024",
        "tcp dport 53 masquerade to :bogus",
        "tcp dport 53 masquerade to :2000-1000",
        "tcp dport 53 masquerade random",
        "tcp dport 53 masquerade to :8080 random fully-random",
        "tcp dport 53 masquerade randomx",
        "tcp dport 53 snat to 10.0.0.10:bad",
        "tcp dport 53 snat to 10.0.0.10 random",
        "tcp dport 53 snat to 10.0.0.10:8080 random fully-random",
        "tcp dport 53 snat to 10.0.0.10 randomx",
        "tcp dport 53 snat to 10.0.0.10-2001:db8::10",
        "tcp dport 53 redirect to 5353",
        "tcp dport 53 redirect random",
        "tcp dport 53 redirect to :5353 random fully-random",
        "tcp dport 53 redirect randomx",
        "tcp dport 53 tproxy",
        "tcp dport 53 tproxy to 127.0.0.1",
        "tcp dport 53 tproxy to :bad",
        "tcp dport 53 tproxy to :12345 random",
        "counter name accept",
        "counter name bad*counter accept",
        "quota bogus accept",
        "limit rate bogus/second accept",
        "notrack",
        "udp dport 53 dnat to [2001:db8::10]",
        "udp dport 53 dnat to [2001:db8::10]:bad",
        "udp dport 53 dnat to 10.0.0.10-10.0.0.20:8080",
        "udp dport 53 snat 10.0.0.10",
        "tcp dport 22 jump",
        "tcp dport 22 goto",
        "queue bogus 3",
        // exthdr invalid
        "tcp option bogus size 1460 accept",
        "tcp option sack-perm size 10 accept",
        // exthdr ipv6 invalid
        "ip6 exthdr bogus exists accept",
        "ip6 exthdr hbh accept",
        // connlimit invalid
        "ct count bogus accept",
        // hash invalid
        "jhash ip saddr mod 0 < 3 accept",
        "symhash mod 0 < 5 accept",
        "jhash bogus saddr mod 10 < 3 accept",
        // rt invalid
        "rt bogus 100 accept",
        "rt ipsec accept",
        // dynset invalid
        "add @blacklist accept",
        "update @ { ip saddr } accept",
    ];

    for expression in unsupported {
        assert!(
            !FirewallNetlinkAdapter::probe_is_system_rule_expression_supported(expression),
            "expected expression to be unsupported: {expression}"
        );
    }
}
