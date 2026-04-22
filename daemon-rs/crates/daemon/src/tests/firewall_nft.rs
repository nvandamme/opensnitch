use crate::adapters::firewall_nft::{FwChainExt, FwRuleNftExt, StrNftExt};
use opensnitch_proto::pb;

#[test]
fn chain_defaults_and_rule_tag_match_expected_values() {
    let chain = pb::FwChain::default();
    assert_eq!(chain.family_or_default(), "inet");
    assert_eq!(chain.table_or_default(), "opensnitch");
    assert_eq!(chain.chain_name_or_default(), "mangle_output");

    let fallback_tag = chain.rule_tag(&pb::FwRule {
        position: 7,
        description: "allow dns".to_string(),
        ..Default::default()
    });
    assert_eq!(
        fallback_tag,
        "opensnitch-sysfw:opensnitch:mangle_output:7:allow dns"
    );

    let uuid_tag = chain.rule_tag(&pb::FwRule {
        uuid: "uuid-1".to_string(),
        ..Default::default()
    });
    assert_eq!(uuid_tag, "opensnitch-sysfw:uuid-1");
}

#[test]
fn nft_expression_prefers_parameters_and_appends_target_parts() {
    let rule = pb::FwRule {
        parameters: "tcp dport 443".to_string(),
        target: "accept".to_string(),
        target_parameters: "comment \"https\"".to_string(),
        ..Default::default()
    };

    assert_eq!(
        rule.nft_expression(0),
        "tcp dport 443 accept comment \"https\""
    );
}

#[test]
fn nft_expression_builds_from_statements_and_rewrites_queue_num() {
    let rule = pb::FwRule {
        expressions: vec![pb::Expressions {
            statement: Some(pb::Statement {
                op: "==".to_string(),
                name: "meta".to_string(),
                values: vec![pb::StatementValues {
                    key: "l4proto".to_string(),
                    value: "tcp".to_string(),
                }],
            }),
        }],
        target: "queue".to_string(),
        target_parameters: "num 0 bypass".to_string(),
        ..Default::default()
    };

    assert_eq!(
        rule.nft_expression(42),
        "meta l4proto == tcp queue num 42 bypass"
    );
}

#[test]
fn nft_rule_line_helpers_extract_handles_and_tags() {
    let listing = r#"
chain mangle_output {
    udp sport 53 queue num 0 comment "opensnitch-queue-dns" # handle 5
    tcp flags & (fin|syn|rst|ack) == syn queue num 0 comment "opensnitch-queue-connections-tcp-syn" # handle 7
}
"#;

    let lines = listing.nft_rule_lines();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].parse_nft_handle().as_deref(), Some("5"));
    assert_eq!(lines[1].parse_nft_handle().as_deref(), Some("7"));
    assert_eq!(lines[0].nft_rule_tag(), "opensnitch-queue-dns");
    assert_eq!(
        lines[1].nft_rule_tag(),
        "opensnitch-queue-connections-tcp-syn"
    );
}

#[test]
fn nft_rule_tag_detects_non_tcp_and_fallback_connection_tags() {
    let non_tcp = "meta l4proto != tcp queue num 0 comment \"opensnitch-queue-connections-non-tcp\" # handle 9";
    let fallback = "meta l4proto tcp queue num 0 comment \"unrelated\" # handle 10";

    assert_eq!(
        non_tcp.nft_rule_tag(),
        "opensnitch-queue-connections-non-tcp"
    );
    assert_eq!(fallback.nft_rule_tag(), "opensnitch-queue-connections");
}

#[test]
fn nft_rule_lines_ignores_non_rule_lines_without_handle() {
    let listing = r#"
table inet opensnitch {
    chain mangle_output {
        type route hook output priority 0; policy accept;
        udp sport 53 queue num 0 comment "opensnitch-queue-dns" # handle 21
    }
}
"#;

    let lines = listing.nft_rule_lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].parse_nft_handle().as_deref(), Some("21"));
}

#[test]
fn nft_expression_skips_empty_statement_parts() {
    let rule = pb::FwRule {
        expressions: vec![
            pb::Expressions {
                statement: Some(pb::Statement {
                    op: "==".to_string(),
                    name: "".to_string(),
                    values: vec![pb::StatementValues {
                        key: "l4proto".to_string(),
                        value: "tcp".to_string(),
                    }],
                }),
            },
            pb::Expressions {
                statement: Some(pb::Statement {
                    op: "".to_string(),
                    name: "meta".to_string(),
                    values: vec![pb::StatementValues {
                        key: "".to_string(),
                        value: "tcp".to_string(),
                    }],
                }),
            },
            pb::Expressions {
                statement: Some(pb::Statement {
                    op: "".to_string(),
                    name: "meta".to_string(),
                    values: vec![pb::StatementValues {
                        key: "mark".to_string(),
                        value: "0x1".to_string(),
                    }],
                }),
            },
        ],
        target: "accept".to_string(),
        ..Default::default()
    };

    assert_eq!(rule.nft_expression(0), "meta mark 0x1 accept");
}

#[test]
fn nft_expression_does_not_rewrite_non_queue_target_parameters() {
    let rule = pb::FwRule {
        expressions: vec![pb::Expressions {
            statement: Some(pb::Statement {
                op: "==".to_string(),
                name: "meta".to_string(),
                values: vec![pb::StatementValues {
                    key: "l4proto".to_string(),
                    value: "tcp".to_string(),
                }],
            }),
        }],
        target: "accept".to_string(),
        target_parameters: "num 0".to_string(),
        ..Default::default()
    };

    assert_eq!(rule.nft_expression(42), "meta l4proto == tcp accept num 0");
}

#[test]
fn nft_expression_keeps_queue_num_zero_when_runtime_queue_is_zero() {
    let rule = pb::FwRule {
        expressions: vec![pb::Expressions {
            statement: Some(pb::Statement {
                op: "==".to_string(),
                name: "meta".to_string(),
                values: vec![pb::StatementValues {
                    key: "l4proto".to_string(),
                    value: "udp".to_string(),
                }],
            }),
        }],
        target: "queue".to_string(),
        target_parameters: "num 0 bypass".to_string(),
        ..Default::default()
    };

    assert_eq!(
        rule.nft_expression(0),
        "meta l4proto == udp queue num 0 bypass"
    );
}

#[test]
fn parse_nft_handle_returns_none_when_marker_missing_or_empty() {
    assert_eq!("meta mark 0x1".parse_nft_handle(), None);
    assert_eq!("meta mark 0x1 # handle   ".parse_nft_handle(), None);
}

#[test]
fn nft_expression_with_parameters_ignores_statement_fallback() {
    let rule = pb::FwRule {
        parameters: "ip protocol tcp".to_string(),
        expressions: vec![pb::Expressions {
            statement: Some(pb::Statement {
                op: "==".to_string(),
                name: "meta".to_string(),
                values: vec![pb::StatementValues {
                    key: "l4proto".to_string(),
                    value: "udp".to_string(),
                }],
            }),
        }],
        target: "accept".to_string(),
        ..Default::default()
    };

    assert_eq!(rule.nft_expression(0), "ip protocol tcp accept");
}

#[test]
fn nft_expression_normalizes_icmp_type_lists_in_parameters() {
    let rule = pb::FwRule {
        parameters: "icmp type echo-request,echo-reply,destination-unreachable".to_string(),
        target: "accept".to_string(),
        ..Default::default()
    };

    assert_eq!(
        rule.nft_expression(0),
        "icmp type { echo-request, echo-reply, destination-unreachable } accept"
    );
}

#[test]
fn nft_expression_normalizes_icmp_type_lists_from_statements() {
    let rule = pb::FwRule {
        expressions: vec![pb::Expressions {
            statement: Some(pb::Statement {
                op: "".to_string(),
                name: "icmp".to_string(),
                values: vec![pb::StatementValues {
                    key: "type".to_string(),
                    value: "echo-request,echo-reply,destination-unreachable".to_string(),
                }],
            }),
        }],
        target: "accept".to_string(),
        ..Default::default()
    };

    assert_eq!(
        rule.nft_expression(0),
        "icmp type { echo-request, echo-reply, destination-unreachable } accept"
    );
}

#[test]
fn chain_defaults_use_explicit_values_when_present() {
    let chain = pb::FwChain {
        family: "ip".to_string(),
        table: "filter".to_string(),
        name: "output".to_string(),
        ..Default::default()
    };

    assert_eq!(chain.family_or_default(), "ip");
    assert_eq!(chain.table_or_default(), "filter");
    assert_eq!(chain.chain_name_or_default(), "output");
}

#[test]
fn chain_rule_tag_uses_explicit_table_chain_and_position_when_uuid_missing() {
    let chain = pb::FwChain {
        family: "inet".to_string(),
        table: "custom-table".to_string(),
        name: "custom-chain".to_string(),
        ..Default::default()
    };

    let tag = chain.rule_tag(&pb::FwRule {
        position: 12,
        description: "custom description".to_string(),
        ..Default::default()
    });

    assert_eq!(
        tag,
        "opensnitch-sysfw:custom-table:custom-chain:12:custom description"
    );
}

#[test]
fn nft_rule_tag_detects_dns_and_tcp_syn_tags() {
    let dns = "udp sport 53 queue num 0 comment \"opensnitch-queue-dns\" # handle 1";
    let tcp_syn = "tcp flags & (fin|syn|rst|ack) == syn queue num 0 comment \"opensnitch-queue-connections-tcp-syn\" # handle 2";

    assert_eq!(dns.nft_rule_tag(), "opensnitch-queue-dns");
    assert_eq!(
        tcp_syn.nft_rule_tag(),
        "opensnitch-queue-connections-tcp-syn"
    );
}

#[test]
fn nft_expression_returns_target_only_when_no_predicates_exist() {
    let rule = pb::FwRule {
        target: "drop".to_string(),
        ..Default::default()
    };

    assert_eq!(rule.nft_expression(0), "drop");
}

#[test]
fn nft_expression_returns_empty_string_when_rule_is_empty() {
    let rule = pb::FwRule::default();
    assert_eq!(rule.nft_expression(0), "");
}

#[test]
fn nft_rule_lines_trim_whitespace_before_filtering_handles() {
    let listing = "\n   udp sport 53 queue num 0 comment \"opensnitch-queue-dns\" # handle 15\n";
    let lines = listing.nft_rule_lines();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("udp sport 53"));
}

#[test]
fn parse_nft_handle_trims_whitespace_around_handle_value() {
    let line = "udp sport 53 queue num 0 comment \"x\" # handle   44   ";
    assert_eq!(line.parse_nft_handle().as_deref(), Some("44"));
}

#[test]
fn rule_tag_with_empty_description_keeps_position_component() {
    let chain = pb::FwChain::default();
    let tag = chain.rule_tag(&pb::FwRule {
        position: 5,
        description: String::new(),
        ..Default::default()
    });

    assert_eq!(tag, "opensnitch-sysfw:opensnitch:mangle_output:5:");
}

#[test]
fn nft_rule_tag_dns_takes_priority_when_multiple_known_tags_present() {
    let mixed = "comment \"opensnitch-queue-dns opensnitch-queue-connections-tcp-syn\" # handle 1";
    assert_eq!(mixed.nft_rule_tag(), "opensnitch-queue-dns");
}
