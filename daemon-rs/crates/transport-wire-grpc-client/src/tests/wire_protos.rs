use std::collections::HashMap;

use opensnitch_transport_wire_core::{
    WireAlert, WireAlertData, WireConnection, WireFwChain, WireFwExpression, WireFwRule,
    WireFwStatement, WireFwStatementValue, WireRule, WireRuleOperator, WireStringInt,
    WireSubscribeConfig, WireSysFirewall,
};

use crate::wire_protos::{
    pb_subscribe_config_from_wire, wire_alert_to_proto, wire_subscribe_config_from_proto,
};

#[test]
fn subscribe_config_round_trips_nested_rule_and_firewall_shapes() {
    let wire = WireSubscribeConfig {
        id: 42,
        name: "ui-client".into(),
        version: "1.2.3".into(),
        is_firewall_running: true,
        config: "{}".into(),
        log_level: 3,
        rules: vec![WireRule {
            created: 7,
            name: "allow-dns".into(),
            description: "dns".into(),
            enabled: true,
            precedence: false,
            nolog: true,
            action: "allow".into(),
            duration: "always".into(),
            operator: Some(WireRuleOperator {
                type_name: "list".into(),
                operand: "dest.host".into(),
                data: "example.org".into(),
                sensitive: false,
                list: vec![WireRuleOperator {
                    type_name: "simple".into(),
                    operand: "protocol".into(),
                    data: "udp".into(),
                    sensitive: false,
                    list: Vec::new(),
                }],
            }),
        }],
        system_firewall: Some(WireSysFirewall {
            enabled: true,
            version: 1,
            rules: vec![WireFwRule {
                table: "filter".into(),
                chain: "output".into(),
                uuid: "rule-1".into(),
                enabled: true,
                position: 1,
                description: "allow dns".into(),
                parameters: "ip".into(),
                expressions: vec![WireFwExpression {
                    statement: Some(WireFwStatement {
                        op: "match".into(),
                        name: "dport".into(),
                        values: vec![WireFwStatementValue {
                            key: "value".into(),
                            value: "53".into(),
                        }],
                    }),
                }],
                target: "accept".into(),
                target_parameters: String::new(),
            }],
            chains: vec![WireFwChain {
                name: "output".into(),
                table: "filter".into(),
                family: "inet".into(),
                priority: "0".into(),
                type_name: "filter".into(),
                hook: "output".into(),
                policy: "accept".into(),
                rules: Vec::new(),
            }],
        }),
    };

    let proto = pb_subscribe_config_from_wire(wire.clone());
    let round_trip = wire_subscribe_config_from_proto(proto);

    assert_eq!(round_trip, wire);
}

#[test]
fn alert_connection_payload_maps_process_tree_without_cloning_shape() {
    let mut env = HashMap::new();
    env.insert("PATH".into(), "/usr/bin".into());

    let alert = WireAlert {
        id: 9,
        alert_type: 2,
        action: 3,
        priority: 4,
        what: 5,
        data: Some(WireAlertData::Connection(WireConnection {
            protocol: "tcp".into(),
            src_ip: "127.0.0.1".into(),
            src_port: 40000,
            dst_ip: "8.8.8.8".into(),
            dst_host: "dns.google".into(),
            dst_port: 53,
            user_id: 1000,
            process_id: 1234,
            process_path: "/usr/bin/dig".into(),
            process_cwd: "/tmp".into(),
            process_args: vec!["dig".into(), "example.org".into()],
            process_env: env,
            process_checksums: HashMap::new(),
            process_tree: vec![WireStringInt {
                key: "dig".into(),
                value: 1234,
            }],
        })),
    };

    let proto = wire_alert_to_proto(alert);
    let connection = match proto.data.expect("connection payload") {
        opensnitch_proto::pb::alert::Data::Conn(conn) => conn,
        other => panic!("unexpected alert payload: {other:?}"),
    };

    assert_eq!(connection.process_tree.len(), 1);
    assert_eq!(connection.process_tree[0].key, "dig");
    assert_eq!(connection.process_tree[0].value, 1234);
}

#[cfg(feature = "subscriptions")]
#[test]
fn subscription_reply_round_trips_refresh_metadata() {
    use opensnitch_transport_wire_core::{WireSubscription, WireSubscriptionRefreshMetadata};

    let reply = opensnitch_proto::pb::SubscriptionReply {
        operation: 4,
        accepted: true,
        message: "ok".into(),
        errors: vec!["none".into()],
        subscriptions: vec![opensnitch_proto::pb::Subscription {
            id: "sub-1".into(),
            name: "community".into(),
            url: "https://example.org/rules".into(),
            filename: "community.yaml".into(),
            groups: vec!["default".into()],
            enabled: true,
            format: "yaml".into(),
            interval_seconds: 3600,
            timeout_seconds: 30,
            max_bytes: 4096,
            node: "node-a".into(),
            status: 2,
            last_updated: "today".into(),
            last_error: String::new(),
            refresh_meta: Some(opensnitch_proto::pb::SubscriptionRefreshMetadata {
                next_refresh_after: 123,
                consecutive_failures: 0,
                etag: "etag".into(),
                last_modified: "yesterday".into(),
            }),
        }],
    };

    let wire = crate::wire_protos::wire_subscription_reply_from_pb(reply);

    assert_eq!(
        wire.subscriptions,
        vec![WireSubscription {
            id: "sub-1".into(),
            name: "community".into(),
            url: "https://example.org/rules".into(),
            filename: "community.yaml".into(),
            groups: vec!["default".into()],
            enabled: true,
            format: "yaml".into(),
            interval_seconds: 3600,
            timeout_seconds: 30,
            max_bytes: 4096,
            node: "node-a".into(),
            status: 2,
            last_updated: "today".into(),
            last_error: String::new(),
            refresh_meta: Some(WireSubscriptionRefreshMetadata {
                next_refresh_after: 123,
                consecutive_failures: 0,
                etag: "etag".into(),
                last_modified: "yesterday".into(),
            }),
        }]
    );
}
