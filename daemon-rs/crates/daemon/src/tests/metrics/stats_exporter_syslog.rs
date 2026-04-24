use std::collections::HashMap;

use transport_wire_core::{WireRuleSubscriptionEntry, WireStatistics, WireSubscriptionStatistics};

use crate::models::metrics_snapshot::MetricsSnapshot;

use super::{SyslogFormat, frame_remote_message};

fn make_snapshot() -> MetricsSnapshot {
    let mut by_proto = HashMap::new();
    by_proto.insert("tcp".to_string(), 42u64);

    let mut by_executable = HashMap::new();
    by_executable.insert("/usr/bin/curl".to_string(), 3u64);

    let mut by_rule = HashMap::new();
    by_rule.insert("allow-dns".to_string(), 7u64);

    let mut by_status = HashMap::new();
    by_status.insert("ready".to_string(), 2u64);

    let mut by_group = HashMap::new();
    by_group.insert("ads".to_string(), 2u64);

    let mut by_node = HashMap::new();
    by_node.insert("node-a".to_string(), 2u64);

    MetricsSnapshot::new(
        WireStatistics {
            rules: 5,
            uptime: 1800,
            dns_responses: 99,
            connections: 100,
            ignored: 4,
            accepted: 90,
            dropped: 6,
            rule_hits: 30,
            rule_misses: 8,
            daemon_version: "0.6.0-test".to_string(),
            by_proto,
            by_executable,
            ..Default::default()
        },
        Some(WireSubscriptionStatistics {
            total: 2,
            ready: 2,
            error: 0,
            refresh_count: 12,
            refresh_errors: 1,
            by_status,
            by_group,
            by_node,
            events: vec![],
            rule_subscriptions: vec![WireRuleSubscriptionEntry {
                rule: "block-ads".to_string(),
                subscriptions: vec!["easylist".to_string(), "oisd".to_string()],
            }],
        }),
        by_rule,
    )
}

#[test]
fn syslog_encoder_emits_rich_metric_records() {
    let snapshot = make_snapshot();
    let out = super::super::encoder_syslog::encode_syslog_metrics(&snapshot.export_view());

    assert!(
        out.iter()
            .any(|line| line.contains("metric=opensnitch_stats")),
        "{out:#?}"
    );
    assert!(
        out.iter()
            .any(|line| line
                .contains("metric=opensnitch_connections_by_proto proto=\"tcp\" value=42")),
        "{out:#?}"
    );
    assert!(
        out.iter().any(|line| {
            line.contains("metric=opensnitch_connections_by_executable")
                && line.contains("/usr/bin/curl")
        }),
        "{out:#?}"
    );
    assert!(
        out.iter()
            .any(|line| line
                .contains("metric=opensnitch_rule_hits_by_rule rule=\"allow-dns\" value=7")),
        "{out:#?}"
    );
    assert!(
        out.iter().any(|line| line.contains("metric=opensnitch_subscription_stats total=2 ready=2 error=0 refresh_count=12 refresh_errors=1")),
        "{out:#?}"
    );
    assert!(
        out.iter()
            .any(|line| line
                .contains("metric=opensnitch_subscription_by_group group=\"ads\" value=2")),
        "{out:#?}"
    );
    assert!(
        out.iter().any(|line| {
            line.contains("metric=opensnitch_subscription_rule_info")
                && line.contains("rule=\"block-ads\"")
                && line.contains("subscription=\"easylist\"")
        }),
        "{out:#?}"
    );
    assert!(
        out.iter().any(|line| {
            line.contains("metric=opensnitch_subscription_rule_info")
                && line.contains("rule=\"block-ads\"")
                && line.contains("subscription=\"oisd\"")
        }),
        "{out:#?}"
    );
}

#[test]
fn remote_syslog_messages_are_framed() {
    let rfc3164 = frame_remote_message(
        SyslogFormat::Rfc3164,
        "opensnitch-metrics",
        "metric=opensnitch_stats",
    );
    let rfc5424 = frame_remote_message(
        SyslogFormat::Rfc5424,
        "opensnitch-metrics",
        "metric=opensnitch_stats",
    );

    assert!(rfc3164.starts_with("<14>"), "{rfc3164}");
    assert!(
        rfc3164.contains(" opensnitch-metrics: metric=opensnitch_stats\n"),
        "{rfc3164}"
    );

    assert!(rfc5424.starts_with("<14>1 "), "{rfc5424}");
    assert!(
        rfc5424.contains(" localhost opensnitch-metrics - - - metric=opensnitch_stats\n"),
        "{rfc5424}"
    );
}
