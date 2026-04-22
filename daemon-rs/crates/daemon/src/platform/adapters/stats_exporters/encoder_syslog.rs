use crate::models::metrics_snapshot::MetricsSnapshot;

pub(crate) fn encode_syslog_metrics(snapshot: &MetricsSnapshot) -> Vec<String> {
    let mut records = Vec::new();
    let stats = &snapshot.stats;

    let mut summary = vec![
        "metric=opensnitch_stats".to_string(),
        format!("rules={}", stats.rules),
        format!("uptime_seconds={}", stats.uptime),
        format!("dns_responses_total={}", stats.dns_responses),
        format!("connections_total={}", stats.connections),
        format!("ignored_total={}", stats.ignored),
        format!("accepted_total={}", stats.accepted),
        format!("dropped_total={}", stats.dropped),
        format!("rule_hits_total={}", stats.rule_hits),
        format!("rule_misses_total={}", stats.rule_misses),
    ];
    if !stats.daemon_version.trim().is_empty() {
        summary.push(format!(
            "daemon_version=\"{}\"",
            sanitize_value(&stats.daemon_version)
        ));
    }
    records.push(summary.join(" "));

    append_breakdown(
        &mut records,
        "opensnitch_connections_by_proto",
        "proto",
        &stats.by_proto,
    );
    append_breakdown(
        &mut records,
        "opensnitch_connections_by_address",
        "address",
        &stats.by_address,
    );
    append_breakdown(
        &mut records,
        "opensnitch_connections_by_host",
        "host",
        &stats.by_host,
    );
    append_breakdown(
        &mut records,
        "opensnitch_connections_by_port",
        "port",
        &stats.by_port,
    );
    append_breakdown(
        &mut records,
        "opensnitch_connections_by_uid",
        "uid",
        &stats.by_uid,
    );
    append_breakdown(
        &mut records,
        "opensnitch_connections_by_executable",
        "executable",
        &stats.by_executable,
    );
    append_breakdown(
        &mut records,
        "opensnitch_rule_hits_by_rule",
        "rule",
        &snapshot.by_rule,
    );

    if let Some(sub) = &snapshot.subscription_stats {
        records.push(
            [
                "metric=opensnitch_subscription_stats".to_string(),
                format!("total={}", sub.total),
                format!("ready={}", sub.ready),
                format!("error={}", sub.error),
                format!("refresh_count={}", sub.refresh_count),
                format!("refresh_errors={}", sub.refresh_errors),
            ]
            .join(" "),
        );

        append_breakdown(
            &mut records,
            "opensnitch_subscription_by_status",
            "status",
            &sub.by_status,
        );
        append_breakdown(
            &mut records,
            "opensnitch_subscription_by_group",
            "group",
            &sub.by_group,
        );
        append_breakdown(
            &mut records,
            "opensnitch_subscription_by_node",
            "node",
            &sub.by_node,
        );

        let mut rule_subscriptions = sub.rule_subscriptions.clone();
        rule_subscriptions.sort_by(|left, right| left.rule.cmp(&right.rule));
        for entry in rule_subscriptions {
            let mut subscriptions = entry.subscriptions;
            subscriptions.sort();
            for subscription in subscriptions {
                records.push(format!(
                    "metric=opensnitch_subscription_rule_info rule=\"{}\" subscription=\"{}\" value=1",
                    sanitize_value(&entry.rule),
                    sanitize_value(&subscription),
                ));
            }
        }
    }

    records
}

fn append_breakdown(
    records: &mut Vec<String>,
    metric: &str,
    label_name: &str,
    values: &std::collections::HashMap<String, u64>,
) {
    let mut pairs: Vec<_> = values
        .iter()
        .map(|(key, value)| (key.clone(), *value))
        .collect();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));

    for (label_value, value) in pairs {
        records.push(format!(
            "metric={metric} {label_name}=\"{}\" value={value}",
            sanitize_value(&label_value),
        ));
    }
}

fn sanitize_value(value: &str) -> String {
    value.replace('\n', " ").replace('"', "")
}
