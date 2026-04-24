use crate::models::metrics_snapshot::MetricsExportSnapshot;

pub(crate) fn encode_syslog_metrics(snapshot: &MetricsExportSnapshot) -> Vec<String> {
    let mut records = Vec::new();

    let mut summary = vec![
        "metric=opensnitch_stats".to_string(),
        format!("rules={}", snapshot.rules),
        format!("uptime_seconds={}", snapshot.uptime),
        format!("dns_responses_total={}", snapshot.dns_responses),
        format!("connections_total={}", snapshot.connections),
        format!("ignored_total={}", snapshot.ignored),
        format!("accepted_total={}", snapshot.accepted),
        format!("dropped_total={}", snapshot.dropped),
        format!("rule_hits_total={}", snapshot.rule_hits),
        format!("rule_misses_total={}", snapshot.rule_misses),
    ];
    if !snapshot.daemon_version.trim().is_empty() {
        summary.push(format!(
            "daemon_version=\"{}\"",
            sanitize_value(&snapshot.daemon_version)
        ));
    }
    records.push(summary.join(" "));

    append_breakdown(
        &mut records,
        "opensnitch_connections_by_proto",
        "proto",
        &snapshot.by_proto,
    );
    append_breakdown(
        &mut records,
        "opensnitch_connections_by_address",
        "address",
        &snapshot.by_address,
    );
    append_breakdown(
        &mut records,
        "opensnitch_connections_by_host",
        "host",
        &snapshot.by_host,
    );
    append_breakdown(
        &mut records,
        "opensnitch_connections_by_port",
        "port",
        &snapshot.by_port,
    );
    append_breakdown(
        &mut records,
        "opensnitch_connections_by_uid",
        "uid",
        &snapshot.by_uid,
    );
    append_breakdown(
        &mut records,
        "opensnitch_connections_by_executable",
        "executable",
        &snapshot.by_executable,
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
            &snapshot.by_subscription_status,
        );
        append_breakdown(
            &mut records,
            "opensnitch_subscription_by_group",
            "group",
            &snapshot.by_subscription_group,
        );
        append_breakdown(
            &mut records,
            "opensnitch_subscription_by_node",
            "node",
            &snapshot.by_subscription_node,
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
    values: &[(String, u64)],
) {
    for (label_value, value) in values {
        records.push(format!(
            "metric={metric} {label_name}=\"{}\" value={value}",
            sanitize_value(&label_value),
        ));
    }
}

fn sanitize_value(value: &str) -> String {
    value.replace('\n', " ").replace('"', "")
}
