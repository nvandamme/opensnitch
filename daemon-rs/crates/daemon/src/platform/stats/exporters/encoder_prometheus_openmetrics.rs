//! OpenMetrics text format 1.0.0 encoder.
//!
//! One encoder, one format.  HTTP scrape/push transports reuse the shared
//! compact exporter snapshot.
//!
//! Feature gate: `metrics-http-serve-openmetrics` OR `metrics-http-push-openmetrics`.
use std::fmt::Write as _;

use crate::models::metrics_snapshot::MetricsExportSnapshot;
use transport_wire_core::WireSubscriptionStatistics;

pub(crate) type OpenMetricsSnapshot = MetricsExportSnapshot;

pub(crate) fn render_openmetrics_text(s: &OpenMetricsSnapshot) -> String {
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    let mut buf = String::with_capacity(4096);

    om_counter(
        &mut buf,
        "opensnitch_connections",
        "Total network connections intercepted",
        s.connections,
        created,
    );
    om_counter(
        &mut buf,
        "opensnitch_accepted",
        "Total connections accepted (including DNS responses)",
        s.accepted,
        created,
    );
    om_counter(
        &mut buf,
        "opensnitch_dropped",
        "Total connections dropped",
        s.dropped,
        created,
    );
    om_counter(
        &mut buf,
        "opensnitch_dns_responses",
        "Total DNS responses tracked",
        s.dns_responses,
        created,
    );
    om_counter(
        &mut buf,
        "opensnitch_ignored",
        "Total connections ignored",
        s.ignored,
        created,
    );
    om_counter(
        &mut buf,
        "opensnitch_rule_hits",
        "Total rule matches",
        s.rule_hits,
        created,
    );
    om_counter(
        &mut buf,
        "opensnitch_rule_misses",
        "Total rule misses (default action applied)",
        s.rule_misses,
        created,
    );

    om_gauge(
        &mut buf,
        "opensnitch_rules",
        "Current number of loaded rules",
        "",
        s.rules,
    );
    om_gauge(
        &mut buf,
        "opensnitch_uptime_seconds",
        "Daemon uptime in seconds",
        "seconds",
        s.uptime,
    );

    subscription_gauges(&mut buf, s.subscription_stats.as_ref());

    om_labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_proto",
        "Connections by transport protocol",
        "proto",
        &s.by_proto,
    );
    om_labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_address",
        "Connections by remote address",
        "address",
        &s.by_address,
    );
    om_labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_host",
        "Connections by remote host",
        "host",
        &s.by_host,
    );
    om_labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_port",
        "Connections by remote port",
        "port",
        &s.by_port,
    );
    om_labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_uid",
        "Connections by user UID",
        "uid",
        &s.by_uid,
    );
    om_labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_executable",
        "Connections by executable",
        "executable",
        &s.by_executable,
    );
    om_labeled_gauge(
        &mut buf,
        "opensnitch_rule_hits_by_rule",
        "Rule hits by rule name",
        "rule",
        &s.by_rule,
    );

    buf.push_str("# EOF\n");
    buf
}

fn om_counter(buf: &mut String, base_name: &str, help: &str, value: u64, created: f64) {
    writeln!(buf, "# HELP {base_name} {help}").ok();
    writeln!(buf, "# TYPE {base_name} counter").ok();
    writeln!(buf, "{base_name}_total {value}").ok();
    writeln!(buf, "{base_name}_created {created}").ok();
}

fn om_gauge(buf: &mut String, name: &str, help: &str, unit: &str, value: u64) {
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} gauge").ok();
    if !unit.is_empty() {
        writeln!(buf, "# UNIT {name} {unit}").ok();
    }
    writeln!(buf, "{name} {value}").ok();
}

fn om_labeled_gauge(
    buf: &mut String,
    name: &str,
    help: &str,
    label: &str,
    pairs: &[(String, u64)],
) {
    if pairs.is_empty() {
        return;
    }
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} gauge").ok();
    for (key, value) in pairs {
        let escaped = escape_label_value(key);
        writeln!(buf, "{name}{{{label}=\"{escaped}\"}} {value}").ok();
    }
}

fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn subscription_gauges(buf: &mut String, sub: Option<&WireSubscriptionStatistics>) {
    let Some(s) = sub else { return };

    om_gauge(
        buf,
        "opensnitch_subscription_total",
        "Total configured subscriptions",
        "",
        s.total,
    );
    om_gauge(
        buf,
        "opensnitch_subscription_ready",
        "Subscriptions in READY state",
        "",
        s.ready,
    );
    om_gauge(
        buf,
        "opensnitch_subscription_error",
        "Subscriptions in ERROR state",
        "",
        s.error,
    );
    om_gauge(
        buf,
        "opensnitch_subscription_refresh_count",
        "Cumulative successful refresh downloads",
        "",
        s.refresh_count,
    );
    om_gauge(
        buf,
        "opensnitch_subscription_refresh_errors",
        "Cumulative refresh errors",
        "",
        s.refresh_errors,
    );

    let by_status: Vec<_> = s.by_status.iter().map(|(k, v)| (k.clone(), *v)).collect();
    let by_group: Vec<_> = s.by_group.iter().map(|(k, v)| (k.clone(), *v)).collect();
    let by_node: Vec<_> = s.by_node.iter().map(|(k, v)| (k.clone(), *v)).collect();

    om_labeled_gauge(
        buf,
        "opensnitch_subscription_by_status",
        "Subscription count by status",
        "status",
        &by_status,
    );
    om_labeled_gauge(
        buf,
        "opensnitch_subscription_by_group",
        "Subscription count by group",
        "group",
        &by_group,
    );
    om_labeled_gauge(
        buf,
        "opensnitch_subscription_by_node",
        "Subscription count by node",
        "node",
        &by_node,
    );

    if !s.rule_subscriptions.is_empty() {
        writeln!(buf, "# HELP opensnitch_subscription_rule_info Rules backed by a subscription list operator (static N:N mapping)").ok();
        writeln!(buf, "# TYPE opensnitch_subscription_rule_info gauge").ok();
        for entry in &s.rule_subscriptions {
            let rule_esc = escape_label_value(&entry.rule);
            for sub_name in &entry.subscriptions {
                let sub_esc = escape_label_value(sub_name);
                writeln!(
                    buf,
                    "opensnitch_subscription_rule_info{{rule=\"{rule_esc}\",subscription=\"{sub_esc}\"}} 1"
                )
                .ok();
            }
        }
    }
}
