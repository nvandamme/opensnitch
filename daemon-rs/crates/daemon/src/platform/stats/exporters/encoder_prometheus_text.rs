//! Prometheus text format 0.0.4 encoder.
//!
//! One encoder, one format.  Used by both the HTTP scrape transport
//! (`http_serve`) and the HTTP push transport (`http_push`).  Each transport
//! reuses the shared compact exporter snapshot and calls
//! [`render_prometheus_text`].
//!
//! Feature gate: `metrics-http-serve-text` OR `metrics-http-push-text`.
use std::fmt::Write as _;

use crate::models::metrics_snapshot::MetricsExportSnapshot;
use transport_wire_core::WireSubscriptionStatistics;

pub(crate) type PrometheusTextSnapshot = MetricsExportSnapshot;

pub(crate) fn render_prometheus_text(s: &PrometheusTextSnapshot) -> String {
    let mut buf = String::with_capacity(4096);

    counter(
        &mut buf,
        "opensnitch_connections_total",
        "Total network connections intercepted",
        s.connections,
    );
    counter(
        &mut buf,
        "opensnitch_accepted_total",
        "Total connections accepted (including DNS responses)",
        s.accepted,
    );
    counter(
        &mut buf,
        "opensnitch_dropped_total",
        "Total connections dropped",
        s.dropped,
    );
    counter(
        &mut buf,
        "opensnitch_dns_responses_total",
        "Total DNS responses tracked",
        s.dns_responses,
    );
    counter(
        &mut buf,
        "opensnitch_ignored_total",
        "Total connections ignored",
        s.ignored,
    );
    counter(
        &mut buf,
        "opensnitch_rule_hits_total",
        "Total rule matches",
        s.rule_hits,
    );
    counter(
        &mut buf,
        "opensnitch_rule_misses_total",
        "Total rule misses (default action applied)",
        s.rule_misses,
    );

    gauge(
        &mut buf,
        "opensnitch_rules",
        "Current number of loaded rules",
        s.rules,
    );
    gauge(
        &mut buf,
        "opensnitch_uptime_seconds",
        "Daemon uptime in seconds",
        s.uptime,
    );

    subscription_gauges(&mut buf, s.subscription_stats.as_ref());

    labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_proto",
        "Connections by transport protocol",
        "proto",
        &s.by_proto,
    );
    labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_address",
        "Connections by remote address",
        "address",
        &s.by_address,
    );
    labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_host",
        "Connections by remote host",
        "host",
        &s.by_host,
    );
    labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_port",
        "Connections by remote port",
        "port",
        &s.by_port,
    );
    labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_uid",
        "Connections by user UID",
        "uid",
        &s.by_uid,
    );
    labeled_gauge(
        &mut buf,
        "opensnitch_connections_by_executable",
        "Connections by executable",
        "executable",
        &s.by_executable,
    );
    labeled_gauge(
        &mut buf,
        "opensnitch_rule_hits_by_rule",
        "Rule hits by rule name",
        "rule",
        &s.by_rule,
    );

    buf
}

fn counter(buf: &mut String, name: &str, help: &str, value: u64) {
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} counter").ok();
    writeln!(buf, "{name} {value}").ok();
}

fn gauge(buf: &mut String, name: &str, help: &str, value: u64) {
    writeln!(buf, "# HELP {name} {help}").ok();
    writeln!(buf, "# TYPE {name} gauge").ok();
    writeln!(buf, "{name} {value}").ok();
}

fn labeled_gauge(buf: &mut String, name: &str, help: &str, label: &str, pairs: &[(String, u64)]) {
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

    gauge(
        buf,
        "opensnitch_subscription_total",
        "Total configured subscriptions",
        s.total,
    );
    gauge(
        buf,
        "opensnitch_subscription_ready",
        "Subscriptions in READY state",
        s.ready,
    );
    gauge(
        buf,
        "opensnitch_subscription_error",
        "Subscriptions in ERROR state",
        s.error,
    );
    gauge(
        buf,
        "opensnitch_subscription_refresh_count",
        "Cumulative successful refresh downloads",
        s.refresh_count,
    );
    gauge(
        buf,
        "opensnitch_subscription_refresh_errors",
        "Cumulative refresh errors",
        s.refresh_errors,
    );

    let by_status: Vec<_> = s.by_status.iter().map(|(k, v)| (k.clone(), *v)).collect();
    let by_group: Vec<_> = s.by_group.iter().map(|(k, v)| (k.clone(), *v)).collect();
    let by_node: Vec<_> = s.by_node.iter().map(|(k, v)| (k.clone(), *v)).collect();

    labeled_gauge(
        buf,
        "opensnitch_subscription_by_status",
        "Subscription count by status",
        "status",
        &by_status,
    );
    labeled_gauge(
        buf,
        "opensnitch_subscription_by_group",
        "Subscription count by group",
        "group",
        &by_group,
    );
    labeled_gauge(
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
                writeln!(buf, "opensnitch_subscription_rule_info{{rule=\"{rule_esc}\",subscription=\"{sub_esc}\"}} 1")
                    .ok();
            }
        }
    }
}
