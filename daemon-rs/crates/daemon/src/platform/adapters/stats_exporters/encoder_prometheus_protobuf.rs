//! Prometheus protobuf encoder (`io.prometheus.client.MetricFamily`, length-delimited).
//!
//! One encoder, one format.  Used by both the HTTP scrape transport
//! (`http_serve`) and the HTTP push transport (`http_push`).  Each transport
//! reuses the shared compact exporter snapshot and calls
//! [`render_prometheus_proto`].
//!
//! Feature gate: `metrics-http-serve-protobuf` OR `metrics-http-push-protobuf`.
use prost::Message;
use transport_wire_core::WireSubscriptionStatistics;

use crate::models::{
    metrics_snapshot::MetricsExportSnapshot,
    prometheus_wire::{Counter, Gauge, LabelPair, Metric, MetricFamily, MetricType},
};

pub(crate) type ProtoSnapshot = MetricsExportSnapshot;

pub(crate) fn render_prometheus_proto(s: &ProtoSnapshot) -> Vec<u8> {
    let mut out = Vec::with_capacity(4096);

    encode_counter(
        &mut out,
        "opensnitch_connections_total",
        "Total network connections intercepted",
        s.connections,
    );
    encode_counter(
        &mut out,
        "opensnitch_accepted_total",
        "Total connections accepted (including DNS responses)",
        s.accepted,
    );
    encode_counter(
        &mut out,
        "opensnitch_dropped_total",
        "Total connections dropped",
        s.dropped,
    );
    encode_counter(
        &mut out,
        "opensnitch_dns_responses_total",
        "Total DNS responses tracked",
        s.dns_responses,
    );
    encode_counter(
        &mut out,
        "opensnitch_ignored_total",
        "Total connections ignored",
        s.ignored,
    );
    encode_counter(
        &mut out,
        "opensnitch_rule_hits_total",
        "Total rule matches",
        s.rule_hits,
    );
    encode_counter(
        &mut out,
        "opensnitch_rule_misses_total",
        "Total rule misses (default action applied)",
        s.rule_misses,
    );

    encode_gauge(
        &mut out,
        "opensnitch_rules",
        "Current number of loaded rules",
        s.rules,
    );
    encode_gauge(
        &mut out,
        "opensnitch_uptime_seconds",
        "Daemon uptime in seconds",
        s.uptime,
    );

    subscription_gauges_proto(&mut out, s.subscription_stats.as_ref());

    encode_labeled_gauge(
        &mut out,
        "opensnitch_connections_by_proto",
        "Connections by transport protocol",
        "proto",
        &s.by_proto,
    );
    encode_labeled_gauge(
        &mut out,
        "opensnitch_connections_by_address",
        "Connections by remote address",
        "address",
        &s.by_address,
    );
    encode_labeled_gauge(
        &mut out,
        "opensnitch_connections_by_host",
        "Connections by remote host",
        "host",
        &s.by_host,
    );
    encode_labeled_gauge(
        &mut out,
        "opensnitch_connections_by_port",
        "Connections by remote port",
        "port",
        &s.by_port,
    );
    encode_labeled_gauge(
        &mut out,
        "opensnitch_connections_by_uid",
        "Connections by user UID",
        "uid",
        &s.by_uid,
    );
    encode_labeled_gauge(
        &mut out,
        "opensnitch_connections_by_executable",
        "Connections by executable",
        "executable",
        &s.by_executable,
    );
    encode_labeled_gauge(
        &mut out,
        "opensnitch_rule_hits_by_rule",
        "Rule hits by rule name",
        "rule",
        &s.by_rule,
    );

    out
}

fn encode_delimited<M: Message>(out: &mut Vec<u8>, msg: &M) {
    let len = msg.encoded_len();
    let mut prefix = Vec::new();
    prost::encoding::encode_varint(len as u64, &mut prefix);
    out.extend_from_slice(&prefix);
    msg.encode(out).ok();
}

fn metric_family_counter(name: &str, help: &str, value: u64) -> MetricFamily {
    MetricFamily {
        name: Some(name.to_string()),
        help: Some(help.to_string()),
        r#type: Some(MetricType::Counter as i32),
        metric: vec![Metric {
            label: vec![],
            gauge: None,
            counter: Some(Counter {
                value: Some(value as f64),
            }),
            timestamp_ms: None,
        }],
    }
}

fn metric_family_gauge(name: &str, help: &str, value: u64) -> MetricFamily {
    MetricFamily {
        name: Some(name.to_string()),
        help: Some(help.to_string()),
        r#type: Some(MetricType::Gauge as i32),
        metric: vec![Metric {
            label: vec![],
            gauge: Some(Gauge {
                value: Some(value as f64),
            }),
            counter: None,
            timestamp_ms: None,
        }],
    }
}

fn metric_family_labeled_gauge(
    name: &str,
    help: &str,
    label_name: &str,
    pairs: &[(String, u64)],
) -> MetricFamily {
    MetricFamily {
        name: Some(name.to_string()),
        help: Some(help.to_string()),
        r#type: Some(MetricType::Gauge as i32),
        metric: pairs
            .iter()
            .map(|(k, v)| Metric {
                label: vec![LabelPair {
                    name: Some(label_name.to_string()),
                    value: Some(k.clone()),
                }],
                gauge: Some(Gauge {
                    value: Some(*v as f64),
                }),
                counter: None,
                timestamp_ms: None,
            })
            .collect(),
    }
}

fn encode_counter(out: &mut Vec<u8>, name: &str, help: &str, value: u64) {
    encode_delimited(out, &metric_family_counter(name, help, value));
}

fn encode_gauge(out: &mut Vec<u8>, name: &str, help: &str, value: u64) {
    encode_delimited(out, &metric_family_gauge(name, help, value));
}

fn encode_labeled_gauge(
    out: &mut Vec<u8>,
    name: &str,
    help: &str,
    label_name: &str,
    pairs: &[(String, u64)],
) {
    if pairs.is_empty() {
        return;
    }
    encode_delimited(
        out,
        &metric_family_labeled_gauge(name, help, label_name, pairs),
    );
}

fn subscription_gauges_proto(out: &mut Vec<u8>, sub: Option<&WireSubscriptionStatistics>) {
    let Some(s) = sub else { return };

    encode_gauge(
        out,
        "opensnitch_subscription_total",
        "Total configured subscriptions",
        s.total,
    );
    encode_gauge(
        out,
        "opensnitch_subscription_ready",
        "Subscriptions in READY state",
        s.ready,
    );
    encode_gauge(
        out,
        "opensnitch_subscription_error",
        "Subscriptions in ERROR state",
        s.error,
    );
    encode_gauge(
        out,
        "opensnitch_subscription_refresh_count",
        "Cumulative successful refresh downloads",
        s.refresh_count,
    );
    encode_gauge(
        out,
        "opensnitch_subscription_refresh_errors",
        "Cumulative refresh errors",
        s.refresh_errors,
    );

    for (map_name, label_key, map) in [
        ("opensnitch_subscription_by_status", "status", &s.by_status),
        ("opensnitch_subscription_by_group", "group", &s.by_group),
        ("opensnitch_subscription_by_node", "node", &s.by_node),
    ] {
        if map.is_empty() {
            continue;
        }
        let pairs: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
        encode_labeled_gauge(
            out,
            map_name,
            &format!("Subscription count by {label_key}"),
            label_key,
            &pairs,
        );
    }

    if !s.rule_subscriptions.is_empty() {
        let mf = MetricFamily {
            name: Some("opensnitch_subscription_rule_info".to_string()),
            help: Some(
                "Rules backed by a subscription list operator (static N:N mapping)".to_string(),
            ),
            r#type: Some(MetricType::Gauge as i32),
            metric: s
                .rule_subscriptions
                .iter()
                .flat_map(|entry| {
                    entry.subscriptions.iter().map(|sub_name| Metric {
                        label: vec![
                            LabelPair {
                                name: Some("rule".to_string()),
                                value: Some(entry.rule.clone()),
                            },
                            LabelPair {
                                name: Some("subscription".to_string()),
                                value: Some(sub_name.clone()),
                            },
                        ],
                        gauge: Some(Gauge { value: Some(1.0) }),
                        ..Default::default()
                    })
                })
                .collect(),
        };
        encode_delimited(out, &mf);
    }
}
