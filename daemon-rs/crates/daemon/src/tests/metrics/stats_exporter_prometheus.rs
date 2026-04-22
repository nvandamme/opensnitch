//! Correctness tests for the Prometheus scrape adapter.
//!
//! This module is declared as a child of `stats_exporter_prometheus` (via
//! `#[path]` in the adapter file), giving it direct access to all private
//! render helpers and types without requiring public probe wrappers.
//!
//! Test surface:
//! - `render_prometheus_text`   — Prometheus text 0.0.4 correctness
//! - `render_openmetrics_text`  — OpenMetrics 1.0.0 correctness (EOF, _total)
//! - `render_prometheus_proto`  — length-delimited protobuf MetricFamilies
//! - `negotiate_format`         — Accept header content negotiation
//! - `gzip_compress`            — round-trip compress / decompress
//! - HTTP endpoint              — live server integration (reqwest GET)

use std::collections::HashMap;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use transport_wire_core::{WireRuleSubscriptionEntry, WireStatistics, WireSubscriptionStatistics};

use crate::models::metrics_snapshot::MetricsSnapshot;
use crate::platform::ports::stats_exporter_port::StatsExporterPort;

// Pull all private items from the parent adapter module.
use super::{
    CompactStats, PrometheusStatsExporter, ResponseFormat, gzip_compress, negotiate_format,
    prom_proto, render_openmetrics_text, render_prometheus_proto, render_prometheus_text,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn make_snapshot() -> MetricsSnapshot {
    let mut by_proto = HashMap::new();
    by_proto.insert("tcp".to_string(), 300u64);
    by_proto.insert("udp".to_string(), 100u64);

    let mut by_host = HashMap::new();
    by_host.insert("example.com".to_string(), 9u64);

    let mut by_rule = HashMap::new();
    by_rule.insert("allow-dns".to_string(), 8u64);

    MetricsSnapshot {
        stats: WireStatistics {
            rules: 8,
            uptime: 7200,
            dns_responses: 150,
            connections: 400,
            ignored: 5,
            accepted: 380,
            dropped: 15,
            rule_hits: 250,
            rule_misses: 40,
            by_proto,
            by_host,
            ..Default::default()
        },
        subscription_stats: None,
        by_rule,
    }
}

fn make_sub_stats() -> WireSubscriptionStatistics {
    let mut by_status = HashMap::new();
    by_status.insert("ready".to_string(), 4u64);
    by_status.insert("error".to_string(), 1u64);

    let mut by_group = HashMap::new();
    by_group.insert("ads".to_string(), 2u64);
    by_group.insert("security".to_string(), 3u64);

    let mut by_node = HashMap::new();
    by_node.insert("node-1".to_string(), 5u64);

    // block-combined references two groups → two subscriptions (N:N)
    let rule_subscriptions = vec![
        WireRuleSubscriptionEntry {
            rule: "block-ads".to_string(),
            subscriptions: vec!["easylist".to_string()],
        },
        WireRuleSubscriptionEntry {
            rule: "block-combined".to_string(),
            subscriptions: vec!["easylist".to_string(), "malware-domains".to_string()],
        },
        WireRuleSubscriptionEntry {
            rule: "block-malware".to_string(),
            subscriptions: vec!["malware-domains".to_string()],
        },
    ];

    WireSubscriptionStatistics {
        total: 5,
        ready: 4,
        error: 1,
        refresh_count: 200,
        refresh_errors: 7,
        by_status,
        by_group,
        by_node,
        events: vec![],
        rule_subscriptions,
    }
}

// ---------------------------------------------------------------------------
// Prometheus text 0.0.4
// ---------------------------------------------------------------------------

#[test]
fn text_scalars_are_correct() {
    let cs = CompactStats::from(&make_snapshot());
    let out = render_prometheus_text(&cs);

    assert!(
        out.contains("opensnitch_connections_total 400\n"),
        "connections\n{out}"
    );
    assert!(
        out.contains("opensnitch_accepted_total 380\n"),
        "accepted\n{out}"
    );
    assert!(
        out.contains("opensnitch_dropped_total 15\n"),
        "dropped\n{out}"
    );
    assert!(
        out.contains("opensnitch_dns_responses_total 150\n"),
        "dns\n{out}"
    );
    assert!(
        out.contains("opensnitch_ignored_total 5\n"),
        "ignored\n{out}"
    );
    assert!(
        out.contains("opensnitch_rule_hits_total 250\n"),
        "rule_hits\n{out}"
    );
    assert!(
        out.contains("opensnitch_rule_misses_total 40\n"),
        "rule_misses\n{out}"
    );
    assert!(out.contains("opensnitch_rules 8\n"), "rules\n{out}");
    assert!(
        out.contains("opensnitch_uptime_seconds 7200\n"),
        "uptime\n{out}"
    );
}

#[test]
fn text_type_and_help_lines_emitted() {
    let cs = CompactStats::from(&make_snapshot());
    let out = render_prometheus_text(&cs);

    assert!(out.contains("# HELP opensnitch_connections_total"), "{out}");
    assert!(
        out.contains("# TYPE opensnitch_connections_total counter"),
        "{out}"
    );
    assert!(out.contains("# HELP opensnitch_rules"), "{out}");
    assert!(out.contains("# TYPE opensnitch_rules gauge"), "{out}");
}

#[test]
fn text_breakdown_maps_emit_labeled_lines() {
    let cs = CompactStats::from(&make_snapshot());
    let out = render_prometheus_text(&cs);

    assert!(
        out.contains("opensnitch_connections_by_proto{proto=\"tcp\"} 300"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_connections_by_proto{proto=\"udp\"} 100"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_connections_by_host{host=\"example.com\"} 9"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_rule_hits_by_rule{rule=\"allow-dns\"} 8"),
        "{out}"
    );
}

#[test]
fn text_omits_subscription_gauges_when_none() {
    let cs = CompactStats::from(&make_snapshot());
    let out = render_prometheus_text(&cs);

    assert!(
        !out.contains("opensnitch_subscription"),
        "unexpected sub lines\n{out}"
    );
}

#[test]
fn text_subscription_scalars_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactStats::from(&snap);
    let out = render_prometheus_text(&cs);

    assert!(out.contains("opensnitch_subscription_total 5\n"), "{out}");
    assert!(out.contains("opensnitch_subscription_ready 4\n"), "{out}");
    assert!(out.contains("opensnitch_subscription_error 1\n"), "{out}");
    assert!(
        out.contains("opensnitch_subscription_refresh_count 200\n"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_refresh_errors 7\n"),
        "{out}"
    );
}

#[test]
fn text_subscription_breakdown_maps_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactStats::from(&snap);
    let out = render_prometheus_text(&cs);

    assert!(
        out.contains("opensnitch_subscription_by_status{status=\"ready\"} 4"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_by_status{status=\"error\"} 1"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_by_group{group=\"ads\"} 2"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_by_group{group=\"security\"} 3"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_by_node{node=\"node-1\"} 5"),
        "{out}"
    );
}

#[test]
fn text_label_value_escaping_backslash_quote_newline() {
    let mut snap = make_snapshot();
    snap.stats.by_host.clear();
    snap.stats.by_host.insert("a\\b\"c\nd".to_string(), 1u64);
    let cs = CompactStats::from(&snap);
    let out = render_prometheus_text(&cs);

    // Prometheus spec: \ → \\  " → \"  \n → \n (literal two chars)
    assert!(
        out.contains(r#"host="a\\b\"c\nd""#),
        "escaped label value missing\n{out}"
    );
}

// ---------------------------------------------------------------------------
// OpenMetrics 1.0.0
// ---------------------------------------------------------------------------

#[test]
fn openmetrics_ends_with_eof_newline() {
    let cs = CompactStats::from(&make_snapshot());
    let out = render_openmetrics_text(&cs);
    assert!(
        out.ends_with("# EOF\n"),
        "must end with # EOF\n, got:\n…{}",
        &out[out.len().saturating_sub(30)..]
    );
}

#[test]
fn openmetrics_counters_use_base_name_in_type_line() {
    let cs = CompactStats::from(&make_snapshot());
    let out = render_openmetrics_text(&cs);

    // OpenMetrics: TYPE line uses base name (no _total), sample uses _total
    assert!(
        out.contains("# TYPE opensnitch_connections counter"),
        "{out}"
    );
    assert!(out.contains("opensnitch_connections_total 400"), "{out}");
}

#[test]
fn openmetrics_contains_created_timestamp_for_counters() {
    let cs = CompactStats::from(&make_snapshot());
    let out = render_openmetrics_text(&cs);

    assert!(out.contains("opensnitch_connections_created"), "{out}");
}

#[test]
fn openmetrics_subscription_scalars_present_when_some() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactStats::from(&snap);
    let out = render_openmetrics_text(&cs);

    assert!(out.contains("opensnitch_subscription_total 5"), "{out}");
    assert!(out.contains("opensnitch_subscription_ready 4"), "{out}");
}

#[test]
fn openmetrics_no_subscription_when_none() {
    let cs = CompactStats::from(&make_snapshot());
    let out = render_openmetrics_text(&cs);

    assert!(
        !out.contains("opensnitch_subscription"),
        "no sub lines expected\n{out}"
    );
}

// ---------------------------------------------------------------------------
// Prometheus protobuf (length-delimited MetricFamily stream)
// ---------------------------------------------------------------------------

/// Decode a varint-length-prefixed stream of `MetricFamily` protobuf messages.
fn decode_proto_families(mut buf: &[u8]) -> Vec<prom_proto::MetricFamily> {
    use prost::Message as _;

    let mut fams = Vec::new();
    while !buf.is_empty() {
        // Decode varint length prefix (up to 10 bytes for u64).
        let mut length: u64 = 0;
        let mut shift = 0u32;
        let mut consumed = 0usize;
        for &b in buf.iter() {
            consumed += 1;
            length |= ((b & 0x7F) as u64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
            if consumed >= 10 {
                break;
            }
        }
        buf = &buf[consumed..];
        let len = length as usize;
        if len == 0 || len > buf.len() {
            break;
        }
        if let Ok(fam) = prom_proto::MetricFamily::decode(&buf[..len]) {
            fams.push(fam);
        }
        buf = &buf[len..];
    }
    fams
}

#[test]
fn proto_contains_scalar_metric_families() {
    let cs = CompactStats::from(&make_snapshot());
    let buf = render_prometheus_proto(&cs);
    let fams = decode_proto_families(&buf);
    let names: Vec<_> = fams.iter().filter_map(|f| f.name.as_deref()).collect();

    assert!(names.contains(&"opensnitch_connections_total"), "{names:?}");
    assert!(names.contains(&"opensnitch_uptime_seconds"), "{names:?}");
    assert!(names.contains(&"opensnitch_rules"), "{names:?}");
    assert!(
        names.contains(&"opensnitch_connections_by_proto"),
        "{names:?}"
    );
}

#[test]
fn proto_no_subscription_families_when_none() {
    let cs = CompactStats::from(&make_snapshot());
    let buf = render_prometheus_proto(&cs);
    let fams = decode_proto_families(&buf);
    let names: Vec<_> = fams.iter().filter_map(|f| f.name.as_deref()).collect();

    assert!(
        !names
            .iter()
            .any(|n| n.starts_with("opensnitch_subscription")),
        "unexpected subscription families: {names:?}"
    );
}

#[test]
fn proto_contains_subscription_families_when_some() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactStats::from(&snap);
    let buf = render_prometheus_proto(&cs);
    let fams = decode_proto_families(&buf);
    let names: Vec<_> = fams.iter().filter_map(|f| f.name.as_deref()).collect();

    assert!(
        names.contains(&"opensnitch_subscription_total"),
        "{names:?}"
    );
    assert!(
        names.contains(&"opensnitch_subscription_ready"),
        "{names:?}"
    );
    assert!(
        names.contains(&"opensnitch_subscription_error"),
        "{names:?}"
    );
    assert!(
        names.contains(&"opensnitch_subscription_by_status"),
        "{names:?}"
    );
    assert!(
        names.contains(&"opensnitch_subscription_by_group"),
        "{names:?}"
    );
    assert!(
        names.contains(&"opensnitch_subscription_by_node"),
        "{names:?}"
    );
}

#[test]
fn proto_subscription_total_gauge_value_is_correct() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactStats::from(&snap);
    let buf = render_prometheus_proto(&cs);
    let fams = decode_proto_families(&buf);

    let fam = fams
        .iter()
        .find(|f| f.name.as_deref() == Some("opensnitch_subscription_total"))
        .expect("opensnitch_subscription_total family missing");
    let val = fam.metric[0].gauge.as_ref().unwrap().value.unwrap();
    assert_eq!(val as u64, 5);
}

#[test]
fn proto_by_status_family_has_correct_label_values() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactStats::from(&snap);
    let buf = render_prometheus_proto(&cs);
    let fams = decode_proto_families(&buf);

    let fam = fams
        .iter()
        .find(|f| f.name.as_deref() == Some("opensnitch_subscription_by_status"))
        .expect("opensnitch_subscription_by_status family missing");

    let mut status_vals: HashMap<&str, u64> = HashMap::new();
    for m in &fam.metric {
        let lv = m
            .label
            .iter()
            .find(|l| l.name.as_deref() == Some("status"))
            .and_then(|l| l.value.as_deref())
            .unwrap_or("");
        let gv = m.gauge.as_ref().and_then(|g| g.value).unwrap_or(0.0) as u64;
        status_vals.insert(lv, gv);
    }
    assert_eq!(
        status_vals.get("ready").copied(),
        Some(4),
        "{status_vals:?}"
    );
    assert_eq!(
        status_vals.get("error").copied(),
        Some(1),
        "{status_vals:?}"
    );
}

#[test]
fn text_subscription_rule_info_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactStats::from(&snap);
    let out = render_prometheus_text(&cs);

    assert!(
        out.contains(
            r#"opensnitch_subscription_rule_info{rule="block-ads",subscription="easylist"} 1"#
        ),
        "block-ads rule_info missing\n{out}"
    );
    assert!(
        out.contains(r#"opensnitch_subscription_rule_info{rule="block-malware",subscription="malware-domains"} 1"#),
        "block-malware rule_info missing\n{out}"
    );
    // block-combined references two subscriptions (N:N)
    assert!(
        out.contains(
            r#"opensnitch_subscription_rule_info{rule="block-combined",subscription="easylist"} 1"#
        ),
        "block-combined×easylist rule_info missing\n{out}"
    );
    assert!(
        out.contains(r#"opensnitch_subscription_rule_info{rule="block-combined",subscription="malware-domains"} 1"#),
        "block-combined×malware-domains rule_info missing\n{out}"
    );
}

#[test]
fn text_subscription_rule_info_absent_when_empty() {
    let mut snap = make_snapshot();
    let mut sub = make_sub_stats();
    sub.rule_subscriptions.clear();
    snap.subscription_stats = Some(sub);
    let cs = CompactStats::from(&snap);
    let out = render_prometheus_text(&cs);

    assert!(
        !out.contains("opensnitch_subscription_rule_info"),
        "rule_info should be absent when map is empty\n{out}"
    );
}

#[test]
fn openmetrics_subscription_rule_info_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactStats::from(&snap);
    let out = render_openmetrics_text(&cs);

    assert!(
        out.contains(
            r#"opensnitch_subscription_rule_info{rule="block-ads",subscription="easylist"} 1"#
        ),
        "rule_info missing in openmetrics\n{out}"
    );
}

#[test]
fn proto_subscription_rule_info_family_present() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactStats::from(&snap);
    let buf = render_prometheus_proto(&cs);
    let fams = decode_proto_families(&buf);
    let names: Vec<_> = fams.iter().filter_map(|f| f.name.as_deref()).collect();

    assert!(
        names.contains(&"opensnitch_subscription_rule_info"),
        "{names:?}"
    );
}

#[test]
fn proto_subscription_rule_info_has_two_labels() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactStats::from(&snap);
    let buf = render_prometheus_proto(&cs);
    let fams = decode_proto_families(&buf);

    let fam = fams
        .iter()
        .find(|f| f.name.as_deref() == Some("opensnitch_subscription_rule_info"))
        .expect("opensnitch_subscription_rule_info family missing");

    // make_sub_stats: block-ads×1 + block-combined×2 + block-malware×1 = 4 metric rows (N:N)
    assert_eq!(
        fam.metric.len(),
        4,
        "expected 4 rule_info metrics (block-combined has 2)"
    );
    for m in &fam.metric {
        let rule = m
            .label
            .iter()
            .find(|l| l.name.as_deref() == Some("rule"))
            .and_then(|l| l.value.as_deref())
            .unwrap_or("");
        let sub = m
            .label
            .iter()
            .find(|l| l.name.as_deref() == Some("subscription"))
            .and_then(|l| l.value.as_deref())
            .unwrap_or("");
        assert!(!rule.is_empty(), "rule label missing");
        assert!(!sub.is_empty(), "subscription label missing");
        assert_eq!(
            m.gauge.as_ref().and_then(|g| g.value),
            Some(1.0),
            "value must be 1"
        );
    }
}

#[test]
fn proto_subscription_rule_info_absent_when_empty() {
    let mut snap = make_snapshot();
    let mut sub = make_sub_stats();
    sub.rule_subscriptions.clear();
    snap.subscription_stats = Some(sub);
    let cs = CompactStats::from(&snap);
    let buf = render_prometheus_proto(&cs);
    let fams = decode_proto_families(&buf);
    let names: Vec<_> = fams.iter().filter_map(|f| f.name.as_deref()).collect();

    assert!(
        !names.contains(&"opensnitch_subscription_rule_info"),
        "rule_info family should be absent when map is empty: {names:?}"
    );
}

#[test]
fn proto_connections_counter_value_is_correct() {
    let cs = CompactStats::from(&make_snapshot());
    let buf = render_prometheus_proto(&cs);
    let fams = decode_proto_families(&buf);

    let fam = fams
        .iter()
        .find(|f| f.name.as_deref() == Some("opensnitch_connections_total"))
        .expect("opensnitch_connections_total missing");
    let val = fam.metric[0].counter.as_ref().unwrap().value.unwrap();
    assert_eq!(val as u64, 400);
}

// ---------------------------------------------------------------------------
// Content negotiation
// ---------------------------------------------------------------------------

#[test]
fn negotiate_none_defaults_to_text() {
    assert!(matches!(negotiate_format(None), ResponseFormat::Text));
}

#[test]
fn negotiate_openmetrics_beats_plain_text() {
    let accept = "application/openmetrics-text; version=1.0.0; charset=utf-8, text/plain;q=0.9";
    assert!(matches!(
        negotiate_format(Some(accept)),
        ResponseFormat::OpenMetrics
    ));
}

#[test]
fn negotiate_proto_wins_when_explicitly_requested() {
    let accept = "application/vnd.google.protobuf; \
                  proto=io.prometheus.client.MetricFamily; encoding=delimited;q=0.9, \
                  text/plain;q=0.1";
    assert!(matches!(
        negotiate_format(Some(accept)),
        ResponseFormat::Proto
    ));
}

#[test]
fn negotiate_text_fallback_for_unknown_mime() {
    let accept = "application/json, application/xml";
    assert!(matches!(
        negotiate_format(Some(accept)),
        ResponseFormat::Text
    ));
}

#[test]
fn negotiate_proto_requires_all_required_params() {
    // Missing proto= param → must NOT resolve to Proto.
    let accept = "application/vnd.google.protobuf; encoding=delimited";
    assert!(!matches!(
        negotiate_format(Some(accept)),
        ResponseFormat::Proto
    ));
}

#[test]
fn negotiate_empty_accept_string_defaults_to_text() {
    assert!(matches!(negotiate_format(Some("")), ResponseFormat::Text));
}

#[test]
fn negotiate_wildcard_accept_defaults_to_text() {
    assert!(matches!(
        negotiate_format(Some("*/*")),
        ResponseFormat::Text
    ));
}

// ---------------------------------------------------------------------------
// Gzip helper
// ---------------------------------------------------------------------------

#[test]
fn gzip_compress_is_smaller_and_roundtrips() {
    use flate2::read::GzDecoder;
    use std::io::Read;

    // Highly compressible payload.
    let data: Vec<u8> = b"opensnitch_connections_total 500\n"
        .iter()
        .cycle()
        .take(2000)
        .copied()
        .collect();

    let compressed = gzip_compress(&data).expect("compression should succeed");
    assert!(
        compressed.len() < data.len(),
        "compressed ({}) must be smaller than original ({})",
        compressed.len(),
        data.len()
    );

    let mut gz = GzDecoder::new(compressed.as_slice());
    let mut decompressed = Vec::new();
    gz.read_to_end(&mut decompressed)
        .expect("decompression failed");
    assert_eq!(decompressed, data, "round-trip mismatch");
}

// ---------------------------------------------------------------------------
// HTTP endpoint integration tests
// ---------------------------------------------------------------------------

/// Bind :0, release the port, then return the address so `spawn_metrics_server`
/// can rebind to the same port.  Usual test-time race window; acceptable here.
fn reserve_port() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}

/// Poll until TCP connect succeeds or timeout.
async fn wait_ready(addr: std::net::SocketAddr) {
    for _ in 0..60 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn http_endpoint_returns_prometheus_text_by_default() {
    let exporter = PrometheusStatsExporter::new();
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    exporter.export_snapshot(&snap);

    let addr = reserve_port();
    let shutdown = CancellationToken::new();
    let _handle = exporter
        .clone()
        .spawn_metrics_server(addr, shutdown.clone());
    wait_ready(addr).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let ct = resp.headers()["content-type"].to_str().unwrap().to_string();
    assert!(ct.contains("text/plain"), "content-type: {ct}");

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("opensnitch_connections_total 400"),
        "connections\n{body}"
    );
    assert!(
        body.contains("opensnitch_subscription_total 5"),
        "sub_total\n{body}"
    );
    assert!(
        body.contains("opensnitch_subscription_by_status{status=\"ready\"} 4"),
        "by_status\n{body}"
    );

    shutdown.cancel();
}

#[tokio::test]
async fn http_endpoint_returns_openmetrics_on_accept_header() {
    let exporter = PrometheusStatsExporter::new();
    exporter.export_snapshot(&make_snapshot());

    let addr = reserve_port();
    let shutdown = CancellationToken::new();
    let _handle = exporter
        .clone()
        .spawn_metrics_server(addr, shutdown.clone());
    wait_ready(addr).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .header(
            "Accept",
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let ct = resp.headers()["content-type"].to_str().unwrap().to_string();
    assert!(ct.contains("openmetrics-text"), "content-type: {ct}");
    let body = resp.text().await.unwrap();
    assert!(body.ends_with("# EOF\n"), "expected # EOF\n{body}");

    shutdown.cancel();
}

#[tokio::test]
async fn http_endpoint_returns_proto_on_accept_header() {
    let exporter = PrometheusStatsExporter::new();
    exporter.export_snapshot(&make_snapshot());

    let addr = reserve_port();
    let shutdown = CancellationToken::new();
    let _handle = exporter
        .clone()
        .spawn_metrics_server(addr, shutdown.clone());
    wait_ready(addr).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .header(
            "Accept",
            "application/vnd.google.protobuf; \
             proto=io.prometheus.client.MetricFamily; encoding=delimited",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let ct = resp.headers()["content-type"].to_str().unwrap().to_string();
    assert!(
        ct.contains("application/vnd.google.protobuf"),
        "content-type: {ct}"
    );

    let body = resp.bytes().await.unwrap();
    let fams = decode_proto_families(&body);
    let names: Vec<_> = fams.iter().filter_map(|f| f.name.as_deref()).collect();
    assert!(names.contains(&"opensnitch_connections_total"), "{names:?}");

    shutdown.cancel();
}

#[tokio::test]
async fn http_endpoint_returns_404_for_unknown_paths() {
    let exporter = PrometheusStatsExporter::new();

    let addr = reserve_port();
    let shutdown = CancellationToken::new();
    let _handle = exporter
        .clone()
        .spawn_metrics_server(addr, shutdown.clone());
    wait_ready(addr).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 404);

    shutdown.cancel();
}

#[tokio::test]
async fn http_endpoint_empty_body_when_no_snapshot_yet() {
    // Exporter created but no `export_snapshot` called yet.
    let exporter = PrometheusStatsExporter::new();

    let addr = reserve_port();
    let shutdown = CancellationToken::new();
    let _handle = exporter
        .clone()
        .spawn_metrics_server(addr, shutdown.clone());
    wait_ready(addr).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.is_empty(),
        "expected empty body before first snapshot, got:\n{body}"
    );

    shutdown.cancel();
}
