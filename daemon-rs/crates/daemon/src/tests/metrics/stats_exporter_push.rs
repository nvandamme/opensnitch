//! Correctness tests for the push-style stats exporter adapter.
//!
//! This module is declared as a child of `stats_exporter_push` (via `#[path]`
//! in the adapter file), giving it direct access to all private render helpers
//! and types without public probe wrappers.
//!
//! Test surface:
//! - `render_prometheus_text`       — Prometheus text 0.0.4 body (push-gateway)
//! - `render_prometheus_proto_push` — length-delimited protobuf push body
//! - `render_influxdb_line_protocol`— InfluxDB line protocol correctness
//! - `build_endpoint`               — URL construction (push-gateway / InfluxDB)
//! - `post_snapshot` (via mock)     — HTTP POST body/content-type verification
//!   for each format (pushgateway text, pushgateway proto, influxdb)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use opensnitch_proto::pb;
use tokio::sync::Mutex;

use crate::models::metrics_snapshot::MetricsSnapshot;
use crate::models::prometheus_wire as prom_wire;

// Pull all private items from the parent push adapter module.
use super::{
    CompactSnapshot, PushConfig, PushFormat, build_endpoint, post_snapshot,
    render_influxdb_line_protocol, render_prometheus_proto_push, render_prometheus_text,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn make_snapshot() -> MetricsSnapshot {
    let mut by_proto = HashMap::new();
    by_proto.insert("tcp".to_string(), 150u64);

    let mut by_rule = HashMap::new();
    by_rule.insert("block-ads".to_string(), 5u64);

    MetricsSnapshot {
        stats: pb::Statistics {
            rules: 5,
            uptime: 1800,
            dns_responses: 80,
            connections: 200,
            ignored: 2,
            accepted: 190,
            dropped: 8,
            rule_hits: 120,
            rule_misses: 20,
            by_proto,
            ..Default::default()
        },
        subscription_stats: None,
        by_rule,
    }
}

fn make_sub_stats() -> pb::SubscriptionStatistics {
    let mut by_status = HashMap::new();
    by_status.insert("ready".to_string(), 2u64);
    by_status.insert("error".to_string(), 1u64);

    let mut by_group = HashMap::new();
    by_group.insert("ads".to_string(), 1u64);
    by_group.insert("malware".to_string(), 2u64);

    let mut by_node = HashMap::new();
    by_node.insert("primary".to_string(), 3u64);

    // block-multi references two subscriptions (N:N)
    let rule_subscriptions = vec![
        pb::RuleSubscriptionEntry {
            rule: "block-ads".to_string(),
            subscriptions: vec!["easylist".to_string()],
        },
        pb::RuleSubscriptionEntry {
            rule: "block-multi".to_string(),
            subscriptions: vec!["easylist".to_string(), "malware-list".to_string()],
        },
    ];

    pb::SubscriptionStatistics {
        total: 3,
        ready: 2,
        error: 1,
        refresh_count: 50,
        refresh_errors: 3,
        by_status,
        by_group,
        by_node,
        events: vec![],
        rule_subscriptions,
    }
}

fn pushgateway_config(url: &str) -> PushConfig {
    PushConfig {
        url: url.to_string(),
        format: PushFormat::Pushgateway,
        job: "opensnitchd".to_string(),
        token: None,
        gzip: false,
        bucket: "opensnitch".to_string(),
        org: String::new(),
    }
}

fn influx_config(url: &str) -> PushConfig {
    PushConfig {
        url: url.to_string(),
        format: PushFormat::InfluxDb,
        job: "opensnitchd".to_string(),
        token: None,
        gzip: false,
        bucket: "opensnitch".to_string(),
        org: "myorg".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Prometheus text renderer (push variant)
// ---------------------------------------------------------------------------

#[test]
fn push_text_scalars_correct() {
    let cs = CompactSnapshot::from(&make_snapshot());
    let out = render_prometheus_text(&cs);

    assert!(out.contains("opensnitch_connections_total 200\n"), "{out}");
    assert!(out.contains("opensnitch_accepted_total 190\n"), "{out}");
    assert!(out.contains("opensnitch_dropped_total 8\n"), "{out}");
    assert!(out.contains("opensnitch_dns_responses_total 80\n"), "{out}");
    assert!(out.contains("opensnitch_rule_hits_total 120\n"), "{out}");
    assert!(out.contains("opensnitch_rule_misses_total 20\n"), "{out}");
    assert!(out.contains("opensnitch_rules 5\n"), "{out}");
    assert!(out.contains("opensnitch_uptime_seconds 1800\n"), "{out}");
}

#[test]
fn push_text_breakdown_maps_emitted() {
    let cs = CompactSnapshot::from(&make_snapshot());
    let out = render_prometheus_text(&cs);

    assert!(
        out.contains("opensnitch_connections_by_proto{proto=\"tcp\"} 150"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_rule_hits_by_rule{rule=\"block-ads\"} 5"),
        "{out}"
    );
}

#[test]
fn push_text_subscription_gauges_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let out = render_prometheus_text(&cs);

    assert!(out.contains("opensnitch_subscription_total 3\n"), "{out}");
    assert!(out.contains("opensnitch_subscription_ready 2\n"), "{out}");
    assert!(out.contains("opensnitch_subscription_error 1\n"), "{out}");
    assert!(
        out.contains("opensnitch_subscription_refresh_count 50\n"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_refresh_errors 3\n"),
        "{out}"
    );
}

#[test]
fn push_text_subscription_breakdowns_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let out = render_prometheus_text(&cs);

    assert!(
        out.contains("opensnitch_subscription_by_status{status=\"ready\"} 2"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_by_status{status=\"error\"} 1"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_by_group{group=\"ads\"} 1"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_by_group{group=\"malware\"} 2"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_by_node{node=\"primary\"} 3"),
        "{out}"
    );
}

#[test]
fn push_text_no_subscription_when_none() {
    let cs = CompactSnapshot::from(&make_snapshot());
    let out = render_prometheus_text(&cs);

    assert!(
        !out.contains("opensnitch_subscription"),
        "unexpected sub lines\n{out}"
    );
}

// ---------------------------------------------------------------------------
// InfluxDB line protocol
// ---------------------------------------------------------------------------

#[test]
fn influx_opensnitch_stats_line_has_all_fields() {
    let cs = CompactSnapshot::from(&make_snapshot());
    let out = render_influxdb_line_protocol(&cs);

    let stats_line = out
        .lines()
        .find(|l| l.starts_with("opensnitch_stats "))
        .expect("opensnitch_stats measurement missing");

    assert!(stats_line.contains("rules=5i"), "{stats_line}");
    assert!(stats_line.contains("uptime=1800i"), "{stats_line}");
    assert!(stats_line.contains("connections=200i"), "{stats_line}");
    assert!(stats_line.contains("accepted=190i"), "{stats_line}");
    assert!(stats_line.contains("dropped=8i"), "{stats_line}");
    assert!(stats_line.contains("dns_responses=80i"), "{stats_line}");
    assert!(stats_line.contains("ignored=2i"), "{stats_line}");
    assert!(stats_line.contains("rule_hits=120i"), "{stats_line}");
    assert!(stats_line.contains("rule_misses=20i"), "{stats_line}");
}

#[test]
fn influx_subscription_by_status_lines_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let out = render_influxdb_line_protocol(&cs);

    assert!(
        out.contains("opensnitch_subscription_by_status,status=ready count=2i"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_by_status,status=error count=1i"),
        "{out}"
    );
}

#[test]
fn influx_subscription_by_group_lines_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let out = render_influxdb_line_protocol(&cs);

    assert!(
        out.contains("opensnitch_subscription_by_group,group=ads count=1i"),
        "{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_by_group,group=malware count=2i"),
        "{out}"
    );
}

#[test]
fn influx_subscription_by_node_lines_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let out = render_influxdb_line_protocol(&cs);

    assert!(
        out.contains("opensnitch_subscription_by_node,node=primary count=3i"),
        "{out}"
    );
}

#[test]
fn influx_no_subscription_lines_when_none() {
    let cs = CompactSnapshot::from(&make_snapshot());
    let out = render_influxdb_line_protocol(&cs);

    assert!(
        !out.contains("opensnitch_subscription_by_"),
        "unexpected sub measurement lines\n{out}"
    );
}

#[test]
fn influx_by_proto_breakdown_present() {
    let cs = CompactSnapshot::from(&make_snapshot());
    let out = render_influxdb_line_protocol(&cs);

    assert!(
        out.contains("opensnitch_by_proto,proto=tcp connections=150i"),
        "{out}"
    );
}

#[test]
fn influx_by_rule_breakdown_emitted() {
    let cs = CompactSnapshot::from(&make_snapshot());
    let out = render_influxdb_line_protocol(&cs);

    assert!(
        out.contains("opensnitch_by_rule,rule=block-ads connections=5i"),
        "{out}"
    );
}

#[test]
fn influx_tag_value_escaping_comma_space_equals() {
    let mut snap = make_snapshot();
    snap.stats.by_host.insert("host,a b=c".to_string(), 1u64);
    let cs = CompactSnapshot::from(&snap);
    let out = render_influxdb_line_protocol(&cs);

    // InfluxDB LP: , → \,   space → \ (escaped space)   = → \=
    assert!(
        out.contains(r"host\,a\ b\=c"),
        "escaped tag value missing\n{out}"
    );
}

#[test]
fn influx_lines_end_with_unix_timestamp() {
    let cs = CompactSnapshot::from(&make_snapshot());
    let out = render_influxdb_line_protocol(&cs);

    // Every measurement line ends with a numeric timestamp.
    for line in out.lines() {
        let last = line.rsplit(' ').next().unwrap_or("");
        assert!(
            last.chars().all(|c| c.is_ascii_digit()),
            "line missing timestamp: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// Prometheus protobuf push renderer
// ---------------------------------------------------------------------------

fn decode_proto_families_push(mut buf: &[u8]) -> Vec<prom_wire::MetricFamily> {
    use prost::Message as _;

    let mut fams = Vec::new();
    while !buf.is_empty() {
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
        if let Ok(fam) = prom_wire::MetricFamily::decode(&buf[..len]) {
            fams.push(fam);
        }
        buf = &buf[len..];
    }
    fams
}

#[test]
fn proto_push_contains_scalar_families() {
    let cs = CompactSnapshot::from(&make_snapshot());
    let buf = render_prometheus_proto_push(&cs);
    let fams = decode_proto_families_push(&buf);
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
fn proto_push_no_subscription_families_when_none() {
    let cs = CompactSnapshot::from(&make_snapshot());
    let buf = render_prometheus_proto_push(&cs);
    let fams = decode_proto_families_push(&buf);
    let names: Vec<_> = fams.iter().filter_map(|f| f.name.as_deref()).collect();

    assert!(
        !names
            .iter()
            .any(|n| n.starts_with("opensnitch_subscription")),
        "unexpected subscription families: {names:?}"
    );
}

#[test]
fn proto_push_contains_subscription_families_when_some() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let buf = render_prometheus_proto_push(&cs);
    let fams = decode_proto_families_push(&buf);
    let names: Vec<_> = fams.iter().filter_map(|f| f.name.as_deref()).collect();

    assert!(
        names.contains(&"opensnitch_subscription_total"),
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
}

#[test]
fn proto_push_subscription_total_value_correct() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let buf = render_prometheus_proto_push(&cs);
    let fams = decode_proto_families_push(&buf);

    let fam = fams
        .iter()
        .find(|f| f.name.as_deref() == Some("opensnitch_subscription_total"))
        .expect("opensnitch_subscription_total not found");
    let val = fam.metric[0].gauge.as_ref().unwrap().value.unwrap();
    assert_eq!(val as u64, 3);
}

#[test]
fn push_text_subscription_rule_info_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let out = render_prometheus_text(&cs);

    assert!(
        out.contains(
            r#"opensnitch_subscription_rule_info{rule="block-ads",subscription="easylist"} 1"#
        ),
        "rule_info line missing in push text\n{out}"
    );
    // block-multi references two subscriptions (N:N)
    assert!(
        out.contains(
            r#"opensnitch_subscription_rule_info{rule="block-multi",subscription="easylist"} 1"#
        ),
        "block-multi×easylist rule_info missing\n{out}"
    );
    assert!(
        out.contains(
            r#"opensnitch_subscription_rule_info{rule="block-multi",subscription="malware-list"} 1"#
        ),
        "block-multi×malware-list rule_info missing\n{out}"
    );
}

#[test]
fn push_text_subscription_rule_info_absent_when_empty() {
    let mut snap = make_snapshot();
    let mut sub = make_sub_stats();
    sub.rule_subscriptions.clear();
    snap.subscription_stats = Some(sub);
    let cs = CompactSnapshot::from(&snap);
    let out = render_prometheus_text(&cs);

    assert!(
        !out.contains("opensnitch_subscription_rule_info"),
        "rule_info should be absent when map is empty\n{out}"
    );
}

#[test]
fn proto_push_subscription_rule_info_family_present() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let buf = render_prometheus_proto_push(&cs);
    let fams = decode_proto_families_push(&buf);
    let names: Vec<_> = fams.iter().filter_map(|f| f.name.as_deref()).collect();

    assert!(
        names.contains(&"opensnitch_subscription_rule_info"),
        "{names:?}"
    );
}

#[test]
fn proto_push_subscription_rule_info_has_two_labels() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let buf = render_prometheus_proto_push(&cs);
    let fams = decode_proto_families_push(&buf);

    let fam = fams
        .iter()
        .find(|f| f.name.as_deref() == Some("opensnitch_subscription_rule_info"))
        .expect("opensnitch_subscription_rule_info family missing");

    // make_sub_stats: block-ads×1 + block-multi×2 = 3 metric rows (N:N)
    assert_eq!(fam.metric.len(), 3, "expected 3 rule_info metrics");
    // Verify all metrics have non-empty rule+subscription labels and value 1
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
fn influx_subscription_rule_line_emitted() {
    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);
    let out = render_influxdb_line_protocol(&cs);

    assert!(
        out.contains("opensnitch_subscription_rule,rule=block-ads,subscription=easylist info=1i"),
        "subscription rule line missing in influxdb output\n{out}"
    );
    assert!(
        out.contains("opensnitch_subscription_rule,rule=block-multi,subscription=easylist info=1i"),
        "block-multi×easylist influx line missing\n{out}"
    );
    assert!(
        out.contains(
            "opensnitch_subscription_rule,rule=block-multi,subscription=malware-list info=1i"
        ),
        "block-multi×malware-list influx line missing\n{out}"
    );
}

#[test]
fn influx_subscription_rule_absent_when_empty() {
    let mut snap = make_snapshot();
    let mut sub = make_sub_stats();
    sub.rule_subscriptions.clear();
    snap.subscription_stats = Some(sub);
    let cs = CompactSnapshot::from(&snap);
    let out = render_influxdb_line_protocol(&cs);

    assert!(
        !out.contains("opensnitch_subscription_rule,"),
        "subscription rule lines should be absent when map is empty\n{out}"
    );
}

// ---------------------------------------------------------------------------
// build_endpoint
// ---------------------------------------------------------------------------

#[test]
fn build_endpoint_pushgateway_appends_job_path() {
    let cfg = PushConfig {
        url: "http://pushgateway:9091".to_string(),
        format: PushFormat::Pushgateway,
        job: "myservice".to_string(),
        token: None,
        gzip: false,
        bucket: String::new(),
        org: String::new(),
    };
    assert_eq!(
        build_endpoint(&cfg),
        "http://pushgateway:9091/metrics/job/myservice"
    );
}

#[test]
fn build_endpoint_pushgateway_proto_produces_same_path() {
    let cfg = PushConfig {
        url: "http://pg:9091".to_string(),
        format: PushFormat::PushgatewayProto,
        job: "svc".to_string(),
        token: None,
        gzip: false,
        bucket: String::new(),
        org: String::new(),
    };
    assert_eq!(build_endpoint(&cfg), "http://pg:9091/metrics/job/svc");
}

#[test]
fn build_endpoint_influxdb_no_query_adds_bucket_precision_org() {
    let cfg = influx_config("http://influxdb:8086/api/v2/write");
    let ep = build_endpoint(&cfg);

    assert!(ep.contains("bucket=opensnitch"), "bucket missing from {ep}");
    assert!(ep.contains("precision=s"), "precision missing from {ep}");
    assert!(ep.contains("org=myorg"), "org missing from {ep}");
}

#[test]
fn build_endpoint_influxdb_preserves_existing_bucket_no_duplicate() {
    let mut cfg = influx_config("http://influxdb:8086/write?bucket=custom&org=mine");
    cfg.bucket = "opensnitch".to_string(); // overridden by URL
    let ep = build_endpoint(&cfg);

    assert_eq!(ep.matches("bucket=").count(), 1, "duplicate bucket in {ep}");
    assert!(ep.contains("precision=s"), "precision missing from {ep}");
}

#[test]
fn build_endpoint_influxdb_no_duplicate_precision_when_already_present() {
    let cfg = influx_config("http://influxdb:8086/write?db=opensnitch&precision=ms");
    let ep = build_endpoint(&cfg);

    assert_eq!(
        ep.matches("precision=").count(),
        1,
        "duplicate precision in {ep}"
    );
}

#[test]
fn build_endpoint_trailing_slash_trimmed() {
    let cfg = PushConfig {
        url: "http://pushgateway:9091/".to_string(),
        format: PushFormat::Pushgateway,
        job: "svc".to_string(),
        token: None,
        gzip: false,
        bucket: String::new(),
        org: String::new(),
    };
    let ep = build_endpoint(&cfg);
    // After trimming the trailing slash no double-slash should appear in the *path* portion.
    let path = ep
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    assert!(!path.contains("//"), "double slash in path portion: {ep}");
    assert!(ep.ends_with("/metrics/job/svc"), "{ep}");
}

// ---------------------------------------------------------------------------
// HTTP push integration tests (mock server)
// ---------------------------------------------------------------------------

/// Spawn a hyper HTTP/1.1 server that captures the content-type and raw body
/// of the first received request and responds with 200 OK.  Returns the base
/// URL and an `Arc<Mutex<Option<(content_type, body_bytes)>>>` that is
/// populated once a request arrives.
async fn spawn_capture_server() -> (String, Arc<Mutex<Option<(String, Vec<u8>)>>>) {
    let captured: Arc<Mutex<Option<(String, Vec<u8>)>>> = Arc::new(Mutex::new(None));
    let captured_outer = captured.clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let cap = captured_outer.clone();
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let cap2 = cap.clone();
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<Incoming>| {
                            let cap3 = cap2.clone();
                            async move {
                                let ct = req
                                    .headers()
                                    .get(hyper::header::CONTENT_TYPE)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                let body = req
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(|c| c.to_bytes().to_vec())
                                    .unwrap_or_default();
                                *cap3.lock().await = Some((ct, body));
                                Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                    Bytes::new(),
                                )))
                            }
                        }),
                    )
                    .await;
            });
        }
    });

    (format!("http://{addr}"), captured)
}

#[tokio::test]
async fn push_gateway_posts_prometheus_text_body() {
    let (base_url, captured) = spawn_capture_server().await;
    let config = pushgateway_config(&base_url);
    let endpoint = build_endpoint(&config);

    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);

    let client = reqwest::Client::new();
    post_snapshot(&client, &config, &endpoint, &cs)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let guard = captured.lock().await;
    let (ct, body_bytes) = guard.as_ref().expect("no request captured");
    assert!(ct.contains("text/plain"), "content-type: {ct}");

    let body = std::str::from_utf8(body_bytes).unwrap();
    assert!(
        body.contains("opensnitch_connections_total 200"),
        "connections\n{body}"
    );
    assert!(
        body.contains("opensnitch_subscription_total 3"),
        "sub_total\n{body}"
    );
    assert!(
        body.contains("opensnitch_subscription_by_status{status=\"ready\"} 2"),
        "by_status ready\n{body}"
    );
    assert!(
        body.contains("opensnitch_subscription_by_group{group=\"malware\"} 2"),
        "by_group malware\n{body}"
    );
}

#[tokio::test]
async fn push_gateway_proto_posts_protobuf_body() {
    let (base_url, captured) = spawn_capture_server().await;
    let config = PushConfig {
        url: base_url,
        format: PushFormat::PushgatewayProto,
        job: "opensnitchd".to_string(),
        token: None,
        gzip: false,
        bucket: String::new(),
        org: String::new(),
    };
    let endpoint = build_endpoint(&config);

    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);

    let client = reqwest::Client::new();
    post_snapshot(&client, &config, &endpoint, &cs)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let guard = captured.lock().await;
    let (ct, body_bytes) = guard.as_ref().expect("no request captured");
    assert!(
        ct.contains("application/vnd.google.protobuf"),
        "content-type: {ct}"
    );

    let fams = decode_proto_families_push(body_bytes);
    let names: Vec<_> = fams.iter().filter_map(|f| f.name.as_deref()).collect();
    assert!(names.contains(&"opensnitch_connections_total"), "{names:?}");
    assert!(
        names.contains(&"opensnitch_subscription_total"),
        "{names:?}"
    );
}

#[tokio::test]
async fn influxdb_push_posts_line_protocol_body() {
    let (base_url, captured) = spawn_capture_server().await;
    let config = influx_config(&base_url);
    let endpoint = build_endpoint(&config);

    let mut snap = make_snapshot();
    snap.subscription_stats = Some(make_sub_stats());
    let cs = CompactSnapshot::from(&snap);

    let client = reqwest::Client::new();
    post_snapshot(&client, &config, &endpoint, &cs)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let guard = captured.lock().await;
    let (ct, body_bytes) = guard.as_ref().expect("no request captured");
    assert!(ct.contains("text/plain"), "content-type: {ct}");

    let body = std::str::from_utf8(body_bytes).unwrap();
    assert!(
        body.starts_with("opensnitch_stats "),
        "stats measurement missing\n{body}"
    );
    assert!(
        body.contains("opensnitch_subscription_by_status,status=ready count=2i"),
        "{body}"
    );
    assert!(
        body.contains("opensnitch_subscription_by_group,group=ads count=1i"),
        "{body}"
    );
    assert!(
        body.contains("opensnitch_by_proto,proto=tcp connections=150i"),
        "{body}"
    );
}

#[tokio::test]
async fn push_gateway_bearer_token_sent_in_authorization_header() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let received_auth: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let received_auth_outer = received_auth.clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let cap = received_auth_outer.clone();
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let cap2 = cap.clone();
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<Incoming>| {
                            let cap3 = cap2.clone();
                            async move {
                                let auth = req
                                    .headers()
                                    .get(hyper::header::AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                // consume body so hyper doesn't complain
                                let _ = req.into_body().collect().await;
                                *cap3.lock().await = Some(auth);
                                Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                    Bytes::new(),
                                )))
                            }
                        }),
                    )
                    .await;
            });
        }
    });

    let config = PushConfig {
        url: format!("http://{addr}"),
        format: PushFormat::Pushgateway,
        job: "opensnitchd".to_string(),
        token: Some("secrettoken".to_string()),
        gzip: false,
        bucket: String::new(),
        org: String::new(),
    };
    let endpoint = build_endpoint(&config);
    let cs = CompactSnapshot::from(&make_snapshot());

    let client = reqwest::Client::new();
    post_snapshot(&client, &config, &endpoint, &cs)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let auth = received_auth.lock().await;
    let auth_val = auth.as_deref().unwrap_or("");
    assert_eq!(
        auth_val, "Bearer secrettoken",
        "Authorization header: {auth_val}"
    );
}
