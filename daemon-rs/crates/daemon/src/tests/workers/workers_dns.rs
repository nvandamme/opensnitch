use crate::{models::dns_payload::DnsPayload, workers::dns::dns_worker::DnsWorkerControl};
use serde_json::json;

#[test]
fn decode_varlink_ip_supports_ipv4_and_ipv6() {
    let v4 = vec![json!(127), json!(0), json!(0), json!(1)];
    assert_eq!(
        DnsWorkerControl::probe_decode_varlink_ip(&v4),
        Some("127.0.0.1".parse().expect("test ip should parse"))
    );

    let v6 = vec![
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(0),
        json!(1),
    ];
    assert_eq!(
        DnsWorkerControl::probe_decode_varlink_ip(&v6),
        Some("::1".parse().expect("test ip should parse"))
    );
}

#[test]
fn extract_dns_events_from_varlink_reads_address_and_cname_answers() {
    let msg = json!({
        "parameters": {
            "state": "success",
            "answer": [
                {
                    "rr": {
                        "key": {"name": "example.com.", "type": 1},
                        "address": [1, 1, 1, 1]
                    }
                },
                {
                    "rr": {
                        "key": {"name": "www.example.com.", "type": 5},
                        "name": "example.com."
                    }
                }
            ]
        }
    });

    let events = DnsWorkerControl::probe_extract_dns_events_from_varlink(&msg);
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0],
        DnsPayload::answer(
            "example.com",
            "1.1.1.1".parse().expect("test ip should parse"),
        )
    );
    assert_eq!(
        events[1],
        DnsPayload::alias("www.example.com", "example.com")
    );
}

#[test]
fn extract_dns_events_from_varlink_ignores_non_success_state() {
    let msg = json!({
        "parameters": {
            "state": "failed",
            "answer": [
                {
                    "rr": {
                        "key": {"name": "example.com.", "type": 1},
                        "address": [1, 1, 1, 1]
                    }
                }
            ]
        }
    });

    let events = DnsWorkerControl::probe_extract_dns_events_from_varlink(&msg);
    assert!(events.is_empty());
}

#[test]
fn extract_dns_events_from_varlink_ignores_missing_state() {
    let msg = json!({
        "parameters": {
            "answer": [
                {
                    "rr": {
                        "key": {"name": "example.com.", "type": 1},
                        "address": [1, 1, 1, 1]
                    }
                }
            ]
        }
    });

    let events = DnsWorkerControl::probe_extract_dns_events_from_varlink(&msg);
    assert!(events.is_empty());
}

#[test]
fn extract_dns_events_from_varlink_filters_non_a_aaaa_cname_records() {
    let msg = json!({
        "parameters": {
            "state": "success",
            "answer": [
                {
                    "rr": {
                        "key": {"name": "example.com.", "type": 1},
                        "address": [8, 8, 8, 8]
                    }
                },
                {
                    "rr": {
                        "key": {"name": "ipv6.example.com.", "type": 28},
                        "address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                    }
                },
                {
                    "rr": {
                        "key": {"name": "www.example.com.", "type": 5},
                        "name": "example.com."
                    }
                },
                {
                    "rr": {
                        "key": {"name": "txt.example.com.", "type": 16},
                        "name": "ignored.example.com."
                    }
                }
            ]
        }
    });

    let events = DnsWorkerControl::probe_extract_dns_events_from_varlink(&msg);
    assert_eq!(events.len(), 3);
    assert_eq!(
        events[0],
        DnsPayload::answer(
            "example.com",
            "8.8.8.8".parse().expect("test ip should parse"),
        )
    );
    assert_eq!(
        events[1],
        DnsPayload::answer(
            "ipv6.example.com",
            "::1".parse().expect("test ip should parse"),
        )
    );
    assert_eq!(
        events[2],
        DnsPayload::alias("www.example.com", "example.com")
    );
}
