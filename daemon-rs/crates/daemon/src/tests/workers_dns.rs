use crate::workers::dns_worker::{decode_varlink_ip, extract_dns_events_from_varlink};
use serde_json::json;

#[test]
fn decode_varlink_ip_supports_ipv4_and_ipv6() {
    let v4 = vec![json!(127), json!(0), json!(0), json!(1)];
    assert_eq!(decode_varlink_ip(&v4), Some("127.0.0.1".to_string()));

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
    assert_eq!(decode_varlink_ip(&v6), Some("::1".to_string()));
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

    let events = extract_dns_events_from_varlink(&msg);
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0],
        ("1.1.1.1".to_string(), "example.com".to_string())
    );
    assert_eq!(
        events[1],
        ("example.com".to_string(), "www.example.com".to_string())
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

    let events = extract_dns_events_from_varlink(&msg);
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

    let events = extract_dns_events_from_varlink(&msg);
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

    let events = extract_dns_events_from_varlink(&msg);
    assert_eq!(events.len(), 3);
    assert_eq!(
        events[0],
        ("8.8.8.8".to_string(), "example.com".to_string())
    );
    assert_eq!(
        events[1],
        ("::1".to_string(), "ipv6.example.com".to_string())
    );
    assert_eq!(
        events[2],
        ("example.com".to_string(), "www.example.com".to_string())
    );
}
