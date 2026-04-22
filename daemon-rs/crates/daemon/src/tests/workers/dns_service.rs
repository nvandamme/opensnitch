use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::{models::dns_payload::DnsAnswerRecord, services::dns::DnsService};

#[tokio::test]
async fn track_skips_loopback_and_self_alias() {
    let service = DnsService::default();

    let _ = service
        .track_answers(DnsAnswerRecord::from_ip(
            "localhost",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ))
        .await;
    let _ = service
        .track_answers(DnsAnswerRecord::from_ip(
            "localhost",
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ))
        .await;
    let _ = service
        .track_alias("example.com".to_string(), "example.com".to_string())
        .await;

    assert!(service.lookup_ip("127.0.0.1".parse().unwrap()).is_none());
    assert!(service.lookup_ip("::1".parse().unwrap()).is_none());
    // non-IP string: no lookup possible, so assert it returns None via a parsed IpAddr that's not in cache
    assert!(service.lookup_ip("0.0.0.0".parse().unwrap()).is_none());
}

#[tokio::test]
async fn lookup_resolves_alias_chain() {
    let service = DnsService::default();
    let _ = service
        .track_answers(DnsAnswerRecord::from_ip(
            "alias.local",
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        ))
        .await;
    let _ = service
        .track_alias("alias.local".to_string(), "final.local".to_string())
        .await;

    assert_eq!(
        service.lookup_ip("1.2.3.4".parse().unwrap()).as_deref(),
        Some("final.local")
    );
}

#[tokio::test]
async fn cache_is_bounded_with_lru_eviction() {
    let service = DnsService::default();
    let cap = DnsService::probe_cache_capacity();

    // Insert 2× capacity to guarantee every shard cycles and oldest items are evicted.
    for idx in 0..(cap * 2) {
        let ip = format!("2001:db8::{idx:x}")
            .parse::<IpAddr>()
            .expect("test IPv6 address should parse");
        let _ = service
            .track_answers(DnsAnswerRecord::from_ip(
                format!("host-{idx}.example.test"),
                ip,
            ))
            .await;
    }

    // Most recently inserted entries are still present.
    let last_idx = cap * 2 - 1;
    let last_ip: IpAddr = format!("2001:db8::{last_idx:x}").parse().unwrap();
    assert_eq!(
        service.lookup_ip(last_ip).as_deref(),
        Some(format!("host-{last_idx}.example.test").as_str())
    );

    // Cache is bounded.
    assert!(service.probe_cache_len().await <= cap);
}

#[tokio::test]
async fn track_answers_accepts_mixed_ip_batches() {
    let service = DnsService::default();
    let record = DnsAnswerRecord::new(
        "mixed.example.test",
        Arc::<[IpAddr]>::from(vec![
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)),
        ]),
    )
    .expect("mixed answer record should not be empty");

    let _ = service.track_answers(record).await;

    assert_eq!(
        service
            .lookup_ip("198.51.100.10".parse().unwrap())
            .as_deref(),
        Some("mixed.example.test")
    );
    assert_eq!(
        service
            .lookup_ip("2001:db8::10".parse().unwrap())
            .as_deref(),
        Some("mixed.example.test")
    );
}

#[tokio::test]
async fn track_answers_reports_truthful_eviction_count() {
    let service = DnsService::default();
    let cap = DnsService::probe_cache_capacity();

    let mut last_eviction = None;
    for idx in 0..(cap * 2) {
        let ip = format!("2001:db8::{idx:x}")
            .parse::<IpAddr>()
            .expect("test IPv6 address should parse");
        let mutation = service
            .track_answers(DnsAnswerRecord::from_ip(
                format!("evict-{idx}.example.test"),
                ip,
            ))
            .await;
        if mutation.evicted > 0 {
            last_eviction = Some(mutation);
            break;
        }
    }

    let mutation = last_eviction.expect("dns cache should eventually evict at capacity");
    assert_eq!(mutation.entries, 1);
    assert!(mutation.evicted >= 1);
}
