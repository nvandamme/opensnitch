use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, sync::Arc};

use crate::{models::dns_payload::DnsAnswerRecord, services::dns::DnsService};

#[tokio::test]
async fn track_skips_loopback_and_self_alias() {
    let service = DnsService::default();

    service
        .track_answers(DnsAnswerRecord::from_ip(
            "localhost",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ))
        .await;
    service
        .track_answers(DnsAnswerRecord::from_ip(
            "localhost",
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ))
        .await;
    service
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
    service
        .track_answers(DnsAnswerRecord::from_ip(
            "alias.local",
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        ))
        .await;
    service
        .track_alias("alias.local".to_string(), "final.local".to_string())
        .await;

    assert_eq!(
        service.lookup_ip("1.2.3.4".parse().unwrap()),
        Some("final.local".to_string())
    );
}

#[tokio::test]
async fn cache_is_bounded_with_lru_eviction() {
    let service = DnsService::default();

    for idx in 0..9000 {
        let ip = format!("2001:db8::{idx:x}")
            .parse::<IpAddr>()
            .expect("test IPv6 address should parse");
        service
            .track_answers(DnsAnswerRecord::from_ip(
                format!("host-{idx}.example.test"),
                ip,
            ))
            .await;
    }

    // Older entries should be evicted once capacity is exceeded.
    assert!(service.lookup_ip("2001:db8::0".parse().unwrap()).is_none());

    // Most recently inserted entries should still be present.
    assert_eq!(
        service.lookup_ip("2001:db8::2327".parse().unwrap()),
        Some("host-8999.example.test".to_string())
    );

    assert_eq!(
        service.probe_cache_len().await,
        DnsService::probe_cache_capacity()
    );
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

    service.track_answers(record).await;

    assert_eq!(
        service.lookup_ip("198.51.100.10".parse().unwrap()),
        Some("mixed.example.test".to_string())
    );
    assert_eq!(
        service.lookup_ip("2001:db8::10".parse().unwrap()),
        Some("mixed.example.test".to_string())
    );
}
