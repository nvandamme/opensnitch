use crate::services::dns_service::DnsService;

#[tokio::test]
async fn track_skips_loopback_and_self_alias() {
    let service = DnsService::default();

    service
        .track("127.0.0.1".to_string(), "localhost".to_string())
        .await;
    service
        .track("::1".to_string(), "localhost".to_string())
        .await;
    service
        .track("example.com".to_string(), "example.com".to_string())
        .await;

    assert!(service.lookup("127.0.0.1").await.is_none());
    assert!(service.lookup("::1").await.is_none());
    assert!(service.lookup("example.com").await.is_none());
}

#[tokio::test]
async fn lookup_resolves_alias_chain() {
    let service = DnsService::default();
    service
        .track("1.2.3.4".to_string(), "alias.local".to_string())
        .await;
    service
        .track("alias.local".to_string(), "final.local".to_string())
        .await;

    assert_eq!(
        service.lookup("1.2.3.4").await,
        Some("final.local".to_string())
    );
}

#[tokio::test]
async fn cache_is_bounded_with_lru_eviction() {
    let service = DnsService::default();

    for idx in 0..9000 {
        let ip = format!("2001:db8::{idx:x}");
        service.track(ip, format!("host-{idx}.example.test")).await;
    }

    // Older entries should be evicted once capacity is exceeded.
    assert!(service.lookup("2001:db8::0").await.is_none());

    // Most recently inserted entries should still be present.
    assert_eq!(
        service.lookup("2001:db8::2327").await,
        Some("host-8999.example.test".to_string())
    );

    assert_eq!(
        service.probe_cache_len().await,
        DnsService::probe_cache_capacity()
    );
}
