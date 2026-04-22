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
