use crate::config::{ClientAuthType, Config};
use crate::models::firewall_config::FirewallConfig;
use crate::services::client::ClientService;
use crate::services::client::transport::ClientPingRequest;
use std::sync::Arc;
use transport_wire_core::WireRule;

#[test]
fn runtime_identity_returns_non_empty_fields() {
    let (name, version) = ClientService::runtime_identity();
    assert!(!name.trim().is_empty());
    assert!(!version.trim().is_empty());
}

#[tokio::test]
async fn build_subscribe_config_keeps_expected_payload_fields() {
    let mut cfg = Config::default();
    cfg.log_level = 7;
    cfg.raw_json = "{\"DefaultAction\":\"allow\"}".to_string();

    let wire_rules = vec![WireRule {
        name: "allow_dns".to_string(),
        enabled: true,
        action: "allow".to_string(),
        duration: "once".to_string(),
        ..Default::default()
    }];

    let system_firewall = Some(FirewallConfig {
        enabled: true,
        version: 3,
        rules: Vec::new(),
        chains: Vec::new(),
    });

    let subscribe = ClientService::build_subscribe_config_from_snapshots(
        &cfg,
        &wire_rules,
        true,
        &Arc::new(system_firewall),
    );
    let (expected_name, expected_version) = ClientService::runtime_identity();

    assert_eq!(subscribe.id, 1);
    assert_eq!(subscribe.name, expected_name);
    assert_eq!(subscribe.version, expected_version);
    assert!(subscribe.is_firewall_running);
    assert_eq!(subscribe.config, cfg.raw_json);
    assert_eq!(subscribe.log_level, cfg.log_level);
    assert_eq!(subscribe.rules.len(), wire_rules.len());
    assert_eq!(subscribe.rules[0].name, "allow_dns");
    assert_eq!(
        subscribe.system_firewall.as_ref().map(|fw| fw.version),
        Some(3)
    );
}

#[tokio::test]
async fn tls_channel_requires_explicit_trust_material_when_skip_verify_is_false() {
    let mut cfg = Config::default();
    cfg.client_addr = "https://127.0.0.1:50051".to_string();
    cfg.client_auth.auth_type = ClientAuthType::TlsSimple;
    cfg.client_auth.tls_options.skip_verify = false;
    cfg.client_auth.tls_options.ca_cert.clear();
    cfg.client_auth.tls_options.server_cert.clear();

    let result = ClientService::connect_with_config(&cfg).await;
    let msg = match result {
        Ok(_) => panic!("tls-simple without CA/server trust material must fail closed"),
        Err(err) => err.to_string(),
    };
    assert!(msg.contains("requires explicit trust material"), "{msg}");
}

#[tokio::test]
async fn stub_wire_selection_handles_ping_without_grpc_transport() {
    let mut cfg = Config::default();
    cfg.client_addr = "stub://local-ui".to_string();

    let mut client = ClientService::connect_with_config(&cfg)
        .await
        .expect("stub wire should connect without grpc runtime");

    let reply = client
        .ping(ClientPingRequest {
            id: 42,
            stats: None,
        })
        .await
        .expect("stub wire ping should succeed");

    assert_eq!(reply.id, 42);
}

#[tokio::test]
async fn stub_wire_selection_bypasses_grpc_tls_requirements() {
    let mut cfg = Config::default();
    cfg.client_addr = "stub://local-ui".to_string();
    cfg.client_auth.auth_type = ClientAuthType::TlsSimple;
    cfg.client_auth.tls_options.skip_verify = false;
    cfg.client_auth.tls_options.ca_cert.clear();
    cfg.client_auth.tls_options.server_cert.clear();

    let result = ClientService::connect_with_config(&cfg).await;
    assert!(
        result.is_ok(),
        "stub wire selection must bypass grpc tls setup"
    );
}
