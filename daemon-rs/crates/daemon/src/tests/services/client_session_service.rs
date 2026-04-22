use crate::{
    config::DefaultAction,
    services::client::{ClientPrincipal, ClientService, ClientSession},
};

#[test]
fn effective_default_action_switches_with_connectivity() {
    let service = ClientService::default();

    assert!(matches!(
        service.effective_default_action(DefaultAction::Allow),
        DefaultAction::Allow
    ));

    service.set_connected_default_action(DefaultAction::Deny);
    service.set_connected(true);
    assert!(service.is_connected());

    assert!(matches!(
        service.effective_default_action(DefaultAction::Allow),
        DefaultAction::Deny
    ));

    service.set_connected(false);
    assert!(!service.is_connected());
    assert!(matches!(
        service.effective_default_action(DefaultAction::Allow),
        DefaultAction::Allow
    ));
}

#[test]
fn client_service_supports_multiple_sessions() {
    let service = ClientService::default();

    service.upsert_session(ClientSession::for_network_identity(
        "alice",
        DefaultAction::Allow,
    ));
    service.upsert_session(ClientSession::for_network_identity(
        "bob",
        DefaultAction::Deny,
    ));

    assert_eq!(service.connected_sessions().len(), 2);

    // No control session exists, so network identity sessions are selected by id.
    assert!(matches!(
        service.effective_default_action(DefaultAction::Deny),
        DefaultAction::Allow
    ));

    service.set_session_default_action("net:alice", DefaultAction::Deny);
    assert!(matches!(
        service.effective_default_action(DefaultAction::Allow),
        DefaultAction::Deny
    ));

    service.disconnect_session("net:alice");
    assert_eq!(service.connected_sessions().len(), 1);
    assert!(matches!(
        service.effective_default_action(DefaultAction::Allow),
        DefaultAction::Deny
    ));
}

#[test]
fn effective_default_prefers_local_uid_then_network_then_ip() {
    let service = ClientService::default();

    service.upsert_session(ClientSession::for_ip_fallback(
        "192.0.2.1".parse().expect("valid test ip"),
        DefaultAction::Deny,
    ));
    service.upsert_session(ClientSession::for_network_identity(
        "remote-cert-subject",
        DefaultAction::Deny,
    ));
    service.upsert_session(ClientSession::for_unix_abstract_name(
        "opensnitchd-ui",
        DefaultAction::Allow,
    ));

    assert!(matches!(
        service.effective_default_action(DefaultAction::Allow),
        DefaultAction::Allow
    ));

    service.upsert_session(ClientSession::for_local_uid(1000, DefaultAction::Allow));
    assert!(matches!(
        service.effective_default_action(DefaultAction::Deny),
        DefaultAction::Allow
    ));
}

#[test]
fn helper_connectors_tie_session_id_to_owner_identity() {
    let service = ClientService::default();

    service.connect_local_uid_session(1000);
    service.connect_network_identity_session("client-cert-cn=test");
    service.connect_ip_fallback_session("198.51.100.7".parse().expect("valid test ip"));

    let sessions = service.connected_sessions();
    assert!(sessions.iter().any(|session| {
        session.id == "uid:1000" && matches!(session.owner, ClientPrincipal::LocalUid(1000))
    }));
    assert!(sessions.iter().any(|session| {
        session.id == "net:client-cert-cn=test"
            && matches!(
                session.owner,
                ClientPrincipal::NetworkIdentity(ref identity) if identity == "client-cert-cn=test"
            )
    }));
    assert!(sessions.iter().any(|session| {
        session.id == "ip:198.51.100.7"
            && matches!(
                session.owner,
                ClientPrincipal::IpFallback(ip) if ip == "198.51.100.7".parse::<std::net::IpAddr>().expect("valid test ip")
            )
    }));
}
