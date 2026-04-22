use transport_wire_core::{WireCommandAction, WireNotificationReplyCode};

use crate::{
    bus::{BusCaps, BusState},
    commands::client::client::{parse_log_level_data, parse_task_notification_data},
    config::{AuthMode, ClientAuthType, Config},
    flows::notification::{NotificationFlow, notification::NotificationAuthorizationClass},
    models::command_action::CommandAction,
    models::firewall_config::{
        FirewallChain, FirewallConfig, FirewallExpression, FirewallRule, FirewallStatement,
        FirewallStatementValue,
    },
    models::rule_record::{RuleOperator, RuleRecord},
    services::client::{ClientPrincipal, ClientService, NotificationStream},
    services::config::ConfigService,
    services::firewall::FirewallService,
    services::rule::RuleService,
};

#[test]
fn notification_hello_reply_matches_go_stream_handshake() {
    let reply = NotificationFlow::notification_hello_reply();
    assert_eq!(reply.id, 0);
    assert_eq!(reply.code, WireNotificationReplyCode::Ok as i32);
    assert!(reply.data.is_empty());
}

#[test]
fn stream_close_notification_recognizes_action_none_and_lower_values() {
    assert!(NotificationFlow::is_stream_close_notification(
        WireCommandAction::None as i32
    ));
    assert!(NotificationFlow::is_stream_close_notification(-1));
    assert!(!NotificationFlow::is_stream_close_notification(
        WireCommandAction::EnableInterception as i32
    ));
}

#[test]
fn session_binding_prefers_ip_owner_for_numeric_endpoints() {
    let cfg = Config::default();
    let binding =
        NotificationFlow::session_binding_from_client_addr("http://127.0.0.1:50051", &cfg);
    assert_eq!(binding.id, "ip:127.0.0.1");
    assert!(matches!(
        binding.owner,
        ClientPrincipal::IpFallback(ip) if ip == "127.0.0.1".parse::<std::net::IpAddr>().expect("valid test ip")
    ));
}

#[test]
fn session_binding_uses_network_identity_for_named_hosts() {
    let cfg = Config::default();
    let binding =
        NotificationFlow::session_binding_from_client_addr("https://ui.example.test:50051", &cfg);
    assert_eq!(binding.id, "net:ui.example.test");
    assert!(matches!(
        binding.owner,
        ClientPrincipal::NetworkIdentity(ref identity) if identity == "ui.example.test"
    ));
}

#[test]
fn session_binding_uses_live_tls_identity_for_remote_principal_resolution() {
    use crate::config::{LocalPrincipal, RemotePrincipalBinding};
    use crate::services::client::transport::CapturedServerCertIdentity;

    let mut cfg = Config::default();
    cfg.remote_principal_bindings = Some(vec![RemotePrincipalBinding {
        name: "ui-live-cert".to_string(),
        cert_fingerprint: Some("abc123live".to_string()),
        cert_subject: None,
        cert_san: None,
        local_principal: LocalPrincipal {
            uid: 1000,
            gid: 100,
        },
        capabilities: vec!["config.write".to_string()],
    }]);

    let live_identity = CapturedServerCertIdentity {
        fingerprint_sha256: Some("ABC123LIVE".to_string()),
        subject: Some("CN=live-ui".to_string()),
        san_dns: Some("ui.example.test".to_string()),
    };

    let binding = NotificationFlow::session_binding_from_client_addr_and_server_identity(
        "https://ui.example.test:50051",
        &cfg,
        Some(&live_identity),
    );

    assert!(matches!(
        binding.owner,
        ClientPrincipal::RemoteCert { ref binding_name, mapped_uid } if binding_name == "ui-live-cert" && mapped_uid == 1000
    ));
    assert!(binding.has_capability("config.write"));
}

#[test]
fn session_binding_does_not_fallback_to_configured_cert_binding_when_live_identity_misses() {
    use crate::config::{LocalPrincipal, RemotePrincipalBinding};
    use crate::services::client::transport::CapturedServerCertIdentity;

    let mut cfg = Config::default();
    cfg.remote_principal_bindings = Some(vec![RemotePrincipalBinding {
        name: "ui-live-cert".to_string(),
        cert_fingerprint: Some("abc123live".to_string()),
        cert_subject: None,
        cert_san: None,
        local_principal: LocalPrincipal {
            uid: 1000,
            gid: 100,
        },
        capabilities: vec!["config.write".to_string()],
    }]);

    let live_identity = CapturedServerCertIdentity {
        fingerprint_sha256: Some("different-fingerprint".to_string()),
        subject: Some("CN=other-ui".to_string()),
        san_dns: Some("ui.example.test".to_string()),
    };

    let binding = NotificationFlow::session_binding_from_client_addr_and_server_identity(
        "https://ui.example.test:50051",
        &cfg,
        Some(&live_identity),
    );

    assert!(matches!(
        binding.owner,
        ClientPrincipal::NetworkIdentity(ref identity) if identity == "ui.example.test"
    ));
}

#[test]
fn session_binding_falls_back_to_unix_abstract_identity_when_uid_unavailable() {
    let cfg = Config::default();
    let binding =
        NotificationFlow::session_binding_from_client_addr("unix-abstract:opensnitchd-ui", &cfg);
    assert_eq!(binding.id, "abs:opensnitchd-ui");
    assert!(matches!(
        binding.owner,
        ClientPrincipal::UnixAbstractName(ref name) if name == "opensnitchd-ui"
    ));
}

#[test]
fn session_binding_falls_back_to_unix_path_identity_when_uid_unavailable() {
    let cfg = Config::default();
    let binding = NotificationFlow::session_binding_from_client_addr(
        "unix:/tmp/opensnitch-missing.sock",
        &cfg,
    );
    assert_eq!(binding.id, "net:unix:/tmp/opensnitch-missing.sock");
    assert!(matches!(
        binding.owner,
        ClientPrincipal::NetworkIdentity(ref identity) if identity == "unix:/tmp/opensnitch-missing.sock"
    ));
}

#[cfg(unix)]
#[test]
fn session_binding_extracts_local_uid_for_live_unix_path_listener() {
    use std::os::unix::net::UnixListener;

    let socket_path = std::env::temp_dir().join(format!(
        "opensnitch-notification-flow-{}-{}.sock",
        std::process::id(),
        crate::utils::time_nonce::unix_epoch_nanos()
    ));
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).expect("bind unix listener");
    let cfg = Config::default();
    let binding = NotificationFlow::session_binding_from_client_addr(
        &format!("unix:{}", socket_path.display()),
        &cfg,
    );

    let expected_uid = nix::unistd::Uid::current().as_raw();
    assert_eq!(binding.id, format!("uid:{expected_uid}"));
    assert!(matches!(
        binding.owner,
        ClientPrincipal::LocalUid(uid) if uid == expected_uid
    ));

    drop(listener);
    let _ = std::fs::remove_file(&socket_path);
}

#[cfg(unix)]
#[test]
fn session_binding_extracts_local_uid_for_live_unix_abstract_listener() {
    use std::os::fd::AsRawFd;

    let abstract_name = format!(
        "opensnitch-notification-flow-{}-{}",
        std::process::id(),
        crate::utils::time_nonce::unix_epoch_nanos()
    );

    let listener_fd = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        None,
    )
    .expect("create unix abstract listener socket");

    let listener_addr = nix::sys::socket::UnixAddr::new_abstract(abstract_name.as_bytes())
        .expect("create unix abstract addr");
    nix::sys::socket::bind(listener_fd.as_raw_fd(), &listener_addr)
        .expect("bind unix abstract listener");
    nix::sys::socket::listen(
        &listener_fd,
        nix::sys::socket::Backlog::new(8).expect("valid backlog"),
    )
    .expect("listen unix abstract listener");

    let cfg = Config::default();
    let binding = NotificationFlow::session_binding_from_client_addr(
        &format!("unix-abstract:{abstract_name}"),
        &cfg,
    );

    let expected_uid = nix::unistd::Uid::current().as_raw();
    assert_eq!(binding.id, format!("uid:{expected_uid}"));
    assert!(matches!(
        binding.owner,
        ClientPrincipal::LocalUid(uid) if uid == expected_uid
    ));
}

#[cfg(unix)]
#[test]
fn local_unix_principal_check_is_not_enforced_when_allowlist_missing() {
    use std::os::unix::net::UnixListener;

    let socket_path = std::env::temp_dir().join(format!(
        "opensnitch-notification-flow-allowlist-missing-{}-{}.sock",
        std::process::id(),
        crate::utils::time_nonce::unix_epoch_nanos()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let _listener = UnixListener::bind(&socket_path).expect("bind unix listener");

    let mut cfg = Config::default();
    cfg.client_addr = format!("unix:{}", socket_path.display());
    cfg.local_control_allowed_principals = None;

    assert!(NotificationFlow::local_peer_principal_allowed(&cfg));

    let _ = std::fs::remove_file(&socket_path);
}

#[cfg(unix)]
#[test]
fn local_unix_principal_check_defaults_to_root_only_in_local_only_mode_without_policy() {
    use std::os::unix::net::UnixListener;

    let socket_path = std::env::temp_dir().join(format!(
        "opensnitch-notification-flow-local-only-root-default-{}-{}.sock",
        std::process::id(),
        crate::utils::time_nonce::unix_epoch_nanos()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let _listener = UnixListener::bind(&socket_path).expect("bind unix listener");

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = format!("unix:{}", socket_path.display());
    cfg.local_control_allowed_principals = None;
    cfg.local_control_allowed_group_gids = None;

    assert_eq!(
        NotificationFlow::local_peer_principal_allowed(&cfg),
        nix::unistd::Uid::current().is_root()
    );

    let _ = std::fs::remove_file(&socket_path);
}

#[cfg(unix)]
#[test]
fn local_unix_principal_check_enforced_when_allowlist_configured() {
    use std::os::unix::net::UnixListener;

    let socket_path = std::env::temp_dir().join(format!(
        "opensnitch-notification-flow-allowlist-enforced-{}-{}.sock",
        std::process::id(),
        crate::utils::time_nonce::unix_epoch_nanos()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let _listener = UnixListener::bind(&socket_path).expect("bind unix listener");

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = format!("unix:{}", socket_path.display());
    cfg.local_control_allowed_principals = Some(vec![crate::config::LocalPrincipal {
        uid: nix::unistd::Uid::current().as_raw(),
        gid: nix::unistd::Gid::current().as_raw(),
    }]);

    assert!(NotificationFlow::local_peer_principal_allowed(&cfg));

    // The allowlist GID acts as a supplementary-group selector, not a primary-GID
    // exact match.  We must pick a GID that is provably absent from all of the
    // current process's groups (primary + supplementary), otherwise the assertion
    // below would be vacuously true for anyone who happens to hold gid+1.
    let all_process_gids: std::collections::HashSet<u32> = {
        let mut gids = nix::unistd::getgroups()
            .unwrap_or_default()
            .into_iter()
            .map(|g| g.as_raw())
            .collect::<std::collections::HashSet<u32>>();
        gids.insert(nix::unistd::Gid::current().as_raw());
        gids
    };
    let absent_gid = (1u32..).find(|g| !all_process_gids.contains(g)).unwrap();

    cfg.local_control_allowed_principals = Some(vec![crate::config::LocalPrincipal {
        uid: nix::unistd::Uid::current().as_raw(),
        gid: absent_gid,
    }]);
    assert!(!NotificationFlow::local_peer_principal_allowed(&cfg));

    let _ = std::fs::remove_file(&socket_path);
}

#[test]
fn local_principal_allowlist_gid_acts_as_group_selector_not_exact_tuple_identity() {
    let allowlist = vec![crate::config::LocalPrincipal {
        uid: 1000,
        gid: 2000,
    }];

    assert!(NotificationFlow::local_principal_allowlist_matches(
        &allowlist,
        1000,
        &[100, 2000, 3000],
    ));
    assert!(!NotificationFlow::local_principal_allowlist_matches(
        &allowlist,
        1000,
        &[100, 3000],
    ));
    assert!(!NotificationFlow::local_principal_allowlist_matches(
        &allowlist,
        1001,
        &[2000],
    ));
}

#[test]
fn allowed_group_selector_matches_primary_or_supplementary_membership() {
    assert!(NotificationFlow::allowed_group_selector_matches(
        &[2000, 2001],
        &[1000, 2001],
    ));
    assert!(!NotificationFlow::allowed_group_selector_matches(
        &[2000, 2001],
        &[1000, 1001],
    ));
    assert!(!NotificationFlow::allowed_group_selector_matches(
        &[],
        &[2000]
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn local_tcp_principal_check_enforced_for_loopback_address() {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let port = listener.local_addr().expect("local addr").port();

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = format!("http://127.0.0.1:{port}");
    let current_uid = nix::unistd::Uid::current().as_raw();

    // No allowlist -> local-only root fallback.
    cfg.local_control_allowed_principals = None;
    assert_eq!(
        NotificationFlow::local_peer_principal_allowed(&cfg),
        nix::unistd::Uid::current().is_root()
    );

    // Current UID plus a matching group selector in allowlist -> pass.
    cfg.local_control_allowed_principals = Some(vec![crate::config::LocalPrincipal {
        uid: current_uid,
        gid: nix::unistd::Gid::current().as_raw(),
    }]);
    assert!(NotificationFlow::local_peer_principal_allowed(&cfg));

    // Wrong group selector for the same UID -> deny.
    cfg.local_control_allowed_principals = Some(vec![crate::config::LocalPrincipal {
        uid: current_uid,
        gid: nix::unistd::Gid::current().as_raw().saturating_add(9999),
    }]);
    assert!(!NotificationFlow::local_peer_principal_allowed(&cfg));

    // Wrong UID -> deny.
    cfg.local_control_allowed_principals = Some(vec![crate::config::LocalPrincipal {
        uid: current_uid.saturating_add(9999),
        gid: nix::unistd::Gid::current().as_raw(),
    }]);
    assert!(!NotificationFlow::local_peer_principal_allowed(&cfg));

    drop(listener);
}

#[test]
fn privileged_notification_actions_are_denied_for_remote_endpoints_in_local_only_mode() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    assert!(!NotificationFlow::notification_action_allowed(
        &cfg,
        CommandAction::ChangeConfig,
    ));
    assert!(!NotificationFlow::notification_action_allowed(
        &cfg,
        CommandAction::EnableFirewall,
    ));
    assert!(NotificationFlow::notification_action_allowed(
        &cfg,
        CommandAction::None,
    ));
}

#[test]
fn privileged_notification_actions_are_denied_for_remote_endpoints_in_local_remote_mode() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalRemoteCapabilities;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    assert!(!NotificationFlow::notification_action_allowed(
        &cfg,
        CommandAction::ChangeConfig,
    ));
    assert!(!NotificationFlow::notification_action_allowed(
        &cfg,
        CommandAction::EnableFirewall,
    ));
    assert!(NotificationFlow::notification_action_allowed(
        &cfg,
        CommandAction::None,
    ));
}

#[test]
fn privileged_notification_actions_are_allowed_in_legacy_mode() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::Legacy;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    assert!(NotificationFlow::notification_action_allowed(
        &cfg,
        CommandAction::ChangeConfig,
    ));
    assert!(NotificationFlow::notification_action_allowed(
        &cfg,
        CommandAction::Stop,
    ));
}

#[test]
fn privileged_classification_marks_global_commands_as_elevated_required() {
    let session = crate::services::client::ClientSession::for_local_uid(
        nix::unistd::Uid::current().as_raw(),
        crate::config::DefaultAction::Deny,
    );

    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::ChangeConfig,
        &[],
        None,
    );

    assert_eq!(class, NotificationAuthorizationClass::ElevatedRequired);
    assert_eq!(
        reason,
        "requested command remains elevated in hardened authorization modes"
    );
}

#[test]
fn privileged_classification_marks_owner_scoped_rule_updates_as_user_scoped_allowed() {
    let owner_uid = nix::unistd::Uid::current().as_raw();
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );
    let scoped_rule = RuleRecord {
        operator: RuleOperator {
            operand: "user.id".to_string(),
            data: owner_uid.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let (class, _reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::ChangeRule,
        &[scoped_rule],
        None,
    );

    assert_eq!(class, NotificationAuthorizationClass::UserScopedAllowed);
}

#[test]
fn privileged_classification_marks_gid_scoped_rule_updates_as_user_scoped_allowed() {
    let owner_uid = nix::unistd::Uid::current().as_raw();
    let owner_gid = nix::unistd::Gid::current().as_raw();
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );
    let scoped_rule = RuleRecord {
        operator: RuleOperator {
            operand: "user.gid".to_string(),
            data: owner_gid.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::ChangeRule,
        &[scoped_rule],
        None,
    );

    assert_eq!(class, NotificationAuthorizationClass::UserScopedAllowed);
    assert_eq!(reason, "rule mutation payload is provably owner-scoped");
}

#[test]
fn privileged_classification_marks_unscoped_rule_updates_as_elevated_required() {
    let owner_uid = nix::unistd::Uid::current().as_raw();
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );
    let unscoped_rule = RuleRecord {
        operator: RuleOperator {
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::ChangeRule,
        &[unscoped_rule],
        None,
    );

    assert_eq!(class, NotificationAuthorizationClass::ElevatedRequired);
    assert_eq!(
        reason,
        "rule mutation payload is not provably scoped to the caller"
    );
}

#[test]
fn privileged_classification_marks_missing_rule_payload_as_always_denied() {
    let owner_uid = nix::unistd::Uid::current().as_raw();
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );

    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::ChangeRule,
        &[],
        None,
    );

    assert_eq!(class, NotificationAuthorizationClass::AlwaysDenied);
    assert_eq!(reason, "rule mutation payload is missing");
}

#[test]
fn privileged_classification_marks_change_rule_without_operand_semantics_as_always_denied() {
    let owner_uid = nix::unistd::Uid::current().as_raw();
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );
    let empty_operator_rule = RuleRecord {
        operator: RuleOperator {
            type_name: "simple".to_string(),
            operand: String::new(),
            data: "/usr/bin/curl".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::ChangeRule,
        &[empty_operator_rule],
        None,
    );

    assert_eq!(class, NotificationAuthorizationClass::AlwaysDenied);
    assert_eq!(reason, "rule mutation payload has no operand semantics");
}

#[test]
fn privileged_classification_keeps_enable_rule_minimal_stub_as_elevated_required() {
    let owner_uid = nix::unistd::Uid::current().as_raw();
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );
    let minimal_stub = RuleRecord {
        name: "legacy-ui-rule".to_string(),
        operator: RuleOperator {
            type_name: String::new(),
            operand: String::new(),
            data: String::new(),
            ..Default::default()
        },
        ..Default::default()
    };

    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::EnableRule,
        &[minimal_stub],
        None,
    );

    assert_eq!(class, NotificationAuthorizationClass::ElevatedRequired);
    assert_eq!(
        reason,
        "rule mutation payload is not provably scoped to the caller"
    );
}

#[test]
fn authorization_rule_candidates_resolve_enable_stub_from_stored_owned_rule() {
    let owner_uid = nix::unistd::Uid::current().as_raw();
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );
    let incoming_stub = RuleRecord {
        name: "owned-rule".to_string(),
        operator: RuleOperator {
            type_name: String::new(),
            operand: String::new(),
            data: String::new(),
            ..Default::default()
        },
        ..Default::default()
    };
    let stored_owned_rule = RuleRecord {
        name: "owned-rule".to_string(),
        operator: RuleOperator {
            type_name: "simple".to_string(),
            operand: "user.id".to_string(),
            data: owner_uid.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let auth_candidates = NotificationFlow::authorization_rule_candidates(
        CommandAction::EnableRule,
        &[incoming_stub],
        &[stored_owned_rule],
    );
    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::EnableRule,
        &auth_candidates,
        None,
    );

    assert_eq!(class, NotificationAuthorizationClass::UserScopedAllowed);
    assert_eq!(reason, "rule mutation payload is provably owner-scoped");
}

#[test]
fn authorization_rule_candidates_resolve_enable_stub_from_stored_gid_scoped_rule() {
    let owner_uid = nix::unistd::Uid::current().as_raw();
    let owner_gid = nix::unistd::Gid::current().as_raw();
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );
    let incoming_stub = RuleRecord {
        name: "owned-by-group-rule".to_string(),
        operator: RuleOperator {
            type_name: String::new(),
            operand: String::new(),
            data: String::new(),
            ..Default::default()
        },
        ..Default::default()
    };
    let stored_gid_scoped_rule = RuleRecord {
        name: "owned-by-group-rule".to_string(),
        operator: RuleOperator {
            type_name: "simple".to_string(),
            operand: "user.gid".to_string(),
            data: owner_gid.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let auth_candidates = NotificationFlow::authorization_rule_candidates(
        CommandAction::EnableRule,
        &[incoming_stub],
        &[stored_gid_scoped_rule],
    );
    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::EnableRule,
        &auth_candidates,
        None,
    );

    assert_eq!(class, NotificationAuthorizationClass::UserScopedAllowed);
    assert_eq!(reason, "rule mutation payload is provably owner-scoped");
}

#[test]
fn authorization_rule_candidates_do_not_override_explicit_conflicting_owner_scope() {
    let owner_uid = nix::unistd::Uid::current().as_raw();
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );
    let incoming_conflicting = RuleRecord {
        name: "owned-rule".to_string(),
        operator: RuleOperator {
            type_name: "simple".to_string(),
            operand: "user.id".to_string(),
            data: (owner_uid.saturating_add(1)).to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    let stored_owned_rule = RuleRecord {
        name: "owned-rule".to_string(),
        operator: RuleOperator {
            type_name: "simple".to_string(),
            operand: "user.id".to_string(),
            data: owner_uid.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let auth_candidates = NotificationFlow::authorization_rule_candidates(
        CommandAction::DeleteRule,
        &[incoming_conflicting],
        &[stored_owned_rule],
    );
    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::DeleteRule,
        &auth_candidates,
        None,
    );

    assert_eq!(class, NotificationAuthorizationClass::ElevatedRequired);
    assert_eq!(
        reason,
        "rule mutation payload is not provably scoped to the caller"
    );
}

#[test]
fn local_only_root_can_run_elevated_global_commands() {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("local addr").port();

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = format!("http://127.0.0.1:{port}");
    cfg.local_control_allowed_principals = Some(vec![crate::config::LocalPrincipal {
        uid: nix::unistd::Uid::current().as_raw(),
        gid: nix::unistd::Gid::current().as_raw(),
    }]);

    let session = crate::services::client::ClientSession::for_local_uid(
        0,
        crate::config::DefaultAction::Deny,
    );

    let result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::ChangeConfig,
        &[],
        None,
    );
    assert_eq!(result, Ok(()));
}

#[cfg(target_os = "linux")]
#[test]
fn local_only_non_root_rule_mutation_requires_owner_scope() {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("local addr").port();

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = format!("http://127.0.0.1:{port}");

    let owner_uid = nix::unistd::Uid::current().as_raw();
    cfg.local_control_allowed_principals = Some(vec![crate::config::LocalPrincipal {
        uid: owner_uid,
        gid: nix::unistd::Gid::current().as_raw(),
    }]);
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );

    let scoped_rule = RuleRecord {
        operator: RuleOperator {
            operand: "user.id".to_string(),
            data: owner_uid.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let scoped_rule_result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::ChangeRule,
        &[scoped_rule],
        None,
    );
    assert_eq!(scoped_rule_result, Ok(()));

    let unscoped_rule = RuleRecord {
        operator: RuleOperator {
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(
        NotificationFlow::notification_command_allowed(
            &cfg,
            &session,
            CommandAction::ChangeRule,
            &[unscoped_rule],
            None,
        )
        .is_err()
    );

    let mut rules_for_normalization = vec![RuleRecord {
        operator: RuleOperator {
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            ..Default::default()
        },
        ..Default::default()
    }];
    let injected = NotificationFlow::normalize_owner_scoped_rule_mutation_rules(
        &cfg,
        &session,
        CommandAction::ChangeRule,
        &mut rules_for_normalization,
    )
    .expect("normalize owner scope");
    assert_eq!(injected, 1);
    assert!(
        NotificationFlow::notification_command_allowed(
            &cfg,
            &session,
            CommandAction::ChangeRule,
            &rules_for_normalization,
            None,
        )
        .is_ok()
    );
}

#[test]
fn local_only_owner_scope_normalization_rejects_conflicting_user_id() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    let owner_uid = 1001u32;
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );
    let mut rules = vec![RuleRecord {
        operator: RuleOperator {
            operand: "user.id".to_string(),
            data: "1002".to_string(),
            ..Default::default()
        },
        ..Default::default()
    }];

    let result = NotificationFlow::normalize_owner_scoped_rule_mutation_rules(
        &cfg,
        &session,
        CommandAction::ChangeRule,
        &mut rules,
    );
    assert_eq!(
        result,
        Err("rule payload owner scope conflicts with authenticated caller")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn local_only_non_root_global_firewall_commands_stay_elevated() {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("local addr").port();

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = format!("http://127.0.0.1:{port}");
    let owner_uid = nix::unistd::Uid::current().as_raw();
    cfg.local_control_allowed_principals = Some(vec![crate::config::LocalPrincipal {
        uid: owner_uid,
        gid: nix::unistd::Gid::current().as_raw(),
    }]);
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );

    assert!(
        NotificationFlow::notification_command_allowed(
            &cfg,
            &session,
            CommandAction::EnableFirewall,
            &[],
            None,
        )
        .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn local_only_non_root_firewall_reload_requires_owner_uid_match() {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("local addr").port();

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = format!("http://127.0.0.1:{port}");
    let owner_uid = nix::unistd::Uid::current().as_raw();
    cfg.local_control_allowed_principals = Some(vec![crate::config::LocalPrincipal {
        uid: owner_uid,
        gid: nix::unistd::Gid::current().as_raw(),
    }]);
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );

    let scoped_fw = FirewallConfig {
        rules: vec![FirewallRule {
            parameters: format!("-m owner --uid-owner {owner_uid}"),
            target: "ACCEPT".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let scoped_firewall_result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::ReloadFwRules,
        &[],
        Some(&scoped_fw),
    );
    assert_eq!(scoped_firewall_result, Ok(()));

    let unscoped_fw = FirewallConfig {
        chains: vec![FirewallChain {
            name: "filter_output".to_string(),
            table: "opensnitch".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    assert!(
        NotificationFlow::notification_command_allowed(
            &cfg,
            &session,
            CommandAction::ReloadFwRules,
            &[],
            Some(&unscoped_fw),
        )
        .is_err()
    );

    let mut fw_for_normalization = FirewallConfig {
        rules: vec![FirewallRule {
            parameters: "-p tcp --dport 443".to_string(),
            target: "ACCEPT".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let injected = NotificationFlow::normalize_owner_scoped_firewall_reload(
        &cfg,
        &session,
        CommandAction::ReloadFwRules,
        Some(&mut fw_for_normalization),
    )
    .expect("normalize firewall owner scope");
    assert_eq!(injected, 1);
    assert!(
        NotificationFlow::notification_command_allowed(
            &cfg,
            &session,
            CommandAction::ReloadFwRules,
            &[],
            Some(&fw_for_normalization),
        )
        .is_ok()
    );

    let owner_gid = nix::unistd::Gid::current().as_raw();
    let gid_scoped_fw = FirewallConfig {
        rules: vec![FirewallRule {
            parameters: format!("-m owner --gid-owner {owner_gid} -p tcp --dport 443"),
            target: "ACCEPT".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let gid_scoped_firewall_result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::ReloadFwRules,
        &[],
        Some(&gid_scoped_fw),
    );
    assert_eq!(gid_scoped_firewall_result, Ok(()));
}

#[test]
fn local_only_firewall_owner_scope_normalization_rejects_conflicting_uid_owner() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    let owner_uid = 1001u32;
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );
    let mut fw = FirewallConfig {
        rules: vec![FirewallRule {
            parameters: "-m owner --uid-owner 1002 -p tcp".to_string(),
            target: "ACCEPT".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let result = NotificationFlow::normalize_owner_scoped_firewall_reload(
        &cfg,
        &session,
        CommandAction::ReloadFwRules,
        Some(&mut fw),
    );
    assert_eq!(
        result,
        Err("system firewall payload owner scope conflicts with authenticated caller")
    );
}

#[test]
fn local_only_nested_firewall_chain_payloads_remain_elevated_required() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    let owner_uid = nix::unistd::Uid::current().as_raw();
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );

    let owner_scoped_chain_fw = FirewallConfig {
        chains: vec![FirewallChain {
            name: "mangle_output".to_string(),
            table: "opensnitch".to_string(),
            family: "inet".to_string(),
            priority: "0".to_string(),
            r#type: "filter".to_string(),
            hook: "output".to_string(),
            policy: "accept".to_string(),
            rules: vec![FirewallRule {
                parameters: format!("-m owner --uid-owner {owner_uid} -p tcp --dport 443"),
                target: "ACCEPT".to_string(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::ReloadFwRules,
        &[],
        Some(&owner_scoped_chain_fw),
    );
    assert_eq!(class, NotificationAuthorizationClass::ElevatedRequired);
    assert_eq!(
        reason,
        "system firewall payload is not provably scoped to the caller"
    );

    let mut fw_for_normalization = owner_scoped_chain_fw.clone();
    let injected = NotificationFlow::normalize_owner_scoped_firewall_reload(
        &cfg,
        &session,
        CommandAction::ReloadFwRules,
        Some(&mut fw_for_normalization),
    )
    .expect("chain payload normalization should remain a no-op");
    assert_eq!(injected, 0);
}

#[test]
fn local_only_firewall_owner_scope_normalization_injects_nft_skuid_expression() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    let owner_uid = 1000u32;
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );

    let mut fw = FirewallConfig {
        rules: vec![FirewallRule {
            expressions: vec![FirewallExpression {
                statement: Some(FirewallStatement {
                    op: "==".to_string(),
                    name: "meta".to_string(),
                    values: vec![FirewallStatementValue {
                        key: "l4proto".to_string(),
                        value: "tcp".to_string(),
                    }],
                }),
            }],
            target: "accept".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let injected = NotificationFlow::normalize_owner_scoped_firewall_reload(
        &cfg,
        &session,
        CommandAction::ReloadFwRules,
        Some(&mut fw),
    )
    .expect("normalize nft firewall owner scope");
    assert_eq!(injected, 1);

    let expressions = &fw.rules[0].expressions;
    assert!(expressions.iter().any(|expression| {
        let Some(statement) = expression.statement.as_ref() else {
            return false;
        };
        statement.name == "meta"
            && statement
                .values
                .iter()
                .any(|value| value.key == "skuid" && value.value == owner_uid.to_string())
    }));

    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::ReloadFwRules,
        &[],
        Some(&fw),
    );
    assert_eq!(class, NotificationAuthorizationClass::UserScopedAllowed);
    assert_eq!(reason, "system firewall payload is provably owner-scoped");
}

#[test]
fn local_only_firewall_owner_scope_normalization_rejects_conflicting_nft_skuid_expression() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalOnly;
    let owner_uid = 1000u32;
    let session = crate::services::client::ClientSession::for_local_uid(
        owner_uid,
        crate::config::DefaultAction::Deny,
    );

    let mut fw = FirewallConfig {
        rules: vec![FirewallRule {
            expressions: vec![FirewallExpression {
                statement: Some(FirewallStatement {
                    op: "==".to_string(),
                    name: "meta".to_string(),
                    values: vec![FirewallStatementValue {
                        key: "skuid".to_string(),
                        value: "9999".to_string(),
                    }],
                }),
            }],
            target: "accept".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let result = NotificationFlow::normalize_owner_scoped_firewall_reload(
        &cfg,
        &session,
        CommandAction::ReloadFwRules,
        Some(&mut fw),
    );
    assert_eq!(
        result,
        Err("system firewall payload owner scope conflicts with authenticated caller")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn session_binding_extracts_local_uid_for_live_loopback_listener() {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("local addr").port();

    let mut cfg = Config::default();
    cfg.client_addr = format!("http://127.0.0.1:{port}");

    let binding = NotificationFlow::session_binding_from_client_addr(&cfg.client_addr, &cfg);
    let expected_uid = nix::unistd::Uid::current().as_raw();

    assert_eq!(binding.id, format!("uid:{expected_uid}"));
    assert!(matches!(binding.owner, ClientPrincipal::LocalUid(uid) if uid == expected_uid));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_flow_runs_ui_poller_path_with_stub_transport() {
    let (bus, _bus_rx) = BusState::build_with_caps(BusCaps::uniform(8));
    let mut config = Config::default();
    config.client_addr = "stub://local-ui".to_string();
    config.client_auth.auth_type = ClientAuthType::Simple;
    let rules = RuleService::default();
    rules
        .load_path(&config.rules_path)
        .await
        .expect("load rules");
    let firewall = FirewallService::new(&config).expect("build firewall service");
    let _flow = NotificationFlow::new(
        bus,
        crate::services::client::AlertBuffer::default(),
        ConfigService::new(config.clone()),
        ClientService::default(),
        rules.clone(),
        firewall.clone(),
        crate::services::audit::AuditService::new(32),
    );

    let mut subscribe_client = ClientService::connect_with_config(&config)
        .await
        .expect("client connect should succeed");

    let rules_snapshot = rules.get_wire_snapshot();
    let firewall_state = firewall.get_snapshot();
    let subscribe_cfg = ClientService::build_subscribe_config_from_snapshots(
        &config,
        rules_snapshot.as_ref(),
        firewall_state.state.enabled,
        &firewall_state.system_firewall,
    );
    subscribe_client
        .subscribe(subscribe_cfg)
        .await
        .expect("subscribe should succeed");

    let mut stream_client = ClientService::connect_with_config(&config)
        .await
        .expect("stream client connect should succeed");
    let _stream = NotificationStream::open(&mut stream_client)
        .await
        .expect("notifications stream open should succeed");
}

#[test]
fn parse_task_notification_accepts_valid_payload() {
    let parsed = parse_task_notification_data(10, r#"{"Name":"pid-monitor","Data":{"pid":1234}}"#)
        .expect("task payload");
    assert_eq!(parsed.notification_id, 10);
    assert_eq!(parsed.name, "pid-monitor");
}

#[test]
fn parse_task_notification_accepts_lowercase_payload_fields() {
    let parsed = parse_task_notification_data(12, r#"{"name":"sockets-monitor","data":{}}"#)
        .expect("task payload");
    assert_eq!(parsed.notification_id, 12);
    assert_eq!(parsed.name, "sockets-monitor");
}

#[test]
fn parse_task_notification_accepts_uppercase_payload_fields() {
    let parsed = parse_task_notification_data(13, r#"{"NAME":"pid-monitor","DATA":{"pid":4321}}"#)
        .expect("task payload");
    assert_eq!(parsed.notification_id, 13);
    assert_eq!(parsed.name, "pid-monitor");
}

#[test]
fn parse_task_notification_rejects_invalid_payload() {
    assert!(parse_task_notification_data(11, "not-json").is_err());
}

#[test]
fn parse_log_level_notification_supports_number_and_object() {
    assert_eq!(parse_log_level_data("3"), Some(3));
    assert_eq!(parse_log_level_data(r#"{"log_level":7}"#), Some(7));
    assert_eq!(parse_log_level_data(r#"{"Log_Level":"9"}"#), Some(9));
    assert_eq!(parse_log_level_data(r#"{"LEVEL":5}"#), Some(5));
}

// ── Remote principal binding resolution ─────────────────────────────────

#[test]
fn resolve_remote_principal_binding_matches_by_fingerprint() {
    use crate::config::{LocalPrincipal, RemotePrincipalBinding};

    let mut cfg = Config::default();
    cfg.remote_principal_bindings = Some(vec![RemotePrincipalBinding {
        name: "ui-server-1".to_string(),
        cert_fingerprint: Some("abc123def456".to_string()),
        cert_subject: None,
        cert_san: None,
        local_principal: LocalPrincipal {
            uid: 1000,
            gid: 100,
        },
        capabilities: vec!["rules.owner.write".to_string()],
    }]);

    let session =
        NotificationFlow::resolve_remote_principal_binding(&cfg, Some("ABC123DEF456"), None, None);
    assert!(session.is_some());
    let session = session.unwrap();
    assert_eq!(
        session.owner,
        crate::services::client::ClientPrincipal::RemoteCert {
            binding_name: "ui-server-1".to_string(),
            mapped_uid: 1000,
        }
    );
    assert!(session.has_capability("rules.owner.write"));
}

#[test]
fn resolve_remote_principal_binding_matches_by_subject() {
    use crate::config::{LocalPrincipal, RemotePrincipalBinding};

    let mut cfg = Config::default();
    cfg.remote_principal_bindings = Some(vec![RemotePrincipalBinding {
        name: "ui-server-subj".to_string(),
        cert_fingerprint: None,
        cert_subject: Some("CN=opensnitch-ui".to_string()),
        cert_san: None,
        local_principal: LocalPrincipal {
            uid: 1001,
            gid: 100,
        },
        capabilities: vec!["config.write".to_string()],
    }]);

    let session = NotificationFlow::resolve_remote_principal_binding(
        &cfg,
        None,
        Some("CN=opensnitch-ui"),
        None,
    );
    assert!(session.is_some());
    let session = session.unwrap();
    assert_eq!(
        session.owner,
        crate::services::client::ClientPrincipal::RemoteCert {
            binding_name: "ui-server-subj".to_string(),
            mapped_uid: 1001,
        }
    );
}

#[test]
fn resolve_remote_principal_binding_matches_by_san() {
    use crate::config::{LocalPrincipal, RemotePrincipalBinding};

    let mut cfg = Config::default();
    cfg.remote_principal_bindings = Some(vec![RemotePrincipalBinding {
        name: "ui-san".to_string(),
        cert_fingerprint: None,
        cert_subject: None,
        cert_san: Some("ui.local".to_string()),
        local_principal: LocalPrincipal {
            uid: 1002,
            gid: 100,
        },
        capabilities: vec!["firewall.toggle".to_string()],
    }]);

    let session =
        NotificationFlow::resolve_remote_principal_binding(&cfg, None, None, Some("ui.local"));
    assert!(session.is_some());
    let session = session.unwrap();
    assert!(session.has_capability("firewall.toggle"));
}

#[test]
fn resolve_remote_principal_binding_returns_none_when_no_match() {
    use crate::config::{LocalPrincipal, RemotePrincipalBinding};

    let mut cfg = Config::default();
    cfg.remote_principal_bindings = Some(vec![RemotePrincipalBinding {
        name: "other".to_string(),
        cert_fingerprint: Some("deadbeef".to_string()),
        cert_subject: None,
        cert_san: None,
        local_principal: LocalPrincipal {
            uid: 1000,
            gid: 100,
        },
        capabilities: vec![],
    }]);

    let session =
        NotificationFlow::resolve_remote_principal_binding(&cfg, Some("cafebabe"), None, None);
    assert!(session.is_none());
}

#[test]
fn resolve_remote_principal_binding_returns_none_when_not_configured() {
    let cfg = Config::default();
    let session = NotificationFlow::resolve_remote_principal_binding(&cfg, Some("abc"), None, None);
    assert!(session.is_none());
}

// ── Required capability mapping ─────────────────────────────────────────

#[test]
fn required_capability_returns_owner_write_for_user_scoped_rule_mutations() {
    use crate::models::auth_capability::{CAP_RULES_OWNER_WRITE, required_capability};

    for action in [
        CommandAction::ChangeRule,
        CommandAction::EnableRule,
        CommandAction::DisableRule,
        CommandAction::DeleteRule,
    ] {
        assert_eq!(
            required_capability(action, NotificationAuthorizationClass::UserScopedAllowed),
            Some(CAP_RULES_OWNER_WRITE),
            "expected owner write cap for {action:?}",
        );
    }
}

#[test]
fn required_capability_returns_global_write_for_elevated_rule_mutations() {
    use crate::models::auth_capability::{CAP_RULES_GLOBAL_WRITE, required_capability};

    assert_eq!(
        required_capability(
            CommandAction::ChangeRule,
            NotificationAuthorizationClass::ElevatedRequired
        ),
        Some(CAP_RULES_GLOBAL_WRITE),
    );
}

#[test]
fn required_capability_returns_none_for_always_allowed_and_always_denied() {
    use crate::models::auth_capability::required_capability;

    assert_eq!(
        required_capability(
            CommandAction::ChangeConfig,
            NotificationAuthorizationClass::AlwaysAllowed
        ),
        None,
    );
    assert_eq!(
        required_capability(
            CommandAction::ChangeConfig,
            NotificationAuthorizationClass::AlwaysDenied
        ),
        None,
    );
}

#[test]
fn required_capability_maps_elevated_commands() {
    use crate::models::auth_capability::{
        CAP_CONFIG_WRITE, CAP_DAEMON_CONTROL_STOP, CAP_FIREWALL_TOGGLE, CAP_INTERCEPTION_TOGGLE,
        CAP_LOG_LEVEL, CAP_TASK_CONTROL, required_capability,
    };

    assert_eq!(
        required_capability(
            CommandAction::ChangeConfig,
            NotificationAuthorizationClass::ElevatedRequired
        ),
        Some(CAP_CONFIG_WRITE),
    );
    assert_eq!(
        required_capability(
            CommandAction::Stop,
            NotificationAuthorizationClass::ElevatedRequired
        ),
        Some(CAP_DAEMON_CONTROL_STOP),
    );
    assert_eq!(
        required_capability(
            CommandAction::EnableFirewall,
            NotificationAuthorizationClass::ElevatedRequired
        ),
        Some(CAP_FIREWALL_TOGGLE),
    );
    assert_eq!(
        required_capability(
            CommandAction::DisableFirewall,
            NotificationAuthorizationClass::ElevatedRequired
        ),
        Some(CAP_FIREWALL_TOGGLE),
    );
    assert_eq!(
        required_capability(
            CommandAction::EnableInterception,
            NotificationAuthorizationClass::ElevatedRequired
        ),
        Some(CAP_INTERCEPTION_TOGGLE),
    );
    assert_eq!(
        required_capability(
            CommandAction::DisableInterception,
            NotificationAuthorizationClass::ElevatedRequired
        ),
        Some(CAP_INTERCEPTION_TOGGLE),
    );
    assert_eq!(
        required_capability(
            CommandAction::TaskStart,
            NotificationAuthorizationClass::ElevatedRequired
        ),
        Some(CAP_TASK_CONTROL),
    );
    assert_eq!(
        required_capability(
            CommandAction::LogLevel,
            NotificationAuthorizationClass::ElevatedRequired
        ),
        Some(CAP_LOG_LEVEL),
    );
}

// ── Remote capability authorization (notification_command_allowed) ───────

#[test]
fn notification_command_allowed_permits_remote_session_with_matching_capability() {
    use crate::models::auth_capability::CAP_CONFIG_WRITE;

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalRemoteCapabilities;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    let session = crate::services::client::ClientSession::for_remote_principal(
        "ui-server",
        1000,
        vec![CAP_CONFIG_WRITE.to_string()],
        crate::config::DefaultAction::Deny,
    );

    let result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::ChangeConfig,
        &[],
        None,
    );
    assert_eq!(result, Ok(()));
}

#[test]
fn notification_command_allowed_denies_remote_session_without_required_capability() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalRemoteCapabilities;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    let session = crate::services::client::ClientSession::for_remote_principal(
        "ui-server",
        1000,
        vec!["rules.owner.write".to_string()], // has rules cap, not config cap
        crate::config::DefaultAction::Deny,
    );

    let result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::ChangeConfig,
        &[],
        None,
    );
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "remote session lacks required capability for this command"
    );
}

#[test]
fn notification_command_allowed_denies_remote_session_with_empty_capabilities() {
    use crate::models::auth_capability::CAP_CONFIG_WRITE;

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalRemoteCapabilities;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    // RemoteCert with no capabilities — falls through to notification_action_allowed
    // which returns false for remote endpoints.
    let session = crate::services::client::ClientSession::for_remote_principal(
        "ui-server",
        1000,
        vec![],
        crate::config::DefaultAction::Deny,
    );

    let result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::ChangeConfig,
        &[],
        None,
    );
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "remote session lacks required capability for this command"
    );

    assert!(!session.has_capability(CAP_CONFIG_WRITE));
}

#[test]
fn notification_command_allowed_permits_remote_root_for_elevated_command() {
    use crate::models::auth_capability::CAP_DAEMON_CONTROL_STOP;

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalRemoteCapabilities;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    // mapped_uid=0 (root) with stop capability
    let session = crate::services::client::ClientSession::for_remote_principal(
        "admin-ui",
        0,
        vec![CAP_DAEMON_CONTROL_STOP.to_string()],
        crate::config::DefaultAction::Deny,
    );

    let result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::Stop,
        &[],
        None,
    );
    assert_eq!(result, Ok(()));
}

#[test]
fn notification_command_allowed_denies_remote_root_without_required_capability() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalRemoteCapabilities;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    // mapped_uid=0 (root) but no stop capability must not bypass remote auth lane
    let session = crate::services::client::ClientSession::for_remote_principal(
        "admin-ui",
        0,
        vec![],
        crate::config::DefaultAction::Deny,
    );

    let result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::Stop,
        &[],
        None,
    );
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "remote session lacks required capability for this command"
    );
}

#[test]
fn notification_command_allowed_permits_remote_owner_scoped_rule_with_owner_cap() {
    use crate::models::auth_capability::CAP_RULES_OWNER_WRITE;

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalRemoteCapabilities;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    let mapped_uid = 1000u32;
    let session = crate::services::client::ClientSession::for_remote_principal(
        "ui-server",
        mapped_uid,
        vec![CAP_RULES_OWNER_WRITE.to_string()],
        crate::config::DefaultAction::Deny,
    );

    let scoped_rule = RuleRecord {
        operator: RuleOperator {
            operand: "user.id".to_string(),
            data: mapped_uid.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::ChangeRule,
        &[scoped_rule],
        None,
    );
    assert_eq!(result, Ok(()));
}

#[test]
fn notification_command_allowed_denies_remote_global_rule_with_only_owner_cap() {
    use crate::models::auth_capability::CAP_RULES_OWNER_WRITE;

    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalRemoteCapabilities;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    let session = crate::services::client::ClientSession::for_remote_principal(
        "ui-server",
        1000,
        vec![CAP_RULES_OWNER_WRITE.to_string()],
        crate::config::DefaultAction::Deny,
    );

    // Unscoped rule → ElevatedRequired → needs CAP_RULES_GLOBAL_WRITE, not owner
    let unscoped_rule = RuleRecord {
        operator: RuleOperator {
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::ChangeRule,
        &[unscoped_rule],
        None,
    );
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "remote session lacks required capability for this command"
    );
}

#[test]
fn notification_command_allowed_skips_capability_check_in_legacy_mode() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::Legacy;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    // Even with no capabilities, legacy mode allows everything.
    let session = crate::services::client::ClientSession::for_remote_principal(
        "ui-server",
        1000,
        vec![],
        crate::config::DefaultAction::Deny,
    );

    let result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::ChangeConfig,
        &[],
        None,
    );
    assert_eq!(result, Ok(()));
}

#[test]
fn notification_command_allowed_allows_non_privileged_action_for_remote_without_caps() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalRemoteCapabilities;
    cfg.client_addr = "https://ui.example.test:50051".to_string();

    let session = crate::services::client::ClientSession::for_remote_principal(
        "ui-server",
        1000,
        vec![],
        crate::config::DefaultAction::Deny,
    );

    // CommandAction::None is not privileged, so no capability check needed.
    let result = NotificationFlow::notification_command_allowed(
        &cfg,
        &session,
        CommandAction::None,
        &[],
        None,
    );
    assert_eq!(result, Ok(()));
}

// ── Remote session construction and has_capability ──────────────────────

#[test]
fn for_remote_principal_creates_session_with_correct_fields() {
    let session = crate::services::client::ClientSession::for_remote_principal(
        "my-binding",
        500,
        vec!["rules.owner.write".to_string(), "config.write".to_string()],
        crate::config::DefaultAction::Deny,
    );

    assert_eq!(session.id, "remote-cert:my-binding");
    assert_eq!(
        session.owner,
        crate::services::client::ClientPrincipal::RemoteCert {
            binding_name: "my-binding".to_string(),
            mapped_uid: 500,
        }
    );
    assert!(session.has_capability("rules.owner.write"));
    assert!(session.has_capability("config.write"));
    assert!(!session.has_capability("daemon.control.stop"));
}

#[test]
fn local_session_has_empty_capabilities() {
    let session = crate::services::client::ClientSession::for_local_uid(
        1000,
        crate::config::DefaultAction::Deny,
    );
    assert!(session.capabilities.is_empty());
    assert!(!session.has_capability("rules.owner.write"));
}

// ── Remote principal classification ─────────────────────────────────────

#[test]
fn classify_privileged_action_works_with_remote_cert_principal() {
    let session = crate::services::client::ClientSession::for_remote_principal(
        "ui-server",
        1000,
        vec!["config.write".to_string()],
        crate::config::DefaultAction::Deny,
    );

    let (class, reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::ChangeConfig,
        &[],
        None,
    );
    assert_eq!(class, NotificationAuthorizationClass::ElevatedRequired);
    assert_eq!(
        reason,
        "requested command remains elevated in hardened authorization modes"
    );
}

#[test]
fn classify_privileged_action_uses_mapped_uid_for_owner_scope_check() {
    let mapped_uid = 1000u32;
    let session = crate::services::client::ClientSession::for_remote_principal(
        "ui-server",
        mapped_uid,
        vec!["rules.owner.write".to_string()],
        crate::config::DefaultAction::Deny,
    );

    let scoped_rule = RuleRecord {
        operator: RuleOperator {
            operand: "user.id".to_string(),
            data: mapped_uid.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let (class, _reason) = NotificationFlow::classify_privileged_notification_action(
        &session,
        CommandAction::ChangeRule,
        &[scoped_rule],
        None,
    );
    assert_eq!(class, NotificationAuthorizationClass::UserScopedAllowed);
}

// ── Owner-scope normalization with RemoteCert ───────────────────────────

#[test]
fn normalize_owner_scoped_rules_works_with_remote_cert_session() {
    let mut cfg = Config::default();
    cfg.auth_mode = AuthMode::LocalRemoteCapabilities;

    let mapped_uid = 1000u32;
    let session = crate::services::client::ClientSession::for_remote_principal(
        "ui-server",
        mapped_uid,
        vec!["rules.owner.write".to_string()],
        crate::config::DefaultAction::Deny,
    );

    let mut rules = vec![RuleRecord {
        operator: RuleOperator {
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            ..Default::default()
        },
        ..Default::default()
    }];

    let result = NotificationFlow::normalize_owner_scoped_rule_mutation_rules(
        &cfg,
        &session,
        CommandAction::ChangeRule,
        &mut rules,
    );
    // Should succeed and inject owner UID scope
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1); // one rule got scope injected
}

// ── RemoteCert PolicyOwner conversion ────────────────────────────────────

#[test]
fn remote_cert_principal_converts_to_network_identity_policy_owner() {
    use crate::models::policy_tx_storage::PolicyOwner;

    let principal = crate::services::client::ClientPrincipal::RemoteCert {
        binding_name: "ui-server-1".to_string(),
        mapped_uid: 1000,
    };
    let owner: PolicyOwner = principal.into();
    assert!(
        matches!(owner, PolicyOwner::NetworkIdentity(ref s) if s == "remote-cert:ui-server-1"),
        "expected NetworkIdentity(\"remote-cert:ui-server-1\"), got {owner:?}"
    );
}

// ── Audit event Display formatting ──────────────────────────────────────

#[test]
fn audit_remote_capability_display_formatting() {
    use crate::models::audit::{client::ClientAuthorizationAction, kind::AuditEventKind};

    let allowed = AuditEventKind::ClientAuthorizationAction(
        ClientAuthorizationAction::AllowedRemoteCapability {
            notification_id: 42,
            action: CommandAction::ChangeConfig,
            reason: "has config.write capability",
        },
    );
    let display = format!("{allowed}");
    assert!(display.contains("AllowedRemoteCapability"));
    assert!(display.contains("nid=42"));

    let denied = AuditEventKind::ClientAuthorizationAction(
        ClientAuthorizationAction::DeniedRemoteCapability {
            notification_id: 99,
            action: CommandAction::Stop,
            reason: "missing daemon.control.stop",
        },
    );
    let display = format!("{denied}");
    assert!(display.contains("DeniedRemoteCapability"));
    assert!(display.contains("nid=99"));

    let resolved = AuditEventKind::ClientAuthorizationAction(
        ClientAuthorizationAction::RemotePrincipalResolved {
            reason: "matched fingerprint binding ui-server-1",
        },
    );
    let display = format!("{resolved}");
    assert!(display.contains("RemotePrincipalResolved"));
    assert!(display.contains("matched fingerprint binding ui-server-1"));
}
