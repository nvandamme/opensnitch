use crate::models::{
    audit::{
        AuditEvent, AuditEventFamily, AuditEventKind, ClientAuthorizationAction, VerdictAction,
    },
    command::action::CommandAction,
    config::runtime::AskFallbackPolicy,
    rule::record::RuleAction,
};
use crate::services::audit::AuditService;

fn wait_for_ring_items(audit: &AuditService, min_items: usize) {
    for _ in 0..100 {
        if audit.ring().len() >= min_items {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("timed out waiting for audit ring items");
}

#[test]
fn emit_persists_events_in_ring_and_drains_in_order() {
    let audit = AuditService::new(2);

    audit.emit(AuditEvent::hot(AuditEventKind::VerdictAction(
        VerdictAction::AskTimeoutFallback {
            request_id: 1,
            fallback_policy: AskFallbackPolicy::DefaultAction,
        },
    )));
    audit.emit(AuditEvent::hot(AuditEventKind::VerdictAction(
        VerdictAction::AskTimeoutFallback {
            request_id: 2,
            fallback_policy: AskFallbackPolicy::Allow,
        },
    )));
    audit.emit(AuditEvent::hot(AuditEventKind::VerdictAction(
        VerdictAction::AskTimeoutFallback {
            request_id: 3,
            fallback_policy: AskFallbackPolicy::Drop,
        },
    )));

    wait_for_ring_items(&audit, 2);

    let drained = audit.ring().drain_recent();
    assert_eq!(drained.len(), 2);

    match drained[0].as_ref() {
        AuditEvent {
            family: AuditEventFamily::HotPath,
            kind:
                AuditEventKind::VerdictAction(VerdictAction::AskTimeoutFallback {
                    request_id,
                    fallback_policy,
                }),
            ..
        } => {
            assert_eq!(*request_id, 2);
            assert_eq!(*fallback_policy, AskFallbackPolicy::Allow);
        }
        _ => panic!("expected ask-timeout client verdict"),
    }
    match drained[1].as_ref() {
        AuditEvent {
            family: AuditEventFamily::HotPath,
            kind:
                AuditEventKind::VerdictAction(VerdictAction::AskTimeoutFallback {
                    request_id,
                    fallback_policy,
                }),
            ..
        } => {
            assert_eq!(*request_id, 3);
            assert_eq!(*fallback_policy, AskFallbackPolicy::Drop);
        }
        _ => panic!("expected ask-timeout client verdict"),
    }

    assert!(audit.ring().is_empty());
}

#[tokio::test]
async fn subscribe_receives_newly_emitted_events() {
    let audit = AuditService::new(8);
    let mut rx = audit.subscribe();

    audit.emit(AuditEvent::cold(AuditEventKind::ClientAuthorizationAction(
        ClientAuthorizationAction::DeniedAuthorizationPolicy {
            notification_id: 42,
            action: CommandAction::ChangeRule,
            reason: "denied",
        },
    )));

    let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout waiting for audit event")
        .expect("broadcast receive failed");

    match received.as_ref() {
        AuditEvent {
            family: AuditEventFamily::ColdPath,
            kind:
                AuditEventKind::ClientAuthorizationAction(
                    ClientAuthorizationAction::DeniedAuthorizationPolicy {
                        notification_id,
                        action,
                        reason,
                    },
                ),
            ..
        } => {
            assert_eq!(*notification_id, 42);
            assert_eq!(*action, CommandAction::ChangeRule);
            assert_eq!(*reason, "denied");
        }
        _ => panic!("expected client authorization verdict event"),
    }
}

#[test]
fn ask_rule_persisted_client_verdict_keeps_payload() {
    let audit = AuditService::new(8);
    audit.emit(AuditEvent::hot(AuditEventKind::VerdictAction(
        VerdictAction::AskRuleRulePersisted {
            request_id: 77,
            rule_name: "allow-https".to_string(),
            action: RuleAction::Allow,
        },
    )));

    wait_for_ring_items(&audit, 1);
    let drained = audit.ring().drain_recent();
    assert_eq!(drained.len(), 1);

    match drained[0].as_ref() {
        AuditEvent {
            family: AuditEventFamily::HotPath,
            kind:
                AuditEventKind::VerdictAction(VerdictAction::AskRuleRulePersisted {
                    request_id,
                    rule_name,
                    action,
                }),
            ..
        } => {
            assert_eq!(*request_id, 77);
            assert_eq!(rule_name, "allow-https");
            assert_eq!(*action, RuleAction::Allow);
        }
        _ => panic!("expected ask-rule-persisted client verdict event"),
    }
}
