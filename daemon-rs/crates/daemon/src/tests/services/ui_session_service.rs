use crate::{config::DefaultAction, services::client::UiSessionService};

#[test]
fn effective_default_action_switches_with_connectivity() {
    let service = UiSessionService::default();

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
