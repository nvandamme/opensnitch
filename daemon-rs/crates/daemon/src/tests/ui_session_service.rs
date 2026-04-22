use crate::{config::DefaultAction, services::ui_session_service::UiSessionService};

#[tokio::test]
async fn effective_default_action_switches_with_connectivity() {
    let service = UiSessionService::default();

    assert!(matches!(
        service.effective_default_action(DefaultAction::Allow).await,
        DefaultAction::Allow
    ));

    service
        .set_connected_default_action(DefaultAction::Deny)
        .await;
    service.set_connected(true);
    assert!(service.is_connected());

    assert!(matches!(
        service.effective_default_action(DefaultAction::Allow).await,
        DefaultAction::Deny
    ));

    service.set_connected(false);
    assert!(!service.is_connected());
    assert!(matches!(
        service.effective_default_action(DefaultAction::Allow).await,
        DefaultAction::Allow
    ));
}
