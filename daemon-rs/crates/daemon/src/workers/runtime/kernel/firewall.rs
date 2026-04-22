pub(crate) async fn handle_firewall_state_event(
    state: crate::models::firewall_state::FirewallState,
) {
    tracing::debug!(
        enabled = state.enabled,
        backend = crate::services::firewall::firewall_backend_name(state.backend),
        "firewall state event received"
    );
}
