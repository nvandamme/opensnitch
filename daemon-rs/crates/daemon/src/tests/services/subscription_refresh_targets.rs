use crate::services::subscription::SubscriptionRecord;
use crate::services::subscription::refresh_targets::{
    has_refresh_targeting, resolve_refresh_targets,
};

fn record(id: &str) -> SubscriptionRecord {
    SubscriptionRecord {
        id: id.to_string(),
        ..Default::default()
    }
}

#[test]
fn blank_request_selectors_are_ignored() {
    let all = vec![record("a"), record("b")];
    let selected = resolve_refresh_targets(all.clone(), &[SubscriptionRecord::default()], &[]);
    assert_eq!(selected.len(), all.len());
}

#[test]
fn whitespace_targets_do_not_enable_explicit_targeting() {
    let explicit = has_refresh_targeting(
        &[SubscriptionRecord::default()],
        &["   ".to_string(), "".to_string()],
    );
    assert!(!explicit);
}

#[test]
fn non_empty_target_enables_explicit_targeting() {
    let explicit = has_refresh_targeting(&[], &["sub-id".to_string()]);
    assert!(explicit);
}
