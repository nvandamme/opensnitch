use crate::{WireAlert, WireCommandAction, status_payload};

#[test]
fn status_payload_is_stable_json_shape() {
    let payload = status_payload("ready");
    let value: serde_json::Value =
        serde_json::from_str(&payload).expect("valid status payload json");

    assert_eq!(value, serde_json::json!({"status": "ready"}));
}

#[test]
fn command_action_from_i32_maps_known_and_unknown_values() {
    assert_eq!(
        WireCommandAction::from_i32(1),
        WireCommandAction::EnableInterception
    );
    assert_eq!(WireCommandAction::from_i32(11), WireCommandAction::LogLevel);
    assert_eq!(WireCommandAction::from_i32(12), WireCommandAction::Stop);
    assert_eq!(
        WireCommandAction::from_i32(13),
        WireCommandAction::TaskStart
    );
    assert_eq!(WireCommandAction::from_i32(14), WireCommandAction::TaskStop);
    assert_eq!(WireCommandAction::from_i32(999), WireCommandAction::None);
}

#[test]
fn alert_default_starts_without_payload() {
    let alert = WireAlert::default();

    assert_eq!(alert.id, 0);
    assert!(alert.data.is_none());
}
