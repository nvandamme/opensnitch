use crate::commands::command_control::CommandControlService;
use crate::config::ProcMonitorMethod;

#[test]
fn log_level_validation_matches_supported_range() {
    let svc = CommandControlService::default();
    assert!(svc.is_valid_log_level(-1));
    assert!(svc.is_valid_log_level(0));
    assert!(svc.is_valid_log_level(5));
    assert!(!svc.is_valid_log_level(-2));
    assert!(!svc.is_valid_log_level(6));
}

#[test]
fn reconfigure_target_disables_proc_workers_when_interception_is_off() {
    let svc = CommandControlService::default();
    assert_eq!(
        svc.reconfigure_target(true, ProcMonitorMethod::Audit),
        Some(ProcMonitorMethod::Audit)
    );
    assert_eq!(svc.reconfigure_target(false, ProcMonitorMethod::Ebpf), None);
}

#[tokio::test]
async fn collect_firewall_errors_aggregates_pending_messages() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(8);
    let _ = tx.send("first error".to_string());
    let _ = tx.send("second error".to_string());

    let errors = CommandControlService::default()
        .collect_firewall_errors(&mut rx, std::time::Duration::from_millis(50))
        .await;
    assert_eq!(errors.as_deref(), Some("first error,second error"));
}

#[tokio::test]
async fn collect_firewall_errors_returns_none_on_timeout_without_messages() {
    let (_tx, mut rx) = tokio::sync::broadcast::channel(8);

    let errors = CommandControlService::default()
        .collect_firewall_errors(&mut rx, std::time::Duration::from_millis(5))
        .await;
    assert!(errors.is_none());
}
