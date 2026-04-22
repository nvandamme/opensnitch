use crate::commands::command_control::{LogLevelExt, reconfigure_target};
use crate::config::ProcMonitorMethod;

#[test]
fn log_level_validation_matches_supported_range() {
    assert!((-1_i32).is_valid_log_level());
    assert!(0_i32.is_valid_log_level());
    assert!(5_i32.is_valid_log_level());
    assert!(!(-2_i32).is_valid_log_level());
    assert!(!6_i32.is_valid_log_level());
}

#[test]
fn reconfigure_target_disables_proc_workers_when_interception_is_off() {
    assert_eq!(
        reconfigure_target(true, ProcMonitorMethod::Audit),
        Some(ProcMonitorMethod::Audit)
    );
    assert_eq!(reconfigure_target(false, ProcMonitorMethod::Ebpf), None);
}
