use crate::utils::proc_fs::proc_pid_exists;

#[test]
fn builds_pid_path_under_proc() {
    assert_eq!(
        std::path::PathBuf::from(format!("/proc/{}", 42)),
        std::path::PathBuf::from("/proc/42")
    );
}

#[test]
fn current_process_pid_exists() {
    assert!(proc_pid_exists(std::process::id()));
}

#[test]
fn implausibly_large_pid_does_not_exist() {
    assert!(!proc_pid_exists(u32::MAX));
}
