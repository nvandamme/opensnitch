use std::path::PathBuf;

pub(crate) fn proc_pid_exists(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).exists()
}

pub(crate) fn proc_sys_kernel_value(name: &str) -> Option<String> {
    std::fs::read_to_string(format!("/proc/sys/kernel/{name}"))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}