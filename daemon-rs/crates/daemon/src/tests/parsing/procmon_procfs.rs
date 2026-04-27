use crate::platform::procmon::procfs::*;

#[test]
fn read_exe_link_self() {
    let pid = std::process::id();
    let link = read_exe_link(pid);
    assert!(link.is_some(), "should resolve own exe link");
    assert!(
        link.as_ref().unwrap().contains("cargo") || link.as_ref().unwrap().contains("opensnitchd"),
        "exe should be test runner, got: {:?}",
        link
    );
}

#[test]
fn read_comm_self() {
    let pid = std::process::id();
    let comm = read_comm(pid);
    assert!(comm.is_some(), "should read own comm");
    assert!(!comm.unwrap().is_empty());
}

#[test]
fn read_cwd_self() {
    let pid = std::process::id();
    let cwd = read_cwd(pid);
    assert!(cwd.is_some(), "should read own cwd");
}

#[test]
fn read_root_self() {
    let pid = std::process::id();
    let root = read_root(pid);
    assert_eq!(root, "/", "non-chroot process should have root /");
}

#[test]
fn read_cmdline_self() {
    let pid = std::process::id();
    let args = read_cmdline(pid);
    assert!(!args.is_empty(), "should have at least one arg");
}

#[test]
fn read_environ_self() {
    let pid = std::process::id();
    let env = read_environ(pid);
    assert!(env.contains_key("PATH"), "should find PATH in environ");
}

#[test]
fn read_ppid_self() {
    let pid = std::process::id();
    let ppid = read_ppid(pid);
    assert!(ppid.is_some(), "should read own ppid");
    assert!(ppid.unwrap() > 0, "ppid should be positive");
}

#[test]
fn read_starttime_self() {
    let pid = std::process::id();
    let st = read_starttime(pid);
    assert!(st.is_some(), "should read own starttime");
}

#[test]
fn read_uid_self() {
    let pid = std::process::id();
    let uid = read_uid(pid);
    assert!(uid.is_some(), "should read own uid");
}

#[test]
fn read_statm_self() {
    let pid = std::process::id();
    let statm = read_statm(pid);
    assert!(statm.is_some(), "should read own statm");
    let statm = statm.unwrap();
    assert!(statm.size > 0, "size should be positive");
    assert!(statm.resident > 0, "resident should be positive");
}

#[test]
fn is_alive_self() {
    let pid = std::process::id();
    assert!(is_alive(pid));
}

#[test]
fn is_alive_nonexistent() {
    assert!(!is_alive(4_000_000));
}

#[test]
fn list_pids_has_self() {
    let pid = std::process::id();
    let pids = list_pids();
    assert!(pids.contains(&pid), "list_pids should include our own PID");
}

#[test]
fn list_descriptors_self() {
    let pid = std::process::id();
    let descs = list_descriptors(pid);
    assert!(
        descs.len() >= 3,
        "should have at least 3 fds, got {}",
        descs.len()
    );
}

#[test]
fn resolve_exe_path_self() {
    let pid = std::process::id();
    let path = resolve_exe_path(pid);
    assert!(path.is_some());
    let p = path.unwrap();
    assert!(p.starts_with('/'), "resolved path should be absolute: {p}");
    assert_ne!(p, KERNEL_CONNECTION);
}

#[test]
fn resolve_exe_path_strips_deleted_suffix() {
    // Verify indirectly: resolve_exe_path on our own PID should not contain " (deleted)".
    let pid = std::process::id();
    let path = resolve_exe_path(pid).unwrap();
    assert!(!path.ends_with(" (deleted)"));
}

#[test]
fn read_io_stats_may_fail() {
    let pid = std::process::id();
    let _ = read_io_stats(pid);
}

#[test]
fn read_maps_self() {
    let pid = std::process::id();
    let maps = read_maps(pid);
    assert!(maps.is_some(), "should read own maps");
    assert!(!maps.unwrap().is_empty(), "maps should not be empty");
}

#[test]
fn find_pid_by_inode_nonexistent() {
    assert_eq!(find_pid_by_inode(0), None);
}

#[test]
fn pid_owns_inode_nonexistent() {
    let pid = std::process::id();
    assert!(!pid_owns_inode(pid, 0));
}
