use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use nix::libc;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn opt_in_enabled() -> bool {
    if is_root() {
        return true;
    }
    if std::env::var("OPENSNITCH_RUN_PRIVILEGED_TESTS")
        .map(|value| value == "1")
        .unwrap_or(false)
    {
        return true;
    }
    if std::env::var("OPENSNITCH_RUN_PRIVILEDGED_TESTS")
        .map(|value| value == "1")
        .unwrap_or(false)
    {
        return true;
    }
    false
}

fn daemon_rs_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cargo_target_dir(root: &PathBuf) -> PathBuf {
    std::env::var_os("OPENSNITCH_CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"))
}

fn run_status(cmd: &mut Command, context: &str) {
    let status = cmd.status().unwrap_or_else(|err| {
        panic!("{context}: failed to spawn command: {err}");
    });
    assert!(status.success(), "{context}: command failed with status {status}");
}

fn resolve_built_rust_ebpf_obj(target_dir: &PathBuf) -> Option<PathBuf> {
    let release_so = target_dir.join("bpfel-unknown-none/release/libopensnitch_ebpf.so");
    let debug_so = target_dir.join("bpfel-unknown-none/debug/libopensnitch_ebpf.so");
    if release_so.exists() {
        Some(release_so)
    } else if debug_so.exists() {
        Some(debug_so)
    } else {
        None
    }
}

#[test]
#[ignore = "requires root privileges and local kernel eBPF support"]
fn aya_proc_trace_smoke_reports_explicit_runtime_active() {
    if !opt_in_enabled() {
        return;
    }

    if !is_root() {
        panic!(
            "aya process trace smoke requires elevated privileges; rerun using sudo/pkexec and OPENSNITCH_RUN_PRIVILEGED_TESTS=1"
        );
    }

    let daemon_root = daemon_rs_root();
    let target_dir = cargo_target_dir(&daemon_root);
    let daemon_bin = target_dir.join("release/opensnitchd-rs");
    run_status(
        Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("-p")
            .arg("opensnitchd-rs")
            .env("CARGO_TARGET_DIR", &target_dir)
            .current_dir(&daemon_root),
        "build opensnitchd-rs",
    );

    run_status(
        Command::new("cargo")
            .arg("+nightly")
            .arg("build")
            .arg("-p")
            .arg("opensnitch-ebpf")
            .arg("-Z")
            .arg("build-std=core")
            .arg("-Z")
            .arg("build-std-features=compiler-builtins-mem")
            .arg("--target")
            .arg("bpfel-unknown-none")
            .arg("--release")
            .env("CARGO_TARGET_DIR", &target_dir)
            .current_dir(&daemon_root),
        "build opensnitch-ebpf",
    );

    let rust_obj = resolve_built_rust_ebpf_obj(&target_dir)
        .unwrap_or_else(|| target_dir.join("bpfel-unknown-none/release/libopensnitch_ebpf.so"));
    assert!(
        rust_obj.exists(),
        "missing rust eBPF object {}; build it first with the privileged bpf build path",
        rust_obj.display()
    );

    let _ = fs::create_dir_all(target_dir.join("bpfel-unknown-none/release"));
    let normalized_obj = target_dir.join("bpfel-unknown-none/release/opensnitch-ebpf");
    fs::copy(&rust_obj, &normalized_obj)
        .unwrap_or_else(|err| panic!("copy rust eBPF object to {} failed: {err}", normalized_obj.display()));

    fs::create_dir_all("/etc/opensnitchd").expect("create /etc/opensnitchd");
    fs::copy(&rust_obj, "/etc/opensnitchd/opensnitch-ebpf")
        .expect("copy /etc/opensnitchd/opensnitch-ebpf");

    let _ = Command::new("pkill").arg("-x").arg("opensnitchd-rs").status();

    // Remove stale pinned ringbuf maps from previous runs so pinning can succeed.
    let _ = fs::remove_file("/sys/fs/bpf/opensnitch-rs/procs/events");
    let _ = fs::remove_file("/sys/fs/bpf/opensnitch_procs/events");

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let smoke_log = std::env::temp_dir().join(format!("opensnitch-aya-proc-trace-test-{unique}.log"));

    let mut daemon = Command::new("timeout")
        .arg("24s")
        .arg(&daemon_bin)
        .env("OPENSNITCH_EBPF_PIN_DOMAIN", "aya")
        .env("OPENSNITCH_TUNE_KERNEL_PROCESS_QUEUE_CAPACITY", "8192")
        .env("OPENSNITCH_TUNE_KERNEL_PROCESS_DISPATCH_BATCH_SIZE", "256")
        .env("RUST_LOG", "debug")
        .stdout(
            fs::File::create(&smoke_log)
                .unwrap_or_else(|err| panic!("create {} failed: {err}", smoke_log.display())),
        )
        .stderr(
            fs::File::options()
                .append(true)
                .open(&smoke_log)
                .unwrap_or_else(|err| panic!("open {} failed: {err}", smoke_log.display())),
        )
        .spawn()
        .expect("start opensnitchd-rs smoke daemon");

    thread::sleep(Duration::from_secs(2));

    for _ in 0..180 {
        let _ = Command::new("/bin/true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("/usr/bin/env")
            .arg("true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        thread::sleep(Duration::from_millis(100));
    }

    let _ = daemon.wait();

    let log = fs::read_to_string(&smoke_log)
        .unwrap_or_else(|err| panic!("read {} failed: {err}", smoke_log.display()));

    assert!(
        log.contains("worker=\"ebpf-proc\""),
        "expected ebpf-proc worker trace in log {}",
        smoke_log.display()
    );
    assert!(
        log.contains("explicit process eBPF runtime active"),
        "expected explicit Aya process runtime activation in log {}",
        smoke_log.display()
    );
    assert!(
        log.contains("explicit process tracepoints attached"),
        "expected explicit process tracepoint attach evidence in log {}",
        smoke_log.display()
    );
    assert!(
        log.contains("native eBPF process state event received"),
        "expected process payload events from eBPF tracepoints in log {}",
        smoke_log.display()
    );
}
