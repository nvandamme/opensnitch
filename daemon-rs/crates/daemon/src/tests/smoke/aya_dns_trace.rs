use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::Duration,
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
    assert!(
        status.success(),
        "{context}: command failed with status {status}"
    );
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

fn dns_smoke_rust_log() -> String {
    std::env::var("OPENSNITCH_AYA_DNS_SMOKE_RUST_LOG")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "debug".to_string())
}

#[test]
#[ignore = "requires root privileges and local kernel eBPF support"]
fn aya_dns_trace_smoke_reports_explicit_runtime_active() {
    if !opt_in_enabled() {
        return;
    }

    if !is_root() {
        panic!(
            "aya dns trace smoke requires elevated privileges; rerun using sudo/pkexec and OPENSNITCH_RUN_PRIVILEGED_TESTS=1"
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

    let rust_dns_obj = resolve_built_rust_ebpf_obj(&target_dir)
        .unwrap_or_else(|| target_dir.join("bpfel-unknown-none/release/libopensnitch_ebpf.so"));
    assert!(
        rust_dns_obj.exists(),
        "missing rust eBPF object {}; build it first with the privileged bpf build path",
        rust_dns_obj.display()
    );

    let normalized_obj = target_dir.join("bpfel-unknown-none/release/opensnitch-ebpf");
    fs::copy(&rust_dns_obj, &normalized_obj).unwrap_or_else(|err| {
        panic!(
            "copy rust eBPF object to {} failed: {err}",
            normalized_obj.display()
        )
    });

    fs::create_dir_all("/etc/opensnitchd").expect("create /etc/opensnitchd");
    fs::copy(&rust_dns_obj, "/etc/opensnitchd/opensnitch-ebpf")
        .expect("copy /etc/opensnitchd/opensnitch-ebpf");

    let _ = Command::new("pkill")
        .arg("-x")
        .arg("opensnitchd-rs")
        .status();

    // Remove stale pinned ringbuf maps from previous runs so pinning can succeed.
    let _ = fs::remove_file("/sys/fs/bpf/opensnitch-rs/dns/events");
    let _ = fs::remove_file("/sys/fs/bpf/opensnitch_dns/events");

    let smoke_log = std::env::temp_dir().join("opensnitch-aya-dns-trace-test.log");
    let _ = fs::remove_file(&smoke_log);
    let rust_log = dns_smoke_rust_log();

    let mut daemon = Command::new("timeout")
        .args(["--kill-after=2s", "18s"])
        .arg(&daemon_bin)
        .env("OPENSNITCH_EBPF_PIN_DOMAIN", "aya")
        .env("RUST_LOG", &rust_log)
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

    thread::sleep(Duration::from_secs(4));

    // Bound DNS probe time to keep smoke runtime deterministic.
    for _ in 0..8 {
        let _ = Command::new("timeout")
            .args(["1s", "getent", "hosts", "example.com"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("timeout")
            .args(["1s", "getent", "ahosts", "cloudflare.com"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        thread::sleep(Duration::from_millis(100));
    }

    let _ = daemon.wait();

    let log = fs::read_to_string(&smoke_log)
        .unwrap_or_else(|err| panic!("read {} failed: {err}", smoke_log.display()));

    assert!(
        log.contains("worker=\"ebpf-dns\""),
        "expected ebpf-dns worker trace in log {}",
        smoke_log.display()
    );
    assert!(
        log.contains("explicit DNS eBPF runtime active"),
        "expected explicit Aya DNS runtime activation in log {}",
        smoke_log.display()
    );
    assert!(
        !log.contains("explicit DNS eBPF attach/runtime unavailable"),
        "unexpected explicit DNS fallback marker in log {}",
        smoke_log.display()
    );
}
