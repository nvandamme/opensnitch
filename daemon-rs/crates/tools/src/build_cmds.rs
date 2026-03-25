//! Build and test commands for the daemon-rs workspace crates.
//!
//! All commands stream output live (inherited stdio) so incremental build
//! progress and test output are immediately visible in the terminal.
//!
//! The daemon-rs workspace root is derived from `CARGO_MANIFEST_DIR` at
//! compile time (tools crate → crates/ → daemon-rs/).
//!
//! Override defaults via CLI flags (see cli.rs) or directly via env vars
//! (listed in brackets for each option).

use std::{
    env,
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::{DynError, env_flag, perf_repeats, perf_rust_log_level};

// ── public commands ───────────────────────────────────────────────────────────

/// `build`: `cargo build --release -p <crate>` in the daemon-rs workspace.
///
/// Crate defaults to `opensnitchd-rs`; override with `--crate=NAME`
/// [`OPENSNITCH_BUILD_CRATE`].
pub(crate) fn run_build() -> Result<(), DynError> {
    let (daemon_rs, crate_name, target) = common_params()?;
    let mut args = vec![
        "build",
        "--manifest-path",
        "Cargo.toml",
        "--release",
        "-p",
        &crate_name,
    ];
    if check_bool_flag("OPENSNITCH_BUILD_ALL_FEATURES") {
        args.push("--all-features");
    }
    run_live(&daemon_rs, &args, &[("CARGO_TARGET_DIR", &target)])
}

/// `aya-smoke-proc`: run `aya_proc_trace_smoke_reports_explicit_runtime_active`
/// with a kill-on-timeout watchdog and verifier log extraction.
///
/// Flags: `--smoke-timeout=N` [`DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS`],
///        `--smoke-kill-after=N` [`DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS`].
pub(crate) fn run_aya_proc_smoke() -> Result<(), DynError> {
    crate::test_guard::with_guard("aya-smoke-proc", || run_aya_smoke(&AyaSmokeSpec {
        label: "proc",
        test_name: "aya_proc_trace_smoke_reports_explicit_runtime_active",
        log_pattern: LogPattern::Glob {
            prefix: "opensnitch-aya-proc-trace-test-",
            suffix: ".log",
            not_found_msg: "no process smoke log found under /tmp/opensnitch-aya-proc-trace-test-*.log",
        },
    }))
}

/// `aya-smoke-dns`: run `aya_dns_trace_smoke_reports_explicit_runtime_active`.
pub(crate) fn run_aya_dns_smoke() -> Result<(), DynError> {
    crate::test_guard::with_guard("aya-smoke-dns", || run_aya_smoke(&AyaSmokeSpec {
        label: "dns",
        test_name: "aya_dns_trace_smoke_reports_explicit_runtime_active",
        log_pattern: LogPattern::Fixed {
            path: "/tmp/opensnitch-aya-dns-trace-test.log",
            not_found_msg: "missing /tmp/opensnitch-aya-dns-trace-test.log",
        },
    }))
}

/// `aya-smoke-conn`: run `aya_conn_trace_smoke_reports_explicit_runtime_active`.
pub(crate) fn run_aya_conn_smoke() -> Result<(), DynError> {
    crate::test_guard::with_guard("aya-smoke-conn", || run_aya_smoke(&AyaSmokeSpec {
        label: "conn",
        test_name: "aya_conn_trace_smoke_reports_explicit_runtime_active",
        log_pattern: LogPattern::Glob {
            prefix: "opensnitch-aya-conn-trace-test-",
            suffix: ".log",
            not_found_msg: "no connection smoke log found under /tmp/opensnitch-aya-conn-trace-test-*.log",
        },
    }))
}

/// `aya-smoke-tunnel`: run `aya_tunnel_trace_smoke_reports_tunnel_probe_activity`.
pub(crate) fn run_aya_tunnel_smoke() -> Result<(), DynError> {
    crate::test_guard::with_guard("aya-smoke-tunnel", || run_aya_smoke(&AyaSmokeSpec {
        label: "tunnel",
        test_name: "aya_tunnel_trace_smoke_reports_tunnel_probe_activity",
        log_pattern: LogPattern::Glob {
            prefix: "opensnitch-aya-tunnel-trace-test-",
            suffix: ".log",
            not_found_msg: "no tunnel smoke log found under /tmp/opensnitch-aya-tunnel-trace-test-*.log",
        },
    }))
}

/// `kernel-profile-harness`: run Rust kernel-pressure and sweep stress tests
/// `perf_repeats` times each.
///
/// Flags: `--repeats=N`, `--rust-log=LEVEL` (should be warn/error for clean output).
pub(crate) fn run_kernel_profile_harness() -> Result<(), DynError> {
    crate::test_guard::with_guard("kernel-profile-harness", || {
    let (daemon_rs, crate_name, target) = common_params()?;
    let repeats = perf_repeats();
    let rust_log = perf_rust_log_level();

    let base_envs: &[(&str, &str)] = &[
        ("CARGO_TARGET_DIR", &target),
        ("RUST_LOG", &rust_log),
        ("OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK", "1"),
    ];

    for test_name in &[
        "stress_profile_reports_kernel_pipeline_pressure",
        "stress_profile_reports_kernel_pipeline_timeout_sweep",
    ] {
        for i in 1..=repeats {
            let kind = if test_name.contains("timeout_sweep") { "sweep" } else { "pressure" };
            eprintln!(
                "[tools] kernel-profile-harness {} run {i}/{repeats}",
                kind
            );
            run_live(
                &daemon_rs,
                &[
                    "test",
                    "--manifest-path",
                    "Cargo.toml",
                    "--release",
                    "-p",
                    &crate_name,
                    test_name,
                    "--",
                    "--ignored",
                    "--nocapture",
                ],
                base_envs,
            )?;
        }
    }
    Ok(())
    }) // with_guard
}

// ── aya smoke internals ───────────────────────────────────────────────────────

enum LogPattern {
    /// Single fixed path.
    Fixed { path: &'static str, not_found_msg: &'static str },
    /// Newest file under /tmp/ whose name starts with `prefix` and ends with `suffix`.
    Glob {
        prefix: &'static str,
        suffix: &'static str,
        not_found_msg: &'static str,
    },
}

struct AyaSmokeSpec {
    label: &'static str,
    test_name: &'static str,
    log_pattern: LogPattern,
}

fn run_aya_smoke(spec: &AyaSmokeSpec) -> Result<(), DynError> {
    let (daemon_rs, _, _) = common_params()?;
    let kernel_target = kernel_target_dir(&daemon_rs);

    let timeout_secs = env::var("DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(90);
    let kill_after_secs = env::var("DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3);

    eprintln!(
        "[tools] aya-smoke-{}: starting (timeout={}s, kill_after={}s)",
        spec.label, timeout_secs, kill_after_secs
    );

    let timed_out = Arc::new(AtomicBool::new(false));
    let timed_out_clone = timed_out.clone();
    let timeout = Duration::from_secs(timeout_secs);
    let kill_after = Duration::from_secs(kill_after_secs);

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&daemon_rs)
        .args(["test", "-p", "opensnitchd-rs", spec.test_name, "--", "--ignored", "--nocapture"])
        .env("OPENSNITCH_RUN_PRIVILEGED_TESTS", "1")
        .env("OPENSNITCH_CARGO_TARGET_DIR", &kernel_target)
        .env("CARGO_TARGET_DIR", &kernel_target);

    let mut child = cmd.spawn()?;
    let child_id = child.id();

    // Watchdog: send SIGTERM after timeout, then SIGKILL after kill_after.
    let watchdog = std::thread::spawn(move || {
        std::thread::sleep(timeout);
        timed_out_clone.store(true, Ordering::Relaxed);
        Command::new("kill").args(["-TERM", &child_id.to_string()]).status().ok();
        std::thread::sleep(kill_after);
        Command::new("kill").args(["-KILL", &child_id.to_string()]).status().ok();
    });

    let status = child.wait()?;
    let _ = watchdog.join();
    let was_timeout = timed_out.load(Ordering::Relaxed);

    // Always attempt verifier log extraction.
    print_verifier_log(spec);

    if was_timeout {
        eprintln!(
            "[tools] aya-smoke-{}: timed out after {}s",
            spec.label, timeout_secs
        );
        // Best-effort cleanup: kill any leftover daemon process.
        Command::new("pkill")
            .args(["-KILL", "-x", "opensnitchd-rs"])
            .status()
            .ok();
        return Err(format!(
            "aya-smoke-{} timed out after {}s (exit 124)",
            spec.label, timeout_secs
        )
        .into());
    }

    if !status.success() {
        return Err(format!("aya-smoke-{} failed: {status}", spec.label).into());
    }

    eprintln!("[tools] aya-smoke-{}: pass", spec.label);
    Ok(())
}

/// Resolve the newest log file for `spec` and print any verifier output block.
fn print_verifier_log(spec: &AyaSmokeSpec) {
    let log_path = match &spec.log_pattern {
        LogPattern::Fixed { path, not_found_msg } => {
            if std::path::Path::new(path).exists() {
                path.to_string()
            } else {
                eprintln!("[tools] aya-smoke-{}: {}", spec.label, not_found_msg);
                return;
            }
        }
        LogPattern::Glob { prefix, suffix, not_found_msg } => {
            match newest_tmp_file_matching(prefix, suffix) {
                Some(p) => p,
                None => {
                    eprintln!("[tools] aya-smoke-{}: {}", spec.label, not_found_msg);
                    return;
                }
            }
        }
    };

    let Ok(f) = fs::File::open(&log_path) else {
        eprintln!("[tools] aya-smoke-{}: could not open {log_path}", spec.label);
        return;
    };

    let reader = BufReader::new(f);
    let mut in_block = false;
    let mut found = false;
    // Timestamp prefix pattern: 4 digits, dash, 2 digits, dash …
    for line in reader.lines().map_while(Result::ok) {
        if line.contains("Verifier output:") {
            if !found {
                println!("=== Extracted verifier output from {log_path} ===");
                found = true;
            }
            println!("{line}");
            in_block = true;
            continue;
        }
        if in_block {
            // Stop at new log timestamp line (e.g. "2026-03-25 12:34:56 …")
            if looks_like_log_timestamp(&line) {
                in_block = false;
            } else {
                println!("{line}");
            }
        }
    }

    if !found {
        eprintln!("[tools] aya-smoke-{}: no verifier stack trace found in {log_path}", spec.label);
    }
}

fn newest_tmp_file_matching(prefix: &str, suffix: &str) -> Option<String> {
    let entries = fs::read_dir("/tmp").ok()?;
    let mut candidates: Vec<(std::time::SystemTime, String)> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with(prefix) && name.ends_with(suffix) {
                let mtime = e.metadata().ok()?.modified().ok()?;
                Some((mtime, format!("/tmp/{name}")))
            } else {
                None
            }
        })
        .collect();
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    candidates.into_iter().next().map(|(_, p)| p)
}

fn looks_like_log_timestamp(line: &str) -> bool {
    // "2026-03-25 12:34:56" — 4 digit year dash 2 digit month dash …
    let b = line.as_bytes();
    b.len() > 10
        && b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b[4] == b'-'
}

fn kernel_target_dir(daemon_rs: &Path) -> String {
    env::var("DAEMON_RS_KERNEL_TARGET_DIR")
        .or_else(|_| env::var("CARGO_TARGET_DIR"))
        .unwrap_or_else(|_| daemon_rs.join("target-kernel").to_string_lossy().to_string())
}

/// `build-all`: `cargo build --release` (full workspace) in daemon-rs.
pub(crate) fn run_build_all() -> Result<(), DynError> {
    let (daemon_rs, _crate, target) = common_params()?;
    run_live(
        &daemon_rs,
        &["build", "--manifest-path", "Cargo.toml", "--release"],
        &[("CARGO_TARGET_DIR", &target)],
    )
}

/// `build-ebpf`: invoke `daemon-rs/scripts/build_ebpf.sh --release`.
///
/// Reads eBPF package/target/toolchain from env (forwarded by the Makefile or
/// CLI).  Requires root; the script enforces this itself and exits cleanly with
/// a helpful message if not root.
///
/// The privilege routing is handled by the caller (Makefile uses TEST_GUARD).
pub(crate) fn run_build_ebpf() -> Result<(), DynError> {
    crate::test_guard::with_guard("build-ebpf", || {
    let tools_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs = tools_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or("tools dir missing daemon-rs parent")?
        .to_path_buf();

    let script = daemon_rs.join("scripts/build_ebpf.sh");
    if !script.exists() {
        return Err(format!("build_ebpf.sh not found at {}", script.display()).into());
    }

    let target = kernel_target_dir(&daemon_rs);
    let pkg = env::var("DAEMON_RS_EBPF_PACKAGE")
        .unwrap_or_else(|_| "opensnitch-ebpf".to_string());
    let tgt = env::var("DAEMON_RS_EBPF_TARGET")
        .unwrap_or_else(|_| "bpfel-unknown-none".to_string());
    let toolchain = env::var("DAEMON_RS_EBPF_TOOLCHAIN")
        .unwrap_or_else(|_| "nightly".to_string());

    let status = Command::new("bash")
        .arg(&script)
        .arg("--release")
        .env("CARGO_TARGET_DIR", &target)
        .env("DAEMON_RS_EBPF_PACKAGE", &pkg)
        .env("DAEMON_RS_EBPF_TARGET", &tgt)
        .env("DAEMON_RS_EBPF_TOOLCHAIN", &toolchain)
        .status()?;

    if !status.success() {
        return Err(format!("build_ebpf.sh failed: {status}").into());
    }
    Ok(())
    }) // with_guard
}

/// `test`: run the three parity test suites in order:
/// `tests::config_service::`, `tests::firewall_service::`, `tests::client::`.
///
/// Flags: `--test-log=LEVEL` [`OPENSNITCH_TEST_LOG_LEVEL`],
///        `--crate=NAME` [`OPENSNITCH_BUILD_CRATE`].
pub(crate) fn run_parity_tests() -> Result<(), DynError> {
    crate::test_guard::with_guard("test", || {
    let (daemon_rs, crate_name, target) = common_params()?;
    let log = rust_test_log_level();
    for suite in &[
        "tests::config_service::",
        "tests::firewall_service::",
        "tests::client::",
    ] {
        run_live(
            &daemon_rs,
            &[
                "test",
                "--manifest-path",
                "Cargo.toml",
                "-p",
                &crate_name,
                suite,
                "--",
                "--nocapture",
            ],
            &[("CARGO_TARGET_DIR", &target), ("RUST_LOG", &log)],
        )?;
    }
    Ok(())
    }) // with_guard
}

/// `test-kernel-it`: run `integration_kernel_tests::` with
/// `OPENSNITCH_RUN_PRIVILEGED_TESTS=1` and `OPENSNITCH_KERNEL_IT_STRICT=1`.
///
/// Flags: `--test-log=LEVEL`, `--crate=NAME`.
pub(crate) fn run_kernel_it() -> Result<(), DynError> {
    crate::test_guard::with_guard("test-kernel-it", || {
    let (daemon_rs, crate_name, target) = common_params()?;
    let log = rust_test_log_level();
    run_live(
        &daemon_rs,
        &[
            "test",
            "--manifest-path",
            "Cargo.toml",
            "-p",
            &crate_name,
            "integration_kernel_tests::",
            "--",
            "--nocapture",
        ],
        &[
            ("CARGO_TARGET_DIR", &target),
            ("RUST_LOG", &log),
            ("OPENSNITCH_RUN_PRIVILEGED_TESTS", "1"),
            ("OPENSNITCH_KERNEL_IT_STRICT", "1"),
        ],
    )
    }) // with_guard
}

/// `test-filter`: run tests matching `--filter=PATTERN`.
///
/// Flags:
/// - `--filter=PATTERN`   (required)  [`OPENSNITCH_TEST_FILTER`]
/// - `--crate=NAME`                   [`OPENSNITCH_BUILD_CRATE`]
/// - `--test-log=LEVEL`               [`OPENSNITCH_TEST_LOG_LEVEL`]
/// - `--privileged`                   [`OPENSNITCH_RUN_PRIVILEGED_TESTS`]
/// - `--kernel-it-strict`             [`OPENSNITCH_KERNEL_IT_STRICT`]
/// - `--release`                      [`OPENSNITCH_TEST_RELEASE`]
/// - `--ignored`                      [`OPENSNITCH_TEST_IGNORED`]
pub(crate) fn run_test_filter() -> Result<(), DynError> {
    let filter = env::var("OPENSNITCH_TEST_FILTER")
        .map_err(|_| "test-filter requires --filter=PATTERN")?;
    let (daemon_rs, crate_name, target) = common_params()?;
    let log = rust_test_log_level();
    let privileged = if env_flag("OPENSNITCH_RUN_PRIVILEGED_TESTS") { "1" } else { "0" };
    let strict = if env_flag("OPENSNITCH_KERNEL_IT_STRICT") { "1" } else { "0" };

    // Build args as Strings so dynamic values (filter, crate_name) stay alive.
    let mut owned: Vec<String> = vec![
        "test".into(),
        "--manifest-path".into(),
        "Cargo.toml".into(),
        "-p".into(),
        crate_name.clone(),
    ];
    if env_flag("OPENSNITCH_TEST_RELEASE") {
        owned.push("--release".into());
    }
    owned.push(filter.clone());
    owned.push("--".into());
    owned.push("--nocapture".into());
    if env_flag("OPENSNITCH_TEST_IGNORED") {
        owned.push("--ignored".into());
    }

    let args: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
    run_live(
        &daemon_rs,
        &args,
        &[
            ("CARGO_TARGET_DIR", &target),
            ("RUST_LOG", &log),
            ("OPENSNITCH_RUN_PRIVILEGED_TESTS", privileged),
            ("OPENSNITCH_KERNEL_IT_STRICT", strict),
        ],
    )
}

// ── internals ─────────────────────────────────────────────────────────────────

fn common_params() -> Result<(std::path::PathBuf, String, String), DynError> {
    let tools_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs = tools_dir
        .parent()           // crates/
        .and_then(|p| p.parent()) // daemon-rs/
        .ok_or("tools crate missing daemon-rs grandparent")?
        .to_path_buf();

    let crate_name = env::var("OPENSNITCH_BUILD_CRATE")
        .unwrap_or_else(|_| "opensnitchd-rs".to_string());

    let target = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| {
        daemon_rs.join("target-kernel").to_string_lossy().to_string()
    });

    Ok((daemon_rs, crate_name, target))
}

fn rust_test_log_level() -> String {
    env::var("OPENSNITCH_TEST_LOG_LEVEL")
        .or_else(|_| env::var("RUST_TEST_LOG_LEVEL"))
        .unwrap_or_else(|_| "info,opensnitchd_rs=debug".to_string())
}

fn check_bool_flag(name: &str) -> bool {
    env_flag(name)
}

/// Run `cargo <cargo_args>` in `cwd` with `envs` set in the child environment.
/// Output streams live to the calling terminal (inherited stdio).
pub(crate) fn run_live(cwd: &Path, cargo_args: &[&str], envs: &[(&str, &str)]) -> Result<(), DynError> {
    let label = cargo_args.first().copied().unwrap_or("");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(cwd).args(cargo_args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    eprintln!("[tools] cargo {}", cargo_args.join(" "));
    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo {label} failed with {status}").into())
    }
}
