//! Portable privilege routing and service lifecycle guard.
//!
//! Mirrors the behaviour of `daemon-rs/scripts/with_test_guard.sh`, allowing
//! all Makefile targets that previously used `$(TEST_GUARD)` to simply invoke
//! the tools binary directly — no shell wrapper needed.
//!
//! ## How it works
//!
//! Each privileged entry-point calls [`with_guard`], which:
//!
//! 1. Calls [`reexec_privileged_if_needed`] — when tools is *not* root, it
//!    re-execs the compiled tools binary under `sudo`/`pkexec`, waits for the
//!    privileged copy to finish, and exits.  The privileged copy then reaches
//!    step 2 normally.
//! 2. Calls [`preflight_cleanup`] — stops any running opensnitch services so
//!    the test payload can open exclusive kernel resources (netfilter queues,
//!    eBPF pins).
//! 3. Runs the test closure.
//! 4. Calls [`restart_stopped_services`] — restores what was stopped (unless
//!    `OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0`).
//!
//! ## Privilege env vars (checked in priority order)
//!
//! 1. `OPENSNITCH_TEST_GUARD_PRIV_CMD` — compatible with `with_test_guard.sh`
//!    and the Makefile `export` directive.
//! 2. `OPENSNITCH_TOOLS_PRIV_CMD` — tools-specific override (used by
//!    `live_logs.rs`).
//!
//! Valid values: `direct` / `none`, `sudo`, `pkexec`.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use crate::DynError;

// ── privilege level ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivCmd {
    Direct,
    Pkexec,
    Sudo,
}

// ── env-var forwarding list ───────────────────────────────────────────────────

/// Variables forwarded to the privileged process when re-executing under
/// `sudo`/`pkexec` (mirrors `with_test_guard.sh run_test_payload`).
const FORWARDED_ENV_KEYS: &[&str] = &[
    "OPENSNITCH_RUN_PRIVILEGED_TESTS",
    "OPENSNITCH_RUN_PRIVILEDGED_TESTS",
    "OPENSNITCH_CARGO_TARGET_DIR",
    "CARGO_TARGET_DIR",
    "RUST_LOG",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "HOME",
    "PATH",
    // Test guard lifecycle
    "OPENSNITCH_TEST_GUARD_RESTART_SERVICES",
    "OPENSNITCH_TEST_GUARD_PRIV_CMD",
    "OPENSNITCH_TOOLS_PRIV_CMD",
    // Perf / harness tunables
    "OPENSNITCH_PERF_REPEATS",
    "OPENSNITCH_PARITY_STRESS_ROUNDS",
    "STRESS_ROUNDS",
    "OPENSNITCH_PERF_RUST_LOG_LEVEL",
    "OPENSNITCH_PERF_GO_LOG_LEVEL",
    "OPENSNITCH_PARITY_PREBUILD",
    "GO_KERNEL_PRESSURE_SECS",
    "GO_KERNEL_PRESSURE_SWEEP_SECS",
    "OPENSNITCH_TEST_LOG_LEVEL",
    "OPENSNITCH_BUILD_CRATE",
    "DAEMON_RS_EBPF_PACKAGE",
    "DAEMON_RS_EBPF_TARGET",
    "DAEMON_RS_EBPF_TOOLCHAIN",
    "DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS",
    "DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS",
    "PERF_MD_PATH",
    "OPENSNITCH_PERF_CACHE_DIR",
    "OPENSNITCH_PARITY_REQUIRE_EXCEED_GO",
    "OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK",
    "OPENSNITCH_PARITY_PREBUILD_DONE",
];

// ── infrastructure helpers ────────────────────────────────────────────────────

pub(crate) fn command_exists(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub(crate) fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Determine privilege routing.  Checks (in order):
/// `OPENSNITCH_TEST_GUARD_PRIV_CMD`, `OPENSNITCH_TOOLS_PRIV_CMD`, already
/// root → Direct, default → Sudo.
pub(crate) fn pick_priv_cmd() -> PrivCmd {
    if is_root() {
        return PrivCmd::Direct;
    }
    for var in &["OPENSNITCH_TEST_GUARD_PRIV_CMD", "OPENSNITCH_TOOLS_PRIV_CMD"] {
        if let Ok(raw) = env::var(var) {
            match raw.trim().to_ascii_lowercase().as_str() {
                "direct" | "none" => return PrivCmd::Direct,
                "pkexec" => return PrivCmd::Pkexec,
                "sudo" => return PrivCmd::Sudo,
                _ => {}
            }
        }
    }
    PrivCmd::Sudo
}

/// Resolve the repository root from `CARGO_MANIFEST_DIR` (set at compile time
/// for the `tools` crate): `tools/` → `crates/` → `daemon-rs/` → repo root.
pub(crate) fn repo_root() -> Result<PathBuf, DynError> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(|p| p.parent()) // daemon-rs/
        .and_then(|p| p.parent()) // repo root
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "cannot resolve repo root from CARGO_MANIFEST_DIR".into())
}

pub(crate) fn ensure_privileged_ready(
    cwd: &Path,
    priv_cmd: PrivCmd,
    action: &str,
) -> Result<(), DynError> {
    match priv_cmd {
        PrivCmd::Direct => Ok(()),
        PrivCmd::Sudo => run_command_capture(cwd, "sudo", &["-v"])
            .map(|_| ())
            .map_err(|err| {
                format!(
                    "{action} requires elevated privileges and sudo auth failed. Details: {err}"
                )
                .into()
            }),
        PrivCmd::Pkexec => {
            if command_exists("pkexec") {
                Ok(())
            } else {
                Err(format!("{action} requires pkexec but it is not in PATH").into())
            }
        }
    }
}

pub(crate) fn run_command_capture(
    cwd: &Path,
    program: &str,
    args: &[&str],
) -> Result<String, DynError> {
    let output = Command::new(program).current_dir(cwd).args(args).output()?;
    if output.status.success() {
        let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok(combined)
    } else {
        Err(format!(
            "command failed: {} {}\nstdout:\n{}\nstderr:\n{}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into())
    }
}

pub(crate) fn run_privileged_command(
    cwd: &Path,
    priv_cmd: PrivCmd,
    program: &str,
    args: &[&str],
) -> Result<String, DynError> {
    match priv_cmd {
        PrivCmd::Direct => run_command_capture(cwd, program, args),
        PrivCmd::Sudo => {
            let mut all = Vec::with_capacity(args.len() + 2);
            all.push("--");
            all.push(program);
            all.extend_from_slice(args);
            run_command_capture(cwd, "sudo", &all)
        }
        PrivCmd::Pkexec => {
            let mut all = Vec::with_capacity(args.len() + 1);
            all.push(program);
            all.extend_from_slice(args);
            match run_command_capture(cwd, "pkexec", &all) {
                Ok(o) => Ok(o),
                Err(e) => {
                    let text = e.to_string();
                    if text.contains("exit status: 126") || text.contains("exit status: 127") {
                        let mut sudo_args = Vec::with_capacity(args.len() + 2);
                        sudo_args.push("--");
                        sudo_args.push(program);
                        sudo_args.extend_from_slice(args);
                        run_command_capture(cwd, "sudo", &sudo_args)
                    } else {
                        Err(e)
                    }
                }
            }
        }
    }
}

pub(crate) fn kill_if_running(repo_root: &Path, priv_cmd: PrivCmd, proc_name: &str) {
    let running = Command::new("pgrep")
        .arg("-x")
        .arg(proc_name)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if running {
        let _ = run_privileged_command(repo_root, priv_cmd, "pkill", &["-x", proc_name]);
    }
}

fn stop_service_if_active(repo_root: &Path, priv_cmd: PrivCmd, scope: &str, svc: &str) -> bool {
    let mut show_args = vec!["show", "--property=ActiveState", svc];
    if scope == "user" {
        show_args.insert(0, "--user");
    }
    let active = match Command::new("systemctl").args(&show_args).output() {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).contains("ActiveState=active")
        }
        _ => false,
    };
    if !active {
        return false;
    }
    if scope == "user" {
        let _ = run_command_capture(repo_root, "systemctl", &["--user", "stop", svc]);
    } else {
        let _ = run_privileged_command(repo_root, priv_cmd, "systemctl", &["stop", svc]);
    }
    true
}

/// Stop all opensnitch-related services and processes.  Returns the list of
/// `(scope, service)` pairs that were stopped so they can be restarted via
/// [`restart_stopped_services`].
pub(crate) fn preflight_cleanup(
    repo_root: &Path,
    priv_cmd: PrivCmd,
) -> Vec<(String, String)> {
    let mut stopped = Vec::new();
    if command_exists("systemctl") {
        for svc in ["opensnitchd-rs", "opensnitchd", "opensnitch-ui"] {
            if stop_service_if_active(repo_root, priv_cmd, "system", svc) {
                stopped.push(("system".to_string(), svc.to_string()));
            }
            if stop_service_if_active(repo_root, priv_cmd, "user", svc) {
                stopped.push(("user".to_string(), svc.to_string()));
            }
        }
    }
    kill_if_running(repo_root, priv_cmd, "opensnitchd-rs");
    kill_if_running(repo_root, priv_cmd, "opensnitchd");
    let _ = run_command_capture(
        repo_root,
        "pkill",
        &["-f", "(^|[[:space:]]|/)opensnitch-ui([[:space:]]|$)"],
    );
    stopped
}

/// Restart services stopped by [`preflight_cleanup`] (reverse order).
/// Skipped when `OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0`.
pub(crate) fn restart_stopped_services(
    repo_root: &Path,
    priv_cmd: PrivCmd,
    stopped: &[(String, String)],
) {
    if env::var("OPENSNITCH_TEST_GUARD_RESTART_SERVICES").as_deref() == Ok("0") {
        return;
    }
    if !command_exists("systemctl") || stopped.is_empty() {
        return;
    }
    for (scope, svc) in stopped.iter().rev() {
        if scope == "user" {
            let _ = run_command_capture(repo_root, "systemctl", &["--user", "start", svc]);
        } else {
            let _ = run_privileged_command(repo_root, priv_cmd, "systemctl", &["start", svc]);
        }
    }
}

// ── re-exec under privilege ───────────────────────────────────────────────────

fn forwarded_env_pairs() -> Vec<String> {
    FORWARDED_ENV_KEYS
        .iter()
        .filter_map(|k| env::var(k).ok().map(|v| format!("{k}={v}")))
        .collect()
}

/// If this process is not root **and** a privilege escalation method is
/// configured, re-execute the compiled tools binary under `sudo env …` /
/// `pkexec env …` with the same arguments, wait for it to finish, and exit
/// with its code.  This mirrors `with_test_guard.sh run_test_payload`.
///
/// Returns `Ok(())` when already root or when `PrivCmd::Direct` is configured,
/// allowing the caller to proceed normally.  On re-exec, this function **never
/// returns** — the current process exits with the privileged child's code.
pub(crate) fn reexec_privileged_if_needed() -> Result<(), DynError> {
    if is_root() {
        return Ok(());
    }
    let priv_cmd = pick_priv_cmd();
    if priv_cmd == PrivCmd::Direct {
        return Ok(());
    }

    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    ensure_privileged_ready(&cwd, priv_cmd, "tools")?;

    let bin = std::env::current_exe()
        .map_err(|e| format!("cannot resolve tools binary path: {e}"))?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pairs = forwarded_env_pairs();

    let build_cmd = |escalator: &str| {
        let mut cmd = Command::new(escalator);
        cmd.arg("env");
        for p in &pairs {
            cmd.arg(p);
        }
        cmd.arg(&bin).args(&args);
        cmd
    };

    let status = match priv_cmd {
        PrivCmd::Direct => unreachable!(),
        PrivCmd::Sudo => build_cmd("sudo").status()?,
        PrivCmd::Pkexec => {
            let s = build_cmd("pkexec").status()?;
            if s.code() == Some(126) || s.code() == Some(127) {
                // pkexec unavailable or auth cancelled — fall back to sudo.
                ensure_privileged_ready(&cwd, PrivCmd::Sudo, "tools (sudo fallback)")?;
                build_cmd("sudo").status()?
            } else {
                s
            }
        }
    };

    std::process::exit(status.code().unwrap_or(1));
}

// ── high-level guard wrapper ──────────────────────────────────────────────────

/// Run `f` wrapped by the full test guard: re-exec under privilege if needed,
/// stop services before the test, restart them afterwards.
///
/// This is the single call-site needed in each privileged command entry point.
pub(crate) fn with_guard<F>(action: &str, f: F) -> Result<(), DynError>
where
    F: FnOnce() -> Result<(), DynError>,
{
    reexec_privileged_if_needed()?;
    let root = repo_root()?;
    let priv_cmd = pick_priv_cmd();
    ensure_privileged_ready(&root, priv_cmd, action)?;
    let stopped = preflight_cleanup(&root, priv_cmd);
    let result = f();
    restart_stopped_services(&root, priv_cmd, &stopped);
    result
}
