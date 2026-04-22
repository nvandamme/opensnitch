use std::{
    collections::{HashMap, HashSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::Duration,
};

use crate::test_guard::{
    PrivCmd, ensure_privileged_ready, pick_priv_cmd, preflight_cleanup, restart_stopped_services,
    run_privileged_command,
};
use crate::{DynError, compact_timestamp, env_flag};

// ── live-test isolation ───────────────────────────────────────────────────────

/// Creates a per-session isolated rules directory under
/// `/tmp/opensnitch-live-test-<ts>/rules/` containing only the dev-default
/// loopback-allow rules from `daemon/data/rules/`.
///
/// Pass the returned path to the daemon with `--rules-path <dir>`, mirroring
/// the Go daemon flag of the same name.  No user- or machine-specific rules
/// (e.g. allow-always-python3) are present, so RFC 5737 TEST-NET traffic is
/// always unmatched and reaches the AskRule flow deterministically.
fn create_live_test_rules_dir(ts: &str, repo_root: &Path) -> Result<PathBuf, DynError> {
    let rules_dir = std::env::temp_dir()
        .join(format!("opensnitch-live-test-{ts}"))
        .join("rules");
    fs::create_dir_all(&rules_dir)?;

    // Copy only the two loopback-allow JSON files from daemon/data/rules/.
    let dev_rules_src = repo_root.join("daemon").join("data").join("rules");
    for entry in fs::read_dir(&dev_rules_src)?.flatten() {
        if entry.path().extension().is_some_and(|e| e == "json") {
            fs::copy(entry.path(), rules_dir.join(entry.file_name()))?;
        }
    }

    println!("live test rules: {}", rules_dir.display());
    Ok(rules_dir)
}

pub(crate) fn launch_daemon_live_logs() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;

    let logs_dir = env::var("OPENSNITCH_DAEMON_RS_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join("logs"));
    fs::create_dir_all(&logs_dir)?;

    let ts = compact_timestamp()?;
    let stem = format!("daemon-rs-live-{ts}");
    let stdout_path = logs_dir.join(format!("{stem}-stdout.log"));
    let stderr_path = logs_dir.join(format!("{stem}-stderr.log"));
    let daemon_log_path = logs_dir.join(format!("daemon-rs-{ts}.log"));
    let latest_path = logs_dir.join("daemon-rs-live.latest");
    let rust_log = env::var("OPENSNITCH_DAEMON_RS_RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let pin_domain = env::var("OPENSNITCH_EBPF_PIN_DOMAIN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "aya".to_string());
    let run_release = !env_flag("OPENSNITCH_DAEMON_RS_LIVE_DEBUG");
    let manifest_path = daemon_rs_dir.join("Cargo.toml");
    let priv_cmd = pick_priv_cmd();

    ensure_privileged_ready(repo_root, priv_cmd, "launch-daemon-live-logs")?;
    let stopped_services = preflight_cleanup(repo_root, priv_cmd);

    // Rules directory: honour explicit CLI override (--rules-path / OPENSNITCH_DAEMON_RULES_PATH);
    // fall back to an isolated temp dir so machine-specific rules can't mask AskRule.
    let rules_path = if let Ok(p) = env::var("OPENSNITCH_DAEMON_RULES_PATH") {
        PathBuf::from(p)
    } else {
        create_live_test_rules_dir(&ts, repo_root)?
    };

    let stdout_file = fs::File::create(&stdout_path)?;
    let stderr_file = fs::File::create(&stderr_path)?;

    let mut command = match priv_cmd {
        PrivCmd::Direct => Command::new("env"),
        PrivCmd::Pkexec => {
            let mut cmd = Command::new("pkexec");
            cmd.arg("env");
            cmd
        }
        PrivCmd::Sudo => {
            let mut cmd = Command::new("sudo");
            cmd.arg("env");
            cmd
        }
    };
    command.arg(format!("RUST_LOG={rust_log}")).arg(format!(
        "OPENSNITCH_DAEMON_RS_LOG_FILE={}",
        daemon_log_path.display()
    ));

    command.arg(format!("OPENSNITCH_EBPF_PIN_DOMAIN={pin_domain}"));

    command.arg("cargo").arg("run");

    if run_release {
        command.arg("--release");
    }

    command
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("-p")
        .arg("opensnitchd-rs")
        // `--` separates cargo flags from binary flags; what follows goes to the daemon.
        .arg("--")
        .arg("--rules-path")
        .arg(&rules_path);

    if let Ok(config_file) = env::var("OPENSNITCH_DAEMON_CONFIG_FILE") {
        command.arg("--config-file").arg(config_file);
    }
    if let Ok(ui_socket) = env::var("OPENSNITCH_DAEMON_UI_SOCKET") {
        command.arg("--ui-socket").arg(ui_socket);
    }

    command
        .current_dir(repo_root)
        .stdout(stdout_file)
        .stderr(stderr_file);

    let child = command.spawn()?;
    let pid = child.id();

    let mode = if run_release { "release" } else { "debug" };
    let privilege = match priv_cmd {
        PrivCmd::Direct => "direct",
        PrivCmd::Pkexec => "pkexec",
        PrivCmd::Sudo => "sudo",
    };
    let stopped_services_field: String = stopped_services
        .iter()
        .map(|(scope, svc)| format!("{scope}:{svc}"))
        .collect::<Vec<_>>()
        .join(" ");
    let latest_content = format!(
        "pid={pid}\nmode={mode}\nprivilege={privilege}\nrust_log={rust_log}\nstdout={}\nstderr={}\nlogfile={}\nstopped_services={stopped_services_field}\n",
        stdout_path.display(),
        stderr_path.display(),
        daemon_log_path.display(),
    );
    fs::write(&latest_path, latest_content)?;

    println!("daemon-rs live log session launched pid={pid} mode={mode} privilege={privilege}");
    println!("stdout={}", stdout_path.display());
    println!("stderr={}", stderr_path.display());
    println!("logfile={}", daemon_log_path.display());
    println!("latest={}", latest_path.display());
    println!("tail: tail -f {}", stdout_path.display(),);
    println!("stop: sudo kill {pid}");

    Ok(())
}

pub(crate) fn stop_daemon_live_logs() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;

    let logs_dir = env::var("OPENSNITCH_DAEMON_RS_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join("logs"));
    let latest_path = logs_dir.join("daemon-rs-live.latest");
    let priv_cmd = pick_priv_cmd();

    if !latest_path.exists() {
        println!(
            "no live session metadata found at {}",
            latest_path.display()
        );
        return Ok(());
    }

    let latest_content = fs::read_to_string(&latest_path)?;
    let Some(pid_line) = latest_content
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
    else {
        fs::remove_file(&latest_path)?;
        println!(
            "stale metadata without pid removed at {}",
            latest_path.display()
        );
        return Ok(());
    };
    let pid_str = pid_line.trim().to_string();
    let stopped_services_record: Vec<(String, String)> = latest_content
        .lines()
        .find_map(|line| line.strip_prefix("stopped_services="))
        .unwrap_or("")
        .split_ascii_whitespace()
        .filter_map(|entry| {
            let mut parts = entry.splitn(2, ':');
            let scope = parts.next()?.to_string();
            let svc = parts.next()?.to_string();
            Some((scope, svc))
        })
        .collect();

    let _pid: u32 = pid_str.parse().map_err(|err| {
        format!(
            "invalid pid '{pid_str}' in {}: {err}",
            latest_path.display()
        )
    })?;

    ensure_privileged_ready(repo_root, priv_cmd, "stop-daemon-live-logs")?;

    match run_privileged_command(repo_root, priv_cmd, "kill", &["-0", pid_str.as_str()]) {
        Ok(_) => {
            let root_pid: u32 = pid_str
                .parse()
                .map_err(|err| format!("invalid pid '{pid_str}': {err}"))?;
            let mut targets = collect_process_tree_pids(root_pid);
            targets.push(root_pid);
            targets.sort_unstable();
            targets.dedup();

            // Kill children before launcher/root to avoid orphaning daemon descendants.
            targets.sort_unstable_by(|a, b| b.cmp(a));
            for pid in &targets {
                let pid_value = pid.to_string();
                let _ = run_privileged_command(
                    repo_root,
                    priv_cmd,
                    "kill",
                    &["-TERM", pid_value.as_str()],
                );
            }

            thread::sleep(Duration::from_millis(200));

            for pid in &targets {
                let pid_value = pid.to_string();
                let still_alive = run_privileged_command(
                    repo_root,
                    priv_cmd,
                    "kill",
                    &["-0", pid_value.as_str()],
                )
                .is_ok();

                if still_alive {
                    let _ = run_privileged_command(
                        repo_root,
                        priv_cmd,
                        "kill",
                        &["-KILL", pid_value.as_str()],
                    );
                }
            }

            println!(
                "stopped daemon-rs live session pid={pid_str} tree_size={}",
                targets.len()
            );
        }
        Err(err) => {
            let text = err.to_string();
            if text.contains("No such process") {
                println!("daemon-rs live session pid={pid_str} was already stopped");
            } else {
                return Err(err);
            }
        }
    }

    fs::remove_file(&latest_path)?;
    println!("removed metadata file {}", latest_path.display());
    restart_stopped_services(repo_root, priv_cmd, &stopped_services_record);

    Ok(())
}

fn wait_for_log_patterns(path: &Path, patterns: &[&str], timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(content) = fs::read_to_string(path) {
            if patterns.iter().all(|pattern| content.contains(pattern)) {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(200));
    }

    false
}

fn stop_mock_ui_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn run_daemon_mock_ui_live_session() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;

    let logs_dir = env::var("OPENSNITCH_DAEMON_RS_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join("logs"));
    fs::create_dir_all(&logs_dir)?;

    let ts = compact_timestamp()?;
    let mock_stdout = logs_dir.join(format!("mock-ui-live-{ts}-stdout.log"));
    let mock_stderr = logs_dir.join(format!("mock-ui-live-{ts}-stderr.log"));
    let ready_file = logs_dir.join(format!("mock-ui-live-{ts}.ready"));

    let mock_socket =
        env::var("OPENSNITCH_MOCK_UI_SOCKET").unwrap_or_else(|_| "/tmp/osui.sock".to_string());
    let session_secs = env::var("OPENSNITCH_MOCK_UI_SESSION_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(180)
        .max(5);
    let mock_runtime_secs = env::var("OPENSNITCH_MOCK_UI_RUNTIME_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(session_secs + 30)
        .max(session_secs + 10);
    let ready_timeout_secs = env::var("OPENSNITCH_MOCK_UI_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10)
        .max(2);

    let script_path = repo_root.join("daemon-rs/scripts/mock_ui_client.py");
    if !script_path.exists() {
        return Err(format!("missing mock-ui script: {}", script_path.display()).into());
    }

    let socket_path = PathBuf::from(&mock_socket);
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }
    if ready_file.exists() {
        let _ = fs::remove_file(&ready_file);
    }

    let stdout_file = fs::File::create(&mock_stdout)?;
    let stderr_file = fs::File::create(&mock_stderr)?;

    let mut mock_cmd = Command::new("python3");
    mock_cmd
        .arg(&script_path)
        .arg("--socket")
        .arg(&mock_socket)
        .arg("--runtime-seconds")
        .arg(mock_runtime_secs.to_string())
        .arg("--ready-file")
        .arg(&ready_file);

    #[cfg(feature = "subscriptions")]
    mock_cmd.arg("--subscriptions");

    let mut mock_child = mock_cmd
        .current_dir(repo_root)
        .stdout(stdout_file)
        .stderr(stderr_file)
        .spawn()?;

    if !wait_for_log_patterns(
        &mock_stdout,
        &["MOCK_UI READY"],
        Duration::from_secs(ready_timeout_secs),
    ) {
        stop_mock_ui_child(&mut mock_child);
        return Err(format!(
            "mock-ui did not become ready in {}s; see {} and {}",
            ready_timeout_secs,
            mock_stdout.display(),
            mock_stderr.display()
        )
        .into());
    }

    launch_daemon_live_logs()?;

    let handshake_markers: Vec<&str> = vec![
        "MOCK_UI Subscribe",
        "MOCK_UI SubscribeNode",
        "MOCK_UI Ping",
        "MOCK_UI Notifications stream open",
        "MOCK_UI PingStats",
        // Notification command round-trips (mock → daemon → NotificationReply)
        "MOCK_UI NotificationCommandReply cmd=LOG_LEVEL",
        "MOCK_UI NotificationCommandReply cmd=CHANGE_RULE",
        "MOCK_UI NotificationCommandReply cmd=ENABLE_RULE",
        "MOCK_UI NotificationCommandReply cmd=DISABLE_RULE",
        "MOCK_UI NotificationCommandReply cmd=DELETE_RULE",
        "MOCK_UI NotificationCommandReply cmd=ENABLE_FIREWALL",
        "MOCK_UI NotificationCommandReply cmd=DISABLE_FIREWALL",
        "MOCK_UI NotificationCommandReply cmd=RELOAD_FW_RULES",
        // Session recap fires once all initial-batch commands are acked.
        // AskRule results (if any background traffic matched) are included.
        "MOCK_UI SessionRecap status=PASS",
        // subscriptions feature: daemon calls back into Subscriptions.List RPC
        #[cfg(feature = "subscriptions")]
        "MOCK_UI SubscriptionsList",
    ];

    let observed = wait_for_log_patterns(
        &mock_stdout,
        &handshake_markers,
        Duration::from_secs(session_secs),
    );

    let _ = stop_daemon_live_logs();
    stop_mock_ui_child(&mut mock_child);

    // Print the recap table directly to test stdout so it's visible without
    // inspecting the log file artifact.  Extract the last ┌…└ block, which
    // corresponds to the final (Case C) stable stream.
    if let Ok(content) = fs::read_to_string(&mock_stdout) {
        let lines: Vec<&str> = content.lines().collect();
        let mut table_start: Option<usize> = None;
        let mut table_end: Option<usize> = None;
        for (i, line) in lines.iter().enumerate() {
            if line.starts_with('┌') {
                table_start = Some(i);
            }
            if line.starts_with('└') {
                table_end = Some(i);
            }
        }
        if let (Some(start), Some(end)) = (table_start, table_end) {
            println!();
            for line in &lines[start..=end] {
                println!("{line}");
            }
            if let Some(recap) = lines
                .iter()
                .rev()
                .find(|l| l.starts_with("MOCK_UI SessionRecap"))
            {
                println!("{recap}");
            }
            println!();
        }
    }

    if !observed {
        return Err(format!(
            "daemon->mock-ui handshake markers were not fully observed within {}s; inspect {}",
            session_secs,
            mock_stdout.display()
        )
        .into());
    }

    #[cfg(feature = "subscriptions")]
    println!(
        "mock-ui live session: pass (subscribe/ping/notifications/ping-stats/log-level-reply/subscriptions-list observed) stdout={} stderr={}",
        mock_stdout.display(),
        mock_stderr.display()
    );
    #[cfg(not(feature = "subscriptions"))]
    println!(
        "mock-ui live session: pass (subscribe/ping/notifications/ping-stats/log-level-reply observed) stdout={} stderr={}",
        mock_stdout.display(),
        mock_stderr.display()
    );

    Ok(())
}

fn collect_process_tree_pids(root_pid: u32) -> Vec<u32> {
    let mut by_parent: HashMap<u32, Vec<u32>> = HashMap::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid_text = file_name.to_string_lossy();
        if !pid_text.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }

        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };

        let status_path = entry.path().join("status");
        let Ok(status_text) = fs::read_to_string(status_path) else {
            continue;
        };

        let mut parent: Option<u32> = None;
        for line in status_text.lines() {
            if let Some(ppid) = line.strip_prefix("PPid:") {
                parent = ppid.trim().parse::<u32>().ok();
                break;
            }
        }

        if let Some(ppid) = parent {
            by_parent.entry(ppid).or_default().push(pid);
        }
    }

    let mut queue = VecDeque::from([root_pid]);
    let mut seen = HashSet::new();
    let mut descendants = Vec::new();

    while let Some(parent) = queue.pop_front() {
        if let Some(children) = by_parent.get(&parent) {
            for child in children {
                if seen.insert(*child) {
                    descendants.push(*child);
                    queue.push_back(*child);
                }
            }
        }
    }

    descendants
}
