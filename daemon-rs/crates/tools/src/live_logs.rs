use std::{
    collections::{HashMap, HashSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

use crate::{DynError, compact_timestamp, env_flag};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivCmd {
    Direct,
    Pkexec,
    Sudo,
}

fn command_exists(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin} >/dev/null 2>&1"))
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "0")
        .unwrap_or(false)
}

fn pick_priv_cmd() -> PrivCmd {
    if is_root() {
        return PrivCmd::Direct;
    }

    if let Ok(raw) = env::var("OPENSNITCH_TOOLS_PRIV_CMD") {
        match raw.trim().to_ascii_lowercase().as_str() {
            "direct" | "none" => return PrivCmd::Direct,
            "pkexec" => return PrivCmd::Pkexec,
            "sudo" => return PrivCmd::Sudo,
            _ => {}
        }
    }

    PrivCmd::Sudo
}

fn run_command_capture(cwd: &Path, program: &str, args: &[&str]) -> Result<String, DynError> {
    let output = Command::new(program).current_dir(cwd).args(args).output()?;
    if output.status.success() {
        let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok(combined)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(format!(
            "command failed: {} {}\nstdout:\n{}\nstderr:\n{}",
            program,
            args.join(" "),
            stdout,
            stderr
        )
        .into())
    }
}

fn ensure_privileged_ready(cwd: &Path, priv_cmd: PrivCmd, action: &str) -> Result<(), DynError> {
    match priv_cmd {
        PrivCmd::Direct => Ok(()),
        PrivCmd::Sudo => run_command_capture(cwd, "sudo", &["-v"]).map(|_| ()).map_err(|err| {
            format!(
                "{action} requires elevated privileges and sudo authentication failed. Details: {err}"
            )
            .into()
        }),
        PrivCmd::Pkexec => {
            if command_exists("pkexec") {
                Ok(())
            } else {
                Err(format!("{action} requires pkexec but it is not available in PATH").into())
            }
        }
    }
}

fn run_privileged_command(
    cwd: &Path,
    priv_cmd: PrivCmd,
    program: &str,
    args: &[&str],
) -> Result<String, DynError> {
    match priv_cmd {
        PrivCmd::Direct => run_command_capture(cwd, program, args),
        PrivCmd::Sudo => {
            let mut all_args = Vec::with_capacity(args.len() + 2);
            all_args.push("--");
            all_args.push(program);
            all_args.extend_from_slice(args);
            run_command_capture(cwd, "sudo", &all_args)
        }
        PrivCmd::Pkexec => {
            let mut all_args = Vec::with_capacity(args.len() + 1);
            all_args.push(program);
            all_args.extend_from_slice(args);
            match run_command_capture(cwd, "pkexec", &all_args) {
                Ok(output) => Ok(output),
                Err(err) => {
                    let text = err.to_string();
                    if text.contains("exit status: 126") || text.contains("exit status: 127") {
                        let mut sudo_args = Vec::with_capacity(args.len() + 2);
                        sudo_args.push("--");
                        sudo_args.push(program);
                        sudo_args.extend_from_slice(args);
                        run_command_capture(cwd, "sudo", &sudo_args)
                    } else {
                        Err(err)
                    }
                }
            }
        }
    }
}

fn kill_if_running(repo_root: &Path, priv_cmd: PrivCmd, proc_name: &str) {
    let running = Command::new("pgrep")
        .arg("-x")
        .arg(proc_name)
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !running {
        return;
    }

    let _ = run_privileged_command(repo_root, priv_cmd, "pkill", &["-x", proc_name]);
}

fn stop_service_if_active(repo_root: &Path, priv_cmd: PrivCmd, scope: &str, service: &str) {
    let mut show_args = vec!["show", "--property=ActiveState", service];
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
        return;
    }

    if scope == "user" {
        let _ = run_command_capture(repo_root, "systemctl", &["--user", "stop", service]);
    } else {
        let _ = run_privileged_command(repo_root, priv_cmd, "systemctl", &["stop", service]);
    }
}

fn preflight_cleanup(repo_root: &Path, priv_cmd: PrivCmd) {
    if command_exists("systemctl") {
        for service in ["opensnitchd-rs", "opensnitchd", "opensnitch-ui"] {
            stop_service_if_active(repo_root, priv_cmd, "system", service);
            stop_service_if_active(repo_root, priv_cmd, "user", service);
        }
    }

    kill_if_running(repo_root, priv_cmd, "opensnitchd-rs");
    kill_if_running(repo_root, priv_cmd, "opensnitchd");

    let _ = run_command_capture(
        repo_root,
        "pkill",
        &["-f", "(^|[[:space:]]|/)opensnitch-ui([[:space:]]|$)"],
    );
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
    preflight_cleanup(repo_root, priv_cmd);

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
    command
        .arg(format!("RUST_LOG={rust_log}"))
        .arg(format!(
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
    let latest_content = format!(
        "pid={pid}\nmode={mode}\nprivilege={privilege}\nrust_log={rust_log}\nstdout={}\nstderr={}\nlogfile={}\n",
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

    let _pid: u32 = pid_str.parse().map_err(|err| {
        format!(
            "invalid pid '{pid_str}' in {}: {err}",
            latest_path.display()
        )
    })?;

    ensure_privileged_ready(repo_root, priv_cmd, "stop-daemon-live-logs")?;

    match run_privileged_command(
        repo_root,
        priv_cmd,
        "kill",
        &["-0", pid_str.as_str()],
    ) {
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
