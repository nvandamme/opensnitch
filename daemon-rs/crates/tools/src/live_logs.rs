use std::{
    collections::{HashMap, HashSet, VecDeque},
    env, fs,
    path::PathBuf,
    process::Command,
    thread,
    time::Duration,
};

use crate::{DynError, compact_timestamp, env_flag, run_command};

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
    let run_release = !env_flag("OPENSNITCH_DAEMON_RS_LIVE_DEBUG");
    let manifest_path = daemon_rs_dir.join("Cargo.toml");

    run_command(repo_root, "sudo", ["-n", "true"], &[])?;

    let stdout_file = fs::File::create(&stdout_path)?;
    let stderr_file = fs::File::create(&stderr_path)?;

    let mut command = Command::new("sudo");
    command
        .arg("-n")
        .arg("env")
        .arg(format!("RUST_LOG={rust_log}"))
        .arg(format!(
            "OPENSNITCH_DAEMON_RS_LOG_FILE={}",
            daemon_log_path.display()
        ))
        .arg("cargo")
        .arg("run");

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
    let latest_content = format!(
        "pid={pid}\nmode={mode}\nrust_log={rust_log}\nstdout={}\nstderr={}\nlogfile={}\n",
        stdout_path.display(),
        stderr_path.display(),
        daemon_log_path.display(),
    );
    fs::write(&latest_path, latest_content)?;

    println!("daemon-rs live log session launched pid={pid} mode={mode}");
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

    run_command(repo_root, "sudo", ["-n", "true"], &[])?;

    match run_command(
        repo_root,
        "sudo",
        ["-n", "kill", "-0", pid_str.as_str()],
        &[],
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
                let _ = run_command(
                    repo_root,
                    "sudo",
                    ["-n", "kill", "-TERM", pid_value.as_str()],
                    &[],
                );
            }

            thread::sleep(Duration::from_millis(200));

            for pid in &targets {
                let pid_value = pid.to_string();
                let still_alive = run_command(
                    repo_root,
                    "sudo",
                    ["-n", "kill", "-0", pid_value.as_str()],
                    &[],
                )
                .is_ok();

                if still_alive {
                    let _ = run_command(
                        repo_root,
                        "sudo",
                        ["-n", "kill", "-KILL", pid_value.as_str()],
                        &[],
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
