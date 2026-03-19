use std::{
    fs,
    path::Path,
    process::Command,
};

use anyhow::{Result, anyhow};

use crate::utils::command_path::command_exists;

const SYSTEMD_SERVICES: [&str; 2] = ["opensnitchd.service", "opensnitchd-rd.service"];
const DAEMON_SOCKET_PATTERNS: [&str; 2] = ["/var/run/opensnitchd.sock", "/run/opensnitchd.sock"];

pub(crate) fn ensure_no_competing_daemon_instances() -> Result<()> {
    let current_pid = std::process::id();

    let service_conflicts = detect_service_conflicts(current_pid);
    let pid_conflicts = detect_pid_conflicts(current_pid);
    let socket_conflicts = detect_unix_socket_conflicts();

    if service_conflicts.is_empty() && pid_conflicts.is_empty() && socket_conflicts.is_empty() {
        return Ok(());
    }

    let mut details = Vec::new();

    if !service_conflicts.is_empty() {
        details.push(format!("active systemd services: {}", service_conflicts.join(", ")));
    }

    if !pid_conflicts.is_empty() {
        details.push(format!("running daemon pids: {}", pid_conflicts.join(", ")));
    }

    if !socket_conflicts.is_empty() {
        details.push(format!(
            "daemon unix sockets present: {}",
            socket_conflicts.join(", ")
        ));
    }

    Err(anyhow!(
        "another OpenSnitch daemon instance appears to be running; refusing startup ({})\nstop conflicting daemons first (for example: `sudo systemctl stop opensnitchd.service opensnitchd-rd.service`) and retry",
        details.join("; ")
    ))
}

fn detect_service_conflicts(current_pid: u32) -> Vec<String> {
    if !command_exists("systemctl") {
        return Vec::new();
    }

    let mut conflicts = Vec::new();

    for service in SYSTEMD_SERVICES {
        let is_active = Command::new("systemctl")
            .args(["is-active", "--quiet", service])
            .status();

        let Ok(status) = is_active else {
            continue;
        };

        if !status.success() {
            continue;
        }

        let maybe_main_pid = Command::new("systemctl")
            .args(["show", service, "--property", "MainPID", "--value"])
            .output()
            .ok()
            .and_then(|out| {
                if !out.status.success() {
                    return None;
                }

                let text = String::from_utf8_lossy(&out.stdout);
                text.trim().parse::<u32>().ok()
            });

        match maybe_main_pid {
            Some(pid) if pid > 0 && pid != current_pid => {
                conflicts.push(format!("{service}(MainPID={pid})"));
            }
            Some(pid) if pid == current_pid => {}
            Some(pid) if pid == 0 => {
                conflicts.push(format!("{service}(active)"));
            }
            _ => {
                conflicts.push(format!("{service}(active)"));
            }
        }
    }

    conflicts
}

fn detect_pid_conflicts(current_pid: u32) -> Vec<String> {
    let mut conflicts = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return conflicts;
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

        if pid == current_pid {
            continue;
        }

        let proc_path = entry.path();
        let cmdline_path = proc_path.join("cmdline");
        let cmdline = fs::read(&cmdline_path)
            .ok()
            .map(|bytes| {
                bytes
                    .split(|b| *b == 0)
                    .filter(|part| !part.is_empty())
                    .map(|part| String::from_utf8_lossy(part).to_string())
                    .collect::<Vec<String>>()
                    .join(" ")
            })
            .unwrap_or_default();

        let exe_name = fs::read_link(proc_path.join("exe"))
            .ok()
            .and_then(|path| path.file_name().map(|name| name.to_string_lossy().to_string()))
            .map(|name| name.to_ascii_lowercase());

        let is_real_daemon_exe = matches!(
            exe_name.as_deref(),
            Some("opensnitchd") | Some("opensnitchd-rs")
        );

        let cmd_first = cmdline
            .split_whitespace()
            .next()
            .map(|token| token.rsplit('/').next().unwrap_or(token).to_ascii_lowercase());
        let is_daemon_cmd = matches!(
            cmd_first.as_deref(),
            Some("opensnitchd") | Some("opensnitchd-rs")
        );

        if !is_real_daemon_exe && !is_daemon_cmd {
            continue;
        }

        let comm = fs::read_to_string(proc_path.join("comm"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let preview = if cmdline.is_empty() {
            comm
        } else {
            cmdline
                .split_whitespace()
                .take(4)
                .collect::<Vec<&str>>()
                .join(" ")
        };
        conflicts.push(format!("{pid}:{preview}"));
    }

    conflicts
}

fn detect_unix_socket_conflicts() -> Vec<String> {
    let mut conflicts = Vec::new();

    if let Ok(contents) = fs::read_to_string("/proc/net/unix") {
        for line in contents.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("opensnitchd.sock") {
                if let Some(path) = line.split_whitespace().last() {
                    conflicts.push(path.to_string());
                }
            }
        }
    }

    for socket in DAEMON_SOCKET_PATTERNS {
        if Path::new(socket).exists() && !conflicts.iter().any(|found| found == socket) {
            conflicts.push(socket.to_string());
        }
    }

    conflicts.sort();
    conflicts.dedup();
    conflicts
}
