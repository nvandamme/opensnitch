use std::fs;

use anyhow::{Context, Result};

use crate::models::process::{ProcessInfo, ProcessNode};

#[derive(Clone, Default)]
pub struct ProcessService;

impl ProcessService {
    pub async fn inspect(&self, pid: u32) -> Result<ProcessInfo> {
        let path = fs::read_link(format!("/proc/{pid}/exe"))
            .with_context(|| format!("read exe for pid {pid}"))?
            .to_string_lossy()
            .into_owned();

        let args: Vec<String> = fs::read(format!("/proc/{pid}/cmdline"))
            .unwrap_or_default()
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        let cwd = fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        let env_preview: Vec<String> = fs::read(format!("/proc/{pid}/environ"))
            .unwrap_or_default()
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .take(16)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        let parent_chain = build_parent_chain(pid);

        Ok(ProcessInfo {
            pid,
            path,
            args,
            cwd,
            env_preview,
            process_hash: None, // TODO: sha256 of exe
            parent_chain,
        })
    }
}

fn build_parent_chain(pid: u32) -> Vec<ProcessNode> {
    let mut chain = Vec::new();
    let mut current = pid;

    loop {
        let exe = fs::read_link(format!("/proc/{current}/exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| format!("[{current}]"));

        chain.push(ProcessNode { pid: current, path: exe });

        if current <= 1 || chain.len() >= 8 {
            break;
        }

        let status = match fs::read_to_string(format!("/proc/{current}/status")) {
            Ok(s) => s,
            Err(_) => break,
        };

        let ppid = status
            .lines()
            .find(|l| l.starts_with("PPid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u32>().ok());

        match ppid {
            Some(0) | None => break,
            Some(p) => current = p,
        }
    }

    chain
}
