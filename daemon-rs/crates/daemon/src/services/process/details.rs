use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
};

use anyhow::{Context, Result};
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

use crate::models::process_state::{ProcessInfo, ProcessNode};

use super::ProcessService;

impl ProcessService {
    pub(super) fn inspect_process(pid: u32) -> Result<ProcessInfo> {
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

        let raw_environ = fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
        let env_entries_hint = if raw_environ.is_empty() {
            0
        } else {
            raw_environ.iter().filter(|&&byte| byte == 0).count() + 1
        };
        let mut env_preview = Vec::with_capacity(env_entries_hint);
        let mut env_map = HashMap::with_capacity(env_entries_hint);
        for entry in raw_environ.split(|&b| b == 0).filter(|s| !s.is_empty()) {
            let entry_text = String::from_utf8_lossy(entry).into_owned();
            if let Some((key, value)) = entry_text.split_once('=') {
                env_map.insert(key.to_string(), value.to_string());
            }
            env_preview.push(entry_text);
        }

        let parent_chain = Self::build_parent_chain(pid);
        let hashes = Self::compute_process_hashes(pid);

        Ok(ProcessInfo {
            pid,
            path,
            args,
            cwd,
            env_preview,
            env_map,
            process_hash: hashes.as_ref().map(|(_, _, sha256)| sha256.clone()),
            process_hash_md5: hashes.as_ref().map(|(md5, _, _)| md5.clone()),
            process_hash_sha1: hashes.as_ref().map(|(_, sha1, _)| sha1.clone()),
            parent_chain,
        })
    }

    fn compute_process_hashes(pid: u32) -> Option<(String, String, String)> {
        let exe_path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let mut file = fs::File::open(exe_path).ok()?;
        let mut hasher_md5 = Md5::new();
        let mut hasher_sha1 = Sha1::new();
        let mut hasher = Sha256::new();
        let mut buf = [0_u8; 8192];

        loop {
            let n = file.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            hasher_md5.update(&buf[..n]);
            hasher_sha1.update(&buf[..n]);
            hasher.update(&buf[..n]);
        }

        let digest_md5 = hasher_md5.finalize();
        let digest_sha1 = hasher_sha1.finalize();
        let digest = hasher.finalize();
        Some((
            format!("{:x}", digest_md5),
            format!("{:x}", digest_sha1),
            format!("{:x}", digest),
        ))
    }

    fn build_parent_chain(pid: u32) -> Vec<ProcessNode> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut current = pid;

        loop {
            if !seen.insert(current) {
                break;
            }

            let exe = fs::read_link(format!("/proc/{current}/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| format!("[{current}]"));

            chain.push(ProcessNode {
                pid: current,
                path: exe,
            });

            if current <= 1 || chain.len() >= 64 {
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

    pub(super) fn read_proc_starttime(pid: u32) -> Option<u64> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after_comm = stat.rsplit_once(") ")?.1;
        after_comm
            .split_whitespace()
            .nth(19)
            .and_then(|value| value.parse::<u64>().ok())
    }
}
