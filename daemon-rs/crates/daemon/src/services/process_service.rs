use std::{
    collections::HashMap,
    fs,
    io::Read,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::models::{
    kernel_event::ProcEventKind,
    process_state::{ProcessInfo, ProcessNode},
};

#[derive(Clone, Default)]
pub struct ProcessService {
    cache: Arc<RwLock<ProcessCache>>,
}

#[derive(Default)]
struct ProcessCache {
    entries: HashMap<u32, ProcessInfo>,
    exit_deadlines: HashMap<u32, Instant>,
}

const EXIT_CACHE_TTL: Duration = Duration::from_secs(2);

trait ProcPidExt {
    fn inspect_process(self) -> Result<ProcessInfo>;
    fn compute_process_hash(self) -> Option<String>;
    fn build_parent_chain(self) -> Vec<ProcessNode>;
}

impl ProcPidExt for u32 {
    fn inspect_process(self) -> Result<ProcessInfo> {
        let path = fs::read_link(format!("/proc/{self}/exe"))
            .with_context(|| format!("read exe for pid {self}"))?
            .to_string_lossy()
            .into_owned();

        let args: Vec<String> = fs::read(format!("/proc/{self}/cmdline"))
            .unwrap_or_default()
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        let cwd = fs::read_link(format!("/proc/{self}/cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        let env_preview: Vec<String> = fs::read(format!("/proc/{self}/environ"))
            .unwrap_or_default()
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .take(16)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        let parent_chain = self.build_parent_chain();

        Ok(ProcessInfo {
            pid: self,
            path,
            args,
            cwd,
            env_preview,
            process_hash: self.compute_process_hash(),
            parent_chain,
        })
    }

    fn compute_process_hash(self) -> Option<String> {
        let exe_path = fs::read_link(format!("/proc/{self}/exe")).ok()?;
        let mut file = fs::File::open(exe_path).ok()?;
        let mut hasher = Sha256::new();
        let mut buf = [0_u8; 8192];

        loop {
            let n = file.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        let digest = hasher.finalize();
        Some(format!("{:x}", digest))
    }

    fn build_parent_chain(self) -> Vec<ProcessNode> {
        let mut chain = Vec::new();
        let mut current = self;

        loop {
            let exe = fs::read_link(format!("/proc/{current}/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| format!("[{current}]"));

            chain.push(ProcessNode {
                pid: current,
                path: exe,
            });

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
}

impl ProcessService {
    pub async fn sync_from_proc_event(&self, pid: u32, kind: ProcEventKind) {
        match kind {
            ProcEventKind::Exit => {
                let mut cache = self.cache.write().await;
                cache.prune_expired();
                cache
                    .exit_deadlines
                    .insert(pid, Instant::now() + EXIT_CACHE_TTL);
            }
            ProcEventKind::Fork | ProcEventKind::Exec => {
                {
                    let mut cache = self.cache.write().await;
                    cache.prune_expired();
                    cache.exit_deadlines.remove(&pid);
                }

                let info = tokio::task::spawn_blocking(move || pid.inspect_process())
                    .await
                    .ok()
                    .and_then(Result::ok);

                if let Some(info) = info {
                    let mut cache = self.cache.write().await;
                    cache.entries.insert(pid, info);
                }
            }
        }
    }

    pub async fn inspect(&self, pid: u32) -> Result<ProcessInfo> {
        {
            let mut cache = self.cache.write().await;
            cache.prune_expired();
            if let Some(info) = cache.entries.get(&pid).cloned() {
                return Ok(info);
            }
        }

        let info = tokio::task::spawn_blocking(move || pid.inspect_process()).await??;
        let mut cache = self.cache.write().await;
        cache.entries.insert(pid, info.clone());
        cache.exit_deadlines.remove(&pid);
        Ok(info)
    }
}

impl ProcessCache {
    fn prune_expired(&mut self) {
        let now = Instant::now();
        self.exit_deadlines.retain(|pid, deadline| {
            if *deadline > now {
                true
            } else {
                self.entries.remove(pid);
                false
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::models::kernel_event::ProcEventKind;

    use super::ProcessService;

    #[tokio::test]
    async fn inspect_unknown_pid_returns_error() {
        let service = ProcessService::default();
        let result = service.inspect(u32::MAX).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn exit_event_does_not_make_inspect_succeed_for_unknown_pid() {
        let service = ProcessService::default();
        service.sync_from_proc_event(0, ProcEventKind::Exit).await;
        let result = service.inspect(0).await;
        assert!(result.is_err());
    }
}
