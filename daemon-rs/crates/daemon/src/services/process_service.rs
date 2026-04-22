use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

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
    entries: HashMap<u32, CachedProcessEntry>,
    exit_deadlines: HashMap<u32, Instant>,
}

#[derive(Clone)]
struct CachedProcessEntry {
    info: ProcessInfo,
    starttime: Option<u64>,
}

const EXIT_CACHE_TTL: Duration = Duration::from_secs(2);
const EXIT_CACHE_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

trait ProcPidExt {
    fn inspect_process(self) -> Result<ProcessInfo>;
    fn compute_process_hashes(self) -> Option<(String, String, String)>;
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
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        let parent_chain = self.build_parent_chain();

        let hashes = self.compute_process_hashes();

        Ok(ProcessInfo {
            pid: self,
            path,
            args,
            cwd,
            env_preview,
            process_hash: hashes.as_ref().map(|(_, _, sha256)| sha256.clone()),
            process_hash_md5: hashes.as_ref().map(|(md5, _, _)| md5.clone()),
            process_hash_sha1: hashes.as_ref().map(|(_, sha1, _)| sha1.clone()),
            parent_chain,
        })
    }

    fn compute_process_hashes(self) -> Option<(String, String, String)> {
        let exe_path = fs::read_link(format!("/proc/{self}/exe")).ok()?;
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

    fn build_parent_chain(self) -> Vec<ProcessNode> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut current = self;

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
}

fn read_proc_starttime(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(") ")?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    fields.get(19)?.parse::<u64>().ok()
}

impl ProcessService {
    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        cache.cleanup_expired();
    }

    pub fn spawn_cleanup_task(&self, shutdown: CancellationToken) -> JoinHandle<()> {
        self.spawn_cleanup_task_with_interval(shutdown, EXIT_CACHE_CLEANUP_INTERVAL)
    }

    fn spawn_cleanup_task_with_interval(
        &self,
        shutdown: CancellationToken,
        interval: Duration,
    ) -> JoinHandle<()> {
        let service = self.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = ticker.tick() => service.cleanup_expired().await,
                }
            }
        })
    }

    pub async fn sync_from_proc_event(&self, pid: u32, kind: ProcEventKind) {
        match kind {
            ProcEventKind::Exit => {
                let mut cache = self.cache.write().await;
                cache.cleanup_expired();
                cache
                    .exit_deadlines
                    .insert(pid, Instant::now() + EXIT_CACHE_TTL);
            }
            ProcEventKind::Fork | ProcEventKind::Exec => {
                {
                    let mut cache = self.cache.write().await;
                    cache.cleanup_expired();
                    cache.exit_deadlines.remove(&pid);
                }

                let info = tokio::task::spawn_blocking(move || pid.inspect_process())
                    .await
                    .ok()
                    .and_then(Result::ok);

                if let Some(info) = info {
                    let mut cache = self.cache.write().await;
                    cache.entries.insert(
                        pid,
                        CachedProcessEntry {
                            info,
                            starttime: read_proc_starttime(pid),
                        },
                    );
                }
            }
        }
    }

    pub async fn inspect(&self, pid: u32) -> Result<ProcessInfo> {
        let now = Instant::now();
        let should_cleanup = {
            let cache = self.cache.read().await;
            match cache.exit_deadlines.get(&pid) {
                Some(deadline) if *deadline <= now => true,
                _ => {
                    if let Some(entry) = cache.entries.get(&pid) {
                        let is_same_process = match (entry.starttime, read_proc_starttime(pid)) {
                            (Some(cached), Some(current)) => cached == current,
                            _ => true,
                        };

                        if is_same_process {
                            return Ok(entry.info.clone());
                        }
                    }
                    true
                }
            }
        };

        if should_cleanup {
            let mut cache = self.cache.write().await;
            cache.cleanup_expired();
            if let Some(entry) = cache.entries.get(&pid).cloned() {
                let is_same_process = match (entry.starttime, read_proc_starttime(pid)) {
                    (Some(cached), Some(current)) => cached == current,
                    _ => true,
                };
                if is_same_process {
                    return Ok(entry.info);
                }
                cache.entries.remove(&pid);
            }
        }

        let info = tokio::task::spawn_blocking(move || pid.inspect_process()).await??;
        let mut cache = self.cache.write().await;
        cache.entries.insert(
            pid,
            CachedProcessEntry {
                info: info.clone(),
                starttime: read_proc_starttime(pid),
            },
        );
        cache.exit_deadlines.remove(&pid);
        Ok(info)
    }
}

impl ProcessCache {
    fn cleanup_expired(&mut self) {
        tracing::debug!(
            "[cache] deleting old events, total byPID: {}",
            self.entries.len()
        );
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
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn cleanup_task_prunes_expired_entries() {
        let service = ProcessService::default();
        {
            let mut cache = service.cache.write().await;
            cache.entries.insert(
                4242,
                CachedProcessEntry {
                    info: ProcessInfo {
                        pid: 4242,
                        path: "/usr/bin/curl".to_string(),
                        args: vec!["curl".to_string()],
                        cwd: None,
                        env_preview: Vec::new(),
                        process_hash: None,
                        process_hash_md5: None,
                        process_hash_sha1: None,
                        parent_chain: Vec::new(),
                    },
                    starttime: None,
                },
            );
            cache
                .exit_deadlines
                .insert(4242, Instant::now() - Duration::from_millis(1));
        }

        let shutdown = CancellationToken::new();
        let handle =
            service.spawn_cleanup_task_with_interval(shutdown.clone(), Duration::from_millis(10));

        timeout(Duration::from_secs(1), async {
            loop {
                if service.cache.read().await.entries.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cleanup task should prune expired entries");

        shutdown.cancel();
        let _ = timeout(Duration::from_secs(1), handle).await;
    }
}
