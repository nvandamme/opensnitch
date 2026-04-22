use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
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
use crate::utils::lru_cache::LruCache;

#[derive(Clone, Default)]
pub struct ProcessService {
    cache: Arc<RwLock<ProcessCache>>,
}

struct ProcessCache {
    entries: LruCache<u32, CachedProcessEntry>,
    exit_deadlines: HashMap<u32, Instant>,
}

impl Default for ProcessCache {
    fn default() -> Self {
        let capacity = PROCESS_INFO_CACHE_CAPACITY.load(Ordering::Relaxed).max(1);
        Self {
            entries: LruCache::new(capacity),
            exit_deadlines: HashMap::new(),
        }
    }
}

#[derive(Clone)]
struct CachedProcessEntry {
    info: ProcessInfo,
    starttime: Option<u64>,
}

const EXIT_CACHE_TTL: Duration = Duration::from_secs(2);
const EXIT_CACHE_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(not(test))]
const DEFAULT_PROCESS_INFO_CACHE_CAPACITY: usize = 131_072;
#[cfg(test)]
const DEFAULT_PROCESS_INFO_CACHE_CAPACITY: usize = 8_192;
static PROCESS_INFO_CACHE_CAPACITY: AtomicUsize =
    AtomicUsize::new(DEFAULT_PROCESS_INFO_CACHE_CAPACITY);

impl ProcessService {
    pub(crate) fn configure_cache_capacity(capacity: usize) {
        PROCESS_INFO_CACHE_CAPACITY.store(capacity.max(1), Ordering::Relaxed);
    }

    fn inspect_process(pid: u32) -> Result<ProcessInfo> {
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

    fn read_proc_starttime(pid: u32) -> Option<u64> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after_comm = stat.rsplit_once(") ")?.1;
        after_comm
            .split_whitespace()
            .nth(19)
            .and_then(|value| value.parse::<u64>().ok())
    }

    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        cache.cleanup_expired();
    }

    pub fn spawn_cleanup_task(&self, shutdown: CancellationToken) -> JoinHandle<()> {
        self.spawn_cleanup_task_with_interval(shutdown, EXIT_CACHE_CLEANUP_INTERVAL)
    }

    pub(crate) fn spawn_cleanup_task_with_interval(
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

                let info = tokio::task::spawn_blocking(move || Self::inspect_process(pid))
                    .await
                    .ok()
                    .and_then(Result::ok);

                if let Some(info) = info {
                    let mut cache = self.cache.write().await;
                    cache.entries.insert(
                        pid,
                        CachedProcessEntry {
                            info,
                            starttime: Self::read_proc_starttime(pid),
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
                    if let Some(entry) = cache.entries.peek_cloned_by(&pid) {
                        let is_same_process =
                            match (entry.starttime, Self::read_proc_starttime(pid)) {
                                (Some(cached), Some(current)) => cached == current,
                                _ => true,
                            };

                        if is_same_process {
                            return Ok(entry.info);
                        }
                    }
                    true
                }
            }
        };

        if should_cleanup {
            let mut cache = self.cache.write().await;
            cache.cleanup_expired();
            if let Some(entry) = cache.entries.get_cloned_by(&pid) {
                let is_same_process = match (entry.starttime, Self::read_proc_starttime(pid)) {
                    (Some(cached), Some(current)) => cached == current,
                    _ => true,
                };
                if is_same_process {
                    return Ok(entry.info);
                }
                cache.entries.remove_by(&pid);
            }
        }

        let info = tokio::task::spawn_blocking(move || Self::inspect_process(pid)).await??;
        let mut cache = self.cache.write().await;
        cache.entries.insert(
            pid,
            CachedProcessEntry {
                info: info.clone(),
                starttime: Self::read_proc_starttime(pid),
            },
        );
        cache.exit_deadlines.remove(&pid);
        Ok(info)
    }

    #[cfg(test)]
    pub(crate) async fn probe_inject_expired_cache_entry(&self, pid: u32) {
        let mut cache = self.cache.write().await;
        cache.entries.insert(
            pid,
            CachedProcessEntry {
                info: ProcessInfo {
                    pid,
                    path: "/usr/bin/curl".to_string(),
                    args: vec!["curl".to_string()],
                    cwd: None,
                    env_preview: Vec::new(),
                    env_map: HashMap::new(),
                    process_hash: None,
                    process_hash_md5: None,
                    process_hash_sha1: None,
                    parent_chain: Vec::new(),
                },
                starttime: None,
            },
        );
        cache.exit_deadlines.insert(
            pid,
            Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap_or_else(Instant::now),
        );
    }

    #[cfg(test)]
    pub(crate) async fn probe_cache_len(&self) -> usize {
        self.cache.read().await.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn probe_cache_capacity() -> usize {
        PROCESS_INFO_CACHE_CAPACITY.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) async fn probe_insert_cache_entry_for_pid(&self, pid: u32) {
        let mut cache = self.cache.write().await;
        cache.entries.insert(
            pid,
            CachedProcessEntry {
                info: ProcessInfo {
                    pid,
                    path: "/usr/bin/true".to_string(),
                    args: vec!["true".to_string()],
                    cwd: None,
                    env_preview: Vec::new(),
                    env_map: HashMap::new(),
                    process_hash: None,
                    process_hash_md5: None,
                    process_hash_sha1: None,
                    parent_chain: Vec::new(),
                },
                starttime: None,
            },
        );
    }

    #[cfg(test)]
    pub(crate) async fn probe_cache_contains_pid(&self, pid: u32) -> bool {
        self.cache
            .read()
            .await
            .entries
            .peek_cloned_by(&pid)
            .is_some()
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
                self.entries.remove_by(pid);
                false
            }
        });
    }
}
