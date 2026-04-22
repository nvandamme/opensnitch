use anyhow::Result;
use std::time::Instant;

use crate::models::{proc_event::ProcEventKind, process_state::ProcessInfo};

use super::{
    ProcessService,
    cache::{CachedProcessEntry, EXIT_CACHE_TTL},
};

impl ProcessService {
    pub async fn sync_from_proc_event(&self, pid: u32, kind: ProcEventKind) {
        match kind {
            ProcEventKind::Exit => {
                self.cache.cleanup_expired().await;
                self.cache
                    .mark_exit_deadline(pid, Instant::now() + EXIT_CACHE_TTL)
                    .await;
            }
            ProcEventKind::Fork | ProcEventKind::Exec => {
                self.cache.cleanup_expired().await;
                self.cache.clear_exit_deadline(pid).await;

                let info = tokio::task::spawn_blocking(move || Self::inspect_process_no_hash(pid))
                    .await
                    .ok()
                    .and_then(Result::ok);

                if let Some(info) = info {
                    let starttime = Self::read_proc_starttime(pid);
                    self.cache
                        .entries
                        .insert(
                        pid,
                        CachedProcessEntry {
                            info,
                            starttime,
                        },
                    );
                    Self::spawn_hash_update(self.cache.clone(), pid, starttime);
                }
            }
        }
    }

    pub async fn inspect(&self, pid: u32) -> Result<ProcessInfo> {
        let now = Instant::now();

        // Expired deadline means the cached entry for this pid may be stale
        // (process exited and pid could be reused); skip cache in that case.
        // cleanup_expired() is NOT called here — the background cleanup task
        // (spawn_cleanup_task) handles TTL-based removal on its own interval,
        // avoiding per-inspect mutex contention under high connection churn.
        let expired = match self.cache.exit_deadline(pid).await {
            Some(deadline) => deadline <= now,
            None => false,
        };

        if !expired {
            if let Some(entry) = self.cache.entries.peek(&pid) {
                let is_same_process = match (entry.starttime, Self::read_proc_starttime(pid)) {
                    (Some(cached), Some(current)) => cached == current,
                    _ => true,
                };

                if is_same_process {
                    return Ok(entry.info);
                }
            }
        }

        // Miss/stale: check hot-tier (get differs from peek in quick-cache).
        if let Some(entry) = self.cache.entries.get(&pid) {
            let is_same_process = match (entry.starttime, Self::read_proc_starttime(pid)) {
                (Some(cached), Some(current)) => cached == current,
                _ => true,
            };
            if is_same_process {
                return Ok(entry.info);
            }
            let _ = self.cache.entries.remove_by(&pid);
        }

        let info = tokio::task::spawn_blocking(move || Self::inspect_process_no_hash(pid)).await??;
        let starttime = Self::read_proc_starttime(pid);
        self.cache.clear_exit_deadline(pid).await;
        self.cache
            .entries
            .insert(
            pid,
            CachedProcessEntry {
                info: info.clone(),
                starttime,
            },
        );
        Self::spawn_hash_update(self.cache.clone(), pid, starttime);
        Ok(info)
    }

    /// Spawn a background task that computes the exe hashes for `pid` and patches the
    /// cached [`CachedProcessEntry`] once complete.  The first verdict for the process
    /// is served with `None` hashes; subsequent lookups (from cache) get the real values.
    fn spawn_hash_update(
        cache: std::sync::Arc<super::cache::ProcessCache>,
        pid: u32,
        starttime: Option<u64>,
    ) {
        tokio::spawn(async move {
            let hashes = tokio::task::spawn_blocking(move || {
                ProcessService::compute_process_hashes(pid)
            })
            .await;
            if let Ok(Some((md5, sha1, sha256))) = hashes {
                if let Some(mut entry) = cache.entries.peek(&pid) {
                    if entry.starttime == starttime {
                        entry.info.process_hash_md5 = Some(md5);
                        entry.info.process_hash_sha1 = Some(sha1);
                        entry.info.process_hash = Some(sha256);
                        cache.entries.insert(pid, entry);
                    }
                }
            }
        });
    }
}
