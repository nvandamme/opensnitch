use anyhow::Result;
use std::fmt::Write as _;
use std::time::Instant;

use crate::models::process::state::ProcessInfo;
use crate::platform::procmon::proc_event::ProcEventKind;

use super::{
    ProcessService,
    cache::{CachedProcessEntry, EXIT_CACHE_TTL},
};

impl ProcessService {
    pub async fn sync_from_proc_event(
        &self,
        pid: u32,
        kind: ProcEventKind,
    ) -> Result<(), &'static str> {
        match kind {
            ProcEventKind::Exit => {
                self.cache.cleanup_expired().await;
                self.cache
                    .mark_exit_deadline(pid, Instant::now() + EXIT_CACHE_TTL)
                    .await;
                Ok(())
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
                        .insert(pid, CachedProcessEntry { info, starttime });
                    Self::spawn_hash_update(self.cache.clone(), pid, starttime);
                    Ok(())
                } else {
                    Err("inspect_process_no_hash failed")
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

        // Read starttime once and reuse across both peek and get branches to
        // avoid a redundant /proc/{pid}/stat filesystem read on cache hits.
        let current_starttime = if !expired {
            Self::read_proc_starttime(pid)
        } else {
            None
        };

        if !expired {
            if let Some(entry) = self.cache.entries.peek(&pid) {
                let is_same_process = match (entry.starttime, current_starttime) {
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
            let is_same_process = match (entry.starttime, current_starttime) {
                (Some(cached), Some(current)) => cached == current,
                _ => true,
            };
            if is_same_process {
                return Ok(entry.info);
            }
            let _ = self.cache.entries.remove_by(&pid);
        }

        let info =
            tokio::task::spawn_blocking(move || Self::inspect_process_no_hash(pid)).await??;
        let starttime = Self::read_proc_starttime(pid);
        self.cache.clear_exit_deadline(pid).await;
        self.cache.entries.insert(
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
    ///
    /// Checks the persistent on-disk hash cache first (keyed on path+inode+mtime+size).
    /// On a persistent-cache hit, the hashes are applied without reading the binary at
    /// all.  On a miss, hashes are computed and stored in both the in-memory entry and
    /// the persistent cache for future daemon restarts.
    fn spawn_hash_update(
        cache: std::sync::Arc<super::cache::ProcessCache>,
        pid: u32,
        starttime: Option<u64>,
    ) {
        if let Some(entry) = cache.entries.peek(&pid)
            && entry.starttime == starttime
            && entry.info.process_hash_md5.is_some()
            && entry.info.process_hash_sha1.is_some()
            && entry.info.process_hash.is_some()
        {
            return;
        }

        let inflight_key = (pid, starttime);
        if cache
            .hash_updates_inflight
            .insert(inflight_key, ())
            .is_some()
        {
            return;
        }

        tokio::spawn(async move {
            let hash_cache = cache.hash_cache.clone();
            let hashes = tokio::task::spawn_blocking(move || {
                // Resolve the exe path for persistent-cache lookup.
                let mut exe_link = String::with_capacity(32);
                let _ = write!(&mut exe_link, "/proc/{pid}/exe");
                let exe_path = std::fs::read_link(exe_link).ok();

                // Try the persistent on-disk cache first (avoids reading the binary).
                if let Some(ref exe) = exe_path {
                    if let Some(hit) = hash_cache.get(exe) {
                        return Some(hit);
                    }
                }

                // Miss: compute hashes from the binary file.
                let result = ProcessService::compute_process_hashes(pid);

                // Store in persistent cache for future daemon restarts.
                if let (Some(ref exe), Some((md5, sha1, sha256))) = (exe_path, &result) {
                    hash_cache.insert(exe, md5, sha1, sha256);
                }

                result
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

            let _ = cache.hash_updates_inflight.remove(&inflight_key);
        });
    }
}
