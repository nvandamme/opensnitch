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

                let info = tokio::task::spawn_blocking(move || Self::inspect_process(pid))
                    .await
                    .ok()
                    .and_then(Result::ok);

                if let Some(info) = info {
                    self.cache
                        .entries
                        .insert(
                        pid,
                        CachedProcessEntry {
                            info,
                            starttime: Self::read_proc_starttime(pid),
                        },
                    )
                        .await;
                }
            }
        }
    }

    pub async fn inspect(&self, pid: u32) -> Result<ProcessInfo> {
        let now = Instant::now();
        let should_cleanup = match self.cache.exit_deadline(pid).await {
            Some(deadline) if deadline <= now => true,
            _ => {
                if let Some(entry) = self.cache.entries.peek(&pid) {
                    let is_same_process = match (entry.starttime, Self::read_proc_starttime(pid)) {
                        (Some(cached), Some(current)) => cached == current,
                        _ => true,
                    };

                    if is_same_process {
                        return Ok(entry.info);
                    }
                }
                true
            }
        };

        if should_cleanup {
            self.cache.cleanup_expired().await;
            if let Some(entry) = self.cache.entries.get(&pid) {
                let is_same_process = match (entry.starttime, Self::read_proc_starttime(pid)) {
                    (Some(cached), Some(current)) => cached == current,
                    _ => true,
                };
                if is_same_process {
                    return Ok(entry.info);
                }
                let _ = self.cache.entries.remove_by(&pid).await;
            }
        }

        let info = tokio::task::spawn_blocking(move || Self::inspect_process(pid)).await??;
        self.cache.clear_exit_deadline(pid).await;
        self.cache
            .entries
            .insert(
            pid,
            CachedProcessEntry {
                info: info.clone(),
                starttime: Self::read_proc_starttime(pid),
            },
        )
            .await;
        Ok(info)
    }
}
