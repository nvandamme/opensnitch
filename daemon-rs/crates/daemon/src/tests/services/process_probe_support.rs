use std::{
    collections::HashMap,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use crate::{models::process_state::ProcessInfo, services::process::ProcessService};

use super::cache::{CachedProcessEntry, PROCESS_INFO_CACHE_CAPACITY};

impl ProcessService {
    pub(crate) async fn probe_inject_expired_cache_entry(&self, pid: u32) {
        self.cache
            .mark_exit_deadline(
                pid,
                Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .unwrap_or_else(Instant::now),
            )
            .await;
        self.cache
            .entries
            .insert(
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
        )
            .await;
    }

    pub(crate) async fn probe_cache_len(&self) -> usize {
        self.cache.entries.len()
    }

    pub(crate) fn probe_cache_capacity() -> usize {
        PROCESS_INFO_CACHE_CAPACITY.load(Ordering::Relaxed)
    }

    pub(crate) async fn probe_insert_cache_entry_for_pid(&self, pid: u32) {
        self.cache
            .entries
            .insert(
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
        )
            .await;
    }

    pub(crate) async fn probe_cache_contains_pid(&self, pid: u32) -> bool {
        self.cache.entries.peek(&pid).is_some()
    }
}
