use std::sync::atomic::Ordering;

use crate::services::storage::StorageOperation;

use super::stats::{StatsService, StorageEventCounters};

impl StatsService {
    pub fn on_rule_miss(&self) {
        self.counters.rule_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_fast_allow(&self) {
        self.fast_allow.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fast_allow_count(&self) -> u64 {
        self.fast_allow.load(Ordering::Relaxed)
    }

    pub fn on_fast_deny(&self) {
        self.fast_deny.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fast_deny_count(&self) -> u64 {
        self.fast_deny.load(Ordering::Relaxed)
    }

    pub fn on_dns_resolved(&self) {
        self.counters.dns_responses.fetch_add(1, Ordering::Relaxed);
        self.counters.accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_verdict(&self, allow: bool) {
        if allow {
            self.counters.accepted.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn on_rule_hit(&self, rule_name: &str) {
        self.counters.rule_hits.fetch_add(1, Ordering::Relaxed);
        let mut bd = self
            .breakdown
            .lock()
            .expect("stats breakdown mutex poisoned");
        let max_stats = bd.max_stats;
        bd.by_rule.bump(rule_name, max_stats);
    }

    // Go parity: when no rule matches and default action is applied, statistics
    // count it as a miss and a dropped connection, regardless of verdict action.
    pub fn on_missed_default_action(&self) {
        self.on_rule_miss();
        self.counters.dropped.fetch_add(1, Ordering::Relaxed);
    }
    // Retained for compatibility with accounting paths that report ignored connections.
    #[allow(dead_code)]
    pub fn on_ignored(&self) {
        self.counters.ignored.fetch_add(1, Ordering::Relaxed);
        self.counters.accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn on_storage_event(&self, operation: StorageOperation) {
        match operation {
            StorageOperation::Read => {
                self.counters.storage_reads.fetch_add(1, Ordering::Relaxed);
            }
            StorageOperation::Write => {
                self.counters.storage_writes.fetch_add(1, Ordering::Relaxed);
            }
            StorageOperation::Delete => {
                self.counters
                    .storage_deletes
                    .fetch_add(1, Ordering::Relaxed);
            }
            StorageOperation::Scan => {
                self.counters.storage_scans.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn storage_event_counts(&self) -> StorageEventCounters {
        StorageEventCounters {
            reads: self.counters.storage_reads.load(Ordering::Relaxed),
            writes: self.counters.storage_writes.load(Ordering::Relaxed),
            deletes: self.counters.storage_deletes.load(Ordering::Relaxed),
            scans: self.counters.storage_scans.load(Ordering::Relaxed),
        }
    }
}
