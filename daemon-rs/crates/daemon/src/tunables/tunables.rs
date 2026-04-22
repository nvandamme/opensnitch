use std::sync::{OnceLock, RwLock};

use tracing::warn;

use crate::models::effective_tunables::{NfqueueOverloadPolicy, RuntimeTunables};
use crate::models::runtime_tunables::RawRuntimeTunables;
use crate::utils::name_parsing::normalized_name;

const MIN_CONNECT_WORKERS: usize = 1;
const MAX_CONNECT_WORKERS: usize = 256;
const MIN_CONNECT_QUEUE_CAPACITY: usize = 16;
const MAX_CONNECT_QUEUE_CAPACITY: usize = 8192;
const MIN_CONNECT_DISPATCH_BATCH: usize = 1;
const MAX_CONNECT_DISPATCH_BATCH: usize = 256;
const MIN_KERNEL_INGRESS_DISPATCH_BATCH: usize = 8;
const MAX_KERNEL_INGRESS_DISPATCH_BATCH: usize = 256;
const MIN_KERNEL_QUEUE_CAPACITY: usize = 64;
const MAX_KERNEL_QUEUE_CAPACITY: usize = 16384;
const MIN_EBPF_PRUNE_THRESHOLD_PERCENT: usize = 50;
const MAX_EBPF_PRUNE_THRESHOLD_PERCENT: usize = 99;
const MIN_EBPF_PRUNE_TARGET_PERCENT: usize = 10;
const MAX_EBPF_PRUNE_TARGET_PERCENT: usize = 90;
const MIN_LRU_CACHE_CAPACITY: usize = 1_024;
const MAX_LRU_CACHE_CAPACITY: usize = 16_000_000;
const MIN_RING_BUFFER_CAPACITY: usize = 1;
const MAX_RING_BUFFER_CAPACITY: usize = 1_000_000;
const MIN_NETLINK_DELAY_MS: usize = 100;
const MAX_NETLINK_DELAY_MS: usize = 10_000;

pub(crate) static EFFECTIVE_TUNABLES: OnceLock<RwLock<RuntimeTunables>> = OnceLock::new();

impl NfqueueOverloadPolicy {
    fn parse(raw: &str) -> Option<Self> {
        match normalized_name(raw).as_str() {
            "fail-open" | "fail_open" | "default-action" => Some(Self::FailOpen),
            "drop-fast" | "drop_fast" | "deny-fast" | "deny_fast" => Some(Self::DropFast),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailOpen => "fail-open",
            Self::DropFast => "drop-fast",
        }
    }
}

impl Default for RuntimeTunables {
    fn default() -> Self {
        Self {
            max_concurrent_connect_attempts: 32,
            connect_worker_queue_capacity: 64,
            connect_dispatch_batch_size: 64,
            kernel_ingress_dispatch_batch_size: 32,
            kernel_dns_dispatch_batch_size: 32,
            kernel_process_dispatch_batch_size: 32,
            kernel_firewall_dispatch_batch_size: 32,
            kernel_dns_queue_capacity: 512,
            kernel_process_queue_capacity: 512,
            kernel_firewall_queue_capacity: 128,
            nfqueue_overload_policy: NfqueueOverloadPolicy::FailOpen,
            netlink_fallback_retry_delay_ms: 800,
            netlink_recovery_poll_interval_ms: 800,
            ebpf_map_prune_enabled: true,
            ebpf_map_prune_threshold_percent: 80,
            ebpf_map_prune_target_percent: 50,
            // AdGuard Home uses large DNS caches by default; keep this generous but tunable.
            dns_lru_cache_capacity: 4_000_000,
            process_info_cache_capacity: 131_072,
            pid_inode_cache_capacity: 262_144,
            pid_inode_key_cache_capacity: 262_144,
            stats_event_ring_capacity: 250,
            alert_overflow_ring_capacity: 32,
            audit_ring_capacity: 256,
        }
    }
}

impl RuntimeTunables {
    pub fn publish_global(self) {
        if let Some(global) = EFFECTIVE_TUNABLES.get() {
            if let Ok(mut current) = global.write() {
                *current = self;
            }
            return;
        }

        let _ = EFFECTIVE_TUNABLES.set(RwLock::new(self));
    }

    pub fn global() -> Self {
        EFFECTIVE_TUNABLES
            .get()
            .and_then(|global| global.read().ok().map(|current| *current))
            .unwrap_or_default()
    }

    pub fn reload_global() -> (Self, String) {
        let (tunables, source) = Self::load_effective();
        tunables.publish_global();
        (tunables, source)
    }

    pub fn load_effective() -> (Self, String) {
        let mut tunables = Self::default();
        let mut source_parts = vec!["defaults(conservative)".to_string()];

        if let Some(path) = Self::resolve_optin_tunables_path() {
            match Self::load_raw_tunables(&path) {
                Ok(raw) => {
                    tunables = tunables.apply_raw(raw);
                    source_parts.push(format!("file={}", path.display()));
                }
                Err(err) => {
                    warn!(path = %path.display(), "failed to load tunables file: {err}");
                }
            }
        }

        let env_override_count = tunables.apply_env_overrides();
        if env_override_count > 0 {
            source_parts.push(format!("env_overrides={env_override_count}"));
        }

        (tunables, source_parts.join(", "))
    }

    fn apply_raw(mut self, raw: RawRuntimeTunables) -> Self {
        if let Some(value) = raw.max_concurrent_connect_attempts {
            self.max_concurrent_connect_attempts =
                Self::clamp(value, MIN_CONNECT_WORKERS, MAX_CONNECT_WORKERS);
        }
        if let Some(value) = raw.connect_worker_queue_capacity {
            self.connect_worker_queue_capacity = Self::clamp(
                value,
                MIN_CONNECT_QUEUE_CAPACITY,
                MAX_CONNECT_QUEUE_CAPACITY,
            );
        }
        if let Some(value) = raw.connect_dispatch_batch_size {
            self.connect_dispatch_batch_size = Self::clamp(
                value,
                MIN_CONNECT_DISPATCH_BATCH,
                MAX_CONNECT_DISPATCH_BATCH,
            );
        }
        if let Some(value) = raw.kernel_ingress_dispatch_batch_size {
            self.kernel_ingress_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
        }
        if let Some(value) = raw.kernel_dns_dispatch_batch_size {
            self.kernel_dns_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
        }
        if let Some(value) = raw.kernel_process_dispatch_batch_size {
            self.kernel_process_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
        }
        if let Some(value) = raw.kernel_firewall_dispatch_batch_size {
            self.kernel_firewall_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
        }
        if let Some(value) = raw.kernel_dns_queue_capacity {
            self.kernel_dns_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
        }
        if let Some(value) = raw.kernel_process_queue_capacity {
            self.kernel_process_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
        }
        if let Some(value) = raw.kernel_firewall_queue_capacity {
            self.kernel_firewall_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
        }
        if let Some(value) = raw.nfqueue_overload_policy {
            if let Some(policy) = NfqueueOverloadPolicy::parse(&value) {
                self.nfqueue_overload_policy = policy;
            } else {
                warn!(
                    value = %value,
                    "invalid nfqueue_overload_policy in tunables file ignored"
                );
            }
        }
        if let Some(value) = raw.netlink_fallback_retry_delay_ms {
            self.netlink_fallback_retry_delay_ms =
                Self::clamp(value, MIN_NETLINK_DELAY_MS, MAX_NETLINK_DELAY_MS);
        }
        if let Some(value) = raw.netlink_recovery_poll_interval_ms {
            self.netlink_recovery_poll_interval_ms =
                Self::clamp(value, MIN_NETLINK_DELAY_MS, MAX_NETLINK_DELAY_MS);
        }
        if let Some(value) = raw.ebpf_map_prune_enabled {
            self.ebpf_map_prune_enabled = value;
        }
        if let Some(value) = raw.ebpf_map_prune_threshold_percent {
            self.ebpf_map_prune_threshold_percent = Self::clamp(
                value,
                MIN_EBPF_PRUNE_THRESHOLD_PERCENT,
                MAX_EBPF_PRUNE_THRESHOLD_PERCENT,
            );
        }
        if let Some(value) = raw.ebpf_map_prune_target_percent {
            self.ebpf_map_prune_target_percent = Self::clamp(
                value,
                MIN_EBPF_PRUNE_TARGET_PERCENT,
                MAX_EBPF_PRUNE_TARGET_PERCENT,
            );
        }
        if let Some(value) = raw.dns_lru_cache_capacity {
            self.dns_lru_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
        }
        if let Some(value) = raw.process_info_cache_capacity {
            self.process_info_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
        }
        if let Some(value) = raw.pid_inode_cache_capacity {
            self.pid_inode_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
        }
        if let Some(value) = raw.pid_inode_key_cache_capacity {
            self.pid_inode_key_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
        }
        if let Some(value) = raw.stats_event_ring_capacity {
            self.stats_event_ring_capacity =
                Self::clamp(value, MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY);
        }
        if let Some(value) = raw.alert_overflow_ring_capacity {
            self.alert_overflow_ring_capacity =
                Self::clamp(value, MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY);
        }
        if let Some(value) = raw.audit_ring_capacity {
            self.audit_ring_capacity =
                Self::clamp(value, MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY);
        }
        self
    }

    fn apply_env_overrides(&mut self) -> usize {
        let mut count = 0;

        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_MAX_CONCURRENT_CONNECT_ATTEMPTS")
        {
            self.max_concurrent_connect_attempts =
                Self::clamp(value, MIN_CONNECT_WORKERS, MAX_CONNECT_WORKERS);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_CONNECT_WORKER_QUEUE_CAPACITY")
        {
            self.connect_worker_queue_capacity = Self::clamp(
                value,
                MIN_CONNECT_QUEUE_CAPACITY,
                MAX_CONNECT_QUEUE_CAPACITY,
            );
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_CONNECT_DISPATCH_BATCH_SIZE") {
            self.connect_dispatch_batch_size = Self::clamp(
                value,
                MIN_CONNECT_DISPATCH_BATCH,
                MAX_CONNECT_DISPATCH_BATCH,
            );
            count += 1;
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_INGRESS_DISPATCH_BATCH_SIZE")
        {
            self.kernel_ingress_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_DNS_DISPATCH_BATCH_SIZE")
        {
            self.kernel_dns_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
            count += 1;
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_PROCESS_DISPATCH_BATCH_SIZE")
        {
            self.kernel_process_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
            count += 1;
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_FIREWALL_DISPATCH_BATCH_SIZE")
        {
            self.kernel_firewall_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_DNS_QUEUE_CAPACITY") {
            self.kernel_dns_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_PROCESS_QUEUE_CAPACITY")
        {
            self.kernel_process_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_FIREWALL_QUEUE_CAPACITY")
        {
            self.kernel_firewall_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
            count += 1;
        }
        if let Some(raw) = std::env::var("OPENSNITCH_TUNE_NFQUEUE_OVERLOAD_POLICY").ok() {
            if let Some(policy) = NfqueueOverloadPolicy::parse(&raw) {
                self.nfqueue_overload_policy = policy;
                count += 1;
            } else {
                warn!(
                    name = "OPENSNITCH_TUNE_NFQUEUE_OVERLOAD_POLICY",
                    value = %raw,
                    "invalid tunable env override ignored"
                );
            }
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_NETLINK_FALLBACK_RETRY_DELAY_MS")
        {
            self.netlink_fallback_retry_delay_ms =
                Self::clamp(value, MIN_NETLINK_DELAY_MS, MAX_NETLINK_DELAY_MS);
            count += 1;
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_NETLINK_RECOVERY_POLL_INTERVAL_MS")
        {
            self.netlink_recovery_poll_interval_ms =
                Self::clamp(value, MIN_NETLINK_DELAY_MS, MAX_NETLINK_DELAY_MS);
            count += 1;
        }
        if let Some(value) = Self::parse_env_bool("OPENSNITCH_TUNE_EBPF_MAP_PRUNE_ENABLED") {
            self.ebpf_map_prune_enabled = value;
            count += 1;
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_EBPF_MAP_PRUNE_THRESHOLD_PERCENT")
        {
            self.ebpf_map_prune_threshold_percent = Self::clamp(
                value,
                MIN_EBPF_PRUNE_THRESHOLD_PERCENT,
                MAX_EBPF_PRUNE_THRESHOLD_PERCENT,
            );
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_EBPF_MAP_PRUNE_TARGET_PERCENT")
        {
            self.ebpf_map_prune_target_percent = Self::clamp(
                value,
                MIN_EBPF_PRUNE_TARGET_PERCENT,
                MAX_EBPF_PRUNE_TARGET_PERCENT,
            );
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_DNS_LRU_CACHE_CAPACITY") {
            self.dns_lru_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_PROCESS_INFO_CACHE_CAPACITY") {
            self.process_info_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_PID_INODE_CACHE_CAPACITY") {
            self.pid_inode_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_PID_INODE_KEY_CACHE_CAPACITY") {
            self.pid_inode_key_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_STATS_EVENT_RING_CAPACITY") {
            self.stats_event_ring_capacity =
                Self::clamp(value, MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_ALERT_OVERFLOW_RING_CAPACITY") {
            self.alert_overflow_ring_capacity =
                Self::clamp(value, MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_AUDIT_RING_CAPACITY") {
            self.audit_ring_capacity =
                Self::clamp(value, MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY);
            count += 1;
        }

        count
    }

    fn parse_env_usize(name: &str) -> Option<usize> {
        let raw = std::env::var(name).ok()?;
        match raw.trim().parse::<usize>() {
            Ok(value) => Some(value),
            Err(err) => {
                warn!(%name, value = %raw, "invalid tunable env override ignored: {err}");
                None
            }
        }
    }

    fn parse_env_bool(name: &str) -> Option<bool> {
        let raw = std::env::var(name).ok()?;
        match normalized_name(&raw).as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => {
                warn!(%name, value = %raw, "invalid tunable bool env override ignored");
                None
            }
        }
    }

    fn clamp(value: usize, min: usize, max: usize) -> usize {
        value.clamp(min, max)
    }
}

#[cfg(test)]
#[path = "../tests/parsing/tunables.rs"]
mod tests;
