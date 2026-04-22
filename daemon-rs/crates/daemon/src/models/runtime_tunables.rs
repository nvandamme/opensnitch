use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawRuntimeTunables {
    pub max_concurrent_connect_attempts: Option<usize>,
    pub connect_worker_queue_capacity: Option<usize>,
    pub connect_dispatch_batch_size: Option<usize>,
    pub kernel_ingress_dispatch_batch_size: Option<usize>,
    pub kernel_dns_dispatch_batch_size: Option<usize>,
    pub kernel_process_dispatch_batch_size: Option<usize>,
    pub kernel_firewall_dispatch_batch_size: Option<usize>,
    pub kernel_dns_queue_capacity: Option<usize>,
    pub kernel_process_queue_capacity: Option<usize>,
    pub kernel_firewall_queue_capacity: Option<usize>,
    pub nfqueue_overload_policy: Option<String>,
    pub netlink_fallback_retry_delay_ms: Option<usize>,
    pub netlink_recovery_poll_interval_ms: Option<usize>,
    pub ebpf_map_prune_enabled: Option<bool>,
    pub ebpf_map_prune_threshold_percent: Option<usize>,
    pub ebpf_map_prune_target_percent: Option<usize>,
    pub dns_lru_cache_capacity: Option<usize>,
    pub process_info_cache_capacity: Option<usize>,
    pub pid_inode_cache_capacity: Option<usize>,
    pub pid_inode_key_cache_capacity: Option<usize>,
    pub stats_event_ring_capacity: Option<usize>,
    pub alert_overflow_ring_capacity: Option<usize>,
    pub audit_ring_capacity: Option<usize>,
}
