#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfqueueOverloadPolicy {
    FailOpen = 0,
    DropFast = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeTunables {
    pub max_concurrent_connect_attempts: usize,
    pub connect_worker_queue_capacity: usize,
    pub connect_dispatch_batch_size: usize,
    pub kernel_ingress_dispatch_batch_size: usize,
    pub kernel_dns_dispatch_batch_size: usize,
    pub kernel_process_dispatch_batch_size: usize,
    pub kernel_firewall_dispatch_batch_size: usize,
    pub kernel_dns_queue_capacity: usize,
    pub kernel_process_queue_capacity: usize,
    pub kernel_firewall_queue_capacity: usize,
    pub nfqueue_overload_policy: NfqueueOverloadPolicy,
    pub netlink_fallback_retry_delay_ms: usize,
    pub netlink_recovery_poll_interval_ms: usize,
    pub ebpf_map_prune_enabled: bool,
    pub ebpf_map_prune_threshold_percent: usize,
    pub ebpf_map_prune_target_percent: usize,
    pub dns_lru_cache_capacity: usize,
    pub process_info_cache_capacity: usize,
    pub pid_inode_cache_capacity: usize,
    pub pid_inode_key_cache_capacity: usize,
    pub stats_event_ring_capacity: usize,
    pub alert_overflow_ring_capacity: usize,
}
