// Snapshot type shared with optional NFQUEUE debug/metrics adapters.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueMetricsSnapshot {
    pub queue_num: u16,
    pub packets_total: u64,
    pub verdict_accept: u64,
    pub verdict_drop: u64,
    pub verdict_requeue: u64,
    pub recv_errors: u64,
}
