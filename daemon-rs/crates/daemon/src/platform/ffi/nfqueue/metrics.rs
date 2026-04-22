use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::{NfqueueMetricsState, PacketVerdict, QUEUE_METRICS, QueueMetrics};

impl NfqueueMetricsState {
    pub(crate) fn queue_metrics_map() -> &'static std::sync::Mutex<HashMap<u16, QueueMetrics>> {
        QUEUE_METRICS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
    }

    #[cfg(test)]
    pub(crate) fn to_snapshot(
        queue_num: u16,
        metrics: QueueMetrics,
    ) -> crate::models::queue_metrics_snapshot::QueueMetricsSnapshot {
        crate::models::queue_metrics_snapshot::QueueMetricsSnapshot {
            queue_num,
            packets_total: metrics.packets_total,
            verdict_accept: metrics.verdict_accept,
            verdict_drop: metrics.verdict_drop,
            verdict_requeue: metrics.verdict_requeue,
            recv_errors: metrics.recv_errors,
        }
    }

    #[cfg(test)]
    pub fn debug_metrics_snapshot()
    -> Vec<crate::models::queue_metrics_snapshot::QueueMetricsSnapshot> {
        let Ok(metrics_map) = Self::queue_metrics_map().lock() else {
            return Vec::new();
        };

        let mut out: Vec<_> = metrics_map
            .iter()
            .map(|(queue_num, metrics)| Self::to_snapshot(*queue_num, *metrics))
            .collect();
        out.sort_by_key(|item| item.queue_num);
        out
    }

    pub(crate) fn record_packet_verdict(queue_num: u16, verdict: &PacketVerdict) {
        let Ok(mut metrics_map) = Self::queue_metrics_map().lock() else {
            return;
        };
        let entry = metrics_map.entry(queue_num).or_default();
        entry.packets_total = entry.packets_total.saturating_add(1);

        match verdict {
            PacketVerdict::Accept { .. } => {
                entry.verdict_accept = entry.verdict_accept.saturating_add(1);
            }
            PacketVerdict::AcceptWithPacket { .. } => {
                entry.verdict_accept = entry.verdict_accept.saturating_add(1);
            }
            PacketVerdict::Drop => {
                entry.verdict_drop = entry.verdict_drop.saturating_add(1);
            }
            PacketVerdict::Requeue { .. } => {
                entry.verdict_requeue = entry.verdict_requeue.saturating_add(1);
            }
        }
    }

    pub(crate) fn record_recv_error(queue_num: u16) {
        let Ok(mut metrics_map) = Self::queue_metrics_map().lock() else {
            return;
        };
        let entry = metrics_map.entry(queue_num).or_default();
        entry.recv_errors = entry.recv_errors.saturating_add(1);
    }

    pub(super) fn maybe_log_queue_metrics(queue_num: u16, last_log: &mut Instant) {
        if last_log.elapsed() < Duration::from_secs(60) {
            return;
        }
        *last_log = Instant::now();

        let Ok(metrics_map) = Self::queue_metrics_map().lock() else {
            return;
        };
        let Some(metrics) = metrics_map.get(&queue_num).copied() else {
            return;
        };

        tracing::debug!(
            queue_num,
            packets_total = metrics.packets_total,
            verdict_accept = metrics.verdict_accept,
            verdict_drop = metrics.verdict_drop,
            verdict_requeue = metrics.verdict_requeue,
            recv_errors = metrics.recv_errors,
            "nfqueue queue metrics"
        );
    }
}
