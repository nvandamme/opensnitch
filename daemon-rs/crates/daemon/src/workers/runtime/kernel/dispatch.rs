use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::{
    daemon::{KernelPipeline, KernelPipelineCounters, ProcessKernelEvent},
    models::{dns_payload::DnsPayload, kernel_event::KernelEvent},
};

const KERNEL_PIPELINE_SEND_RETRIES: usize = 8;
const KERNEL_PIPELINE_SEND_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

pub(crate) fn fanout_kernel_ingress_event(
    event: KernelEvent,
    dns_ingress_tx: &tokio::sync::mpsc::UnboundedSender<DnsPayload>,
    process_ingress_tx: &tokio::sync::mpsc::UnboundedSender<ProcessKernelEvent>,
    firewall_ingress_tx: &tokio::sync::mpsc::UnboundedSender<
        crate::models::firewall_state::FirewallState,
    >,
) -> bool {
    match event {
        KernelEvent::DnsUpdate(payload) => dns_ingress_tx.send(payload).is_ok(),
        KernelEvent::ProcStateChanged { pid, kind } => process_ingress_tx
            .send(ProcessKernelEvent::ProcStateChanged { pid, kind })
            .is_ok(),
        KernelEvent::EbpfProcStateChanged(payload) => process_ingress_tx
            .send(ProcessKernelEvent::EbpfProcStateChanged(payload))
            .is_ok(),
        KernelEvent::EbpfProcessMapHit { pid, uid, note } => process_ingress_tx
            .send(ProcessKernelEvent::EbpfProcessMapHit { pid, uid, note })
            .is_ok(),
        KernelEvent::FirewallState(state) => firewall_ingress_tx.send(state).is_ok(),
    }
}

pub(crate) async fn dispatch_kernel_pipeline_event<T>(
    tx: &tokio::sync::mpsc::Sender<T>,
    event: T,
    shutdown: &CancellationToken,
    counters: &Arc<KernelPipelineCounters>,
    pipeline: KernelPipeline,
) -> bool {
    let pending = event;

    for _ in 0..KERNEL_PIPELINE_SEND_RETRIES {
        if shutdown.is_cancelled() {
            return false;
        }

        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(pending);
                return true;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                tokio::select! {
                    _ = shutdown.cancelled() => return false,
                    _ = tokio::time::sleep(KERNEL_PIPELINE_SEND_BACKOFF) => {}
                }
            }
        }
    }

    let dropped = counters.increment_drop(pipeline);
    tracing::warn!(
        pipeline = pipeline.as_str(),
        dropped_count = dropped,
        "kernel event pipeline queue saturated; dropping event"
    );
    true
}
