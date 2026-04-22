use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::{
    daemon::{KernelPipeline, KernelPipelineCounters, ProcessKernelEvent},
    models::{dns_payload::DnsPayload, kernel_event::KernelEvent},
};

const KERNEL_PIPELINE_SEND_RETRIES: usize = 8;
const KERNEL_PIPELINE_SEND_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

/// Fan-out a kernel event to the appropriate typed ingress channel.
///
/// Uses [`Sender::try_send`] so this function remains synchronous and
/// lock-free on the hot path.  When the ingress channel is full the event is
/// dropped (counted via `counters.increment_drop`) rather than blocking the
/// fan-out task.  Returns `false` only when the target receiver has been
/// dropped (daemon shutdown), signalling the caller to break its event loop.
pub(crate) fn fanout_kernel_ingress_event(
    event: KernelEvent,
    dns_ingress_tx: &tokio::sync::mpsc::Sender<DnsPayload>,
    process_ingress_tx: &tokio::sync::mpsc::Sender<ProcessKernelEvent>,
    firewall_ingress_tx: &tokio::sync::mpsc::Sender<
        crate::models::firewall_state::FirewallState,
    >,
    counters: &KernelPipelineCounters,
) -> bool {
    match event {
        KernelEvent::DnsUpdate(payload) => match dns_ingress_tx.try_send(payload) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                counters.increment_drop(KernelPipeline::Dns);
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        },
        KernelEvent::ProcStateChanged { pid, kind } => {
            match process_ingress_tx
                .try_send(ProcessKernelEvent::ProcStateChanged { pid, kind })
            {
                Ok(()) => true,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    counters.increment_drop(KernelPipeline::Process);
                    true
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
            }
        }
        KernelEvent::EbpfProcStateChanged(payload) => {
            match process_ingress_tx.try_send(ProcessKernelEvent::EbpfProcStateChanged(payload)) {
                Ok(()) => true,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    counters.increment_drop(KernelPipeline::Process);
                    true
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
            }
        }
        KernelEvent::EbpfProcessMapHit { pid, uid, note } => match process_ingress_tx
            .try_send(ProcessKernelEvent::EbpfProcessMapHit { pid, uid, note })
        {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                counters.increment_drop(KernelPipeline::Process);
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        },
        KernelEvent::FirewallState(state) => match firewall_ingress_tx.try_send(state) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                counters.increment_drop(KernelPipeline::Firewall);
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        },
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
