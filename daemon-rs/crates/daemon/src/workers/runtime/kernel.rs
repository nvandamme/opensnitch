use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::{
    daemon::{KernelPipeline, KernelPipelineCounters, ProcessKernelEvent},
    models::{dns::payload::DnsPayload, kernel::event::KernelEvent},
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
        crate::platform::firewall::state::FirewallState,
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
            match process_ingress_tx.try_send(ProcessKernelEvent::ProcStateChanged { pid, kind }) {
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

// --- firewall handler ---

pub(crate) async fn handle_firewall_state_event(
    state: crate::platform::firewall::state::FirewallState,
) {
    tracing::debug!(
        enabled = state.enabled,
        backend = crate::services::firewall::firewall_backend_name(state.backend),
        "firewall state event received"
    );
}

// --- process handler ---

use crate::{
    models::audit::{AuditEvent, AuditEventKind, ProcessAction},
    services::{audit::AuditService, process::ProcessService},
};

pub(crate) async fn handle_process_kernel_event(
    process_service: &ProcessService,
    audit: &AuditService,
    event: ProcessKernelEvent,
) {
    match event {
        ProcessKernelEvent::ProcStateChanged { pid, kind } => {
            if let Err(reason) = process_service.sync_from_proc_event(pid, kind).await {
                audit.emit(AuditEvent::hot(AuditEventKind::ProcessAction(
                    ProcessAction::ProcessScanFailed { pid, reason },
                )));
            }
            tracing::debug!(pid, ?kind, "proc state changed event received");
        }
        ProcessKernelEvent::EbpfProcStateChanged(payload) => {
            if let Err(reason) = process_service
                .sync_from_proc_event(payload.pid, payload.kind)
                .await
            {
                audit.emit(AuditEvent::hot(AuditEventKind::ProcessAction(
                    ProcessAction::ProcessScanFailed {
                        pid: payload.pid,
                        reason,
                    },
                )));
            }
            tracing::debug!(
                pid = payload.pid,
                uid = payload.uid,
                ppid = payload.ppid,
                kind = ?payload.kind,
                comm = payload.comm,
                exe = payload.exe,
                args = ?payload.args,
                args_partial = payload.args_partial,
                ret_code = payload.ret_code,
                "native eBPF process state event received"
            );
        }
        ProcessKernelEvent::EbpfProcessMapHit { pid, uid, note } => {
            if pid != std::process::id() {
                let kind = if note.contains("sched_exit") {
                    crate::platform::procmon::proc_event::ProcEventKind::Exit
                } else {
                    crate::platform::procmon::proc_event::ProcEventKind::Exec
                };
                if let Err(reason) = process_service.sync_from_proc_event(pid, kind).await {
                    audit.emit(AuditEvent::hot(AuditEventKind::ProcessAction(
                        ProcessAction::ProcessScanFailed { pid, reason },
                    )));
                }
            }
            tracing::debug!(pid, uid, note, "ebpf runtime status event received");
        }
    }
}
