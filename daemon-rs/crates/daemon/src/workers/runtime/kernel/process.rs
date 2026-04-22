use crate::{
    daemon::ProcessKernelEvent,
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
                    crate::models::proc_event::ProcEventKind::Exit
                } else {
                    crate::models::proc_event::ProcEventKind::Exec
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
