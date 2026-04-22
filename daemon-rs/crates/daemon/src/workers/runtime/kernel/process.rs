use crate::{daemon::ProcessKernelEvent, services::process::ProcessService};

pub(crate) async fn handle_process_kernel_event(
    process_service: &ProcessService,
    event: ProcessKernelEvent,
) {
    match event {
        ProcessKernelEvent::ProcStateChanged { pid, kind } => {
            process_service.sync_from_proc_event(pid, kind).await;
            tracing::debug!(pid, ?kind, "proc state changed event received");
        }
        ProcessKernelEvent::EbpfProcStateChanged(payload) => {
            process_service
                .sync_from_proc_event(payload.pid, payload.kind)
                .await;
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
                process_service.sync_from_proc_event(pid, kind).await;
            }
            tracing::debug!(pid, uid, note, "ebpf runtime status event received");
        }
    }
}
