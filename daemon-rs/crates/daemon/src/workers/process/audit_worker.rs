use std::{path::PathBuf, thread, thread::JoinHandle, time::Duration};

use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    bus::Bus,
    models::kernel::event::{KernelEvent, ProcEventKind},
    platform::procmon::audit::AuditNetlinkSocket,
    workers::{KernelEventDispatch, runtime::helpers::build_current_thread_runtime},
};

pub(crate) struct AuditWorkerControl;

impl AuditWorkerControl {
    fn is_relevant_audit_line(data: &str) -> bool {
        data.contains("key=\"opensnitch\"")
            || data.contains("syscall=42")
            || data.contains("syscall=41")
            || data.contains("syscall=53")
            || data.contains("syscall=59")
            || data.contains("syscall=102")
    }

    fn parse_audit_pid(data: &str) -> Option<u32> {
        for token in data.split_whitespace() {
            if let Some(pid) = token.strip_prefix("pid=") {
                let pid = pid.trim_matches('"');
                if let Ok(value) = pid.parse::<u32>() {
                    return Some(value);
                }
            }
        }

        None
    }

    pub fn spawn(bus: Bus, socket_path: PathBuf, shutdown: CancellationToken) -> JoinHandle<()> {
        thread::spawn(move || {
            let Some(runtime) = build_current_thread_runtime("failed to initialize audit runtime")
            else {
                return;
            };

            runtime.block_on(async move {
                debug!(
                    fallback_path = %socket_path.display(),
                    "audit worker using netlink audit stream"
                );

                loop {
                    if shutdown.is_cancelled() {
                        break;
                    }

                    let mut socket = match AuditNetlinkSocket::open() {
                        Ok(socket) => socket,
                        Err(err) => {
                            warn!("audit netlink unavailable, retrying: {err}");
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            continue;
                        }
                    };

                    if let Err(err) = socket.enable_events().await {
                        warn!("failed to enable audit events, retrying: {err}");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }

                    debug!("audit netlink monitor connected");

                    loop {
                        if shutdown.is_cancelled() {
                            return;
                        }

                        match socket.recv_event(Duration::from_millis(500)).await {
                            Ok(Some(event)) => {
                                if !Self::is_relevant_audit_line(&event.data) {
                                    continue;
                                }

                                if let Some(pid) = Self::parse_audit_pid(&event.data)
                                    && matches!(
                                        crate::workers::dispatch_kernel_event_with_backoff(
                                            &bus.kernel_tx,
                                            KernelEvent::ProcStateChanged {
                                                pid,
                                                kind: ProcEventKind::Exec,
                                            },
                                        ),
                                        KernelEventDispatch::ChannelClosed
                                    )
                                {
                                    return;
                                }
                            }
                            Ok(None) => {}
                            Err(err) => {
                                warn!("audit netlink stream ended, reconnecting: {err}");
                                break;
                            }
                        }
                    }
                }
            });
        })
    }
}
