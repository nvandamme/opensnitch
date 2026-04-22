use std::{path::PathBuf, thread, thread::JoinHandle, time::Duration};

use netlink_packet_core::NetlinkPayload;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    bus::Bus,
    models::{kernel_event::KernelEvent, proc_event::ProcEventKind},
    workers::{KernelEventDispatch, runtime::support::build_current_thread_runtime},
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

                    let (connection, mut handle, mut messages) = match audit::new_connection() {
                        Ok(parts) => parts,
                        Err(err) => {
                            warn!("audit netlink unavailable, retrying: {err}");
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            continue;
                        }
                    };

                    tokio::spawn(connection);

                    if let Err(err) = handle.enable_events().await {
                        warn!("failed to enable audit events, retrying: {err}");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }

                    debug!("audit netlink monitor connected");

                    loop {
                        tokio::select! {
                            _ = shutdown.cancelled() => return,
                            message = messages.next() => {
                                let Some((msg, _)) = message else {
                                    warn!("audit netlink stream ended, reconnecting");
                                    break;
                                };

                                if let NetlinkPayload::InnerMessage(audit::packet::AuditMessage::Event((_kind, data))) = msg.payload {
                                    if !Self::is_relevant_audit_line(&data) {
                                        continue;
                                    }

                                    if let Some(pid) = Self::parse_audit_pid(&data)
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
                            }
                        }
                    }
                }
            });
        })
    }
}
