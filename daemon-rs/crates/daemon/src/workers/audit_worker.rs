use std::{path::PathBuf, thread, thread::JoinHandle, time::Duration};

use netlink_packet_core::NetlinkPayload;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    bus::Bus,
    models::kernel_event::{KernelEvent, ProcEventKind},
    workers::{KernelEventDispatch, dispatch_kernel_event_with_backoff},
};

trait AuditLineExt {
    fn is_relevant_audit_line(&self) -> bool;
    fn parse_audit_pid(&self) -> Option<u32>;
}

impl AuditLineExt for str {
    fn is_relevant_audit_line(&self) -> bool {
        self.contains("key=\"opensnitch\"")
            || self.contains("syscall=42")
            || self.contains("syscall=41")
            || self.contains("syscall=102")
    }

    fn parse_audit_pid(&self) -> Option<u32> {
        for token in self.split_whitespace() {
            if let Some(pid) = token.strip_prefix("pid=") {
                let pid = pid.trim_matches('"');
                if let Ok(value) = pid.parse::<u32>() {
                    return Some(value);
                }
            }
        }

        None
    }
}

pub fn spawn(bus: Bus, socket_path: PathBuf, shutdown: CancellationToken) -> JoinHandle<()> {
    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                warn!("failed to initialize audit runtime: {err}");
                return;
            }
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
                                if !data.is_relevant_audit_line() {
                                    continue;
                                }

                                if let Some(pid) = data.parse_audit_pid()
                                    && matches!(
                                        dispatch_kernel_event_with_backoff(
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
