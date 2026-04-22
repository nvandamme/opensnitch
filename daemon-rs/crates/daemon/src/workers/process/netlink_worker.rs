use std::{sync::mpsc, thread, thread::JoinHandle, time::Duration};

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    bus::Bus,
    models::{kernel_event::KernelEvent, proc_event::ProcEventKind},
    platform::ports::proc_connector_port::{NativeProcConnectorPort, ProcConnectorPlatformPort},
    workers::{KernelEventDispatch, runtime::support::build_current_thread_runtime},
};

const PROC_EVENT_WORKERS: usize = 4;
const PROC_EVENT_CHANNEL_CAPACITY: usize = 512;

pub(crate) struct NetlinkProcWorkerControl;

impl NetlinkProcWorkerControl {
    fn spawn_dispatch_workers(
        bus: Bus,
        shutdown: CancellationToken,
    ) -> (
        Vec<mpsc::SyncSender<crate::models::proc_event::ProcPidEvent>>,
        Vec<JoinHandle<()>>,
    ) {
        let mut senders = Vec::with_capacity(PROC_EVENT_WORKERS);
        let mut handles = Vec::with_capacity(PROC_EVENT_WORKERS);

        for _ in 0..PROC_EVENT_WORKERS {
            let (tx, rx) = mpsc::sync_channel::<crate::models::proc_event::ProcPidEvent>(PROC_EVENT_CHANNEL_CAPACITY);
            let worker_bus = bus.clone();
            let worker_shutdown = shutdown.clone();
            let handle = thread::spawn(move || {
                while !worker_shutdown.is_cancelled() {
                    let Ok(event) = rx.recv_timeout(Duration::from_millis(500)) else {
                        continue;
                    };

                    if matches!(event.kind, ProcEventKind::Fork) {
                        continue;
                    }

                    if matches!(
                        crate::workers::dispatch_kernel_event_with_backoff(
                            &worker_bus.kernel_tx,
                            KernelEvent::ProcStateChanged {
                                pid: event.pid,
                                kind: event.kind,
                            },
                        ),
                        KernelEventDispatch::ChannelClosed
                    ) {
                        return;
                    }
                }
            });

            senders.push(tx);
            handles.push(handle);
        }

        (senders, handles)
    }

    pub fn spawn(bus: Bus, shutdown: CancellationToken) -> JoinHandle<()> {
        thread::spawn(move || {
            let Some(runtime) = build_current_thread_runtime("failed to initialize proc connector runtime") else {
                return;
            };

            runtime.block_on(async move {
                while !shutdown.is_cancelled() {
                    debug!("MonitorProcEvents start");
                    let mut socket = match NativeProcConnectorPort::open() {
                        Ok(sock) => sock,
                        Err(err) => {
                            warn!("unable to start netlink.ProcEventMonitor (0): {err}");
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            continue;
                        }
                    };

                    info!("ProcEventMonitor started");
                    let (dispatchers, dispatcher_handles) =
                        Self::spawn_dispatch_workers(bus.clone(), shutdown.clone());
                    let mut next_dispatcher = 0_usize;

                    let mut consecutive_errors = 0_u32;

                    while !shutdown.is_cancelled() {
                        match socket.recv_pid_event_async(Duration::from_secs(1)).await {
                            Ok(Some(event)) => {
                                consecutive_errors = 0;
                                if dispatchers.is_empty() {
                                    continue;
                                }
                                let idx = next_dispatcher % dispatchers.len();
                                next_dispatcher = (idx + 1) % dispatchers.len();
                                match dispatchers[idx].try_send(event) {
                                    Ok(()) => {}
                                    Err(mpsc::TrySendError::Full(_)) => {
                                        // Backpressure: drop event rather than blocking the socket reader.
                                    }
                                    Err(mpsc::TrySendError::Disconnected(_)) => {
                                        warn!(
                                            "proc event dispatcher channel closed, reinitializing listener"
                                        );
                                        break;
                                    }
                                }
                            }
                            Ok(None) => {
                                consecutive_errors = 0;
                            }
                            Err(err) => {
                                consecutive_errors += 1;
                                warn!("proc connector read error: {err}");
                                tokio::time::sleep(Duration::from_millis(250)).await;
                                if consecutive_errors >= 5 {
                                    warn!("proc connector unstable, reinitializing listener");
                                    break;
                                }
                            }
                        }
                    }

                    drop(dispatchers);
                    for handle in dispatcher_handles {
                        let _ = handle.join();
                    }

                    if !shutdown.is_cancelled() {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            });
        })
    }
}
