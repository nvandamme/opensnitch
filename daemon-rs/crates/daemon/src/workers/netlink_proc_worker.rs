use std::{sync::mpsc, thread, thread::JoinHandle, time::Duration};

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    bus::Bus,
    models::{kernel_event::KernelEvent, proc_event::ProcEventKind, proc_event::ProcEventSocket},
    workers::KernelEventDispatch,
};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);
const PROC_EVENT_WORKERS: usize = 4;

pub(crate) struct NetlinkProcWorkerControl;

impl NetlinkProcWorkerControl {
    fn spawn_dispatch_workers(
        bus: Bus,
        shutdown: CancellationToken,
    ) -> (
        Vec<mpsc::Sender<crate::models::proc_event::ProcPidEvent>>,
        Vec<JoinHandle<()>>,
    ) {
        let mut senders = Vec::with_capacity(PROC_EVENT_WORKERS);
        let mut handles = Vec::with_capacity(PROC_EVENT_WORKERS);

        for _ in 0..PROC_EVENT_WORKERS {
            let (tx, rx) = mpsc::channel::<crate::models::proc_event::ProcPidEvent>();
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
                                kind: match event.kind {
                                    ProcEventKind::Fork => {
                                        crate::models::kernel_event::ProcEventKind::Fork
                                    }
                                    ProcEventKind::Exec => {
                                        crate::models::kernel_event::ProcEventKind::Exec
                                    }
                                    ProcEventKind::Exit => {
                                        crate::models::kernel_event::ProcEventKind::Exit
                                    }
                                }
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
            while !shutdown.is_cancelled() {
                debug!("MonitorProcEvents start");
                let socket = match ProcEventSocket::open() {
                    Ok(sock) => sock,
                    Err(err) => {
                        warn!("unable to start netlink.ProcEventMonitor (0): {err}");
                        if crate::workers::sleep_with_shutdown(
                            &shutdown,
                            Duration::from_secs(3),
                            SHUTDOWN_POLL_INTERVAL,
                        ) {
                            break;
                        }
                        continue;
                    }
                };

                info!("ProcEventMonitor started");
                let (dispatchers, dispatcher_handles) =
                    Self::spawn_dispatch_workers(bus.clone(), shutdown.clone());
                let mut next_dispatcher = 0_usize;

                let mut consecutive_errors = 0_u32;

                while !shutdown.is_cancelled() {
                    match socket.recv_pid_event(Duration::from_secs(1)) {
                        Ok(Some(event)) => {
                            consecutive_errors = 0;
                            if dispatchers.is_empty() {
                                continue;
                            }
                            let idx = next_dispatcher % dispatchers.len();
                            next_dispatcher = (idx + 1) % dispatchers.len();
                            if dispatchers[idx].send(event).is_err() {
                                warn!(
                                    "proc event dispatcher channel closed, reinitializing listener"
                                );
                                break;
                            }
                        }
                        Ok(None) => {
                            consecutive_errors = 0;
                        }
                        Err(err) => {
                            consecutive_errors += 1;
                            warn!("proc connector read error: {err}");
                            if crate::workers::sleep_with_shutdown(
                                &shutdown,
                                Duration::from_millis(250),
                                SHUTDOWN_POLL_INTERVAL,
                            ) {
                                break;
                            }
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
                    if crate::workers::sleep_with_shutdown(
                        &shutdown,
                        Duration::from_secs(1),
                        SHUTDOWN_POLL_INTERVAL,
                    ) {
                        break;
                    }
                }
            }
        })
    }
}
