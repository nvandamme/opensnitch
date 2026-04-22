use std::{
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    adapters::proc_connector::open_proc_events,
    bus::Bus,
    models::{kernel_event::KernelEvent, proc_event::ProcEventKind},
    workers::{KernelEventDispatch, dispatch_kernel_event_with_backoff},
};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub fn spawn(bus: Bus, shutdown: CancellationToken) -> JoinHandle<()> {
    thread::spawn(move || {
        while !shutdown.is_cancelled() {
            let socket = match open_proc_events() {
                Ok(sock) => sock,
                Err(err) => {
                    warn!("proc connector unavailable: {err}");
                    if sleep_with_shutdown(&shutdown, Duration::from_secs(3)) {
                        break;
                    }
                    continue;
                }
            };

            let mut consecutive_errors = 0_u32;

            while !shutdown.is_cancelled() {
                match socket.recv_pid_event(Duration::from_secs(1)) {
                    Ok(Some(event)) => {
                        consecutive_errors = 0;
                        if matches!(event.kind, ProcEventKind::Fork) {
                            continue;
                        }
                        if matches!(
                            dispatch_kernel_event_with_backoff(
                                &bus.kernel_tx,
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
                                    },
                                },
                            ),
                            KernelEventDispatch::ChannelClosed
                        ) {
                            return;
                        }
                    }
                    Ok(None) => {
                        consecutive_errors = 0;
                    }
                    Err(err) => {
                        consecutive_errors += 1;
                        warn!("proc connector read error: {err}");
                        if sleep_with_shutdown(&shutdown, Duration::from_millis(250)) {
                            break;
                        }
                        if consecutive_errors >= 5 {
                            warn!("proc connector unstable, reinitializing listener");
                            break;
                        }
                    }
                }
            }

            if !shutdown.is_cancelled() {
                if sleep_with_shutdown(&shutdown, Duration::from_secs(1)) {
                    break;
                }
            }
        }
    })
}

fn sleep_with_shutdown(shutdown: &CancellationToken, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    while !shutdown.is_cancelled() {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }

        let remaining = deadline.saturating_duration_since(now);
        thread::sleep(remaining.min(SHUTDOWN_POLL_INTERVAL));
    }

    true
}
