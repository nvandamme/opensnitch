use std::{
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::models::kernel_event::KernelEvent;

const KERNEL_EVENT_SEND_RETRIES: usize = 8;
const KERNEL_EVENT_SEND_BACKOFF: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelEventDispatch {
    Sent,
    ChannelClosed,
    DroppedBackpressure,
}

pub(crate) fn dispatch_kernel_event_with_backoff(
    tx: &mpsc::Sender<KernelEvent>,
    event: KernelEvent,
) -> KernelEventDispatch {
    let mut pending = event;

    for _ in 0..KERNEL_EVENT_SEND_RETRIES {
        match tx.try_send(pending) {
            Ok(()) => return KernelEventDispatch::Sent,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                debug!("kernel event channel closed during dispatch");
                return KernelEventDispatch::ChannelClosed;
            }
            Err(mpsc::error::TrySendError::Full(event)) => {
                pending = event;
                thread::sleep(KERNEL_EVENT_SEND_BACKOFF);
            }
        }
    }

    warn!(
        retries = KERNEL_EVENT_SEND_RETRIES,
        "kernel event dispatch dropped due to sustained backpressure"
    );
    KernelEventDispatch::DroppedBackpressure
}

pub(crate) fn sleep_with_shutdown(
    shutdown: &CancellationToken,
    duration: Duration,
    poll_interval: Duration,
) -> bool {
    let deadline = Instant::now() + duration;
    while !shutdown.is_cancelled() {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }

        let remaining = deadline.saturating_duration_since(now);
        thread::sleep(remaining.min(poll_interval));
    }

    true
}

pub(crate) fn join_thread_with_timeout(
    name: &str,
    handle: JoinHandle<()>,
    timeout: Duration,
    poll_interval: Duration,
) {
    let started = Instant::now();
    while !handle.is_finished() && started.elapsed() < timeout {
        thread::sleep(poll_interval);
    }

    if !handle.is_finished() {
        warn!("{name} thread did not stop within {timeout:?}; detaching");
        return;
    }

    let _ = handle.join();
}
