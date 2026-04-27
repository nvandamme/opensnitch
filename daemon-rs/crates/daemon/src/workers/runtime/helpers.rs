use std::{
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::models::kernel::event::KernelEvent;

const KERNEL_EVENT_SEND_RETRIES: usize = 8;
const KERNEL_EVENT_SEND_BACKOFF: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelEventDispatch {
    Sent,
    ChannelClosed,
    DroppedBackpressure,
}

#[derive(Debug)]
pub(crate) struct TryRecvBurst<T> {
    pub items: Vec<T>,
    pub disconnected: bool,
}

/// Sealed trait so `drain_try_recv_burst_impl` works for both bounded and
/// unbounded tokio mpsc receivers without exposing the abstraction publicly.
trait TryRecvChannel<T> {
    fn try_recv_item(&mut self) -> Result<T, mpsc::error::TryRecvError>;
}

impl<T> TryRecvChannel<T> for mpsc::Receiver<T> {
    fn try_recv_item(&mut self) -> Result<T, mpsc::error::TryRecvError> {
        self.try_recv()
    }
}

impl<T> TryRecvChannel<T> for mpsc::UnboundedReceiver<T> {
    fn try_recv_item(&mut self) -> Result<T, mpsc::error::TryRecvError> {
        self.try_recv()
    }
}

fn drain_try_recv_burst_impl<T, C>(
    rx: &mut dyn TryRecvChannel<T>,
    max_items: usize,
    mut should_continue: C,
) -> TryRecvBurst<T>
where
    C: FnMut() -> bool,
{
    let mut items = Vec::with_capacity(max_items);

    for _ in 0..max_items {
        if !should_continue() {
            break;
        }

        match rx.try_recv_item() {
            Ok(item) => items.push(item),
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return TryRecvBurst {
                    items,
                    disconnected: true,
                };
            }
        }
    }

    TryRecvBurst {
        items,
        disconnected: false,
    }
}

pub(crate) fn drain_try_recv_burst<T, C>(
    rx: &mut mpsc::Receiver<T>,
    max_items: usize,
    should_continue: C,
) -> TryRecvBurst<T>
where
    C: FnMut() -> bool,
{
    drain_try_recv_burst_impl(rx, max_items, should_continue)
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

pub(crate) fn build_current_thread_runtime(
    init_error_context: &str,
) -> Option<tokio::runtime::Runtime> {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => Some(runtime),
        Err(err) => {
            warn!("{init_error_context}: {err}");
            None
        }
    }
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
