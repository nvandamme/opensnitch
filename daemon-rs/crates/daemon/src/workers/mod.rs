use std::{thread, time::Duration};

use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::models::kernel_event::KernelEvent;

pub mod audit_worker;
pub mod control;
pub mod dns_worker;
pub mod ebpf_worker;
pub mod firewall_worker;
pub mod netlink_proc_worker;
pub mod nfqueue_worker;

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

#[cfg(test)]
mod tests {
    use crate::{
        bus::build_bus,
        models::{
            firewall_state::{FirewallBackend, FirewallState},
            kernel_event::KernelEvent,
        },
    };

    use super::{KernelEventDispatch, dispatch_kernel_event_with_backoff};

    #[test]
    fn dispatch_kernel_event_with_backoff_drops_when_queue_remains_full() {
        let (bus, _rx) = build_bus(1);

        let first = KernelEvent::FirewallState(FirewallState {
            enabled: true,
            backend: FirewallBackend::Nftables,
        });
        let second = KernelEvent::FirewallState(FirewallState {
            enabled: false,
            backend: FirewallBackend::Iptables,
        });

        assert!(bus.kernel_tx.try_send(first).is_ok());
        assert_eq!(
            dispatch_kernel_event_with_backoff(&bus.kernel_tx, second),
            KernelEventDispatch::DroppedBackpressure
        );
    }
}
