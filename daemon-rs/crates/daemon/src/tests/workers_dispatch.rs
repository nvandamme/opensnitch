use crate::{
    bus::build_bus,
    models::{
        firewall_state::{FirewallBackend, FirewallState},
        kernel_event::KernelEvent,
    },
    workers::{KernelEventDispatch, dispatch_kernel_event_with_backoff},
};

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
