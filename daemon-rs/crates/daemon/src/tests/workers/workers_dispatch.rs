use crate::{
    bus::{BusCaps, BusState},
    models::kernel::event::KernelEvent,
    platform::firewall::state::{FirewallBackend, FirewallState},
    workers::KernelEventDispatch,
};

#[test]
fn dispatch_kernel_event_with_backoff_drops_when_queue_remains_full() {
    let (bus, _rx) = BusState::build_with_caps(BusCaps::uniform(1));

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
        crate::workers::dispatch_kernel_event_with_backoff(&bus.kernel_tx, second),
        KernelEventDispatch::DroppedBackpressure
    );
}
