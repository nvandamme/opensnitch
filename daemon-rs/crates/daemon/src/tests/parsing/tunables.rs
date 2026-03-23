use super::*;

#[test]
fn apply_raw_accepts_ring_buffer_capacities() {
    let tunables = RuntimeTunables::default().apply_raw(RawRuntimeTunables {
        stats_event_ring_capacity: Some(512),
        alert_overflow_ring_capacity: Some(64),
        ..Default::default()
    });

    assert_eq!(tunables.stats_event_ring_capacity, 512);
    assert_eq!(tunables.alert_overflow_ring_capacity, 64);
}

#[test]
fn apply_raw_clamps_ring_buffer_capacities() {
    let tunables = RuntimeTunables::default().apply_raw(RawRuntimeTunables {
        stats_event_ring_capacity: Some(0),
        alert_overflow_ring_capacity: Some(usize::MAX),
        ..Default::default()
    });

    assert_eq!(tunables.stats_event_ring_capacity, MIN_RING_BUFFER_CAPACITY);
    assert_eq!(
        tunables.alert_overflow_ring_capacity,
        MAX_RING_BUFFER_CAPACITY
    );
}
