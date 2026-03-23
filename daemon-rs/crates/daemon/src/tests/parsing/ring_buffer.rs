use crate::utils::ring_buffer::RingBuffer;

#[test]
fn push_overwrite_keeps_latest_n_items() {
    let mut ring = RingBuffer::new(3);
    ring.push_overwrite(1_u32);
    ring.push_overwrite(2_u32);
    ring.push_overwrite(3_u32);
    ring.push_overwrite(4_u32);

    assert_eq!(ring.len(), 3);
    assert_eq!(ring.drain_all(), vec![2_u32, 3_u32, 4_u32]);
}

#[test]
fn set_capacity_trims_oldest_items() {
    let mut ring = RingBuffer::new(5);
    for value in 0..5_u32 {
        ring.push_overwrite(value);
    }

    ring.set_capacity(2);
    assert_eq!(ring.len(), 2);
    assert_eq!(ring.drain_all(), vec![3_u32, 4_u32]);
}

#[test]
fn drain_all_clears_ring() {
    let mut ring = RingBuffer::new(4);
    ring.push_overwrite(10_u32);
    ring.push_overwrite(11_u32);

    let drained = ring.drain_all();
    assert_eq!(drained, vec![10_u32, 11_u32]);
    assert!(ring.is_empty());
}
