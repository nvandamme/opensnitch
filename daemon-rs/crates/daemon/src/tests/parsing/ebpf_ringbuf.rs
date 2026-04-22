use crate::services::ebpf::probe_select_opensnitch_ringbuf_map_id;
use opensnitch_ebpf_common::maps::EVENTS_MAP_MAX_ENTRIES;

#[test]
fn selects_latest_matching_ringbuf_candidate() {
    let selected = probe_select_opensnitch_ringbuf_map_id(&[
        (3, true, true, EVENTS_MAP_MAX_ENTRIES),
        (9, true, true, EVENTS_MAP_MAX_ENTRIES),
    ]);

    assert_eq!(selected, Some(9));
}

#[test]
fn rejects_candidates_with_wrong_shape() {
    let selected = probe_select_opensnitch_ringbuf_map_id(&[
        (4, false, true, EVENTS_MAP_MAX_ENTRIES),
        (5, true, false, EVENTS_MAP_MAX_ENTRIES),
        (6, true, true, 4096),
    ]);

    assert_eq!(selected, None);
}

#[test]
fn selects_same_map_for_aya_and_libbpf_shaped_candidates() {
    let libbpf_selected = probe_select_opensnitch_ringbuf_map_id(&[
        (8, true, true, EVENTS_MAP_MAX_ENTRIES),
        (11, true, true, EVENTS_MAP_MAX_ENTRIES),
        (12, false, true, EVENTS_MAP_MAX_ENTRIES),
    ]);
    let aya_selected = probe_select_opensnitch_ringbuf_map_id(&[
        (8, true, true, EVENTS_MAP_MAX_ENTRIES),
        (11, true, true, EVENTS_MAP_MAX_ENTRIES),
        (77, true, false, EVENTS_MAP_MAX_ENTRIES),
    ]);

    assert_eq!(libbpf_selected, Some(11));
    assert_eq!(aya_selected, libbpf_selected);
}

#[cfg(feature = "aya-ebpf")]
#[test]
fn aya_poll_timeout_produces_empty_sample_path() {
    assert!(!crate::services::ebpf::probe_aya_poll_has_readable_samples(
        0,
        rustix::event::PollFlags::empty(),
    ));
}

#[cfg(feature = "aya-ebpf")]
#[test]
fn aya_poll_without_readable_event_produces_empty_sample_path() {
    assert!(!crate::services::ebpf::probe_aya_poll_has_readable_samples(
        1,
        rustix::event::PollFlags::OUT,
    ));
}

#[cfg(feature = "aya-ebpf")]
#[test]
fn aya_poll_with_readable_event_allows_sample_drain() {
    assert!(crate::services::ebpf::probe_aya_poll_has_readable_samples(
        1,
        rustix::event::PollFlags::IN,
    ));
}
