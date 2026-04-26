use crate::platform::firewall::monitor::probe_should_process_nft_event_message;
use nix::libc;

#[test]
fn nft_monitor_ignores_noop_and_done_control_messages() {
    assert!(
        !probe_should_process_nft_event_message(libc::NLMSG_NOOP as u16, b"")
            .expect("noop should parse")
    );
    assert!(
        !probe_should_process_nft_event_message(libc::NLMSG_DONE as u16, b"")
            .expect("done should parse")
    );
}

#[test]
fn nft_monitor_ignores_success_error_ack() {
    let payload = 0_i32.to_ne_bytes();
    assert!(
        !probe_should_process_nft_event_message(libc::NLMSG_ERROR as u16, &payload)
            .expect("zero-error ack should be ignored")
    );
}

#[test]
fn nft_monitor_surfaces_nonzero_error_errno() {
    let payload = (-libc::EPERM).to_ne_bytes();
    let err = probe_should_process_nft_event_message(libc::NLMSG_ERROR as u16, &payload)
        .expect_err("non-zero netlink error should fail");
    let io = err.downcast_ref::<std::io::Error>().expect("io error");
    assert_eq!(io.raw_os_error(), Some(libc::EPERM));
}

#[test]
fn nft_monitor_processes_regular_event_messages() {
    assert!(
        probe_should_process_nft_event_message(0x1234, b"nft-event")
            .expect("regular message should parse")
    );
}
