use crate::platform::netlink::control::{NetlinkControlFlow, classify_nlmsg_control};
use nix::libc;

#[test]
fn control_classifier_ignores_noop_done_and_zero_error() {
    assert_eq!(
        classify_nlmsg_control(libc::NLMSG_NOOP as u16, b"").expect("noop classify"),
        NetlinkControlFlow::Ignore
    );
    assert_eq!(
        classify_nlmsg_control(libc::NLMSG_DONE as u16, b"").expect("done classify"),
        NetlinkControlFlow::Ignore
    );
    assert_eq!(
        classify_nlmsg_control(libc::NLMSG_ERROR as u16, &0_i32.to_ne_bytes())
            .expect("zero error classify"),
        NetlinkControlFlow::Ignore
    );
}

#[test]
fn control_classifier_processes_non_control_messages() {
    assert_eq!(
        classify_nlmsg_control(0x1234, b"payload").expect("data classify"),
        NetlinkControlFlow::Process
    );
}

#[test]
fn control_classifier_surfaces_errno_for_nonzero_error() {
    let err = classify_nlmsg_control(libc::NLMSG_ERROR as u16, &(-libc::EPERM).to_ne_bytes())
        .expect_err("non-zero error should fail");
    let io = err.downcast_ref::<std::io::Error>().expect("io error");
    assert_eq!(io.raw_os_error(), Some(libc::EPERM));
}
