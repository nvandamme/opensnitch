use crate::adapters::proc_connector::{
    CN_MSG_LEN, NLMSG_HDR_LEN, PROC_EVENT_EXEC, PROC_EVENT_EXEC_PID_OFFSET, PROC_EVENT_EXIT,
    PROC_EVENT_FORK, PROC_EVENT_FORK_CHILD_PID_OFFSET, PROC_EVENT_HEADER_LEN,
};
use crate::models::proc_event::ProcEventKind;
use crate::models::proc_event::ProcEventSocket;

fn build_frame(what: u32, pid: u32, is_fork: bool) -> Vec<u8> {
    let total = NLMSG_HDR_LEN + CN_MSG_LEN + 32;
    let mut frame = vec![0_u8; total];

    // nlmsghdr.nlmsg_len
    frame[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
    // cn_msg.len
    frame[NLMSG_HDR_LEN + 16..NLMSG_HDR_LEN + 18].copy_from_slice(&(32_u16).to_ne_bytes());
    // proc_event.what
    let payload_offset = NLMSG_HDR_LEN + CN_MSG_LEN;
    frame[payload_offset..payload_offset + 4].copy_from_slice(&what.to_ne_bytes());

    let pid_offset = if is_fork {
        payload_offset + PROC_EVENT_FORK_CHILD_PID_OFFSET
    } else {
        payload_offset + PROC_EVENT_EXEC_PID_OFFSET
    };
    frame[pid_offset..pid_offset + 4].copy_from_slice(&pid.to_ne_bytes());

    frame
}

#[test]
fn parse_proc_pid_event_exec() {
    let frame = build_frame(PROC_EVENT_EXEC, 1234, false);
    let parsed = ProcEventSocket::probe_parse_pid_event(&frame).expect("exec event should parse");
    assert_eq!(parsed.pid, 1234);
    assert!(matches!(parsed.kind, ProcEventKind::Exec));
}

#[test]
fn parse_proc_pid_event_exit() {
    let frame = build_frame(PROC_EVENT_EXIT, 4321, false);
    let parsed = ProcEventSocket::probe_parse_pid_event(&frame).expect("exit event should parse");
    assert_eq!(parsed.pid, 4321);
    assert!(matches!(parsed.kind, ProcEventKind::Exit));
}

#[test]
fn parse_proc_pid_event_fork_uses_child_pid() {
    let frame = build_frame(PROC_EVENT_FORK, 777, true);
    let parsed = ProcEventSocket::probe_parse_pid_event(&frame).expect("fork event should parse");
    assert_eq!(parsed.pid, 777);
    assert!(matches!(parsed.kind, ProcEventKind::Fork));
}

#[test]
fn parse_proc_pid_event_rejects_short_or_empty_frames() {
    assert!(ProcEventSocket::probe_parse_pid_event(&[]).is_none());

    let mut frame = build_frame(PROC_EVENT_EXEC, 10, false);
    frame.truncate(NLMSG_HDR_LEN + CN_MSG_LEN + PROC_EVENT_HEADER_LEN - 1);
    assert!(ProcEventSocket::probe_parse_pid_event(&frame).is_none());

    let mut frame = build_frame(PROC_EVENT_EXEC, 10, false);
    frame[NLMSG_HDR_LEN + 16..NLMSG_HDR_LEN + 18].copy_from_slice(&(0_u16).to_ne_bytes());
    assert!(ProcEventSocket::probe_parse_pid_event(&frame).is_none());
}

#[test]
fn parse_proc_pid_event_returns_none_for_unknown_event_kind() {
    let frame = build_frame(0xDEAD_BEEF, 2222, false);
    assert!(ProcEventSocket::probe_parse_pid_event(&frame).is_none());
}

#[test]
fn connector_payload_rejects_when_cn_len_exceeds_frame() {
    let mut frame = build_frame(PROC_EVENT_EXEC, 123, false);
    let too_large = (frame.len() as u16).saturating_add(32);
    frame[NLMSG_HDR_LEN + 16..NLMSG_HDR_LEN + 18].copy_from_slice(&too_large.to_ne_bytes());

    assert!(ProcEventSocket::probe_connector_payload(&frame).is_none());
    assert!(ProcEventSocket::probe_parse_pid_event(&frame).is_none());
}

#[test]
fn parse_proc_pid_event_handles_missing_pid_bytes_as_none() {
    let mut frame = build_frame(PROC_EVENT_EXEC, 999, false);
    let payload_offset = NLMSG_HDR_LEN + CN_MSG_LEN;
    frame.truncate(payload_offset + PROC_EVENT_EXEC_PID_OFFSET + 2);

    assert!(ProcEventSocket::probe_parse_pid_event(&frame).is_none());
}

#[test]
fn connector_read_helpers_return_none_out_of_bounds() {
    let frame = build_frame(PROC_EVENT_EXEC, 321, false);

    assert!(ProcEventSocket::probe_read_u16_ne_at(&frame, frame.len() - 1).is_none());
    assert!(ProcEventSocket::probe_read_u32_ne_at(&frame, frame.len() - 2).is_none());
}

#[test]
fn connector_payload_requires_minimum_proc_event_header_bytes() {
    let mut frame = build_frame(PROC_EVENT_EXEC, 456, false);
    let short_len = (PROC_EVENT_HEADER_LEN - 1) as u16;
    frame[NLMSG_HDR_LEN + 16..NLMSG_HDR_LEN + 18].copy_from_slice(&short_len.to_ne_bytes());

    assert_eq!(
        ProcEventSocket::probe_connector_payload(&frame).map(|payload| payload.len()),
        Some((PROC_EVENT_HEADER_LEN - 1) as usize)
    );
    assert!(ProcEventSocket::probe_parse_pid_event(&frame).is_none());
}
