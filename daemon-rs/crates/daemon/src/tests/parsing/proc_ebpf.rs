use opensnitch_ebpf_common::process::{
    EV_TYPE_EXEC, EV_TYPE_FORK, EV_TYPE_SCHED_EXIT, ExecEvent,
};

use crate::{
    models::proc_event::ProcEventKind,
    services::process::ProcessService,
};

fn base_exec_sample(ev_type: u64, pid: u32, uid: u32) -> [u8; ExecEvent::LEN] {
    let mut sample = [0_u8; ExecEvent::LEN];
    sample[0..8].copy_from_slice(&ev_type.to_ne_bytes());
    sample[8..12].copy_from_slice(&pid.to_ne_bytes());
    sample[12..16].copy_from_slice(&uid.to_ne_bytes());
    sample
}

#[test]
fn exec_event_wire_len_matches_daemon_parser_expectation() {
    assert_eq!(ExecEvent::LEN, ProcessService::EBPF_EXEC_EVENT_LEN);
}

#[test]
fn parse_ebpf_proc_state_payload_decodes_exec_fork_exit_kinds() {
    let exec = base_exec_sample(EV_TYPE_EXEC, 4242, 1000);
    let fork = base_exec_sample(EV_TYPE_FORK, 4243, 1001);
    let exit = base_exec_sample(EV_TYPE_SCHED_EXIT, 4244, 1002);

    assert!(matches!(
        ProcessService::parse_ebpf_proc_state_payload(&exec).map(|p| p.kind),
        Some(ProcEventKind::Exec)
    ));
    assert!(matches!(
        ProcessService::parse_ebpf_proc_state_payload(&fork).map(|p| p.kind),
        Some(ProcEventKind::Fork)
    ));
    assert!(matches!(
        ProcessService::parse_ebpf_proc_state_payload(&exit).map(|p| p.kind),
        Some(ProcEventKind::Exit)
    ));
}

#[test]
fn parse_ebpf_proc_state_payload_rejects_unknown_event_type() {
    let sample = base_exec_sample(99, 4242, 1000);
    assert!(ProcessService::parse_ebpf_proc_state_payload(&sample).is_none());
}
