#[cfg(feature = "native-ebpf-ringbuf")]
use crate::models::dns::payload::DnsPayload;
#[cfg(feature = "native-ebpf-ringbuf")]
use crate::platform::procmon::proc_event::ProcEventKind;
use crate::workers::runtime::ebpf::EbpfWorkerControl;

#[cfg(feature = "native-ebpf-ringbuf")]
#[test]
fn native_exec_sample_maps_to_proc_event_kinds() {
    fn sample_with_type(ev_type: u64, pid: u32, uid: u32) -> Vec<u8> {
        const EXEC_EVENT_LEN: usize = 26 + 4096 + (20 * 256) + 16;
        let mut sample = vec![0_u8; EXEC_EVENT_LEN];
        sample[0..8].copy_from_slice(&ev_type.to_ne_bytes());
        sample[8..12].copy_from_slice(&pid.to_ne_bytes());
        sample[12..16].copy_from_slice(&uid.to_ne_bytes());
        sample
    }

    let exec = sample_with_type(1, 4242, 1000);
    assert!(matches!(
        EbpfWorkerControl::probe_parse_native_proc_kind(&exec),
        Some(ProcEventKind::Exec)
    ));

    let execveat = sample_with_type(2, 4243, 1000);
    assert!(matches!(
        EbpfWorkerControl::probe_parse_native_proc_kind(&execveat),
        Some(ProcEventKind::Exec)
    ));

    let fork = sample_with_type(3, 4244, 1000);
    assert!(matches!(
        EbpfWorkerControl::probe_parse_native_proc_kind(&fork),
        Some(ProcEventKind::Fork)
    ));

    let exit = sample_with_type(4, 4245, 1000);
    assert!(matches!(
        EbpfWorkerControl::probe_parse_native_proc_kind(&exit),
        Some(ProcEventKind::Exit)
    ));

    let payload = EbpfWorkerControl::probe_parse_native_proc_payload(&exec)
        .expect("expected typed eBPF process payload");
    assert_eq!(payload.pid, 4242);
    assert_eq!(payload.uid, 1000);
    assert!(matches!(payload.kind, ProcEventKind::Exec));
}

#[cfg(feature = "native-ebpf-ringbuf")]
#[test]
fn native_dns_sample_maps_to_dns_payload() {
    let mut sample = vec![0_u8; 4 + 16 + 252];
    sample[0..4].copy_from_slice(&2_u32.to_ne_bytes());
    sample[4] = 8;
    sample[5] = 8;
    sample[6] = 4;
    sample[7] = 4;
    let host = b"WWW.Example.COM.";
    sample[20..20 + host.len()].copy_from_slice(host);

    let payload = EbpfWorkerControl::probe_parse_native_dns_payload(&sample)
        .expect("expected typed eBPF dns payload");
    assert_eq!(
        payload,
        DnsPayload::answer(
            "www.example.com",
            "8.8.4.4".parse().expect("test ip should parse"),
        )
    );
}

#[cfg(feature = "native-ebpf-ringbuf")]
#[test]
fn native_dns_dedup_blocks_immediate_duplicates() {
    let verdicts = EbpfWorkerControl::probe_should_emit_dns_sequence(&[
        ("1.1.1.1", "example.com"),
        ("1.1.1.1", "example.com"),
        ("1.1.1.2", "example.com"),
        ("1.1.1.1", "example.com"),
    ]);

    assert_eq!(verdicts, vec![true, false, true, false]);
}

#[test]
fn explicit_dns_runtime_prefers_rust_object_in_aya_pin_domain() {
    assert_eq!(
        EbpfWorkerControl::probe_select_dns_explicit_runtime(
            crate::services::ebpf::EbpfPinDomain::Aya,
            true,
            true,
        ),
        Some("aya")
    );
}

#[test]
fn explicit_dns_runtime_uses_rust_object_when_legacy_is_unavailable() {
    assert_eq!(
        EbpfWorkerControl::probe_select_dns_explicit_runtime(
            crate::services::ebpf::EbpfPinDomain::Aya,
            false,
            true,
        ),
        Some("aya")
    );
}

#[test]
fn explicit_dns_runtime_falls_back_to_legacy_object_when_rust_object_missing() {
    assert_eq!(
        EbpfWorkerControl::probe_select_dns_explicit_runtime(
            crate::services::ebpf::EbpfPinDomain::Aya,
            true,
            false,
        ),
        Some("libbpf")
    );
    assert_eq!(
        EbpfWorkerControl::probe_select_dns_explicit_runtime(
            crate::services::ebpf::EbpfPinDomain::Legacy,
            true,
            true,
        ),
        Some("libbpf")
    );
}

#[test]
fn explicit_dns_runtime_returns_none_when_no_dns_object_is_available() {
    assert_eq!(
        EbpfWorkerControl::probe_select_dns_explicit_runtime(
            crate::services::ebpf::EbpfPinDomain::Aya,
            false,
            false,
        ),
        None
    );
}

#[test]
fn explicit_process_runtime_prefers_rust_object_in_aya_pin_domain() {
    assert_eq!(
        EbpfWorkerControl::probe_select_proc_explicit_runtime(
            crate::services::ebpf::EbpfPinDomain::Aya,
            true,
        ),
        Some("aya")
    );
}

#[test]
fn explicit_process_runtime_returns_none_without_rust_object() {
    assert_eq!(
        EbpfWorkerControl::probe_select_proc_explicit_runtime(
            crate::services::ebpf::EbpfPinDomain::Aya,
            false,
        ),
        None
    );
    assert_eq!(
        EbpfWorkerControl::probe_select_proc_explicit_runtime(
            crate::services::ebpf::EbpfPinDomain::Legacy,
            true,
        ),
        None
    );
}
