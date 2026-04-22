use crate::services::ebpf::{EbpfPinDomain, resolve_pin_domain};
use std::path::Path;

#[test]
fn pin_domain_defaults_to_legacy_without_override() {
    assert_eq!(resolve_pin_domain(None), EbpfPinDomain::Legacy);
    assert_eq!(resolve_pin_domain(Some("")), EbpfPinDomain::Legacy);
}

#[test]
fn pin_domain_accepts_aya_override_aliases() {
    assert_eq!(resolve_pin_domain(Some("aya")), EbpfPinDomain::Aya);
    assert_eq!(
        resolve_pin_domain(Some("opensnitch-rs")),
        EbpfPinDomain::Aya
    );
    assert_eq!(resolve_pin_domain(Some("rust")), EbpfPinDomain::Aya);
}

#[test]
fn aya_domain_uses_isolated_bpffs_roots_and_ringbuf_paths() {
    assert_eq!(EbpfPinDomain::Aya.conn_root(), "/sys/fs/bpf/opensnitch-rs");
    assert_eq!(
        EbpfPinDomain::Aya.proc_root(),
        "/sys/fs/bpf/opensnitch-rs/procs"
    );
    assert_eq!(
        EbpfPinDomain::Aya.dns_root(),
        "/sys/fs/bpf/opensnitch-rs/dns"
    );
    assert_eq!(
        EbpfPinDomain::Aya.native_ringbuf_candidates(true, true),
        vec![
            "/sys/fs/bpf/opensnitch-rs/procs/events",
            "/sys/fs/bpf/opensnitch-rs/dns/events",
        ]
    );
}

#[test]
fn rust_dns_object_candidates_include_normalized_build_outputs() {
    let candidates = crate::services::ebpf::EbpfService::probe_rust_dns_object_candidates(
        Path::new("/workspace/daemon-rs"),
    );

    assert!(
        candidates.contains(
            &Path::new("/workspace/daemon-rs/target/bpfel-unknown-none/release/opensnitch-ebpf")
                .to_path_buf()
        )
    );
    assert!(
        candidates.contains(
            &Path::new("/workspace/daemon-rs/target/bpfel-unknown-none/debug/opensnitch-ebpf")
                .to_path_buf()
        )
    );
}
