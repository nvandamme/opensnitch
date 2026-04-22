use crate::services::ebpf::{
    EbpfPinDomain, EbpfRuntimeMode, probe_runtime_fallback_chain,
};

#[test]
fn aya_pin_domain_prefers_managed_then_compat_modes() {
    assert_eq!(
        probe_runtime_fallback_chain(EbpfPinDomain::Aya),
        vec![
            EbpfRuntimeMode::AyaManagedRs,
            EbpfRuntimeMode::AyaLegacyCompat,
            EbpfRuntimeMode::LibbpfLegacyCompat,
            EbpfRuntimeMode::UserspaceFallback,
        ]
    );
}

#[test]
fn legacy_pin_domain_skips_managed_rs_mode() {
    assert_eq!(
        probe_runtime_fallback_chain(EbpfPinDomain::Legacy),
        vec![
            EbpfRuntimeMode::AyaLegacyCompat,
            EbpfRuntimeMode::LibbpfLegacyCompat,
            EbpfRuntimeMode::UserspaceFallback,
        ]
    );
}