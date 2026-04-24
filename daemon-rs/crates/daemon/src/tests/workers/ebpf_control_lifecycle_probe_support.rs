use super::*;

impl EbpfWorkerControl {
    pub(crate) fn probe_select_dns_explicit_runtime(
        pin_domain: EbpfPinDomain,
        has_legacy_dns_obj: bool,
        has_rust_dns_obj: bool,
    ) -> Option<&'static str> {
        #[cfg(feature = "aya-ebpf")]
        let runtime = Self::select_dns_explicit_runtime_parts(
            pin_domain,
            has_legacy_dns_obj.then_some(Path::new("legacy-dns.o")),
            has_rust_dns_obj.then_some(Path::new("opensnitch-ebpf")),
        );

        #[cfg(not(feature = "aya-ebpf"))]
        let _ = has_rust_dns_obj;

        #[cfg(not(feature = "aya-ebpf"))]
        let runtime = Self::select_dns_explicit_runtime_parts(
            pin_domain,
            has_legacy_dns_obj.then_some(Path::new("legacy-dns.o")),
        );

        runtime.map(|runtime| match runtime.kind {
            #[cfg(feature = "aya-ebpf")]
            DnsExplicitRuntimeKind::Aya => "aya",
            DnsExplicitRuntimeKind::Libbpf => "libbpf",
        })
    }

    pub(crate) fn probe_select_proc_explicit_runtime(
        pin_domain: EbpfPinDomain,
        has_rust_ebpf_obj: bool,
    ) -> Option<&'static str> {
        #[cfg(feature = "aya-ebpf")]
        {
            let runtime = Self::select_proc_explicit_runtime_parts(
                pin_domain,
                has_rust_ebpf_obj.then_some(Path::new("opensnitch-ebpf")),
            );
            return runtime.map(|runtime| match runtime.kind {
                ProcExplicitRuntimeKind::Aya => "aya",
            });
        }

        #[cfg(not(feature = "aya-ebpf"))]
        {
            let _ = pin_domain;
            let _ = has_rust_ebpf_obj;
            None
        }
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) fn probe_parse_native_proc_kind(
        sample: &[u8],
    ) -> Option<crate::models::proc_event::ProcEventKind> {
        match Self::parse_native_sample(sample) {
            Some(NativeQueuedEvent::ProcStateChanged(payload)) => Some(payload.kind),
            _ => None,
        }
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) fn probe_parse_native_proc_payload(sample: &[u8]) -> Option<EbpfProcStatePayload> {
        match Self::parse_native_sample(sample) {
            Some(NativeQueuedEvent::ProcStateChanged(payload)) => Some(payload),
            _ => None,
        }
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) fn probe_parse_native_dns_payload(sample: &[u8]) -> Option<DnsPayload> {
        match Self::parse_native_sample(sample) {
            Some(NativeQueuedEvent::DnsUpdate(payload)) => Some(payload),
            _ => None,
        }
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) fn probe_should_emit_dns_sequence(events: &[(&str, &str)]) -> Vec<bool> {
        let mut recent = HashMap::<DnsDedupKey, Instant>::new();
        let now = Instant::now();
        events
            .iter()
            .map(|(ip, host)| {
                let key = if let Ok(parsed_ip) = ip.parse() {
                    DnsDedupKey::Answer {
                        ip: parsed_ip,
                        host: std::sync::Arc::<str>::from(*host),
                    }
                } else {
                    DnsDedupKey::Alias {
                        alias: std::sync::Arc::<str>::from(*ip),
                        host: std::sync::Arc::<str>::from(*host),
                    }
                };
                NativeRingbuf::should_emit_dns_event_at(&mut recent, key, now)
            })
            .collect()
    }
}
