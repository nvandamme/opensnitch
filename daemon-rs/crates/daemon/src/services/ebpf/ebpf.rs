use std::path::PathBuf;

use crate::{models::ebpf_availability::EbpfObjectAvailability, services::ebpf::EbpfPinDomain};

#[cfg(feature = "aya-ebpf")]
#[derive(Debug)]
pub(crate) struct AyaManagedRingbufAsset {
    pub(crate) source: String,
    pub(crate) map_data: aya::maps::MapData,
}

#[cfg(feature = "aya-ebpf")]
#[derive(Debug, Default)]
pub(super) struct AyaManagedRingbufRegistry {
    proc_ringbuf: Option<AyaManagedRingbufAsset>,
    dns_ringbuf: Option<AyaManagedRingbufAsset>,
}

#[derive(Debug)]
pub struct EbpfService {
    pub(crate) pin_domain: EbpfPinDomain,
    pub conn_obj: Option<PathBuf>,
    pub proc_obj: Option<PathBuf>,
    pub process_obj: Option<PathBuf>,
    pub dns_obj: Option<PathBuf>,
    pub rust_dns_obj: Option<PathBuf>,
    #[cfg(feature = "aya-ebpf")]
    pub(super) managed_ringbufs: AyaManagedRingbufRegistry,
}

impl EbpfService {
    pub fn probe_availability() -> EbpfObjectAvailability {
        match Self::load_existing_objects() {
            Ok(runtime) => EbpfObjectAvailability {
                conn_available: runtime.conn_obj.is_some(),
                proc_available: runtime.proc_obj.is_some(),
                process_available: runtime.process_obj.is_some(),
                dns_available: runtime.dns_obj.is_some() || runtime.rust_dns_obj.is_some(),
            },
            Err(_) => EbpfObjectAvailability::default(),
        }
    }

    #[allow(dead_code)]
    pub fn process_pin_root(&self) -> &'static str {
        let Some(obj) = self.process_obj.as_ref() else {
            return self.pin_domain.conn_root();
        };

        let file_name = obj.file_name().and_then(|v| v.to_str()).unwrap_or_default();

        if file_name.to_lowercase().contains("procs") {
            self.pin_domain.proc_root()
        } else {
            self.pin_domain.conn_root()
        }
    }

    pub(crate) fn pin_domain(&self) -> EbpfPinDomain {
        self.pin_domain
    }

    pub(crate) fn selected_pin_domain() -> EbpfPinDomain {
        super::resolve_pin_domain(
            std::env::var(super::OPENSNITCH_EBPF_PIN_DOMAIN_ENV)
                .ok()
                .as_deref(),
        )
    }

    #[cfg(feature = "aya-ebpf")]
    pub(crate) fn refresh_aya_managed_ringbufs(&mut self) {
        if self.pin_domain != EbpfPinDomain::Aya {
            return;
        }

        self.managed_ringbufs.refresh(self.pin_domain);
    }

    #[cfg(feature = "aya-ebpf")]
    pub(crate) fn take_aya_managed_ringbuf(
        &mut self,
        enable_proc: bool,
        enable_dns: bool,
    ) -> Option<AyaManagedRingbufAsset> {
        self.managed_ringbufs.take_for_mode(enable_proc, enable_dns)
    }
}

#[cfg(feature = "aya-ebpf")]
impl AyaManagedRingbufRegistry {
    fn refresh(&mut self, pin_domain: EbpfPinDomain) {
        if self.proc_ringbuf.is_none() {
            self.proc_ringbuf = Self::open_asset(pin_domain.proc_events_path());
        }

        if self.dns_ringbuf.is_none() {
            self.dns_ringbuf = Self::open_asset(pin_domain.dns_events_path());
        }
    }

    fn take_for_mode(
        &mut self,
        enable_proc: bool,
        enable_dns: bool,
    ) -> Option<AyaManagedRingbufAsset> {
        if enable_proc {
            if let Some(asset) = self.proc_ringbuf.take() {
                return Some(asset);
            }
        }

        if enable_dns {
            if let Some(asset) = self.dns_ringbuf.take() {
                return Some(asset);
            }
        }

        None
    }

    fn open_asset(path: &'static str) -> Option<AyaManagedRingbufAsset> {
        let map_data = aya::maps::MapData::from_pin(path).ok()?;
        Some(AyaManagedRingbufAsset {
            source: path.to_string(),
            map_data,
        })
    }
}
