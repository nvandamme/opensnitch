use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use opensnitch_ebpf_common::pinning::{
    AYA_CONN_ROOT, AYA_CONN_TCP_MAP_PATH, AYA_DNS_EVENTS_PATH, AYA_PROC_EVENTS_PATH, AYA_PROC_ROOT,
    LEGACY_CONN_ROOT, LEGACY_CONN_TCP_MAP_PATH, LEGACY_DNS_EVENTS_PATH, LEGACY_PROC_EVENTS_PATH,
    LEGACY_PROC_ROOT,
};
#[cfg(test)]
use opensnitch_ebpf_common::pinning::{AYA_DNS_ROOT, LEGACY_DNS_ROOT};

use super::EbpfService;

pub(crate) const OPENSNITCH_EBPF_PIN_DOMAIN_ENV: &str = "OPENSNITCH_EBPF_PIN_DOMAIN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EbpfPinDomain {
    Legacy,
    Aya,
}

impl EbpfPinDomain {
    pub(crate) fn conn_root(self) -> &'static str {
        match self {
            Self::Legacy => LEGACY_CONN_ROOT,
            Self::Aya => AYA_CONN_ROOT,
        }
    }

    pub(crate) fn proc_root(self) -> &'static str {
        match self {
            Self::Legacy => LEGACY_PROC_ROOT,
            Self::Aya => AYA_PROC_ROOT,
        }
    }

    #[cfg(test)]
    pub(crate) fn dns_root(self) -> &'static str {
        match self {
            Self::Legacy => LEGACY_DNS_ROOT,
            Self::Aya => AYA_DNS_ROOT,
        }
    }

    pub(crate) fn conn_tcp_map_path(self) -> &'static str {
        match self {
            Self::Legacy => LEGACY_CONN_TCP_MAP_PATH,
            Self::Aya => AYA_CONN_TCP_MAP_PATH,
        }
    }

    pub(crate) fn proc_events_path(self) -> &'static str {
        match self {
            Self::Legacy => LEGACY_PROC_EVENTS_PATH,
            Self::Aya => AYA_PROC_EVENTS_PATH,
        }
    }

    pub(crate) fn dns_events_path(self) -> &'static str {
        match self {
            Self::Legacy => LEGACY_DNS_EVENTS_PATH,
            Self::Aya => AYA_DNS_EVENTS_PATH,
        }
    }

    pub(crate) fn native_ringbuf_candidates(
        self,
        enable_proc: bool,
        enable_dns: bool,
    ) -> Vec<&'static str> {
        match (enable_proc, enable_dns) {
            (true, true) => vec![self.proc_events_path(), self.dns_events_path()],
            (true, false) => vec![self.proc_events_path()],
            (false, true) => vec![self.dns_events_path()],
            (false, false) => Vec::new(),
        }
    }
}

pub(crate) fn resolve_pin_domain(value: Option<&str>) -> EbpfPinDomain {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return EbpfPinDomain::Legacy;
    };

    match value.to_ascii_lowercase().as_str() {
        "aya" | "rs" | "rust" | "opensnitch-rs" => EbpfPinDomain::Aya,
        _ => EbpfPinDomain::Legacy,
    }
}

impl EbpfService {
    pub(super) fn first_existing_path(paths: &[PathBuf]) -> Option<PathBuf> {
        paths.iter().find(|path| path.exists()).cloned()
    }

    fn rust_dns_object_candidates(root: &Path) -> Vec<PathBuf> {
        vec![
            root.join("target/bpfel-unknown-none/release/opensnitch-ebpf"),
            root.join("target/bpfel-unknown-none/release/opensnitch-ebpf.o"),
            root.join("target/bpfel-unknown-none/debug/opensnitch-ebpf"),
            root.join("target/bpfel-unknown-none/debug/opensnitch-ebpf.o"),
            PathBuf::from("/usr/local/lib/opensnitchd/ebpf/opensnitch-ebpf"),
            PathBuf::from("/usr/local/lib/opensnitchd/ebpf/opensnitch-ebpf.o"),
            PathBuf::from("/usr/lib/opensnitchd/ebpf/opensnitch-ebpf"),
            PathBuf::from("/usr/lib/opensnitchd/ebpf/opensnitch-ebpf.o"),
            PathBuf::from("/etc/opensnitchd/opensnitch-ebpf"),
            PathBuf::from("/etc/opensnitchd/opensnitch-ebpf.o"),
        ]
    }

    pub fn load_existing_objects() -> Result<Self> {
        let pin_domain = Self::selected_pin_domain();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let conn_obj = [
            root.join("ebpf_prog/opensnitch.o"),
            PathBuf::from("/usr/local/lib/opensnitchd/ebpf/opensnitch.o"),
            PathBuf::from("/usr/lib/opensnitchd/ebpf/opensnitch.o"),
            PathBuf::from("/etc/opensnitchd/opensnitch.o"),
        ];
        let conn_obj = Self::first_existing_path(&conn_obj);

        let proc_obj = [
            root.join("ebpf_prog/opensnitch-procs.o"),
            PathBuf::from("/usr/local/lib/opensnitchd/ebpf/opensnitch-procs.o"),
            PathBuf::from("/usr/lib/opensnitchd/ebpf/opensnitch-procs.o"),
            PathBuf::from("/etc/opensnitchd/opensnitch-procs.o"),
        ];
        let proc_obj = Self::first_existing_path(&proc_obj);
        let process_obj = conn_obj.clone().or_else(|| proc_obj.clone());

        let dns_obj = [
            root.join("ebpf_prog/opensnitch-dns.o"),
            PathBuf::from("/usr/local/lib/opensnitchd/ebpf/opensnitch-dns.o"),
            PathBuf::from("/usr/lib/opensnitchd/ebpf/opensnitch-dns.o"),
            PathBuf::from("/etc/opensnitchd/opensnitch-dns.o"),
        ];
        let dns_obj = Self::first_existing_path(&dns_obj);

        let rust_dns_obj = Self::first_existing_path(&Self::rust_dns_object_candidates(&root));

        if conn_obj.is_none() && proc_obj.is_none() && dns_obj.is_none() && rust_dns_obj.is_none() {
            return Err(anyhow!(
                "no eBPF objects found (expected opensnitch.o/opensnitch-procs.o, opensnitch-dns.o, or opensnitch-ebpf)"
            ));
        }

        Ok(Self {
            pin_domain,
            conn_obj,
            proc_obj,
            process_obj,
            dns_obj,
            rust_dns_obj,
            #[cfg(feature = "aya-ebpf")]
            managed_ringbufs: Default::default(),
        })
    }
}

#[cfg(test)]
impl EbpfService {
    pub(crate) fn probe_rust_dns_object_candidates(root: &Path) -> Vec<PathBuf> {
        Self::rust_dns_object_candidates(root)
    }
}
