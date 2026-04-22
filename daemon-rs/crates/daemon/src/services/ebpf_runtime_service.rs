use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

#[derive(Debug, Clone)]
pub struct EbpfRuntimeService {
    pub process_obj: Option<PathBuf>,
    pub dns_obj: Option<PathBuf>,
}

impl EbpfRuntimeService {
    #[cfg(test)]
    pub(crate) fn probe_first_existing_path(paths: &[PathBuf]) -> Option<PathBuf> {
        Self::first_existing_path(paths)
    }

    fn first_existing_path(paths: &[PathBuf]) -> Option<PathBuf> {
        paths.iter().find(|path| path.exists()).cloned()
    }

    pub fn load_existing_objects() -> Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let process_obj = [
            root.join("ebpf_prog/opensnitch.o"),
            PathBuf::from("/usr/lib/opensnitchd/ebpf/opensnitch.o"),
        ];
        let process_obj = Self::first_existing_path(&process_obj);

        let dns_obj = [
            root.join("ebpf_prog/opensnitch-dns.o"),
            PathBuf::from("/usr/lib/opensnitchd/ebpf/opensnitch-dns.o"),
        ];
        let dns_obj = Self::first_existing_path(&dns_obj);

        if process_obj.is_none() && dns_obj.is_none() {
            return Err(anyhow!(
                "no eBPF objects found (expected opensnitch.o or opensnitch-dns.o)"
            ));
        }

        Ok(Self {
            process_obj,
            dns_obj,
        })
    }
}
