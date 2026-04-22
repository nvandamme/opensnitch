use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

pub(crate) trait ExistingPathCandidatesExt {
    fn first_existing(&self) -> Option<PathBuf>;
}

impl ExistingPathCandidatesExt for [PathBuf] {
    fn first_existing(&self) -> Option<PathBuf> {
        self.iter().find(|path| path.exists()).cloned()
    }
}

#[derive(Debug, Clone)]
pub struct EbpfRuntimeService {
    pub process_obj: Option<PathBuf>,
    pub dns_obj: Option<PathBuf>,
}

impl EbpfRuntimeService {
    pub fn load_existing_objects() -> Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let process_obj = [
            root.join("ebpf_prog/opensnitch.o"),
            PathBuf::from("/usr/lib/opensnitchd/ebpf/opensnitch.o"),
        ]
        .first_existing();

        let dns_obj = [
            root.join("ebpf_prog/opensnitch-dns.o"),
            PathBuf::from("/usr/lib/opensnitchd/ebpf/opensnitch-dns.o"),
        ]
        .first_existing();

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
