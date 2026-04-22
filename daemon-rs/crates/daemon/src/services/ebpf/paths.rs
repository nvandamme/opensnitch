use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

use super::EbpfService;

impl EbpfService {
    pub(super) fn first_existing_path(paths: &[PathBuf]) -> Option<PathBuf> {
        paths.iter().find(|path| path.exists()).cloned()
    }

    pub fn load_existing_objects() -> Result<Self> {
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

        if conn_obj.is_none() && proc_obj.is_none() && dns_obj.is_none() {
            return Err(anyhow!(
                "no eBPF objects found (expected opensnitch.o/opensnitch-procs.o or opensnitch-dns.o)"
            ));
        }

        Ok(Self {
            conn_obj,
            proc_obj,
            process_obj,
            dns_obj,
        })
    }
}
