use std::path::PathBuf;

use crate::models::ebpf_availability::EbpfObjectAvailability;

#[derive(Debug, Clone)]
pub struct EbpfService {
    pub conn_obj: Option<PathBuf>,
    pub proc_obj: Option<PathBuf>,
    pub process_obj: Option<PathBuf>,
    pub dns_obj: Option<PathBuf>,
}

impl EbpfService {
    pub fn probe_availability() -> EbpfObjectAvailability {
        match Self::load_existing_objects() {
            Ok(runtime) => EbpfObjectAvailability {
                conn_available: runtime.conn_obj.is_some(),
                proc_available: runtime.proc_obj.is_some(),
                process_available: runtime.process_obj.is_some(),
                dns_available: runtime.dns_obj.is_some(),
            },
            Err(_) => EbpfObjectAvailability::default(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn process_pin_root(&self) -> &'static str {
        let Some(obj) = self.process_obj.as_ref() else {
            return "/sys/fs/bpf/opensnitch";
        };

        let file_name = obj
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or_default();

        if file_name.to_lowercase().contains("procs") {
            "/sys/fs/bpf/opensnitch_procs"
        } else {
            "/sys/fs/bpf/opensnitch"
        }
    }

    pub fn conn_pin_root(&self) -> &'static str {
        "/sys/fs/bpf/opensnitch"
    }

    pub fn proc_pin_root(&self) -> &'static str {
        "/sys/fs/bpf/opensnitch_procs"
    }
}
