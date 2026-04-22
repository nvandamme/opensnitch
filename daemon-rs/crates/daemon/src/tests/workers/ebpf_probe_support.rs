use std::path::PathBuf;

use crate::services::ebpf::EbpfService;

impl EbpfService {
    pub(crate) fn probe_first_existing_path(paths: &[PathBuf]) -> Option<PathBuf> {
        Self::first_existing_path(paths)
    }
}
