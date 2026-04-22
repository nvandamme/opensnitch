use anyhow::Result;

use super::ebpf::EbpfService;
use crate::services::lifecycle::{ServiceFactory, ServiceRuntimeControl};

impl EbpfService {
    /// Re-probe eBPF runtime assets and swap the active object set.
    pub(crate) fn reload_runtime_objects(&mut self) -> Result<()> {
        let next = Self::load_existing_objects()?;
        self.pin_domain = next.pin_domain;
        self.conn_obj = next.conn_obj;
        self.proc_obj = next.proc_obj;
        self.process_obj = next.process_obj;
        self.dns_obj = next.dns_obj;
        self.rust_dns_obj = next.rust_dns_obj;
        #[cfg(feature = "aya-ebpf")]
        {
            self.managed_ringbufs = Default::default();
        }
        Ok(())
    }
}

impl ServiceFactory for EbpfService {
    type FactoryInput = ();

    async fn init(_input: Self::FactoryInput) -> Result<Self> {
        Self::load_existing_objects()
    }
}

impl ServiceRuntimeControl for EbpfService {
    type ReloadInput = ();

    async fn reload(&mut self, _input: Self::ReloadInput) -> Result<()> {
        self.reload_runtime_objects()
    }
}
