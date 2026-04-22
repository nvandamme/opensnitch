use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

use super::Daemon;
pub(crate) use crate::models::kernel_pipeline::{
    KernelPipeline, KernelPipelineDropStats, KernelPipelineIngressStats, ProcessKernelEvent,
};

impl KernelPipeline {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Process => "process",
            Self::Firewall => "firewall",
        }
    }
}

impl KernelPipelineIngressStats {
    pub(crate) fn saturating_delta(self, previous: Self) -> Self {
        Self {
            dns: self.dns.saturating_sub(previous.dns),
            process: self.process.saturating_sub(previous.process),
            firewall: self.firewall.saturating_sub(previous.firewall),
        }
    }

    pub(crate) fn total(self) -> u64 {
        self.dns
            .saturating_add(self.process)
            .saturating_add(self.firewall)
    }
}

impl KernelPipelineDropStats {
    pub(crate) fn saturating_delta(self, previous: Self) -> Self {
        Self {
            dns: self.dns.saturating_sub(previous.dns),
            process: self.process.saturating_sub(previous.process),
            firewall: self.firewall.saturating_sub(previous.firewall),
        }
    }

    pub(crate) fn total(self) -> u64 {
        self.dns
            .saturating_add(self.process)
            .saturating_add(self.firewall)
    }
}

#[repr(align(64))]
struct CacheAlignedAtomicU64(AtomicU64);

impl Default for CacheAlignedAtomicU64 {
    fn default() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl CacheAlignedAtomicU64 {
    fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    fn fetch_add(&self, value: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(value, ordering)
    }
}

#[derive(Default)]
struct KernelPipelineDropCounters {
    dns: CacheAlignedAtomicU64,
    process: CacheAlignedAtomicU64,
    firewall: CacheAlignedAtomicU64,
}

static KERNEL_PIPELINE_DROP_COUNTERS: OnceLock<KernelPipelineDropCounters> = OnceLock::new();

#[derive(Default)]
struct KernelPipelineIngressCounters {
    dns: CacheAlignedAtomicU64,
    process: CacheAlignedAtomicU64,
    firewall: CacheAlignedAtomicU64,
}

static KERNEL_PIPELINE_INGRESS_COUNTERS: OnceLock<KernelPipelineIngressCounters> = OnceLock::new();

impl Daemon {
    fn kernel_pipeline_drop_counters() -> &'static KernelPipelineDropCounters {
        KERNEL_PIPELINE_DROP_COUNTERS.get_or_init(KernelPipelineDropCounters::default)
    }

    fn kernel_pipeline_ingress_counters() -> &'static KernelPipelineIngressCounters {
        KERNEL_PIPELINE_INGRESS_COUNTERS.get_or_init(KernelPipelineIngressCounters::default)
    }

    pub(super) fn kernel_pipeline_drop_stats() -> KernelPipelineDropStats {
        let counters = Self::kernel_pipeline_drop_counters();
        KernelPipelineDropStats {
            dns: counters.dns.load(Ordering::Relaxed),
            process: counters.process.load(Ordering::Relaxed),
            firewall: counters.firewall.load(Ordering::Relaxed),
        }
    }

    pub(super) fn kernel_pipeline_ingress_stats() -> KernelPipelineIngressStats {
        let counters = Self::kernel_pipeline_ingress_counters();
        KernelPipelineIngressStats {
            dns: counters.dns.load(Ordering::Relaxed),
            process: counters.process.load(Ordering::Relaxed),
            firewall: counters.firewall.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn increment_kernel_pipeline_drop(pipeline: KernelPipeline) -> u64 {
        let counters = Self::kernel_pipeline_drop_counters();
        let previous = match pipeline {
            KernelPipeline::Dns => counters.dns.fetch_add(1, Ordering::Relaxed),
            KernelPipeline::Process => counters.process.fetch_add(1, Ordering::Relaxed),
            KernelPipeline::Firewall => counters.firewall.fetch_add(1, Ordering::Relaxed),
        };
        previous.saturating_add(1)
    }

    pub(crate) fn increment_kernel_pipeline_ingress(pipeline: KernelPipeline) -> u64 {
        let counters = Self::kernel_pipeline_ingress_counters();
        let previous = match pipeline {
            KernelPipeline::Dns => counters.dns.fetch_add(1, Ordering::Relaxed),
            KernelPipeline::Process => counters.process.fetch_add(1, Ordering::Relaxed),
            KernelPipeline::Firewall => counters.firewall.fetch_add(1, Ordering::Relaxed),
        };
        previous.saturating_add(1)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_kernel_pipeline_drop_stats() -> KernelPipelineDropStats {
        Self::kernel_pipeline_drop_stats()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_kernel_pipeline_ingress_stats() -> KernelPipelineIngressStats {
        Self::kernel_pipeline_ingress_stats()
    }
}
