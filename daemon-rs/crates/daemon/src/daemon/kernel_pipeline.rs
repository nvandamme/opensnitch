use std::sync::atomic::{AtomicU64, Ordering};

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

#[derive(Default)]
struct KernelPipelineIngressCounters {
    dns: CacheAlignedAtomicU64,
    process: CacheAlignedAtomicU64,
    firewall: CacheAlignedAtomicU64,
}

#[derive(Default)]
pub(crate) struct KernelPipelineCounters {
    drop: KernelPipelineDropCounters,
    ingress: KernelPipelineIngressCounters,
}

impl KernelPipelineCounters {
    pub(crate) fn drop_stats(&self) -> KernelPipelineDropStats {
        KernelPipelineDropStats {
            dns: self.drop.dns.load(Ordering::Relaxed),
            process: self.drop.process.load(Ordering::Relaxed),
            firewall: self.drop.firewall.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn ingress_stats(&self) -> KernelPipelineIngressStats {
        KernelPipelineIngressStats {
            dns: self.ingress.dns.load(Ordering::Relaxed),
            process: self.ingress.process.load(Ordering::Relaxed),
            firewall: self.ingress.firewall.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn increment_drop(&self, pipeline: KernelPipeline) -> u64 {
        let previous = match pipeline {
            KernelPipeline::Dns => self.drop.dns.fetch_add(1, Ordering::Relaxed),
            KernelPipeline::Process => self.drop.process.fetch_add(1, Ordering::Relaxed),
            KernelPipeline::Firewall => self.drop.firewall.fetch_add(1, Ordering::Relaxed),
        };
        previous.saturating_add(1)
    }

    pub(crate) fn increment_ingress(&self, pipeline: KernelPipeline) -> u64 {
        let previous = match pipeline {
            KernelPipeline::Dns => self.ingress.dns.fetch_add(1, Ordering::Relaxed),
            KernelPipeline::Process => self.ingress.process.fetch_add(1, Ordering::Relaxed),
            KernelPipeline::Firewall => self.ingress.firewall.fetch_add(1, Ordering::Relaxed),
        };
        previous.saturating_add(1)
    }
}

impl Daemon {
    pub(super) fn kernel_pipeline_drop_stats(&self) -> KernelPipelineDropStats {
        self.runtime.kernel_pipeline_counters.drop_stats()
    }

    pub(crate) fn increment_kernel_pipeline_drop(&self, pipeline: KernelPipeline) -> u64 {
        self.runtime.kernel_pipeline_counters.increment_drop(pipeline)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_kernel_pipeline_drop_stats(&self) -> KernelPipelineDropStats {
        self.kernel_pipeline_drop_stats()
    }
}
