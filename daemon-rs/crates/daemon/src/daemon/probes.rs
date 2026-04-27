use super::Daemon;

impl Daemon {
    // Test probe — called from smoke tests to dispatch connection attempts directly into worker channels.
    #[cfg(test)]
    pub(crate) async fn probe_dispatch_connect_attempt_to_worker(
        worker_txs: &[tokio::sync::mpsc::Sender<
            crate::models::connection::state::ConnectionAttempt,
        >],
        next_worker: &mut usize,
        shutdown: &tokio_util::sync::CancellationToken,
        attempt: crate::models::connection::state::ConnectionAttempt,
    ) -> bool {
        crate::workers::runtime::connect::dispatch_connect_attempt_to_worker(
            worker_txs,
            next_worker,
            shutdown,
            attempt,
        )
        .await
    }

    // Test probe — called from smoke tests to inject kernel pipeline events without running the real eBPF path.
    #[cfg(test)]
    pub(crate) async fn probe_dispatch_kernel_pipeline_event<T>(
        &self,
        tx: &tokio::sync::mpsc::Sender<T>,
        event: T,
        shutdown: &tokio_util::sync::CancellationToken,
        pipeline: super::KernelPipeline,
    ) -> bool {
        crate::workers::runtime::kernel::dispatch_kernel_pipeline_event(
            tx,
            event,
            shutdown,
            &self.runtime.kernel_pipeline_counters,
            pipeline,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) fn probe_fanout_kernel_ingress_event(
        event: crate::models::kernel::event::KernelEvent,
        dns_ingress_tx: &tokio::sync::mpsc::Sender<crate::models::dns::payload::DnsPayload>,
        process_ingress_tx: &tokio::sync::mpsc::Sender<super::ProcessKernelEvent>,
        firewall_ingress_tx: &tokio::sync::mpsc::Sender<
            crate::platform::firewall::state::FirewallState,
        >,
        counters: &super::KernelPipelineCounters,
    ) -> bool {
        crate::workers::runtime::kernel::fanout_kernel_ingress_event(
            event,
            dns_ingress_tx,
            process_ingress_tx,
            firewall_ingress_tx,
            counters,
        )
    }
}
