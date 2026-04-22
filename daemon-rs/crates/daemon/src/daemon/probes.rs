use super::Daemon;

impl Daemon {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn probe_dispatch_connect_attempt_to_worker(
        worker_txs: &[tokio::sync::mpsc::Sender<
            crate::models::connection_state::ConnectionAttempt,
        >],
        next_worker: &mut usize,
        shutdown: &tokio_util::sync::CancellationToken,
        attempt: crate::models::connection_state::ConnectionAttempt,
    ) -> bool {
        crate::workers::runtime::connect::dispatch::dispatch_connect_attempt_to_worker(
            worker_txs,
            next_worker,
            shutdown,
            attempt,
        )
        .await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn probe_dispatch_kernel_pipeline_event<T>(
        tx: &tokio::sync::mpsc::Sender<T>,
        event: T,
        shutdown: &tokio_util::sync::CancellationToken,
        pipeline: super::KernelPipeline,
    ) -> bool {
        crate::workers::runtime::kernel::dispatch::dispatch_kernel_pipeline_event(
            tx,
            event,
            shutdown,
            pipeline.as_str(),
            || Self::increment_kernel_pipeline_drop(pipeline),
        )
        .await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_fanout_kernel_ingress_event(
        event: crate::models::kernel_event::KernelEvent,
        dns_ingress_tx: &tokio::sync::mpsc::UnboundedSender<crate::models::dns_payload::DnsPayload>,
        process_ingress_tx: &tokio::sync::mpsc::UnboundedSender<super::ProcessKernelEvent>,
        firewall_ingress_tx: &tokio::sync::mpsc::UnboundedSender<
            crate::models::firewall_state::FirewallState,
        >,
    ) -> bool {
        crate::workers::runtime::kernel::dispatch::fanout_kernel_ingress_event(
            event,
            dns_ingress_tx,
            process_ingress_tx,
            firewall_ingress_tx,
        )
    }
}
