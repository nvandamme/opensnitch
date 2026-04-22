use std::future::Future;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    daemon::{KernelPipeline, KernelPipelineCounters, ProcessKernelEvent},
    models::{
        audit::{AuditEvent, AuditEventKind, DnsAction, ProcessAction},
        dns_payload::DnsPayload,
        kernel_event::KernelEvent,
        proc_event::ProcEventKind,
    },
    services::{
        audit::AuditService, dns::DnsService, process::ProcessService, stats::StatsService,
    },
    tunables::RuntimeTunables,
    workers::runtime::{
        kernel::{
            dispatch as kernel_dispatch, firewall as kernel_firewall, process as kernel_process,
        },
        support,
    },
};

#[derive(Clone)]
pub struct KernelFlow {
    shutdown: CancellationToken,
    tunables: RuntimeTunables,
    counters: std::sync::Arc<KernelPipelineCounters>,
    verbose_hot_path_audit: bool,
}

impl KernelFlow {
    pub(crate) fn new(
        shutdown: CancellationToken,
        tunables: RuntimeTunables,
        counters: std::sync::Arc<KernelPipelineCounters>,
        verbose_hot_path_audit: bool,
    ) -> Self {
        Self {
            shutdown,
            tunables,
            counters,
            verbose_hot_path_audit,
        }
    }

    fn spawn_pipeline_dispatch_task<T: Send + 'static>(
        mut ingress_rx: tokio::sync::mpsc::Receiver<T>,
        dispatch_tx: tokio::sync::mpsc::Sender<T>,
        shutdown: CancellationToken,
        counters: std::sync::Arc<KernelPipelineCounters>,
        pipeline: KernelPipeline,
        batch_size: usize,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let first = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = ingress_rx.recv() => {
                        match msg {
                            Some(event) => event,
                            None => break,
                        }
                    }
                };

                if !kernel_dispatch::dispatch_kernel_pipeline_event(
                    &dispatch_tx,
                    first,
                    &shutdown,
                    &counters,
                    pipeline,
                )
                .await
                {
                    break;
                }

                let burst = support::drain_try_recv_burst(
                    &mut ingress_rx,
                    batch_size.saturating_sub(1),
                    || !shutdown.is_cancelled(),
                );
                for next in burst.items {
                    if !kernel_dispatch::dispatch_kernel_pipeline_event(
                        &dispatch_tx,
                        next,
                        &shutdown,
                        &counters,
                        pipeline,
                    )
                    .await
                    {
                        break;
                    }
                }
                if burst.disconnected {
                    break;
                }
            }
        })
    }

    fn spawn_consumer_task<T, H, Fut>(
        mut rx: tokio::sync::mpsc::Receiver<T>,
        shutdown: CancellationToken,
        mut handle_event: H,
    ) -> JoinHandle<()>
    where
        T: Send + 'static,
        H: FnMut(T) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = rx.recv() => {
                        match msg {
                            Some(event) => handle_event(event).await,
                            None => break,
                        }
                    }
                }
            }
        })
    }

    fn classify_kernel_pipeline(event: &KernelEvent) -> KernelPipeline {
        match event {
            KernelEvent::DnsUpdate(_) => KernelPipeline::Dns,
            KernelEvent::ProcStateChanged { .. }
            | KernelEvent::EbpfProcStateChanged(_)
            | KernelEvent::EbpfProcessMapHit { .. } => KernelPipeline::Process,
            KernelEvent::FirewallState(_) => KernelPipeline::Firewall,
        }
    }

    pub(crate) fn spawn(
        self,
        process: ProcessService,
        dns: DnsService,
        stats: StatsService,
        audit: AuditService,
        mut kernel_rx: tokio::sync::mpsc::Receiver<KernelEvent>,
    ) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let tunables = self.tunables;
        let counters = self.counters.clone();
        let verbose_hot_path_audit = self.verbose_hot_path_audit;

        tokio::spawn(async move {
            let kernel_fanout_batch = tunables.kernel_ingress_dispatch_batch_size;
            let kernel_dns_dispatch_batch = tunables.kernel_dns_dispatch_batch_size;
            let kernel_process_dispatch_batch = tunables.kernel_process_dispatch_batch_size;
            let kernel_firewall_dispatch_batch = tunables.kernel_firewall_dispatch_batch_size;

            let (dns_tx, dns_rx) =
                tokio::sync::mpsc::channel::<DnsPayload>(tunables.kernel_dns_queue_capacity);
            let (process_tx, process_rx) = tokio::sync::mpsc::channel::<ProcessKernelEvent>(
                tunables.kernel_process_queue_capacity,
            );
            let (firewall_tx, firewall_rx) = tokio::sync::mpsc::channel::<
                crate::models::firewall_state::FirewallState,
            >(tunables.kernel_firewall_queue_capacity);

            // Bounded ingress channels: the fan-out task uses try_send so it never
            // blocks; events are dropped (counted) rather than accumulating without
            // bound when consumers fall behind.
            let (dns_ingress_tx, dns_ingress_rx) =
                tokio::sync::mpsc::channel::<DnsPayload>(tunables.kernel_dns_queue_capacity);
            let (process_ingress_tx, process_ingress_rx) =
                tokio::sync::mpsc::channel::<ProcessKernelEvent>(
                    tunables.kernel_process_queue_capacity,
                );
            let (firewall_ingress_tx, firewall_ingress_rx) =
                tokio::sync::mpsc::channel::<crate::models::firewall_state::FirewallState>(
                    tunables.kernel_firewall_queue_capacity,
                );

            let dns_service = dns.clone();
            let dns_stats = stats.clone();
            let dns_audit = audit.clone();
            let dns_handle = Self::spawn_consumer_task(dns_rx, shutdown.clone(), move |update| {
                let dns_service = dns_service.clone();
                let dns_stats = dns_stats.clone();
                let dns_audit = dns_audit.clone();
                async move {
                    match update {
                        DnsPayload::Answers(record) => {
                            dns_stats.on_dns_resolved();
                            let cache_mutation = dns_service.track_answers(record.clone()).await;
                            if verbose_hot_path_audit {
                                dns_audit.emit(AuditEvent::hot(AuditEventKind::DnsAction(
                                    DnsAction::ResolutionReceived {
                                        hostname: record.host.as_ref().into(),
                                    },
                                )));
                                if cache_mutation.entries > 0 {
                                    dns_audit.emit(AuditEvent::hot(AuditEventKind::DnsAction(
                                        DnsAction::CacheUpdated {
                                            entries: cache_mutation.entries,
                                        },
                                    )));
                                }
                                if cache_mutation.evicted > 0 {
                                    dns_audit.emit(AuditEvent::hot(AuditEventKind::DnsAction(
                                        DnsAction::CacheEvicted {
                                            entries: cache_mutation.evicted,
                                        },
                                    )));
                                }
                            }
                        }
                        DnsPayload::Alias { alias, host } => {
                            dns_stats.on_dns_resolved();
                            let cache_mutation = dns_service.track_alias(alias, host.clone()).await;
                            if verbose_hot_path_audit {
                                dns_audit.emit(AuditEvent::hot(AuditEventKind::DnsAction(
                                    DnsAction::ResolutionReceived {
                                        hostname: host.as_ref().into(),
                                    },
                                )));
                                if cache_mutation.entries > 0 {
                                    dns_audit.emit(AuditEvent::hot(AuditEventKind::DnsAction(
                                        DnsAction::CacheUpdated {
                                            entries: cache_mutation.entries,
                                        },
                                    )));
                                }
                                if cache_mutation.evicted > 0 {
                                    dns_audit.emit(AuditEvent::hot(AuditEventKind::DnsAction(
                                        DnsAction::CacheEvicted {
                                            entries: cache_mutation.evicted,
                                        },
                                    )));
                                }
                            }
                        }
                        DnsPayload::NxDomain { host, error_code } => {
                            // Emit failure unconditionally; operational tracking
                            // events are emitted separately only when verbose
                            // hot-path audit mode is enabled.
                            dns_audit.emit(AuditEvent::hot(AuditEventKind::DnsAction(
                                DnsAction::ResolutionFailed {
                                    hostname: host.as_ref().into(),
                                    reason: "nxdomain",
                                },
                            )));
                            tracing::debug!(
                                host = %host,
                                error_code = %error_code,
                                "[DNS] resolution failed"
                            );
                        }
                    }
                }
            });

            let process_service = process.clone();
            let process_audit = audit.clone();
            let process_handle =
                Self::spawn_consumer_task(process_rx, shutdown.clone(), move |event| {
                    let process_service = process_service.clone();
                    let process_audit = process_audit.clone();
                    async move {
                        if verbose_hot_path_audit {
                            match &event {
                                ProcessKernelEvent::ProcStateChanged { pid, kind } => match kind {
                                    ProcEventKind::Exit => process_audit.emit(AuditEvent::hot(
                                        AuditEventKind::ProcessAction(
                                            ProcessAction::ProcessEvicted { pid: *pid },
                                        ),
                                    )),
                                    ProcEventKind::Fork | ProcEventKind::Exec => process_audit
                                        .emit(AuditEvent::hot(AuditEventKind::ProcessAction(
                                            ProcessAction::ProcessTracked { pid: *pid },
                                        ))),
                                },
                                ProcessKernelEvent::EbpfProcStateChanged(payload) => {
                                    match payload.kind {
                                        ProcEventKind::Exit => process_audit.emit(AuditEvent::hot(
                                            AuditEventKind::ProcessAction(
                                                ProcessAction::ProcessEvicted { pid: payload.pid },
                                            ),
                                        )),
                                        ProcEventKind::Fork | ProcEventKind::Exec => process_audit
                                            .emit(AuditEvent::hot(AuditEventKind::ProcessAction(
                                                ProcessAction::ProcessTracked { pid: payload.pid },
                                            ))),
                                    }
                                }
                                ProcessKernelEvent::EbpfProcessMapHit { pid, note, .. } => {
                                    let kind = if note.contains("sched_exit") {
                                        ProcessAction::ProcessEvicted { pid: *pid }
                                    } else {
                                        ProcessAction::ProcessTracked { pid: *pid }
                                    };
                                    process_audit
                                        .emit(AuditEvent::hot(AuditEventKind::ProcessAction(kind)));
                                }
                            }
                        }
                        kernel_process::handle_process_kernel_event(
                            &process_service,
                            &process_audit,
                            event,
                        )
                        .await;
                    }
                });

            let firewall_handle =
                Self::spawn_consumer_task(firewall_rx, shutdown.clone(), move |state| async move {
                    kernel_firewall::handle_firewall_state_event(state).await;
                });

            let dns_dispatch_handle = Self::spawn_pipeline_dispatch_task(
                dns_ingress_rx,
                dns_tx.clone(),
                shutdown.clone(),
                counters.clone(),
                KernelPipeline::Dns,
                kernel_dns_dispatch_batch,
            );

            let process_dispatch_handle = Self::spawn_pipeline_dispatch_task(
                process_ingress_rx,
                process_tx.clone(),
                shutdown.clone(),
                counters.clone(),
                KernelPipeline::Process,
                kernel_process_dispatch_batch,
            );

            let firewall_dispatch_handle = Self::spawn_pipeline_dispatch_task(
                firewall_ingress_rx,
                firewall_tx.clone(),
                shutdown.clone(),
                counters.clone(),
                KernelPipeline::Firewall,
                kernel_firewall_dispatch_batch,
            );

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = kernel_rx.recv() => {
                        match msg {
                            Some(event) => {
                                counters.increment_ingress(Self::classify_kernel_pipeline(&event));

                                if !kernel_dispatch::fanout_kernel_ingress_event(
                                    event,
                                    &dns_ingress_tx,
                                    &process_ingress_tx,
                                    &firewall_ingress_tx,
                                    &counters,
                                ) {
                                    break;
                                }

                                let burst = support::drain_try_recv_burst(
                                    &mut kernel_rx,
                                    kernel_fanout_batch.saturating_sub(1),
                                    || !shutdown.is_cancelled(),
                                );
                                let mut drained = 1usize;
                                for next in burst.items {
                                    counters.increment_ingress(Self::classify_kernel_pipeline(&next));

                                    if !kernel_dispatch::fanout_kernel_ingress_event(
                                        next,
                                        &dns_ingress_tx,
                                        &process_ingress_tx,
                                        &firewall_ingress_tx,
                                        &counters,
                                    ) {
                                        break;
                                    }

                                    drained += 1;
                                }
                                if burst.disconnected {
                                    break;
                                }

                                // Keep burst processing, but yield after full drains to avoid
                                // starving connect-attempt handling under sustained kernel load.
                                if drained >= kernel_fanout_batch {
                                    tokio::task::yield_now().await;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            drop(dns_ingress_tx);
            drop(process_ingress_tx);
            drop(firewall_ingress_tx);

            let _ = tokio::join!(
                dns_dispatch_handle,
                process_dispatch_handle,
                firewall_dispatch_handle
            );

            drop(dns_tx);
            drop(process_tx);
            drop(firewall_tx);

            let _ = tokio::join!(dns_handle, process_handle, firewall_handle);
        })
    }
}
