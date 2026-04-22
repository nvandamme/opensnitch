use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    flows::verdict::VerdictFlow,
    models::connection_state::ConnectionAttempt,
    services::stats::StatsService,
    tunables::RuntimeTunables,
    workers::runtime::{
        connect::dispatch as connect_dispatch, support, verdict::dispatch as verdict_dispatch,
    },
};

#[derive(Clone)]
pub struct ConnectFlow {
    shutdown: CancellationToken,
    tunables: RuntimeTunables,
    verdict_tx: tokio::sync::mpsc::Sender<crate::models::verdict_rpc::VerdictReply>,
}

impl ConnectFlow {
    pub(crate) fn new(
        shutdown: CancellationToken,
        tunables: RuntimeTunables,
        verdict_tx: tokio::sync::mpsc::Sender<crate::models::verdict_rpc::VerdictReply>,
    ) -> Self {
        Self {
            shutdown,
            tunables,
            verdict_tx,
        }
    }

    pub(crate) fn spawn(
        self,
        flow: VerdictFlow,
        stats: StatsService,
        mut connect_rx: tokio::sync::mpsc::Receiver<ConnectionAttempt>,
    ) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let daemon_pid = std::process::id();
        let tunables = self.tunables;
        let verdict_tx = self.verdict_tx.clone();

        let mut worker_handles = Vec::with_capacity(tunables.max_concurrent_connect_attempts);
        let mut worker_txs = Vec::with_capacity(tunables.max_concurrent_connect_attempts);
        for _ in 0..tunables.max_concurrent_connect_attempts {
            let worker_shutdown = shutdown.clone();
            let worker_flow = flow.clone();
            let (worker_tx, mut worker_rx) = tokio::sync::mpsc::channel::<ConnectionAttempt>(
                tunables.connect_worker_queue_capacity,
            );
            worker_txs.push(worker_tx);

            worker_handles.push(tokio::spawn(async move {
                'worker: loop {
                    let first = tokio::select! {
                        _ = worker_shutdown.cancelled() => break 'worker,
                        msg = worker_rx.recv() => {
                            match msg {
                                Some(attempt) => attempt,
                                None => break 'worker,
                            }
                        }
                    };

                    worker_flow.handle_connect_attempt(first).await;

                    // Drain a bounded burst from this lane to amortize wake-up/scheduling cost.
                    let burst = support::drain_try_recv_burst(
                        &mut worker_rx,
                        tunables.connect_dispatch_batch_size.saturating_sub(1),
                        || !worker_shutdown.is_cancelled(),
                    );
                    for next in burst.items {
                        if worker_shutdown.is_cancelled() {
                            break 'worker;
                        }
                        worker_flow.handle_connect_attempt(next).await;
                    }
                    if burst.disconnected {
                        break 'worker;
                    }
                }
            }));
        }

        tokio::spawn(async move {
            let mut next_worker = 0usize;

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = connect_rx.recv() => {
                        match msg {
                            Some(attempt) => {
                                // Process first message.
                                if attempt.pid == daemon_pid {
                                    verdict_dispatch::try_send_or_enqueue(
                                        &verdict_tx,
                                        verdict_dispatch::daemon_self_allow_verdict(
                                            attempt.request_id,
                                        ),
                                    )
                                    .await;
                                } else {
                                    stats.on_connect_attempt(&attempt);
                                    if !connect_dispatch::dispatch_connect_attempt_to_worker(
                                        &worker_txs,
                                        &mut next_worker,
                                        &shutdown,
                                        attempt,
                                    )
                                    .await
                                    {
                                        break;
                                    }
                                }

                                // Drain additional already-queued connect attempts in a bounded burst.
                                let burst = support::drain_try_recv_burst(
                                    &mut connect_rx,
                                    tunables.connect_dispatch_batch_size.saturating_sub(1),
                                    || true,
                                );
                                for next in burst.items {

                                    if next.pid == daemon_pid {
                                        verdict_dispatch::try_send_or_enqueue(
                                            &verdict_tx,
                                            verdict_dispatch::daemon_self_allow_verdict(
                                                next.request_id,
                                            ),
                                        )
                                        .await;
                                    } else {
                                        stats.on_connect_attempt(&next);
                                        if !connect_dispatch::dispatch_connect_attempt_to_worker(
                                            &worker_txs,
                                            &mut next_worker,
                                            &shutdown,
                                            next,
                                        )
                                        .await
                                        {
                                            break;
                                        }
                                    }
                                }
                                if burst.disconnected {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            worker_txs.clear();
            for handle in worker_handles {
                let _ = handle.await;
            }
        })
    }
}
