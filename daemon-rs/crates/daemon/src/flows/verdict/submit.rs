use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    platform::ports::nfqueue_runtime_port::NfqueueRuntimePort,
    models::verdict_rpc::VerdictReply, services::stats::StatsService,
    workers::runtime::verdict::dispatch as verdict_dispatch,
};

#[derive(Clone)]
pub struct VerdictSubmitFlow {
    shutdown: CancellationToken,
}

impl VerdictSubmitFlow {
    pub(crate) fn new(shutdown: CancellationToken) -> Self {
        Self { shutdown }
    }

    pub(crate) fn spawn(
        self,
        mut verdict_rx: tokio::sync::mpsc::Receiver<VerdictReply>,
        stats: StatsService,
    ) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = verdict_rx.recv() => {
                        match msg {
                            Some(reply) => {
                                if reply.count_stats {
                                    stats.on_verdict(reply.allow);
                                }
                                NfqueueRuntimePort::submit_verdict(
                                    reply.request_id,
                                    reply.allow,
                                    reply.reject,
                                );
                                let decision = verdict_dispatch::decision_label(&reply);
                                if tracing::enabled!(tracing::Level::DEBUG) {
                                    let source = verdict_dispatch::source_label(&reply);
                                    tracing::debug!(
                                        id = reply.request_id,
                                        decision,
                                        stats = reply.count_stats,
                                        source = %source,
                                        "verdict reply"
                                    );
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        })
    }
}
