use std::time::Duration;

use opensnitch_proto::pb;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    commands::subscription::SubscriptionCommandService,
    services::{
        client::{ClientService, GrpcChannelCache},
        config::ConfigService,
        subscription::SubscriptionService,
    },
};

const ACK_CHANNEL_CAPACITY: usize = 16;

/// Dedicated task that maintains the `Subscriptions.Commands` bidi stream,
/// receiving `SubscriptionCommand` items from the Python UI and sending back
/// `SubscriptionCommandAck` items after local processing.
///
/// Completely decoupled from `ui.proto` and the `Notifications` stream.
/// Pattern mirrors `SubscriptionFlow`: owns its own `GrpcChannelCache` and
/// reconnect loop (5 s delay), handling commands inline without touching the
/// `ClientCommand` bus.
pub(crate) struct SubscriptionCommandFlow {
    shutdown: CancellationToken,
    config: ConfigService,
    subscriptions: SubscriptionService,
}

impl SubscriptionCommandFlow {
    pub(crate) fn new(
        shutdown: CancellationToken,
        config: ConfigService,
        subscriptions: SubscriptionService,
    ) -> Self {
        Self {
            shutdown,
            config,
            subscriptions,
        }
    }

    pub(crate) fn spawn(self) -> JoinHandle<()> {
        let Self {
            shutdown,
            config,
            subscriptions,
        } = self;

        let command_service = SubscriptionCommandService::new(subscriptions);

        tokio::spawn(async move {
            debug!("subscription command flow: started");
            let grpc_cache = GrpcChannelCache::default();

            'reconnect: loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                if shutdown.is_cancelled() {
                    break;
                }

                let config_snapshot = config.get_snapshot();
                let mut client =
                    match ClientService::connect_or_reuse(&config_snapshot, &grpc_cache).await {
                        Ok(c) => c,
                        Err(err) => {
                            debug!(
                                addr = %config_snapshot.client_addr,
                                "subscription command flow: connect failed: {err}"
                            );
                            grpc_cache.invalidate();
                            continue;
                        }
                    };

                let (ack_tx, ack_rx) =
                    mpsc::channel::<pb::SubscriptionCommandAck>(ACK_CHANNEL_CAPACITY);
                let ack_stream = ReceiverStream::new(ack_rx);

                let mut cmd_stream =
                    match client.subscription_commands(ack_stream).await {
                        Ok(stream) => stream,
                        Err(err) => {
                            debug!(
                                "subscription command flow: Commands stream open failed: {err}"
                            );
                            grpc_cache.invalidate();
                            continue;
                        }
                    };

                debug!("subscription command flow: Commands stream open");

                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break 'reconnect,
                        incoming = cmd_stream.message() => {
                            match incoming {
                                Ok(Some(cmd)) => {
                                    // ClientService is Clone — short-lived copy for the
                                    // per-command back-sync RPC to the Python UI.
                                    let mut back_sync = client.clone();
                                    let ack = command_service
                                        .handle_command(cmd, &mut back_sync)
                                        .await;
                                    if ack_tx.send(ack).await.is_err() {
                                        debug!("subscription command flow: ack channel closed; reconnecting");
                                        grpc_cache.invalidate();
                                        continue 'reconnect;
                                    }
                                }
                                Ok(None) => {
                                    debug!("subscription command flow: Commands stream closed by server; reconnecting");
                                    grpc_cache.invalidate();
                                    continue 'reconnect;
                                }
                                Err(err) => {
                                    debug!(
                                        "subscription command flow: Commands stream error: {err}; reconnecting"
                                    );
                                    grpc_cache.invalidate();
                                    continue 'reconnect;
                                }
                            }
                        }
                    }
                }
            }

            debug!("subscription command flow: stopped");
        })
    }
}
