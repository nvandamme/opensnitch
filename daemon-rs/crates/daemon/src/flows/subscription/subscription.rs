use std::time::Duration;

use opensnitch_proto::pb;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::services::{
    client::{ClientService, GrpcChannelCache},
    config::ConfigService,
    subscription::SubscriptionService,
};

/// Periodic task that maintains a gRPC connection to the Python UI's
/// `Subscriptions` service (served on the same socket as `UIServicer`) and
/// syncs the daemon's local subscription list on every (re)connect.
///
/// Pattern mirrors `StatsFlow`: owns a `GrpcChannelCache` for cheap channel
/// reuse, connects via `ClientService::connect_or_reuse`, and drives the
/// subscription RPC surface from a single long-running Tokio task.
pub(crate) struct SubscriptionFlow {
    shutdown: CancellationToken,
    config: ConfigService,
    subscriptions: SubscriptionService,
}

impl SubscriptionFlow {
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

        tokio::spawn(async move {
            debug!("subscription flow: started");
            let grpc_cache = GrpcChannelCache::default();

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                if shutdown.is_cancelled() {
                    break;
                }

                let config_snapshot = config.get_snapshot();
                let mut client = match ClientService::connect_or_reuse(&config_snapshot, &grpc_cache).await {
                    Ok(c) => c,
                    Err(err) => {
                        debug!(
                            addr = %config_snapshot.client_addr,
                            "subscription flow: connect failed: {err}"
                        );
                        grpc_cache.invalidate();
                        continue;
                    }
                };

                let req = pb::SubscriptionRequest {
                    operation: pb::SubscriptionAction::List as i32,
                    subscriptions: subscriptions.list(),
                    ..Default::default()
                };
                if let Err(err) = client.subscription_list(req).await {
                    debug!("subscription flow: list sync failed: {err}");
                    grpc_cache.invalidate();
                }
            }

            debug!("subscription flow: stopped");
        })
    }
}
