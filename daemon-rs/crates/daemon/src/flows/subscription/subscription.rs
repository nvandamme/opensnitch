use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use transport_wire_core::ClientTransportConnectorPort;

use crate::models::subscription::rpc::{SubscriptionCommand, SubscriptionOperation};
use crate::services::{
    client::{ClientTransportConnector, WireSessionCache},
    config::ConfigService,
    subscription::SubscriptionService,
};

/// Periodic task that maintains a transport connection to the Python UI's
/// `Subscriptions` service (served on the same socket as `UIServicer`) and
/// syncs the daemon's local subscription list on every (re)connect.
///
/// Pattern mirrors `StatsFlow`: owns a `WireSessionCache` for cheap transport-session
/// reuse via `ClientTransportConnectorPort::connect_or_reuse`, and drives the
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
            let connector = ClientTransportConnector::new(WireSessionCache::default());

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                if shutdown.is_cancelled() {
                    break;
                }

                let config_snapshot = config.get_snapshot();
                let mut client = match ClientTransportConnectorPort::connect_or_reuse(
                    &connector,
                    &config_snapshot,
                )
                .await
                {
                    Ok(c) => c,
                    Err(err) => {
                        debug!(
                            addr = %config_snapshot.client_addr,
                            "subscription flow: connect failed: {err}"
                        );
                        ClientTransportConnectorPort::invalidate(&connector);
                        continue;
                    }
                };

                let cmd = SubscriptionCommand {
                    operation: SubscriptionOperation::List,
                    subscriptions: subscriptions.list_records(),
                    targets: Vec::new(),
                    force: false,
                };
                if let Err(err) = client.subscription_execute(cmd).await {
                    debug!("subscription flow: list sync failed: {err}");
                    ClientTransportConnectorPort::invalidate(&connector);
                }
            }

            debug!("subscription flow: stopped");
        })
    }
}
