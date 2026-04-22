use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use transport_wire_core::ClientTransportConnectorPort;
use transport_wire_core::{SubscriptionCommandInboundPort, WireSubscriptionCommandAck};

use crate::{
    commands::subscription::SubscriptionCommandService,
    models::audit::{AuditEvent, AuditEventKind, SubscriptionFlowLifecycle},
    services::{
        audit::AuditService,
        client::{ClientTransportConnector, WireSessionCache},
        config::ConfigService,
        subscription::SubscriptionService,
    },
};

/// Dedicated task that maintains the `Subscriptions.Commands` bidi stream,
/// receiving `SubscriptionCommand` items from the Python UI and sending back
/// `SubscriptionCommandAck` items after local processing.
///
/// Completely decoupled from `ui.proto` and the `Notifications` stream.
/// Pattern mirrors `SubscriptionFlow`: owns its own `WireSessionCache` and
/// reconnect loop (5 s delay), handling commands inline without touching the
/// `ClientCommand` bus.
pub(crate) struct SubscriptionCommandFlow {
    shutdown: CancellationToken,
    config: ConfigService,
    subscriptions: SubscriptionService,
    audit: AuditService,
}

impl SubscriptionCommandFlow {
    pub(crate) fn new(
        shutdown: CancellationToken,
        config: ConfigService,
        subscriptions: SubscriptionService,
        audit: AuditService,
    ) -> Self {
        Self {
            shutdown,
            config,
            subscriptions,
            audit,
        }
    }

    pub(crate) fn spawn(self) -> JoinHandle<()> {
        let Self {
            shutdown,
            config,
            subscriptions,
            audit,
        } = self;

        let command_service = SubscriptionCommandService::new(subscriptions);

        tokio::spawn(async move {
            debug!("subscription command flow: started");
            let connector = ClientTransportConnector::new(WireSessionCache::default());

            'reconnect: loop {
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
                            "subscription command flow: connect failed: {err}"
                        );
                        ClientTransportConnectorPort::invalidate(&connector);
                        continue;
                    }
                };

                let (mut cmd_stream, ack_tx): (
                    Box<dyn SubscriptionCommandInboundPort>,
                    tokio::sync::mpsc::Sender<WireSubscriptionCommandAck>,
                ) = match client.subscription_commands_open().await {
                    Ok(opened) => opened,
                    Err(err) => {
                        debug!("subscription command flow: Commands stream open failed: {err}");
                        audit.emit(AuditEvent::cold(AuditEventKind::SubscriptionFlowLifecycle(
                            SubscriptionFlowLifecycle::CommandStreamFailed {
                                reason: "stream-open-failed",
                            },
                        )));
                        ClientTransportConnectorPort::invalidate(&connector);
                        continue;
                    }
                };

                debug!("subscription command flow: Commands stream open");

                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break 'reconnect,
                        incoming = cmd_stream.recv_command() => {
                            match incoming {
                                Ok(Some(cmd)) => {
                                    // ClientService is Clone — short-lived copy for the
                                    // per-command back-sync RPC to the Python UI.
                                    let mut back_sync = client.clone();
                                    let ack = command_service
                                        .handle_command(cmd, &mut back_sync)
                                        .await;
                                    if ack_tx.send(WireSubscriptionCommandAck {
                                        id: ack.id,
                                        action: ack.action,
                                        accepted: ack.accepted,
                                        message: ack.message,
                                    }).await.is_err() {
                                        debug!("subscription command flow: ack channel closed; reconnecting");
                                        audit.emit(AuditEvent::cold(AuditEventKind::SubscriptionFlowLifecycle(
                                            SubscriptionFlowLifecycle::CommandStreamFailed { reason: "ack-channel-closed" },
                                        )));
                                        ClientTransportConnectorPort::invalidate(&connector);
                                        continue 'reconnect;
                                    }
                                }
                                Ok(None) => {
                                    debug!("subscription command flow: Commands stream closed by server; reconnecting");
                                    audit.emit(AuditEvent::cold(AuditEventKind::SubscriptionFlowLifecycle(
                                        SubscriptionFlowLifecycle::CommandStreamFailed { reason: "stream-closed-by-server" },
                                    )));
                                    ClientTransportConnectorPort::invalidate(&connector);
                                    continue 'reconnect;
                                }
                                Err(err) => {
                                    debug!(
                                        "subscription command flow: Commands stream error: {err}; reconnecting"
                                    );
                                    audit.emit(AuditEvent::cold(AuditEventKind::SubscriptionFlowLifecycle(
                                        SubscriptionFlowLifecycle::CommandStreamFailed { reason: "stream-error" },
                                    )));
                                    ClientTransportConnectorPort::invalidate(&connector);
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
