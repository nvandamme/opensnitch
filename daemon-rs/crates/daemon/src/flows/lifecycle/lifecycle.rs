use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    services::{
        connection::ConnectionService,
        dns::DnsService,
        firewall::FirewallService,
        lifecycle::{EventSubscription, StatusSubscription},
        process::ProcessService,
    },
    workers::runtime::control::RuntimeHandles,
};

pub struct ServiceLifecycleFlow {
    shutdown: CancellationToken,
}

impl ServiceLifecycleFlow {
    pub fn new(shutdown: CancellationToken) -> Self {
        Self { shutdown }
    }

    /// Spawn a task that forwards service lifecycle status channel updates to tracing.
    fn spawn_status_observer(
        handles: &mut RuntimeHandles,
        task_name: &'static str,
        service: &'static str,
        mut status_sub: StatusSubscription,
        shutdown: CancellationToken,
    ) {
        handles.push_task(
            task_name,
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        changed = status_sub.changed() => {
                            match changed {
                                Ok(()) => {
                                    let snapshot = status_sub.borrow_and_update().clone();
                                    debug!(
                                        service,
                                        state = ?snapshot.state,
                                        last_error = ?snapshot.last_error,
                                        "service lifecycle status update"
                                    );
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            }),
        );
    }

    /// Spawn a task that receives service lifecycle events and forwards them to tracing.
    fn spawn_event_observer(
        handles: &mut RuntimeHandles,
        task_name: &'static str,
        service: &'static str,
        mut event_sub: EventSubscription,
        shutdown: CancellationToken,
    ) {
        handles.push_task(
            task_name,
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        event = event_sub.recv() => {
                            match event {
                                Ok(crate::services::lifecycle::ServiceEvent::StateChanged { from, to, last_error }) => {
                                    tracing::info!(
                                        service,
                                        from = ?from,
                                        to = ?to,
                                        last_error = ?last_error,
                                        "service lifecycle state transition"
                                    );
                                }
                                Ok(crate::services::lifecycle::ServiceEvent::HealthCheckFailed { error }) => {
                                    warn!(service, error = %error, "service lifecycle health-check failure event");
                                }
                                Ok(crate::services::lifecycle::ServiceEvent::Message { text }) => {
                                    debug!(service, message = %text, "service lifecycle event");
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                    warn!(service, skipped, "service lifecycle event observer lagged");
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    }
                }
            }),
        );
    }

    /// Subscribe and spawn status + event observer tasks for all intent-monitored services.
    pub fn spawn_observers(
        &self,
        handles: &mut RuntimeHandles,
        connections: &ConnectionService,
        process: &ProcessService,
        dns: &DnsService,
        firewall: &FirewallService,
    ) {
        let shutdown = self.shutdown.clone();

        let connection_stats = connections.monitor_stats();
        let connection_status = connections.status();
        debug!(
            service = "connection",
            state = ?connection_status.state,
            last_error = ?connection_status.last_error,
            status_subscribers = connection_stats.status_subscribers,
            event_subscribers = connection_stats.event_subscribers,
            "intent lifecycle observer bootstrap"
        );
        match connections.subscribe_status() {
            Ok(status_sub) => Self::spawn_status_observer(
                handles,
                "intent-connection-status",
                "connection",
                status_sub,
                shutdown.clone(),
            ),
            Err(err) => warn!("failed to subscribe to connection intent status: {err}"),
        }
        match connections.subscribe_events() {
            Ok(event_sub) => Self::spawn_event_observer(
                handles,
                "intent-connection-events",
                "connection",
                event_sub,
                shutdown.clone(),
            ),
            Err(err) => warn!("failed to subscribe to connection intent events: {err}"),
        }

        let process_stats = process.monitor_stats();
        let process_status = process.status();
        debug!(
            service = "process",
            state = ?process_status.state,
            last_error = ?process_status.last_error,
            status_subscribers = process_stats.status_subscribers,
            event_subscribers = process_stats.event_subscribers,
            "intent lifecycle observer bootstrap"
        );
        match process.subscribe_status() {
            Ok(status_sub) => Self::spawn_status_observer(
                handles,
                "intent-process-status",
                "process",
                status_sub,
                shutdown.clone(),
            ),
            Err(err) => warn!("failed to subscribe to process intent status: {err}"),
        }
        match process.subscribe_events() {
            Ok(event_sub) => Self::spawn_event_observer(
                handles,
                "intent-process-events",
                "process",
                event_sub,
                shutdown.clone(),
            ),
            Err(err) => warn!("failed to subscribe to process intent events: {err}"),
        }

        let dns_stats = dns.monitor_stats();
        let dns_status = dns.status();
        debug!(
            service = "dns",
            state = ?dns_status.state,
            last_error = ?dns_status.last_error,
            status_subscribers = dns_stats.status_subscribers,
            event_subscribers = dns_stats.event_subscribers,
            "intent lifecycle observer bootstrap"
        );
        match dns.subscribe_status() {
            Ok(status_sub) => Self::spawn_status_observer(
                handles,
                "intent-dns-status",
                "dns",
                status_sub,
                shutdown.clone(),
            ),
            Err(err) => warn!("failed to subscribe to dns intent status: {err}"),
        }
        match dns.subscribe_events() {
            Ok(event_sub) => Self::spawn_event_observer(
                handles,
                "intent-dns-events",
                "dns",
                event_sub,
                shutdown.clone(),
            ),
            Err(err) => warn!("failed to subscribe to dns intent events: {err}"),
        }

        let firewall_stats = firewall.monitor_stats();
        let firewall_status = firewall.status();
        debug!(
            service = "firewall",
            state = ?firewall_status.state,
            last_error = ?firewall_status.last_error,
            status_subscribers = firewall_stats.status_subscribers,
            event_subscribers = firewall_stats.event_subscribers,
            "intent lifecycle observer bootstrap"
        );
        match firewall.subscribe_status() {
            Ok(status_sub) => Self::spawn_status_observer(
                handles,
                "intent-firewall-status",
                "firewall",
                status_sub,
                shutdown.clone(),
            ),
            Err(err) => warn!("failed to subscribe to firewall intent status: {err}"),
        }
        match firewall.subscribe_events() {
            Ok(event_sub) => Self::spawn_event_observer(
                handles,
                "intent-firewall-events",
                "firewall",
                event_sub,
                shutdown,
            ),
            Err(err) => warn!("failed to subscribe to firewall intent events: {err}"),
        }
    }
}
