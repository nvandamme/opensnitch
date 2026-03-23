use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn};

use super::Daemon;
use crate::utils::systemd_notify::{NotifyState, notify};
use crate::{
    bus::BusRx,
    flows::{notification::NotificationFlow, verdict::VerdictFlow},
    workers::runtime::control::RuntimeHandles,
};

impl Daemon {
    pub async fn serve(&self, rx: BusRx) -> Result<()> {
        let config = self.inner.config.get_snapshot();
        notify(NotifyState::Status("Starting daemon runtime bootstrap..."));
        info!(addr = %config.client_addr, "daemon runtime: starting serve loop");
        info!(queue = self.inner.nfqueue_num, "running on netfilter queue");
        if let Err(err) = crate::logging::LoggingState::apply_config(&config) {
            warn!("failed to apply startup logging config: {err}");
        }
        let mut handles = RuntimeHandles::new();
        handles.push_spawn_once_thread_with_arg(
            "startup-status-notify",
            "startup UI handshake scheduled".to_string(),
            Self::publish_startup_status_once,
        );
        handles.push_spawn_once_async_thread_with_arg(
            "startup-ui-handshake",
            (self.clone(), config.clone()),
            Self::startup_ui_handshake_once,
        );

        #[allow(unused_mut)]
        let mut verdict_flow = VerdictFlow::new(
            self.inner.bus.clone(),
            self.inner.config.clone(),
            self.inner.ui_session.clone(),
            self.inner.rules.clone(),
            self.inner.connections.clone(),
            self.inner.stats.clone(),
        );

        let exporter = Arc::new(
            crate::platform::adapters::connection_event_logger::ConnectionEventLoggerAdapter::new(
                &config.loggers,
            ),
        );
        if exporter.has_sinks() {
            info!("siem event logger enabled");
        } else {
            info!("siem event logger configured with no active sinks");
        }
        verdict_flow = verdict_flow.with_event_exporter(exporter);

        let notification_flow = NotificationFlow::new(
            self.inner.bus.clone(),
            self.inner.config.clone(),
            self.inner.ui_session.clone(),
            self.inner.rules.clone(),
            self.inner.firewall.clone(),
            self.inner.stats.clone(),
            self.inner.subscriptions.clone(),
        );

        self.spawn_workers(&mut handles).await;
        self.spawn_tasks(&mut handles, rx, verdict_flow, notification_flow);
        info!("daemon runtime: workers and tasks started");
        notify(NotifyState::Ready(Some("opensnitchd-rs runtime ready")));

        self.run_signal_loop().await?;

        notify(NotifyState::Stopping(Some("Daemon stopping...")));
        self.shutdown().await;
        self.stop_proc_workers().await;
        handles.join_all().await;
        info!("daemon runtime: shutdown complete");
        notify(NotifyState::Status("Daemon stopped"));

        Ok(())
    }
}
