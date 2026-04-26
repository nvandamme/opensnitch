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
        let config = self.runtime.config.get_snapshot();
        notify(NotifyState::Status("Starting daemon runtime bootstrap..."));
        info!(addr = %config.client_addr, "daemon runtime: starting serve loop");
        info!(
            queue = self.runtime.nfqueue_num,
            "running on netfilter queue"
        );
        if let Err(err) = crate::logging::LoggingState::apply_config(&config) {
            warn!("failed to apply startup logging config: {err}");
        }
        let mut handles = RuntimeHandles::new();
        handles.push_spawn_once_thread_with_arg(
            "startup-status-notify",
            "startup client handshake scheduled".to_string(),
            Self::publish_startup_status_once,
        );
        handles.push_spawn_once_async_thread_with_arg(
            "startup-client-handshake",
            (self.clone(), config.clone()),
            Self::startup_client_handshake_once,
        );

        let mut verdict_flow = VerdictFlow::new(
            self.runtime.bus.clone(),
            self.runtime.alert_buffer.clone(),
            self.runtime.config.clone(),
            self.runtime.client.clone(),
            self.runtime.rules.clone(),
            self.runtime.connections.clone(),
            self.runtime.stats.clone(),
            self.runtime.audit.clone(),
        );

        let exporter = Arc::new(
            crate::platform::conman::event_logger::ConnectionEventLoggerAdapter::new(
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
            self.runtime.bus.clone(),
            self.runtime.alert_buffer.clone(),
            self.runtime.config.clone(),
            self.runtime.client.clone(),
            self.runtime.rules.clone(),
            self.runtime.firewall.clone(),
            self.runtime.audit.clone(),
        );

        self.spawn_workers(&mut handles).await;
        self.spawn_tasks(&mut handles, rx, verdict_flow, notification_flow);
        info!("daemon runtime: workers and tasks started");
        notify(NotifyState::Ready(Some("opensnitchd-rs runtime ready")));

        self.run_signal_loop().await?;

        notify(NotifyState::Stopping(Some("Daemon stopping...")));
        self.stop().await;
        self.stop_proc_workers().await;
        handles.join_all().await;
        info!("daemon runtime: shutdown complete");
        notify(NotifyState::Status("Daemon stopped"));

        Ok(())
    }
}
