use std::sync::Arc;

use anyhow::Result;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::{
    config::Config,
    models::firewall_state::FirewallState,
    services::{
        config::ConfigService,
        lifecycle::{
            EventSubscription, ServiceLifecycle, ServiceMonitorStats, ServiceState, ServiceStatus,
            StatusSubscription,
        },
    },
    workers::firewall::watch_worker as firewall_watch_worker,
};

use super::{
    runtime_lifecycle::FirewallLifecycle,
    runtime_store::{FirewallRuntime, FirewallRuntimeStore},
};

#[derive(Clone)]
pub struct FirewallService {
    pub(super) runtime: FirewallRuntimeStore,
    pub(super) lifecycle: FirewallLifecycle,
    pub(super) error_tx: broadcast::Sender<String>,
}

impl FirewallService {
    pub fn new(config: &Config) -> Result<Self> {
        let (error_tx, _) = broadcast::channel(256);
        let runtime = FirewallRuntimeStore::new(FirewallRuntime {
            state: FirewallState {
                enabled: false,
                backend: config.firewall_backend,
            },
            queue_num: config.firewall_queue_num,
            queue_bypass: config.firewall_queue_bypass,
            interception_enabled: true,
            system_firewall: Arc::new(Self::load_system_firewall_from_path(
                &config.firewall_config_path,
            )?),
        });
        let lifecycle = FirewallLifecycle::new(ServiceState::Stopped);
        tracing::info!(
            backend = ?config.firewall_backend,
            queue = config.firewall_queue_num,
            bypass = config.firewall_queue_bypass,
            path = %config.firewall_config_path.display(),
            "initializing firewall service"
        );
        Ok(Self {
            runtime,
            lifecycle,
            error_tx,
        })
    }

    pub fn subscribe_errors(&self) -> broadcast::Receiver<String> {
        self.error_tx.subscribe()
    }

    pub fn subscribe_status(&self) -> anyhow::Result<StatusSubscription> {
        ServiceLifecycle::subscribe_status(&self.lifecycle)
    }

    pub fn subscribe_events(&self) -> anyhow::Result<EventSubscription> {
        ServiceLifecycle::subscribe_events(&self.lifecycle)
    }

    pub fn status(&self) -> ServiceStatus {
        ServiceLifecycle::status(&self.lifecycle)
    }

    pub fn monitor_stats(&self) -> ServiceMonitorStats {
        ServiceLifecycle::monitor_stats(&self.lifecycle)
    }

    pub async fn ensure_rules(&self) -> Result<()> {
        let snapshot = self.runtime_snapshot();
        let backend = snapshot.state.backend;
        let queue_num = snapshot.queue_num;
        let queue_bypass = snapshot.queue_bypass;
        let interception_enabled = snapshot.interception_enabled;

        if !interception_enabled {
            tracing::info!("firewall interception disabled; ensuring backend rules are removed");
            self.disable_rules().await?;
            return Ok(());
        }

        tracing::info!(backend = ?backend, queue = queue_num, bypass = queue_bypass, "ensuring firewall backend rules");

        self.ensure_backend_rules(backend, queue_num, queue_bypass)
            .await?;

        if let Some(sysfw) = snapshot.system_firewall.as_ref().as_ref() {
            self.apply_system_firewall_for_backend(backend, sysfw, queue_num)
                .await?;
        }

        self.build_and_publish_runtime(|current: &FirewallRuntime| {
            let mut next = current.clone();
            next.state.enabled = true;
            next
        });
        tracing::info!(backend = ?backend, "firewall backend enabled");
        Ok(())
    }

    pub async fn set_enabled(&self, enabled: bool) -> Result<()> {
        tracing::info!(enabled, "updating firewall enabled state");
        if enabled {
            if let Err(err) = self.ensure_rules().await {
                self.emit_error(format!("failed to enable firewall rules: {err}"));
                return Err(err);
            }
            return Ok(());
        }

        if let Err(err) = self.disable_rules().await {
            self.emit_error(format!("failed to disable firewall rules: {err}"));
            return Err(err);
        }

        Ok(())
    }

    pub async fn set_interception(&self, enabled: bool) -> Result<()> {
        tracing::info!(enabled, "updating firewall interception state");
        self.build_and_publish_runtime(|current: &FirewallRuntime| {
            let mut next = current.clone();
            next.interception_enabled = enabled;
            next
        });
        if enabled {
            if let Err(err) = self.ensure_rules().await {
                self.emit_error(format!(
                    "failed to enable firewall interception rules: {err}"
                ));
                return Err(err);
            }
            Ok(())
        } else {
            if let Err(err) = self.disable_rules().await {
                self.emit_error(format!(
                    "failed to disable firewall interception rules: {err}"
                ));
                return Err(err);
            }
            Ok(())
        }
    }

    pub fn get_snapshot(&self) -> Arc<FirewallRuntime> {
        self.runtime_snapshot()
    }

    pub async fn heal_if_drifted(&self) -> Result<()> {
        let snapshot = self.runtime_snapshot();
        let backend = snapshot.state.backend;
        let queue_num = snapshot.queue_num;
        let queue_bypass = snapshot.queue_bypass;
        let enabled = snapshot.state.enabled;
        let interception_enabled = snapshot.interception_enabled;

        if !enabled || !interception_enabled {
            return Ok(());
        }

        let healthy = Self::backend_rules_healthy(backend, queue_num, queue_bypass).await?;

        if healthy {
            return Ok(());
        }

        tracing::warn!(backend = ?backend, queue = queue_num, bypass = queue_bypass, "firewall rule drift detected; reloading interception rules");
        self.disable_rules().await?;
        self.ensure_rules().await
    }

    pub(crate) fn spawn_watch_task(
        &self,
        shutdown: CancellationToken,
        config: ConfigService,
    ) -> Box<dyn crate::workers::runtime::control::WorkerControl> {
        firewall_watch_worker::start(self.clone(), config, shutdown)
    }
}
