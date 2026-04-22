use std::sync::Arc;

use anyhow::Result;

use crate::{
    config::Config,
    models::{
        firewall_config::FirewallConfig,
        firewall_state::{FirewallBackend, FirewallState},
    },
};

use super::{firewall::FirewallService, runtime_store::FirewallRuntime};

impl FirewallService {
    pub async fn reload_from_config(&self, config: &Config) -> Result<()> {
        tracing::info!(
            backend = ?config.firewall_backend,
            queue = config.firewall_queue_num,
            bypass = config.firewall_queue_bypass,
            path = %config.firewall_config_path.display(),
            "reloading firewall service from config"
        );
        let path = config.firewall_config_path.clone();
        let system_firewall =
            match tokio::task::spawn_blocking(move || Self::load_system_firewall_from_path(&path))
                .await
            {
                Ok(Ok(system_firewall)) => system_firewall,
                Ok(Err(err)) => {
                    self.emit_error(format!("failed to reload firewall config from disk: {err}"));
                    return Err(err);
                }
                Err(err) => {
                    self.emit_error(format!("failed to join firewall reload task: {err}"));
                    return Err(err.into());
                }
            };
        let current = self.runtime_snapshot();
        let next = FirewallRuntime {
            state: FirewallState {
                enabled: current.state.enabled,
                backend: config.firewall_backend,
            },
            queue_num: config.firewall_queue_num,
            queue_bypass: config.firewall_queue_bypass,
            interception_enabled: current.interception_enabled,
            system_firewall: Arc::new(system_firewall),
        };
        self.publish_runtime_snapshot(next);
        tracing::info!(backend = ?config.firewall_backend, "firewall runtime config reloaded");
        Ok(())
    }

    pub async fn reconcile_from_config(&self, config: &Config) -> Result<()> {
        tracing::info!(backend = ?config.firewall_backend, path = %config.firewall_config_path.display(), "reconciling firewall runtime from config");
        let path = config.firewall_config_path.clone();
        let system_firewall =
            match tokio::task::spawn_blocking(move || Self::load_system_firewall_from_path(&path))
                .await
            {
                Ok(Ok(system_firewall)) => system_firewall,
                Ok(Err(err)) => {
                    self.emit_error(format!(
                        "failed to read firewall config during reconcile: {err}"
                    ));
                    return Err(err);
                }
                Err(err) => {
                    self.emit_error(format!("failed to join firewall reconcile task: {err}"));
                    return Err(err.into());
                }
            };

        let current = self.runtime_snapshot();
        let was_enabled = current.state.enabled;
        let old_backend = current.state.backend;
        let old_queue_num = current.queue_num;
        let old_queue_bypass = current.queue_bypass;

        if was_enabled {
            Self::clear_system_firewall_for_backend(
                old_backend,
                current.system_firewall.as_ref().as_ref(),
            )
            .await;
            if let Err(err) =
                Self::disable_backend_rules(old_backend, old_queue_num, old_queue_bypass).await
            {
                self.emit_error(format!(
                    "failed to disable previous firewall backend rules: {err}"
                ));
                return Err(err);
            }
        }

        let next = FirewallRuntime {
            state: FirewallState {
                enabled: was_enabled,
                backend: config.firewall_backend,
            },
            queue_num: config.firewall_queue_num,
            queue_bypass: config.firewall_queue_bypass,
            interception_enabled: current.interception_enabled,
            system_firewall: Arc::new(system_firewall),
        };

        if matches!(next.state.backend, FirewallBackend::Nftables) {
            if let Some(sysfw) = next.system_firewall.as_ref().as_ref()
                && !sysfw.enabled
            {
                tracing::info!("[nftables] AddSystemRules() fw disabled");
            }
            tracing::info!("Using nftables firewall");
        }

        self.publish_runtime_snapshot(next);

        if was_enabled {
            self.ensure_rules().await?;
        }

        tracing::info!(backend = ?config.firewall_backend, enabled = was_enabled, "firewall reconcile completed");

        Ok(())
    }

    pub async fn replace_system_firewall(
        &self,
        system_firewall: Option<FirewallConfig>,
        config: &Config,
    ) -> Result<()> {
        if let Some(sysfw) = system_firewall.as_ref() {
            let path = config.firewall_config_path.clone();
            let sysfw = sysfw.clone();
            match tokio::task::spawn_blocking(move || {
                Self::save_system_firewall_to_path(&path, &sysfw)
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    self.emit_error(format!("failed to persist firewall config: {err}"));
                    return Err(err);
                }
                Err(err) => {
                    self.emit_error(format!("failed to join firewall persistence task: {err}"));
                    return Err(err.into());
                }
            }
        }

        if let Err(err) = self.reconcile_from_config(config).await {
            self.emit_error(format!("failed to reconcile firewall after replace: {err}"));
            return Err(err);
        }

        Ok(())
    }
}
