use std::{fs, path::Path, sync::Arc};

use anyhow::Result;
use opensnitch_proto::pb;
use tokio::sync::{broadcast, watch};

use crate::{
    config::Config,
    models::{
        firewall_state::{FirewallBackend, FirewallState},
        firewall_storage::{
            PersistedExpressions, PersistedFwChain, PersistedFwChains, PersistedFwRule,
            PersistedStatement, PersistedStatementValue, RawExpressions, RawFwChain, RawFwChains,
            RawFwRule, RawStatement, RawStatementValue, RawSysFirewall,
        },
    },
};

#[derive(Clone)]
pub struct FirewallService {
    snapshot_tx: watch::Sender<Arc<FirewallRuntime>>,
    snapshot_rx: watch::Receiver<Arc<FirewallRuntime>>,
    error_tx: broadcast::Sender<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct FirewallRuntime {
    pub(crate) state: FirewallState,
    pub(crate) queue_num: u16,
    pub(crate) queue_bypass: bool,
    pub(crate) interception_enabled: bool,
    pub(crate) system_firewall: Arc<Option<pb::SysFirewall>>,
}

impl FirewallService {
    fn runtime_snapshot(&self) -> Arc<FirewallRuntime> {
        self.snapshot_rx.borrow().clone()
    }

    fn publish_runtime_snapshot(&self, next: FirewallRuntime) {
        self.snapshot_tx.send_replace(Arc::new(next));
    }

    fn build_and_publish_runtime<F>(&self, build: F) -> Arc<FirewallRuntime>
    where
        F: FnOnce(&FirewallRuntime) -> FirewallRuntime,
    {
        let current = self.runtime_snapshot();
        let next = Arc::new(build(current.as_ref()));
        self.snapshot_tx.send_replace(next.clone());
        next
    }

    fn load_system_firewall_from_path(path: &Path) -> Result<Option<pb::SysFirewall>> {
        use anyhow::Context;

        if !path.exists() {
            tracing::error!(
                "Error reading firewall configuration from disk {}: open {}: no such file or directory",
                path.display(),
                path.display()
            );
            return Ok(None);
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read firewall config {}", path.display()))?;
        let parsed: RawSysFirewall = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse firewall config {}", path.display()))?;

        Ok(Some(pb::SysFirewall {
            enabled: parsed.enabled,
            version: parsed.version,
            system_rules: parsed
                .system_rules
                .into_iter()
                .map(pb::FwChains::from)
                .collect(),
        }))
    }

    fn save_system_firewall_to_path(path: &Path, sysfw: &pb::SysFirewall) -> Result<()> {
        use anyhow::Context;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create firewall config dir {}", parent.display())
            })?;
        }

        let persisted = crate::models::firewall_storage::PersistedSysFirewall {
            enabled: sysfw.enabled,
            version: sysfw.version,
            system_rules: sysfw
                .system_rules
                .iter()
                .cloned()
                .map(PersistedFwChains::from)
                .collect(),
        };

        let raw = serde_json::to_string_pretty(&persisted)
            .context("failed to serialize system firewall config")?;
        fs::write(path, raw)
            .with_context(|| format!("failed to write firewall config {}", path.display()))?;
        tracing::info!(
            path = %path.display(),
            version = sysfw.version,
            "persisted firewall config to disk"
        );
        Ok(())
    }

    pub fn new(config: &Config) -> Result<Self> {
        let (error_tx, _) = broadcast::channel(256);
        let (snapshot_tx, snapshot_rx) = watch::channel(Arc::new(FirewallRuntime {
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
        }));
        tracing::info!(
            backend = ?config.firewall_backend,
            queue = config.firewall_queue_num,
            bypass = config.firewall_queue_bypass,
            path = %config.firewall_config_path.display(),
            "initializing firewall service"
        );
        Ok(Self {
            snapshot_tx,
            snapshot_rx,
            error_tx,
        })
    }

    pub fn subscribe_errors(&self) -> broadcast::Receiver<String> {
        self.error_tx.subscribe()
    }

    fn emit_error(&self, message: String) {
        let _ = self.error_tx.send(message);
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

        match backend {
            FirewallBackend::Nftables => {
                if let Err(err) = crate::adapters::firewall_nft::FirewallNftAdapter::ensure(
                    queue_num,
                    queue_bypass,
                )
                .await
                {
                    tracing::error!("Error while adding interception tables: {err}");
                    self.emit_error(format!("Error while adding interception tables: {err}"));
                    tracing::info!("Using nftables firewall");
                    return Err(err);
                }
                tracing::info!("Using nftables firewall");
            }
            FirewallBackend::Iptables => {
                if let Err(err) =
                    crate::adapters::firewall_iptables::FirewallIptablesAdapter::ensure(
                        queue_num,
                        queue_bypass,
                    )
                    .await
                {
                    self.emit_error(format!(
                        "failed to ensure iptables interception rules: {err}"
                    ));
                    return Err(err);
                }
            }
        }

        if let Some(sysfw) = snapshot.system_firewall.as_ref().as_ref() {
            match backend {
                FirewallBackend::Nftables => {
                    if let Err(err) =
                        crate::adapters::firewall_nft::FirewallNftAdapter::apply_system_firewall(sysfw, queue_num).await
                    {
                        self.emit_error(format!("failed to apply nftables system firewall: {err}"));
                        return Err(err);
                    }
                }
                FirewallBackend::Iptables => {
                    if let Err(err) =
                        crate::adapters::firewall_iptables::FirewallIptablesAdapter::apply_system_firewall(sysfw).await
                    {
                        self.emit_error(format!("failed to apply iptables system firewall: {err}"));
                        return Err(err);
                    }
                }
            }
        }

        self.build_and_publish_runtime(|current| {
            let mut next = current.clone();
            next.state.enabled = true;
            next
        });
        tracing::info!(backend = ?backend, "firewall backend enabled");
        Ok(())
    }

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
        system_firewall: Option<pb::SysFirewall>,
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
        self.build_and_publish_runtime(|current| {
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

    pub fn snapshot_arc(&self) -> Arc<FirewallRuntime> {
        self.runtime_snapshot()
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> Arc<FirewallRuntime> {
        self.snapshot_arc()
    }

    #[cfg(test)]
    pub fn system_firewall(&self) -> Arc<Option<pb::SysFirewall>> {
        self.runtime_snapshot().system_firewall.clone()
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

        let healthy = match backend {
            FirewallBackend::Nftables => {
                crate::adapters::firewall_nft::FirewallNftAdapter::interception_rules_valid().await?
            }
            FirewallBackend::Iptables => {
                crate::adapters::firewall_iptables::FirewallIptablesAdapter::interception_rules_valid(
                    queue_num,
                    queue_bypass,
                )
                .await?
            }
        };

        if healthy {
            return Ok(());
        }

        tracing::warn!(backend = ?backend, queue = queue_num, bypass = queue_bypass, "firewall rule drift detected; reloading interception rules");
        self.disable_rules().await?;
        self.ensure_rules().await
    }

    async fn disable_rules(&self) -> Result<()> {
        let snapshot = self.runtime_snapshot();
        let backend = snapshot.state.backend;
        let queue_num = snapshot.queue_num;
        let queue_bypass = snapshot.queue_bypass;

        Self::clear_system_firewall_for_backend(
            backend,
            snapshot.system_firewall.as_ref().as_ref(),
        )
        .await;
        if let Err(err) = Self::disable_backend_rules(backend, queue_num, queue_bypass).await {
            self.emit_error(format!("failed to disable firewall backend rules: {err}"));
            return Err(err);
        }

        self.build_and_publish_runtime(|current| {
            let mut next = current.clone();
            next.state.enabled = false;
            next
        });
        tracing::info!(backend = ?backend, "firewall backend disabled");
        Ok(())
    }

    async fn clear_system_firewall_for_backend(
        backend: FirewallBackend,
        sysfw: Option<&pb::SysFirewall>,
    ) {
        let Some(sysfw) = sysfw else {
            return;
        };

        match backend {
            FirewallBackend::Iptables => {
                let _ = crate::adapters::firewall_iptables::FirewallIptablesAdapter::clear_system_firewall(sysfw).await;
            }
            FirewallBackend::Nftables => {
                let _ =
                    crate::adapters::firewall_nft::FirewallNftAdapter::clear_system_firewall(sysfw)
                        .await;
            }
        }
    }

    async fn disable_backend_rules(
        backend: FirewallBackend,
        queue_num: u16,
        queue_bypass: bool,
    ) -> Result<()> {
        match backend {
            FirewallBackend::Nftables => {
                crate::adapters::firewall_nft::FirewallNftAdapter::disable().await
            }
            FirewallBackend::Iptables => {
                crate::adapters::firewall_iptables::FirewallIptablesAdapter::disable(
                    queue_num,
                    queue_bypass,
                )
                .await
            }
        }
    }
}

impl FirewallService {
    #[cfg(test)]
    pub(crate) fn probe_load_system_firewall(path: &Path) -> Result<Option<pb::SysFirewall>> {
        Self::load_system_firewall_from_path(path)
    }

    #[cfg(test)]
    pub(crate) fn probe_save_system_firewall(path: &Path, sysfw: &pb::SysFirewall) -> Result<()> {
        Self::save_system_firewall_to_path(path, sysfw)
    }
}

impl From<RawFwChains> for pb::FwChains {
    fn from(value: RawFwChains) -> Self {
        Self {
            rule: value.rule.map(pb::FwRule::from),
            chains: value.chains.into_iter().map(pb::FwChain::from).collect(),
        }
    }
}

impl From<RawFwChain> for pb::FwChain {
    fn from(value: RawFwChain) -> Self {
        Self {
            name: value.name,
            table: value.table,
            family: value.family,
            priority: value.priority,
            r#type: value.r#type,
            hook: value.hook,
            policy: value.policy,
            rules: value.rules.into_iter().map(pb::FwRule::from).collect(),
        }
    }
}

impl From<RawFwRule> for pb::FwRule {
    fn from(value: RawFwRule) -> Self {
        Self {
            table: value.table,
            chain: value.chain,
            uuid: value.uuid,
            enabled: value.enabled,
            position: value.position,
            description: value.description,
            parameters: value.parameters,
            expressions: value
                .expressions
                .into_iter()
                .map(pb::Expressions::from)
                .collect(),
            target: value.target,
            target_parameters: value.target_parameters,
        }
    }
}

impl From<RawExpressions> for pb::Expressions {
    fn from(value: RawExpressions) -> Self {
        Self {
            statement: value.statement.map(pb::Statement::from),
        }
    }
}

impl From<RawStatement> for pb::Statement {
    fn from(value: RawStatement) -> Self {
        Self {
            op: value.op,
            name: value.name,
            values: value
                .values
                .into_iter()
                .map(pb::StatementValues::from)
                .collect(),
        }
    }
}

impl From<RawStatementValue> for pb::StatementValues {
    fn from(value: RawStatementValue) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

impl From<pb::FwChains> for PersistedFwChains {
    fn from(value: pb::FwChains) -> Self {
        Self {
            rule: value.rule.map(PersistedFwRule::from),
            chains: value
                .chains
                .into_iter()
                .map(PersistedFwChain::from)
                .collect(),
        }
    }
}

impl From<pb::FwChain> for PersistedFwChain {
    fn from(value: pb::FwChain) -> Self {
        Self {
            name: value.name,
            table: value.table,
            family: value.family,
            priority: value.priority,
            r#type: value.r#type,
            hook: value.hook,
            policy: value.policy,
            rules: value.rules.into_iter().map(PersistedFwRule::from).collect(),
        }
    }
}

impl From<pb::FwRule> for PersistedFwRule {
    fn from(value: pb::FwRule) -> Self {
        Self {
            table: value.table,
            chain: value.chain,
            uuid: value.uuid,
            enabled: value.enabled,
            position: value.position,
            description: value.description,
            parameters: value.parameters,
            expressions: value
                .expressions
                .into_iter()
                .map(PersistedExpressions::from)
                .collect(),
            target: value.target,
            target_parameters: value.target_parameters,
        }
    }
}

impl From<pb::Expressions> for PersistedExpressions {
    fn from(value: pb::Expressions) -> Self {
        Self {
            statement: value.statement.map(PersistedStatement::from),
        }
    }
}

impl From<pb::Statement> for PersistedStatement {
    fn from(value: pb::Statement) -> Self {
        Self {
            op: value.op,
            name: value.name,
            values: value
                .values
                .into_iter()
                .map(PersistedStatementValue::from)
                .collect(),
        }
    }
}

impl From<pb::StatementValues> for PersistedStatementValue {
    fn from(value: pb::StatementValues) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}
