use std::{fs, path::Path, sync::Arc};

use anyhow::{Context, Result};
use opensnitch_proto::pb;
use tokio::sync::{RwLock, broadcast};

use crate::{
    config::Config,
    models::{
        firewall_state::{FirewallBackend, FirewallState},
        firewall_storage::{
            PersistedExpressions, PersistedFwChain, PersistedFwChains, PersistedFwRule,
            PersistedStatement, PersistedStatementValue, PersistedSysFirewall, RawExpressions,
            RawFwChain, RawFwChains, RawFwRule, RawStatement, RawStatementValue, RawSysFirewall,
        },
    },
};

#[derive(Clone)]
pub struct FirewallService {
    state: Arc<RwLock<FirewallRuntime>>,
    error_tx: broadcast::Sender<String>,
}

#[derive(Debug, Clone)]
struct FirewallRuntime {
    state: FirewallState,
    queue_num: u16,
    queue_bypass: bool,
    interception_enabled: bool,
    system_firewall: Option<pb::SysFirewall>,
}

impl FirewallService {
    pub fn new(config: &Config) -> Result<Self> {
        let (error_tx, _) = broadcast::channel(256);
        tracing::info!(
            backend = ?config.firewall_backend,
            queue = config.firewall_queue_num,
            bypass = config.firewall_queue_bypass,
            path = %config.firewall_config_path.display(),
            "initializing firewall service"
        );
        Ok(Self {
            state: Arc::new(RwLock::new(FirewallRuntime {
                state: FirewallState {
                    enabled: false,
                    backend: config.firewall_backend,
                },
                queue_num: config.firewall_queue_num,
                queue_bypass: config.firewall_queue_bypass,
                interception_enabled: true,
                system_firewall: load_system_firewall(&config.firewall_config_path)?,
            })),
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
        let state = self.state.read().await;
        let backend = state.state.backend;
        let queue_num = state.queue_num;
        let queue_bypass = state.queue_bypass;
        let interception_enabled = state.interception_enabled;
        let system_firewall = state.system_firewall.clone();
        drop(state);

        if !interception_enabled {
            tracing::info!("firewall interception disabled; ensuring backend rules are removed");
            self.disable_rules().await?;
            return Ok(());
        }

        tracing::info!(backend = ?backend, queue = queue_num, bypass = queue_bypass, "ensuring firewall backend rules");

        match backend {
            FirewallBackend::Nftables => {
                if let Err(err) =
                    crate::adapters::firewall_nft::ensure(queue_num, queue_bypass).await
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
                    crate::adapters::firewall_iptables::ensure(queue_num, queue_bypass).await
                {
                    self.emit_error(format!(
                        "failed to ensure iptables interception rules: {err}"
                    ));
                    return Err(err);
                }
            }
        }

        if let Some(sysfw) = system_firewall.as_ref() {
            match backend {
                FirewallBackend::Nftables => {
                    if let Err(err) =
                        crate::adapters::firewall_nft::apply_system_firewall(sysfw, queue_num).await
                    {
                        self.emit_error(format!("failed to apply nftables system firewall: {err}"));
                        return Err(err);
                    }
                }
                FirewallBackend::Iptables => {
                    if let Err(err) =
                        crate::adapters::firewall_iptables::apply_system_firewall(sysfw).await
                    {
                        self.emit_error(format!("failed to apply iptables system firewall: {err}"));
                        return Err(err);
                    }
                }
            }
        }

        self.state.write().await.state.enabled = true;
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
            match tokio::task::spawn_blocking(move || load_system_firewall(&path)).await {
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
        let mut state = self.state.write().await;
        state.state.backend = config.firewall_backend;
        state.queue_num = config.firewall_queue_num;
        state.queue_bypass = config.firewall_queue_bypass;
        state.system_firewall = system_firewall;
        tracing::info!(backend = ?state.state.backend, "firewall runtime config reloaded");
        Ok(())
    }

    pub async fn reconcile_from_config(&self, config: &Config) -> Result<()> {
        tracing::info!(backend = ?config.firewall_backend, path = %config.firewall_config_path.display(), "reconciling firewall runtime from config");
        let path = config.firewall_config_path.clone();
        let system_firewall =
            match tokio::task::spawn_blocking(move || load_system_firewall(&path)).await {
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

        let state = self.state.read().await;
        let was_enabled = state.state.enabled;
        let old_backend = state.state.backend;
        let old_queue_num = state.queue_num;
        let old_queue_bypass = state.queue_bypass;
        let old_system_firewall = state.system_firewall.clone();
        drop(state);

        if was_enabled {
            Self::clear_system_firewall_for_backend(old_backend, old_system_firewall.as_ref())
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

        {
            let mut state = self.state.write().await;
            state.state.backend = config.firewall_backend;
            state.queue_num = config.firewall_queue_num;
            state.queue_bypass = config.firewall_queue_bypass;
            state.system_firewall = system_firewall;

            if matches!(state.state.backend, FirewallBackend::Nftables) {
                if let Some(sysfw) = state.system_firewall.as_ref()
                    && !sysfw.enabled
                {
                    tracing::info!("[nftables] AddSystemRules() fw disabled");
                }
                tracing::info!("Using nftables firewall");
            }
        }

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
            match tokio::task::spawn_blocking(move || save_system_firewall(&path, &sysfw)).await {
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

        {
            let mut state = self.state.write().await;
            state.system_firewall = system_firewall;
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
        self.state.write().await.interception_enabled = enabled;
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

    pub async fn snapshot(&self) -> FirewallState {
        self.state.read().await.state
    }

    pub async fn system_firewall(&self) -> Option<pb::SysFirewall> {
        self.state.read().await.system_firewall.clone()
    }

    pub async fn heal_if_drifted(&self) -> Result<()> {
        let state = self.state.read().await;
        let backend = state.state.backend;
        let queue_num = state.queue_num;
        let queue_bypass = state.queue_bypass;
        let enabled = state.state.enabled;
        let interception_enabled = state.interception_enabled;
        drop(state);

        if !enabled || !interception_enabled {
            return Ok(());
        }

        let healthy = match backend {
            FirewallBackend::Nftables => {
                crate::adapters::firewall_nft::interception_rules_valid().await?
            }
            FirewallBackend::Iptables => {
                crate::adapters::firewall_iptables::interception_rules_valid(
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
        let state = self.state.read().await;
        let backend = state.state.backend;
        let queue_num = state.queue_num;
        let queue_bypass = state.queue_bypass;
        let system_firewall = state.system_firewall.clone();
        drop(state);

        Self::clear_system_firewall_for_backend(backend, system_firewall.as_ref()).await;
        if let Err(err) = Self::disable_backend_rules(backend, queue_num, queue_bypass).await {
            self.emit_error(format!("failed to disable firewall backend rules: {err}"));
            return Err(err);
        }

        self.state.write().await.state.enabled = false;
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
                let _ = crate::adapters::firewall_iptables::clear_system_firewall(sysfw).await;
            }
            FirewallBackend::Nftables => {
                let _ = crate::adapters::firewall_nft::clear_system_firewall(sysfw).await;
            }
        }
    }

    async fn disable_backend_rules(
        backend: FirewallBackend,
        queue_num: u16,
        queue_bypass: bool,
    ) -> Result<()> {
        match backend {
            FirewallBackend::Nftables => crate::adapters::firewall_nft::disable().await,
            FirewallBackend::Iptables => {
                crate::adapters::firewall_iptables::disable(queue_num, queue_bypass).await
            }
        }
    }
}

fn load_system_firewall(path: &Path) -> Result<Option<pb::SysFirewall>> {
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

fn save_system_firewall(path: &Path, sysfw: &pb::SysFirewall) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create firewall config dir {}", parent.display())
        })?;
    }

    let persisted = PersistedSysFirewall {
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
    tracing::info!(path = %path.display(), version = sysfw.version, "persisted firewall config to disk");
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::fs;

    use opensnitch_proto::pb;

    use super::{load_system_firewall, save_system_firewall};
    use crate::utils::test_support::TestDir;

    #[test]
    fn save_and_load_system_firewall_round_trip() {
        let dir = TestDir::new("opensnitch-firewall-service-test");
        let path = dir.path.join("system-fw.json");

        let sysfw = pb::SysFirewall {
            enabled: true,
            version: 1,
            system_rules: vec![pb::FwChains {
                rule: Some(pb::FwRule {
                    table: "filter".to_string(),
                    chain: "OUTPUT".to_string(),
                    uuid: "uuid-1".to_string(),
                    enabled: true,
                    position: 1,
                    description: "allow-dns".to_string(),
                    parameters: "-p udp --dport 53".to_string(),
                    expressions: Vec::new(),
                    target: "ACCEPT".to_string(),
                    target_parameters: "".to_string(),
                }),
                chains: Vec::new(),
            }],
        };

        save_system_firewall(&path, &sysfw).expect("save sysfw");
        let loaded = load_system_firewall(&path)
            .expect("load sysfw")
            .expect("present sysfw");

        assert!(loaded.enabled);
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.system_rules.len(), 1);
        assert_eq!(
            loaded.system_rules[0]
                .rule
                .as_ref()
                .map(|r| r.uuid.as_str()),
            Some("uuid-1")
        );
    }

    #[test]
    fn load_system_firewall_missing_file_returns_none() {
        let dir = TestDir::new("opensnitch-firewall-service-missing-load");
        let path = dir.path.join("missing-system-fw.json");

        let loaded = load_system_firewall(&path).expect("missing path should not fail");
        assert!(loaded.is_none());
    }

    #[test]
    fn load_system_firewall_invalid_json_returns_error() {
        let dir = TestDir::new("opensnitch-firewall-service-invalid-json");
        let path = dir.path.join("invalid-system-fw.json");
        fs::write(&path, "{not-json").expect("write invalid json");

        let err = load_system_firewall(&path).expect_err("invalid json must error");
        assert!(format!("{err:#}").contains("failed to parse firewall config"));
    }

    #[test]
    fn save_and_load_preserves_nested_chain_expressions() {
        let dir = TestDir::new("opensnitch-firewall-service-nested-roundtrip");
        let path = dir.path.join("nested-system-fw.json");

        let sysfw = pb::SysFirewall {
            enabled: true,
            version: 7,
            system_rules: vec![pb::FwChains {
                rule: None,
                chains: vec![pb::FwChain {
                    name: "mangle_output".to_string(),
                    table: "opensnitch".to_string(),
                    family: "inet".to_string(),
                    priority: "mangle".to_string(),
                    r#type: "filter".to_string(),
                    hook: "output".to_string(),
                    policy: "accept".to_string(),
                    rules: vec![pb::FwRule {
                        table: "opensnitch".to_string(),
                        chain: "mangle_output".to_string(),
                        uuid: "uuid-nested-1".to_string(),
                        enabled: true,
                        position: 11,
                        description: "nested expression".to_string(),
                        parameters: "".to_string(),
                        expressions: vec![pb::Expressions {
                            statement: Some(pb::Statement {
                                op: "==".to_string(),
                                name: "meta".to_string(),
                                values: vec![pb::StatementValues {
                                    key: "l4proto".to_string(),
                                    value: "tcp".to_string(),
                                }],
                            }),
                        }],
                        target: "queue".to_string(),
                        target_parameters: "num 0 bypass".to_string(),
                    }],
                }],
            }],
        };

        save_system_firewall(&path, &sysfw).expect("save nested sysfw");
        let loaded = load_system_firewall(&path)
            .expect("load nested sysfw")
            .expect("nested sysfw should exist");

        assert_eq!(loaded.version, 7);
        let chain = &loaded.system_rules[0].chains[0];
        assert_eq!(chain.name, "mangle_output");
        assert_eq!(chain.rules.len(), 1);
        let expr = &chain.rules[0].expressions[0];
        let statement = expr.statement.as_ref().expect("statement present");
        assert_eq!(statement.name, "meta");
        assert_eq!(statement.values[0].key, "l4proto");
        assert_eq!(statement.values[0].value, "tcp");
    }

    #[test]
    fn load_system_firewall_minimal_json_uses_defaults() {
        let dir = TestDir::new("opensnitch-firewall-service-minimal-json");
        let path = dir.path.join("minimal-system-fw.json");
        fs::write(&path, "{}").expect("write minimal json");

        let loaded = load_system_firewall(&path)
            .expect("load minimal sysfw")
            .expect("minimal sysfw should deserialize");

        assert!(!loaded.enabled);
        assert_eq!(loaded.version, 0);
        assert!(loaded.system_rules.is_empty());
    }

    #[test]
    fn load_system_firewall_supports_top_level_rule_only() {
        let dir = TestDir::new("opensnitch-firewall-service-top-rule");
        let path = dir.path.join("top-rule-system-fw.json");
        fs::write(
            &path,
            r#"{
    "Enabled": true,
    "Version": 2,
    "SystemRules": [
        {
            "Rule": {
                "Table": "filter",
                "Chain": "OUTPUT",
                "UUID": "rule-only-uuid",
                "Enabled": true,
                "Position": 9,
                "Description": "top-level-rule",
                "Parameters": "-p udp --dport 53",
                "Expressions": [],
                "Target": "ACCEPT",
                "TargetParameters": ""
            },
            "Chains": []
        }
    ]
}"#,
        )
        .expect("write top-level rule json");

        let loaded = load_system_firewall(&path)
            .expect("load top-level rule sysfw")
            .expect("top-level rule sysfw should deserialize");

        assert!(loaded.enabled);
        assert_eq!(loaded.version, 2);
        assert_eq!(loaded.system_rules.len(), 1);
        let rule = loaded.system_rules[0]
            .rule
            .as_ref()
            .expect("rule entry should be present");
        assert_eq!(rule.uuid, "rule-only-uuid");
        assert_eq!(rule.position, 9);
        assert_eq!(rule.target, "ACCEPT");
    }

    #[test]
    fn load_system_firewall_parses_position_from_string_or_invalid_to_zero() {
        let dir = TestDir::new("opensnitch-firewall-service-position-string");
        let path = dir.path.join("position-system-fw.json");
        fs::write(
            &path,
            r#"{
    "Enabled": true,
    "Version": 3,
    "SystemRules": [
        {
            "Rule": {
                "UUID": "pos-string",
                "Enabled": true,
                "Position": "13",
                "Target": "ACCEPT"
            },
            "Chains": []
        },
        {
            "Rule": {
                "UUID": "pos-invalid",
                "Enabled": true,
                "Position": "not-a-number",
                "Target": "DROP"
            },
            "Chains": []
        }
    ]
}"#,
        )
        .expect("write position parsing json");

        let loaded = load_system_firewall(&path)
            .expect("load position parsing sysfw")
            .expect("position parsing sysfw should deserialize");

        let first = loaded.system_rules[0].rule.as_ref().expect("first rule");
        let second = loaded.system_rules[1].rule.as_ref().expect("second rule");

        assert_eq!(first.position, 13);
        assert_eq!(second.position, 0);
    }
}
