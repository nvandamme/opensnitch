use std::{fs, path::Path, sync::Arc};

use anyhow::{Context, Result};
use opensnitch_proto::pb;
use tokio::sync::RwLock;

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
        })
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
            self.disable_rules().await?;
            return Ok(());
        }

        match backend {
            FirewallBackend::Nftables => {
                crate::adapters::firewall_nft::ensure(queue_num, queue_bypass).await?
            }
            FirewallBackend::Iptables => {
                crate::adapters::firewall_iptables::ensure(queue_num, queue_bypass).await?
            }
        }

        if let Some(sysfw) = system_firewall.as_ref() {
            match backend {
                FirewallBackend::Nftables => {
                    crate::adapters::firewall_nft::apply_system_firewall(sysfw, queue_num).await?
                }
                FirewallBackend::Iptables => {
                    crate::adapters::firewall_iptables::apply_system_firewall(sysfw).await?
                }
            }
        }

        self.state.write().await.state.enabled = true;
        Ok(())
    }

    pub async fn reload_from_config(&self, config: &Config) -> Result<()> {
        let path = config.firewall_config_path.clone();
        let system_firewall =
            tokio::task::spawn_blocking(move || load_system_firewall(&path)).await??;
        let mut state = self.state.write().await;
        state.state.backend = config.firewall_backend;
        state.queue_num = config.firewall_queue_num;
        state.queue_bypass = config.firewall_queue_bypass;
        state.system_firewall = system_firewall;
        Ok(())
    }

    pub async fn reconcile_from_config(&self, config: &Config) -> Result<()> {
        let path = config.firewall_config_path.clone();
        let system_firewall =
            tokio::task::spawn_blocking(move || load_system_firewall(&path)).await??;

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
            Self::disable_backend_rules(old_backend, old_queue_num, old_queue_bypass).await?;
        }

        {
            let mut state = self.state.write().await;
            state.state.backend = config.firewall_backend;
            state.queue_num = config.firewall_queue_num;
            state.queue_bypass = config.firewall_queue_bypass;
            state.system_firewall = system_firewall;
        }

        if was_enabled {
            self.ensure_rules().await?;
        }

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
            tokio::task::spawn_blocking(move || save_system_firewall(&path, &sysfw)).await??;
        }

        {
            let mut state = self.state.write().await;
            state.system_firewall = system_firewall;
        }

        self.reconcile_from_config(config).await
    }

    pub async fn set_enabled(&self, enabled: bool) -> Result<()> {
        if enabled {
            self.ensure_rules().await?;
            return Ok(());
        }

        self.disable_rules().await
    }

    pub async fn set_interception(&self, enabled: bool) -> Result<()> {
        self.state.write().await.interception_enabled = enabled;
        if enabled {
            self.ensure_rules().await
        } else {
            self.disable_rules().await
        }
    }

    pub async fn snapshot(&self) -> FirewallState {
        self.state.read().await.state
    }

    pub async fn system_firewall(&self) -> Option<pb::SysFirewall> {
        self.state.read().await.system_firewall.clone()
    }

    async fn disable_rules(&self) -> Result<()> {
        let state = self.state.read().await;
        let backend = state.state.backend;
        let queue_num = state.queue_num;
        let queue_bypass = state.queue_bypass;
        let system_firewall = state.system_firewall.clone();
        drop(state);

        Self::clear_system_firewall_for_backend(backend, system_firewall.as_ref()).await;
        Self::disable_backend_rules(backend, queue_num, queue_bypass).await?;

        self.state.write().await.state.enabled = false;
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
    use std::path::PathBuf;

    use opensnitch_proto::pb;

    use super::{load_system_firewall, save_system_firewall};
    use crate::{
        config::Config,
        models::firewall_state::FirewallBackend,
        utils::test_support::TestDir,
    };

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

    #[tokio::test]
    async fn reload_from_config_updates_runtime_backend_and_system_firewall() {
        let dir = TestDir::new("opensnitch-firewall-reload");
        let nft_path = dir.path.join("system-fw-nft.json");
        let ipt_path = dir.path.join("system-fw-ipt.json");

        let nft_sysfw = pb::SysFirewall {
            enabled: true,
            version: 1,
            system_rules: vec![pb::FwChains {
                rule: Some(pb::FwRule {
                    table: "filter".to_string(),
                    chain: "OUTPUT".to_string(),
                    uuid: "nft-uuid".to_string(),
                    enabled: true,
                    position: 1,
                    description: "nft rule".to_string(),
                    parameters: "".to_string(),
                    expressions: Vec::new(),
                    target: "ACCEPT".to_string(),
                    target_parameters: "".to_string(),
                }),
                chains: Vec::new(),
            }],
        };

        let ipt_sysfw = pb::SysFirewall {
            enabled: true,
            version: 2,
            system_rules: vec![pb::FwChains {
                rule: Some(pb::FwRule {
                    table: "mangle".to_string(),
                    chain: "OUTPUT".to_string(),
                    uuid: "ipt-uuid".to_string(),
                    enabled: true,
                    position: 1,
                    description: "ipt rule".to_string(),
                    parameters: "".to_string(),
                    expressions: Vec::new(),
                    target: "NFQUEUE".to_string(),
                    target_parameters: "".to_string(),
                }),
                chains: Vec::new(),
            }],
        };

        save_system_firewall(&nft_path, &nft_sysfw).expect("save nft sysfw");
        save_system_firewall(&ipt_path, &ipt_sysfw).expect("save iptables sysfw");

        let mut initial_cfg = Config::default();
        initial_cfg.firewall_backend = FirewallBackend::Nftables;
        initial_cfg.firewall_queue_num = 0;
        initial_cfg.firewall_queue_bypass = true;
        initial_cfg.firewall_config_path = nft_path.clone();
        initial_cfg.rules_path = PathBuf::from(&dir.path);
        initial_cfg.tasks_config_path = dir.path.join("tasks.json");

        let service = super::FirewallService::new(&initial_cfg).expect("firewall service");
        let initial_state = service.snapshot().await;
        assert!(matches!(initial_state.backend, FirewallBackend::Nftables));

        let initial_sysfw = service
            .system_firewall()
            .await
            .expect("initial system firewall must exist");
        assert_eq!(initial_sysfw.version, 1);

        let mut reloaded_cfg = initial_cfg.clone();
        reloaded_cfg.firewall_backend = FirewallBackend::Iptables;
        reloaded_cfg.firewall_queue_num = 23;
        reloaded_cfg.firewall_queue_bypass = false;
        reloaded_cfg.firewall_config_path = ipt_path;

        service
            .reload_from_config(&reloaded_cfg)
            .await
            .expect("reload from config");

        let reloaded_state = service.snapshot().await;
        assert!(matches!(reloaded_state.backend, FirewallBackend::Iptables));

        let reloaded_sysfw = service
            .system_firewall()
            .await
            .expect("reloaded system firewall must exist");
        assert_eq!(reloaded_sysfw.version, 2);
        assert_eq!(
            reloaded_sysfw.system_rules[0]
                .rule
                .as_ref()
                .map(|r| r.uuid.as_str()),
            Some("ipt-uuid")
        );
    }
}
