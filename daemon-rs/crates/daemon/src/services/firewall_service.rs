use std::{fs, path::Path, sync::Arc};

use anyhow::{Context, Result};
use opensnitch_proto::pb;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::{
    config::Config,
    models::firewall::{FirewallBackend, FirewallState},
};

#[derive(Clone)]
pub struct FirewallService {
    state: Arc<RwLock<FirewallRuntime>>,
}

#[derive(Debug, Clone)]
struct FirewallRuntime {
    state: FirewallState,
    interception_enabled: bool,
    system_firewall: Option<pb::SysFirewall>,
}

#[derive(Debug, Default, Deserialize)]
struct RawSysFirewall {
    #[serde(rename = "Enabled", default)]
    enabled: bool,
    #[serde(rename = "Version", default)]
    version: u32,
    #[serde(rename = "SystemRules", default)]
    system_rules: Vec<RawFwChains>,
}

#[derive(Debug, Default, Deserialize)]
struct RawFwChains {
    #[serde(rename = "Rule", default)]
    rule: Option<RawFwRule>,
    #[serde(rename = "Chains", default)]
    chains: Vec<RawFwChain>,
}

#[derive(Debug, Default, Deserialize)]
struct RawFwChain {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Table", default)]
    table: String,
    #[serde(rename = "Family", default)]
    family: String,
    #[serde(rename = "Priority", default)]
    priority: String,
    #[serde(rename = "Type", default)]
    r#type: String,
    #[serde(rename = "Hook", default)]
    hook: String,
    #[serde(rename = "Policy", default)]
    policy: String,
    #[serde(rename = "Rules", default)]
    rules: Vec<RawFwRule>,
}

#[derive(Debug, Default, Deserialize)]
struct RawFwRule {
    #[serde(rename = "Table", default)]
    table: String,
    #[serde(rename = "Chain", default)]
    chain: String,
    #[serde(rename = "UUID", default)]
    uuid: String,
    #[serde(rename = "Enabled", default)]
    enabled: bool,
    #[serde(rename = "Position", default, deserialize_with = "deserialize_u64")]
    position: u64,
    #[serde(rename = "Description", default)]
    description: String,
    #[serde(rename = "Parameters", default)]
    parameters: String,
    #[serde(rename = "Expressions", default)]
    expressions: Vec<RawExpressions>,
    #[serde(rename = "Target", default)]
    target: String,
    #[serde(rename = "TargetParameters", default)]
    target_parameters: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawExpressions {
    #[serde(rename = "Statement", default)]
    statement: Option<RawStatement>,
}

#[derive(Debug, Default, Deserialize)]
struct RawStatement {
    #[serde(rename = "Op", default)]
    op: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Values", default)]
    values: Vec<RawStatementValue>,
}

#[derive(Debug, Default, Deserialize)]
struct RawStatementValue {
    #[serde(rename = "Key", default)]
    key: String,
    #[serde(rename = "Value", default)]
    value: String,
}

impl FirewallService {
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            state: Arc::new(RwLock::new(FirewallRuntime {
                state: FirewallState {
                    enabled: false,
                    backend: config.firewall_backend,
                },
                interception_enabled: true,
                system_firewall: load_system_firewall(&config.firewall_config_path)?,
            })),
        })
    }

    pub async fn ensure_rules(&self) -> Result<()> {
        let backend = self.state.read().await.state.backend;
        match backend {
            FirewallBackend::Nftables => crate::adapters::firewall_nft::ensure().await?,
            FirewallBackend::Iptables => crate::adapters::firewall_iptables::ensure().await?,
        }

        self.state.write().await.state.enabled = true;
        Ok(())
    }

    pub async fn reload_from_config(&self, config: &Config) -> Result<()> {
        let system_firewall = load_system_firewall(&config.firewall_config_path)?;
        let mut state = self.state.write().await;
        state.state.backend = config.firewall_backend;
        state.system_firewall = system_firewall;
        Ok(())
    }

    pub async fn set_enabled(&self, enabled: bool) {
        self.state.write().await.state.enabled = enabled;
    }

    pub async fn set_interception(&self, enabled: bool) {
        self.state.write().await.interception_enabled = enabled;
    }

    pub async fn snapshot(&self) -> FirewallState {
        self.state.read().await.state
    }

    pub async fn system_firewall(&self) -> Option<pb::SysFirewall> {
        self.state.read().await.system_firewall.clone()
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
        system_rules: parsed.system_rules.into_iter().map(map_fw_chains).collect(),
    }))
}

fn map_fw_chains(value: RawFwChains) -> pb::FwChains {
    pb::FwChains {
        rule: value.rule.map(map_fw_rule),
        chains: value.chains.into_iter().map(map_fw_chain).collect(),
    }
}

fn map_fw_chain(value: RawFwChain) -> pb::FwChain {
    pb::FwChain {
        name: value.name,
        table: value.table,
        family: value.family,
        priority: value.priority,
        r#type: value.r#type,
        hook: value.hook,
        policy: value.policy,
        rules: value.rules.into_iter().map(map_fw_rule).collect(),
    }
}

fn map_fw_rule(value: RawFwRule) -> pb::FwRule {
    pb::FwRule {
        table: value.table,
        chain: value.chain,
        uuid: value.uuid,
        enabled: value.enabled,
        position: value.position,
        description: value.description,
        parameters: value.parameters,
        expressions: value.expressions.into_iter().map(map_expression).collect(),
        target: value.target,
        target_parameters: value.target_parameters,
    }
}

fn map_expression(value: RawExpressions) -> pb::Expressions {
    pb::Expressions {
        statement: value.statement.map(map_statement),
    }
}

fn map_statement(value: RawStatement) -> pb::Statement {
    pb::Statement {
        op: value.op,
        name: value.name,
        values: value.values.into_iter().map(map_statement_value).collect(),
    }
}

fn map_statement_value(value: RawStatementValue) -> pb::StatementValues {
    pb::StatementValues {
        key: value.key,
        value: value.value,
    }
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RawValue {
        Integer(u64),
        String(String),
    }

    Ok(match RawValue::deserialize(deserializer)? {
        RawValue::Integer(value) => value,
        RawValue::String(value) => value.parse().unwrap_or(0),
    })
}
