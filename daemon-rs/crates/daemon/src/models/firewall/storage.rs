use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
pub struct RawFirewallConfig {
    #[serde(rename = "Enabled", default)]
    pub enabled: bool,
    #[serde(rename = "Version", default)]
    pub version: u32,
    #[serde(rename = "SystemRules", default)]
    pub system_rules: Vec<RawFirewallGroup>,
    #[serde(rename = "Zones", default)]
    pub zones: Vec<RawFirewallZone>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFirewallZone {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Chains", default)]
    pub chains: Vec<RawFirewallChain>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFirewallGroup {
    #[serde(rename = "Rule", default)]
    pub rule: Option<RawFirewallRule>,
    #[serde(rename = "Chains", default)]
    pub chains: Vec<RawFirewallChain>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFirewallChain {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Table", default)]
    pub table: String,
    #[serde(rename = "Family", default)]
    pub family: String,
    #[serde(rename = "Priority", default)]
    pub priority: String,
    #[serde(rename = "Type", default)]
    pub r#type: String,
    #[serde(rename = "Hook", default)]
    pub hook: String,
    #[serde(rename = "Policy", default)]
    pub policy: String,
    #[serde(rename = "Rules", default)]
    pub rules: Vec<RawFirewallRule>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFirewallRule {
    #[serde(rename = "Table", default)]
    pub table: String,
    #[serde(rename = "Chain", default)]
    pub chain: String,
    #[serde(rename = "UUID", default)]
    pub uuid: String,
    #[serde(rename = "Enabled", default)]
    pub enabled: bool,
    #[serde(
        rename = "Position",
        default,
        deserialize_with = "crate::utils::serde_helpers::deserialize_u64"
    )]
    pub position: u64,
    #[serde(rename = "Description", default)]
    pub description: String,
    #[serde(rename = "Parameters", default)]
    pub parameters: String,
    #[serde(rename = "Expressions", default)]
    pub expressions: Vec<RawFirewallExpression>,
    #[serde(rename = "Target", default)]
    pub target: String,
    #[serde(rename = "TargetParameters", default)]
    pub target_parameters: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFirewallExpression {
    #[serde(rename = "Statement", default)]
    pub statement: Option<RawFirewallStatement>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFirewallStatement {
    #[serde(rename = "Op", default)]
    pub op: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Values", default)]
    pub values: Vec<RawFirewallStatementValue>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFirewallStatementValue {
    #[serde(rename = "Key", default)]
    pub key: String,
    #[serde(rename = "Value", default)]
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct PersistedFirewallConfig {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "SystemRules")]
    pub system_rules: Vec<PersistedFirewallGroup>,
    #[serde(rename = "Zones")]
    pub zones: Vec<PersistedFirewallZone>,
}

#[derive(Debug, Serialize)]
pub struct PersistedFirewallZone {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Chains")]
    pub chains: Vec<PersistedFirewallChain>,
}

#[derive(Debug, Serialize)]
pub struct PersistedFirewallGroup {
    #[serde(rename = "Rule")]
    pub rule: Option<PersistedFirewallRule>,
    #[serde(rename = "Chains")]
    pub chains: Vec<PersistedFirewallChain>,
}

#[derive(Debug, Serialize)]
pub struct PersistedFirewallChain {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Table")]
    pub table: String,
    #[serde(rename = "Family")]
    pub family: String,
    #[serde(rename = "Priority")]
    pub priority: String,
    #[serde(rename = "Type")]
    pub r#type: String,
    #[serde(rename = "Hook")]
    pub hook: String,
    #[serde(rename = "Policy")]
    pub policy: String,
    #[serde(rename = "Rules")]
    pub rules: Vec<PersistedFirewallRule>,
}

#[derive(Debug, Serialize)]
pub struct PersistedFirewallRule {
    #[serde(rename = "Table")]
    pub table: String,
    #[serde(rename = "Chain")]
    pub chain: String,
    #[serde(rename = "UUID")]
    pub uuid: String,
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "Position")]
    pub position: u64,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Parameters")]
    pub parameters: String,
    #[serde(rename = "Expressions")]
    pub expressions: Vec<PersistedFirewallExpression>,
    #[serde(rename = "Target")]
    pub target: String,
    #[serde(rename = "TargetParameters")]
    pub target_parameters: String,
}

#[derive(Debug, Serialize)]
pub struct PersistedFirewallExpression {
    #[serde(rename = "Statement")]
    pub statement: Option<PersistedFirewallStatement>,
}

#[derive(Debug, Serialize)]
pub struct PersistedFirewallStatement {
    #[serde(rename = "Op")]
    pub op: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Values")]
    pub values: Vec<PersistedFirewallStatementValue>,
}

#[derive(Debug, Serialize)]
pub struct PersistedFirewallStatementValue {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Value")]
    pub value: String,
}
