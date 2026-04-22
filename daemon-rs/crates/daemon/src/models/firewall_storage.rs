use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
pub struct RawSysFirewall {
    #[serde(rename = "Enabled", default)]
    pub enabled: bool,
    #[serde(rename = "Version", default)]
    pub version: u32,
    #[serde(rename = "SystemRules", default)]
    pub system_rules: Vec<RawFwChains>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFwChains {
    #[serde(rename = "Rule", default)]
    pub rule: Option<RawFwRule>,
    #[serde(rename = "Chains", default)]
    pub chains: Vec<RawFwChain>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFwChain {
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
    pub rules: Vec<RawFwRule>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawFwRule {
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
    pub expressions: Vec<RawExpressions>,
    #[serde(rename = "Target", default)]
    pub target: String,
    #[serde(rename = "TargetParameters", default)]
    pub target_parameters: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawExpressions {
    #[serde(rename = "Statement", default)]
    pub statement: Option<RawStatement>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawStatement {
    #[serde(rename = "Op", default)]
    pub op: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Values", default)]
    pub values: Vec<RawStatementValue>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawStatementValue {
    #[serde(rename = "Key", default)]
    pub key: String,
    #[serde(rename = "Value", default)]
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct PersistedSysFirewall {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "SystemRules")]
    pub system_rules: Vec<PersistedFwChains>,
}

#[derive(Debug, Serialize)]
pub struct PersistedFwChains {
    #[serde(rename = "Rule")]
    pub rule: Option<PersistedFwRule>,
    #[serde(rename = "Chains")]
    pub chains: Vec<PersistedFwChain>,
}

#[derive(Debug, Serialize)]
pub struct PersistedFwChain {
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
    pub rules: Vec<PersistedFwRule>,
}

#[derive(Debug, Serialize)]
pub struct PersistedFwRule {
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
    pub expressions: Vec<PersistedExpressions>,
    #[serde(rename = "Target")]
    pub target: String,
    #[serde(rename = "TargetParameters")]
    pub target_parameters: String,
}

#[derive(Debug, Serialize)]
pub struct PersistedExpressions {
    #[serde(rename = "Statement")]
    pub statement: Option<PersistedStatement>,
}

#[derive(Debug, Serialize)]
pub struct PersistedStatement {
    #[serde(rename = "Op")]
    pub op: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Values")]
    pub values: Vec<PersistedStatementValue>,
}

#[derive(Debug, Serialize)]
pub struct PersistedStatementValue {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Value")]
    pub value: String,
}
