use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct RuleFileOperator {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub operand: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::utils::serde_helpers::deserialize_operator_list"
    )]
    pub list: Vec<RuleFileOperator>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleFile {
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub duration: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub precedence: bool,
    #[serde(default)]
    pub nolog: bool,
    #[serde(default)]
    pub operator: RuleFileOperator,
}
