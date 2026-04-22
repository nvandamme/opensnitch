use std::path::Path;

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

impl RuleFile {
    pub fn normalize_legacy_operator_lists(&mut self) -> anyhow::Result<()> {
        self.operator.normalize_legacy_list_data()
    }
}

impl RuleFileOperator {
    fn normalize_legacy_list_data(&mut self) -> anyhow::Result<()> {
        for item in &mut self.list {
            item.normalize_legacy_list_data()?;
        }

        if self.r#type.eq_ignore_ascii_case("list")
            && self.list.is_empty()
            && !self.data.trim().is_empty()
        {
            self.list =
                crate::services::storage::StorageService::parse_with_storage_format_for_path::<
                    Vec<RuleFileOperator>,
                >(Path::new("legacy-operator-list.json"), &self.data)
                .map_err(|err| {
                    anyhow::anyhow!("invalid legacy list payload in operator data: {err}")
                })?;
            self.data.clear();

            for item in &mut self.list {
                item.normalize_legacy_list_data()?;
            }
        }

        Ok(())
    }
}
