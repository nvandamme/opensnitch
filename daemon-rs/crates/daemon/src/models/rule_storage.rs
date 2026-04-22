use serde::{Deserialize, Deserializer, Serialize};

fn deserialize_operator_list<'de, D>(deserializer: D) -> Result<Vec<RuleFileOperator>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<RuleFileOperator>>::deserialize(deserializer)?.unwrap_or_default())
}

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
    #[serde(default, deserialize_with = "deserialize_operator_list")]
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

#[cfg(test)]
mod tests {
    use super::RuleFile;

    #[test]
    fn operator_list_null_deserializes_as_empty() {
        let raw = r#"
                {
                    "created": "2026-02-16T19:31:13+01:00",
                    "updated": "2026-02-16T19:31:13+01:00",
                    "name": "LocalNet",
                    "description": "",
                    "action": "allow",
                    "duration": "always",
                    "operator": {
                        "operand": "list",
                        "data": "",
                        "type": "list",
                        "list": [
                            {
                                "operand": "source.network",
                                "data": "10.0.0.0/8",
                                "type": "network",
                                "list": null,
                                "sensitive": false
                            }
                        ],
                        "sensitive": false
                    },
                    "enabled": true,
                    "precedence": false,
                    "nolog": false
                }
                "#;

        let parsed: RuleFile = serde_json::from_str(raw).expect("deserialize rule with null list");
        assert_eq!(parsed.operator.list.len(), 1);
        assert!(parsed.operator.list[0].list.is_empty());
    }
}
