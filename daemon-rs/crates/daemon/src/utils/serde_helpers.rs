use serde::{Deserialize, Deserializer};

use crate::models::rule::storage::RuleFileOperator;

pub fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
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

pub fn deserialize_operator_list<'de, D>(deserializer: D) -> Result<Vec<RuleFileOperator>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<RuleFileOperator>>::deserialize(deserializer)?.unwrap_or_default())
}
