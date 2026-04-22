use anyhow::Result;

use crate::{config::Config, utils::json_value::object_get_case_insensitive};

use super::ConfigService;

impl ConfigService {
    pub(super) fn parse_raw_json_with_base(base: &Config, raw_json: &str) -> Result<Config> {
        let mut parsed = Config::from_raw_json(&base.config_path, raw_json.to_string())?;
        let log_level_present = serde_json::from_str::<serde_json::Value>(raw_json)
            .ok()
            .and_then(|value| {
                value
                    .as_object()
                    .map(|obj| object_get_case_insensitive(obj, &["LogLevel"]).is_some())
            })
            .unwrap_or(false);
        if !log_level_present {
            parsed.log_level = base.log_level;
        }
        Ok(parsed)
    }
}
