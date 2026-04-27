use crate::{config::Config, models::config::storage::RawConfig};
use anyhow::Result;

use super::ConfigService;

impl ConfigService {
    pub(super) fn parse_raw_json_with_base(base: &Config, raw_json: &str) -> Result<Config> {
        let mut parsed = Config::from_raw_json(&base.config_path, raw_json.to_string())?;
        let log_level_present = RawConfig::parse_normalized_for_path(&base.config_path, raw_json)
            .ok()
            .map(|raw| raw.log_level.is_some())
            .unwrap_or(false);
        if !log_level_present {
            parsed.log_level = base.log_level;
        }
        Ok(parsed)
    }
}
