use opensnitch_storage_format_core::StorageFormatCodec;
use serde::{Serialize, de::DeserializeOwned};

use crate::TomlCodecError;

/// Stateless TOML codec backed by the `toml` crate.
#[derive(Clone, Debug, Default)]
pub struct TomlStorageFormat;

impl StorageFormatCodec for TomlStorageFormat {
    type Error = TomlCodecError;

    fn parse_from_storage<T: DeserializeOwned>(&self, raw: &str) -> Result<T, Self::Error> {
        toml::from_str(raw).map_err(TomlCodecError::De)
    }

    fn convert_to_storage<T: Serialize>(&self, value: &T) -> Result<String, Self::Error> {
        toml::to_string(value).map_err(TomlCodecError::Ser)
    }

    fn convert_to_storage_pretty<T: Serialize>(&self, value: &T) -> Result<String, Self::Error> {
        toml::to_string_pretty(value).map_err(TomlCodecError::Ser)
    }
}
