use opensnitch_storage_format_core::StorageFormatCodec;
use serde::{Serialize, de::DeserializeOwned};

/// Stateless JSON codec backed by `serde_json`.
#[derive(Clone, Debug, Default)]
pub struct JsonStorageFormat;

impl StorageFormatCodec for JsonStorageFormat {
    type Error = serde_json::Error;

    fn parse_from_storage<T: DeserializeOwned>(&self, raw: &str) -> Result<T, Self::Error> {
        serde_json::from_str(raw)
    }

    fn convert_to_storage<T: Serialize>(&self, value: &T) -> Result<String, Self::Error> {
        serde_json::to_string(value)
    }

    fn convert_to_storage_pretty<T: Serialize>(&self, value: &T) -> Result<String, Self::Error> {
        serde_json::to_string_pretty(value)
    }
}

impl JsonStorageFormat {
    /// Parse raw JSON into an intermediate `serde_json::Value`.
    ///
    /// Useful when callers need to inspect or transform the structure before
    /// final deserialization (for example config key-normalisation passes).
    /// This is JSON-specific and deliberately not part of the
    /// `StorageFormatCodec` trait.
    pub fn parse_value(&self, raw: &str) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_str(raw)
    }

    /// Deserialize an already-parsed `serde_json::Value` into a DTO.
    ///
    /// Pair with [`JsonStorageFormat::parse_value`] when a normalisation pass sits
    /// between the raw string and the final type.
    pub fn parse_value_as<T: DeserializeOwned>(
        &self,
        value: serde_json::Value,
    ) -> Result<T, serde_json::Error> {
        serde_json::from_value(value)
    }
}
