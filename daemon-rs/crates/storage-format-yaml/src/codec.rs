use opensnitch_storage_format_core::StorageFormatCodec;
use serde::{Serialize, de::DeserializeOwned};

/// Stateless YAML codec backed by `serde_yml`.
///
/// YAML is inherently human-readable, so compact and pretty rendering
/// produce identical output.
#[derive(Clone, Debug, Default)]
pub struct YamlStorageFormat;

impl StorageFormatCodec for YamlStorageFormat {
    type Error = serde_yml::Error;

    fn parse_from_storage<T: DeserializeOwned>(&self, raw: &str) -> Result<T, Self::Error> {
        serde_yml::from_str(raw)
    }

    fn convert_to_storage<T: Serialize>(&self, value: &T) -> Result<String, Self::Error> {
        serde_yml::to_string(value)
    }

    fn convert_to_storage_pretty<T: Serialize>(&self, value: &T) -> Result<String, Self::Error> {
        serde_yml::to_string(value)
    }
}
