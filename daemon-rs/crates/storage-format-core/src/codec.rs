use serde::{Serialize, de::DeserializeOwned};

/// Port contract for format-agnostic loadable-state codecs.
///
/// Each format library (JSON, YAML, TOML, UCI, ...) provides a type that
/// implements this trait. Service/storage code depending on
/// `impl StorageFormatCodec`
/// can be rewired to a different format at the adapter boundary with no
/// policy-layer changes.
///
/// Generic methods make `StorageFormatCodec` intentionally non-object-safe; codec
/// selection is a compile-time / wiring concern, not a runtime dispatch one.
pub trait StorageFormatCodec: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Parse a raw storage payload into an in-memory DTO.
    fn parse_from_storage<T: DeserializeOwned>(&self, raw: &str) -> Result<T, Self::Error>;

    /// Convert an in-memory DTO into a compact storage payload for writing.
    fn convert_to_storage<T: Serialize>(&self, value: &T) -> Result<String, Self::Error>;

    /// Convert an in-memory DTO into a human-readable storage payload for writing.
    /// For formats with no indentation concept (for example pure YAML) this may
    /// be identical to `convert_to_storage`.
    fn convert_to_storage_pretty<T: Serialize>(&self, value: &T) -> Result<String, Self::Error>;
}
