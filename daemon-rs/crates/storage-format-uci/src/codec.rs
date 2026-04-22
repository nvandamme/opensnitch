use opensnitch_storage_format_core::StorageFormatCodec;
use serde::{Serialize, de::DeserializeOwned};

use crate::document::UciDocument;
use crate::error::UciCodecError;
use crate::{emitter, parser, serde_bridge};

/// Pure-Rust UCI format codec.
///
/// Parses and emits OpenWrt UCI configuration files. Uses an intermediate
/// `serde_json::Value` bridge to support the generic [`StorageFormatCodec`]
/// contract.
///
/// The serde mapping convention requires a 3-level JSON structure:
/// - Level 1: section type → object
/// - Level 2: section name → object
/// - Level 3: option name → string value, list name → string array
///
/// UCI is inherently human-readable with tab-indented sections, so
/// `convert_to_storage` and `convert_to_storage_pretty` produce identical
/// output.
#[derive(Clone, Debug, Default)]
pub struct UciStorageFormat;

impl StorageFormatCodec for UciStorageFormat {
    type Error = UciCodecError;

    fn parse_from_storage<T: DeserializeOwned>(&self, raw: &str) -> Result<T, Self::Error> {
        let doc = parser::parse(raw).map_err(UciCodecError::Parse)?;
        let value = serde_bridge::document_to_value(&doc);
        serde_json::from_value(value).map_err(UciCodecError::SerdeJson)
    }

    fn convert_to_storage<T: Serialize>(&self, value: &T) -> Result<String, Self::Error> {
        let json_value = serde_json::to_value(value).map_err(UciCodecError::SerdeJson)?;
        let doc = serde_bridge::value_to_document(&json_value)?;
        Ok(emitter::emit(&doc))
    }

    fn convert_to_storage_pretty<T: Serialize>(&self, value: &T) -> Result<String, Self::Error> {
        self.convert_to_storage(value)
    }
}

impl UciStorageFormat {
    /// Parse raw UCI text into a [`UciDocument`] for direct structural access.
    ///
    /// Use this when callers need the section/option/list model without going
    /// through serde. Inspired by `rust-uci`'s approach of exposing the
    /// document context directly.
    pub fn parse_document(&self, raw: &str) -> Result<UciDocument, UciCodecError> {
        parser::parse(raw).map_err(UciCodecError::Parse)
    }

    /// Emit a [`UciDocument`] as UCI text.
    pub fn emit_document(&self, doc: &UciDocument) -> String {
        emitter::emit(doc)
    }
}
