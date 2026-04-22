//! UCI storage-format adapter — pure-Rust parser/emitter for OpenWrt UCI config files.
//!
//! Provides a [`UciStorageFormat`] codec implementing
//! [`StorageFormatCodec`](opensnitch_storage_format_core::StorageFormatCodec)
//! and a standalone [`UciDocument`] model for direct access to UCI
//! section/option/list structure.
//!
//! No C/FFI dependency. This crate parses UCI text files (`/etc/config/*`)
//! into an in-memory document model and emits them back. For runtime `uci`
//! operations (staging, commit, revert via `ubusd`), see the transport-wire
//! adapter layer.

mod codec;
mod document;
mod emitter;
mod error;
mod parser;
mod serde_bridge;

pub use codec::*;
pub use document::*;
pub use error::*;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
