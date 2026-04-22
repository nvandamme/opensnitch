//! TOML storage-format adapter.

mod codec;
mod error;

pub use codec::*;
pub use error::*;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
