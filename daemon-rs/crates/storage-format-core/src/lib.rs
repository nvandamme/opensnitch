//! Storage-format adapter core containing the format-agnostic codec contract.

mod codec;

pub use codec::*;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
