//! JSON storage-format adapter.

mod codec;

pub use codec::*;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
