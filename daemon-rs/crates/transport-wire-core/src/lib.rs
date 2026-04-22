//! Unified transport core for daemon transport boundaries.
//!
//! This crate hosts both transport-facing port contracts and transport wire helpers,
//! separated by submodules:
//! - `ports`: trait contracts (`*Port`) and async port future aliases.
//! - `wire_helpers`: protocol/wire payload shaping helpers.

mod ports;
mod wire_helpers;

pub use ports::*;
pub use wire_helpers::*;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
