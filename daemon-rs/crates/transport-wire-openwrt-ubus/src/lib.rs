//! OpenWrt ubus transport-wire adapter primitives.
//!
//! This crate owns ubus runtime/wire behavior only. UCI file parsing belongs
//! in `storage-format-uci`, while imperative `uci` CLI planning belongs in
//! daemon platform adapters.

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
