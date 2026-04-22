#![cfg(any(feature = "subscriptions", test))]

use std::hash::{Hash, Hasher};

#[derive(Clone, Copy)]
pub(crate) struct BackoffOptions {
    pub min_seconds: i64,
    pub cap_seconds: i64,
    pub max_shift: u32,
    pub jitter_divisor: i64,
}

pub(crate) fn deterministic_exponential_backoff_seconds(
    jitter_key: &str,
    attempt: u32,
    opts: BackoffOptions,
) -> i64 {
    let cap = opts.cap_seconds.max(opts.min_seconds);
    let shift = attempt.saturating_sub(1).min(opts.max_shift);
    let multiplier = 1i64.checked_shl(shift).unwrap_or(i64::MAX);
    let base = opts.min_seconds.saturating_mul(multiplier).min(cap);

    let spread = (base / opts.jitter_divisor.max(1)).max(1);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    jitter_key.hash(&mut hasher);
    attempt.hash(&mut hasher);
    let modulo = (spread.saturating_mul(2).saturating_add(1)) as u64;
    let offset = (hasher.finish() % modulo) as i64 - spread;

    base.saturating_add(offset).clamp(opts.min_seconds, cap)
}
