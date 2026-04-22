use std::time::Duration;

use crate::utils::schedule_backoff::{BackoffOptions, deterministic_exponential_backoff_seconds};
use crate::utils::schedule_wake::bounded_wake_duration_from_timestamps;
use crate::utils::time_nonce::unix_timestamp_now_utc;

const MIN_REFRESH_BACKOFF_SECONDS: i64 = 60;
const MAX_REFRESH_BACKOFF_SECONDS: i64 = 6 * 3600;

pub(super) fn build_refresh_message(
    refreshed: usize,
    unchanged: usize,
    skipped: usize,
    failed: usize,
) -> String {
    format!("{refreshed} refreshed, {unchanged} not modified, {skipped} skipped, {failed} failed")
}

pub(super) fn next_refresh_success(interval_seconds: u32) -> i64 {
    unix_timestamp_now_utc().saturating_add(i64::from(interval_seconds.max(1)))
}

pub(super) fn next_refresh_failure(
    jitter_key: &str,
    interval_seconds: u32,
    consecutive_failures: u32,
) -> i64 {
    unix_timestamp_now_utc()
        + compute_backoff_seconds(jitter_key, interval_seconds, consecutive_failures)
}

pub(super) fn scheduler_wake_duration<I>(next_refresh_after: I) -> Duration
where
    I: IntoIterator<Item = i64>,
{
    const MIN_SLEEP: i64 = 10;
    const MAX_SLEEP: i64 = 5 * 60;

    bounded_wake_duration_from_timestamps(
        next_refresh_after,
        unix_timestamp_now_utc(),
        MIN_SLEEP,
        MAX_SLEEP,
    )
}

fn compute_backoff_seconds(
    jitter_key: &str,
    interval_seconds: u32,
    consecutive_failures: u32,
) -> i64 {
    deterministic_exponential_backoff_seconds(
        jitter_key,
        consecutive_failures,
        BackoffOptions {
            min_seconds: MIN_REFRESH_BACKOFF_SECONDS,
            cap_seconds: i64::from(interval_seconds)
                .clamp(MIN_REFRESH_BACKOFF_SECONDS, MAX_REFRESH_BACKOFF_SECONDS),
            max_shift: 16,
            jitter_divisor: 5,
        },
    )
}
