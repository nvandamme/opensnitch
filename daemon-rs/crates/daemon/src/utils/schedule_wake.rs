#![cfg(feature = "subscriptions")]

use std::time::Duration;

pub(crate) fn bounded_wake_duration_from_timestamps<I>(
    timestamps: I,
    now_unix: i64,
    min_sleep_seconds: i64,
    max_sleep_seconds: i64,
) -> Duration
where
    I: IntoIterator<Item = i64>,
{
    let max_sleep_seconds = max_sleep_seconds.max(min_sleep_seconds);
    let earliest = timestamps
        .into_iter()
        .map(|value| if value == 0 { now_unix } else { value })
        .min()
        .unwrap_or(now_unix.saturating_add(max_sleep_seconds));

    let secs = (earliest - now_unix).clamp(min_sleep_seconds, max_sleep_seconds);
    Duration::from_secs(secs.max(0) as u64)
}
