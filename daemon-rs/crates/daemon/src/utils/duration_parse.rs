use std::time::Duration;

use crate::utils::name_parsing::normalized_name;

#[derive(Clone, Copy)]
pub(crate) struct DurationParseOptions {
    pub allow_fractional: bool,
    pub min_ms: u64,
    pub min_s: u64,
    pub min_m: u64,
    pub min_h: u64,
}

pub(crate) const TASK_INTERVAL_OPTIONS: DurationParseOptions = DurationParseOptions {
    allow_fractional: false,
    min_ms: 100,
    min_s: 1,
    min_m: 1,
    min_h: 1,
};

pub(crate) fn parse_human_duration(raw: &str, opts: DurationParseOptions) -> Option<Duration> {
    let value = normalized_name(raw);

    let units = [
        ("ms", 1_u64, opts.min_ms),
        ("s", 1_000_u64, opts.min_s),
        ("m", 60_000_u64, opts.min_m),
        ("h", 3_600_000_u64, opts.min_h),
    ];

    for (suffix, multiplier, min_value) in units {
        if let Some(number) = value.strip_suffix(suffix) {
            if opts.allow_fractional {
                let parsed = number.trim().parse::<f64>().ok()?;
                if parsed.is_sign_negative() || !parsed.is_finite() {
                    return None;
                }
                let bounded = parsed.max(min_value as f64);
                let millis = (bounded * multiplier as f64).round() as u64;
                return Some(Duration::from_millis(millis.max(1)));
            }

            let parsed = number.trim().parse::<u64>().ok()?;
            let bounded = parsed.max(min_value);
            let millis = bounded.saturating_mul(multiplier);
            return Some(Duration::from_millis(millis.max(1)));
        }
    }

    None
}
