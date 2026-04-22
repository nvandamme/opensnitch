#![cfg_attr(not(feature = "subscriptions"), allow(dead_code))]

pub fn unix_epoch_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

pub(crate) fn unix_timestamp_now_utc() -> i64 {
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    if ts < 0 { 0 } else { ts }
}

pub(crate) fn now_rfc3339_utc() -> String {
    use time::format_description::well_known::Rfc3339;

    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

pub fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}-{}", std::process::id(), unix_epoch_nanos())
}
