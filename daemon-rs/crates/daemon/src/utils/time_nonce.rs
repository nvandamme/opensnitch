pub fn unix_epoch_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

pub fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}-{}", std::process::id(), unix_epoch_nanos())
}
