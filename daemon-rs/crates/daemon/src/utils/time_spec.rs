pub(crate) fn matches_hms_spec(spec: &str, hour: u8, minute: u8, second: u8) -> bool {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return false;
    }

    let mut parts = trimmed.split(':');
    let Some(hour_part) = parts.next() else {
        return false;
    };
    let Some(minute_part) = parts.next() else {
        return false;
    };
    let second_part = parts.next();
    if parts.next().is_some() {
        return false;
    }

    let Ok(h) = hour_part.parse::<u8>() else {
        return false;
    };
    let Ok(m) = minute_part.parse::<u8>() else {
        return false;
    };
    let s = if let Some(second_part) = second_part {
        let Ok(s) = second_part.parse::<u8>() else {
            return false;
        };
        s
    } else {
        0
    };

    h == hour && m == minute && s == second
}
