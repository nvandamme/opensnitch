use serde_json::Value;

fn field_value<'a>(data: &'a Value, key: &str) -> Option<&'a Value> {
    data.as_object()?.get(key)
}

fn lowered_candidates(candidates: &[&str]) -> Vec<String> {
    candidates
        .iter()
        .map(|candidate| candidate.to_lowercase())
        .collect()
}

pub(crate) fn field_string_or_u64(data: &Value, key: &str) -> Option<String> {
    field_value(data, key).and_then(|v| {
        if let Some(s) = v.as_str() {
            Some(s.to_string())
        } else {
            v.as_u64().map(|n| n.to_string())
        }
    })
}

pub(crate) fn field_u8(data: &Value, key: &str) -> Option<u8> {
    field_value(data, key).and_then(|v| {
        if let Some(n) = v.as_u64() {
            u8::try_from(n).ok()
        } else if let Some(s) = v.as_str() {
            s.parse::<u8>().ok()
        } else {
            None
        }
    })
}

pub(crate) fn object_get_case_insensitive<'a>(
    obj: &'a serde_json::Map<String, Value>,
    candidates: &[&str],
) -> Option<&'a Value> {
    let candidates_lowered = lowered_candidates(candidates);
    obj.iter().find_map(|(key, value)| {
        let key_lower = key.to_lowercase();
        candidates_lowered
            .iter()
            .any(|candidate| key_lower == *candidate)
            .then_some(value)
    })
}
