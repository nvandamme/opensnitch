use serde_json::Value;

fn field_value<'a>(data: &'a Value, key: &str) -> Option<&'a Value> {
    data.as_object()?.get(key)
}

fn lowered_candidates(candidates: &[&str]) -> Vec<String> {
    candidates.iter().map(|candidate| candidate.to_lowercase()).collect()
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

fn find_first_number(node: &Value) -> Option<u64> {
    match node {
        Value::Number(n) => n.as_u64(),
        Value::Object(map) => map.values().find_map(find_first_number),
        Value::Array(items) => items.iter().find_map(find_first_number),
        _ => None,
    }
}

pub(crate) fn find_numeric_for_keys(node: &Value, wanted_keys: &[&str]) -> Option<u64> {
    let wanted_keys_lowered = lowered_candidates(wanted_keys);
    find_numeric_for_lowered_keys(node, &wanted_keys_lowered)
}

fn find_numeric_for_lowered_keys(node: &Value, wanted_keys: &[String]) -> Option<u64> {
    match node {
        Value::Number(_) => None,
        Value::Object(map) => {
            for (k, v) in map {
                let key = k.to_lowercase();
                if wanted_keys.iter().any(|w| key == *w) {
                    if let Some(num) = v.as_u64() {
                        return Some(num);
                    }

                    if let Some(num) = find_first_number(v) {
                        return Some(num);
                    }
                }
            }

            for value in map.values() {
                if let Some(num) = find_numeric_for_lowered_keys(value, wanted_keys) {
                    return Some(num);
                }
            }

            None
        }
        Value::Array(items) => items
            .iter()
            .find_map(|item| find_numeric_for_lowered_keys(item, wanted_keys)),
        _ => None,
    }
}
