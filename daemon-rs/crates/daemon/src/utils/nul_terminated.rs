pub(crate) fn nul_terminated_bytes(value: &[u8]) -> &[u8] {
    let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
    &value[..end]
}

pub(crate) fn nul_terminated_utf8(value: &[u8]) -> Option<&str> {
    let bytes = nul_terminated_bytes(value);
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text),
        Err(_) => None,
    }
}

pub(crate) fn nul_terminated_utf8_lossy(value: &[u8]) -> String {
    let bytes = nul_terminated_bytes(value);
    if bytes.is_empty() {
        return String::new();
    }
    String::from_utf8_lossy(bytes).to_string()
}
