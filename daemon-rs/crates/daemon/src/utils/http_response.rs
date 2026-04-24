use hyper::{StatusCode, header};

const DEFAULT_HTTP_ERROR_BODY_PREVIEW_BYTES: usize = 160;

pub(crate) fn header_value(value: Option<&header::HeaderValue>) -> String {
    value
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

pub(crate) fn summarize_http_error(status: StatusCode, response_body: &[u8]) -> String {
    let body = String::from_utf8_lossy(
        &response_body[..response_body
            .len()
            .min(DEFAULT_HTTP_ERROR_BODY_PREVIEW_BYTES)],
    )
    .trim()
    .to_string();

    if body.is_empty() {
        format!("unexpected HTTP status {}", status.as_u16())
    } else {
        format!("unexpected HTTP status {}: {body}", status.as_u16())
    }
}
