#![cfg_attr(not(feature = "subscriptions"), allow(dead_code))]

use reqwest::{Response, StatusCode, header};

const DEFAULT_HTTP_ERROR_BODY_PREVIEW_BYTES: usize = 160;

pub(crate) fn header_value(value: Option<&header::HeaderValue>) -> String {
    value
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

pub(crate) async fn summarize_http_error(status: StatusCode, response: Response) -> String {
    let body = match response.bytes().await {
        Ok(bytes) => {
            String::from_utf8_lossy(
                &bytes[..bytes.len().min(DEFAULT_HTTP_ERROR_BODY_PREVIEW_BYTES)],
            )
            .trim()
            .to_string()
        }
        Err(_) => String::new(),
    };

    if body.is_empty() {
        format!("unexpected HTTP status {}", status.as_u16())
    } else {
        format!("unexpected HTTP status {}: {body}", status.as_u16())
    }
}