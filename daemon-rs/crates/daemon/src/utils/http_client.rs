use std::time::Duration;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

#[derive(Debug, Clone)]
pub(crate) struct HttpResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

pub(crate) type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

pub(crate) fn build_http_client() -> HttpClient {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("native root certs must be available")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    Client::builder(TokioExecutor::new()).build(https)
}

pub(crate) fn build_request(
    method: Method,
    uri: &str,
    headers: &[(HeaderName, String)],
    body: Vec<u8>,
) -> Result<Request<Full<Bytes>>> {
    let uri: Uri = uri
        .parse()
        .with_context(|| format!("invalid HTTP uri: {uri}"))?;

    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        let value = HeaderValue::from_str(value)
            .with_context(|| format!("invalid header value for {}", name.as_str()))?;
        builder = builder.header(name, value);
    }

    builder
        .body(Full::from(Bytes::from(body)))
        .context("building HTTP request")
}

pub(crate) async fn send_request(
    client: &HttpClient,
    request: Request<Full<Bytes>>,
    timeout: Duration,
    max_body_bytes: Option<u64>,
) -> Result<HttpResponse> {
    let response = tokio::time::timeout(timeout, client.request(request))
        .await
        .context("request timed out")?
        .context("request failed")?;

    collect_response(response, timeout, max_body_bytes).await
}

async fn collect_response(
    response: hyper::Response<Incoming>,
    timeout: Duration,
    max_body_bytes: Option<u64>,
) -> Result<HttpResponse> {
    let (parts, mut body) = response.into_parts();
    let mut bytes = Vec::new();

    while let Some(frame) = tokio::time::timeout(timeout, body.frame())
        .await
        .context("response body timed out")?
    {
        let frame = frame.context("response body frame error")?;
        if let Some(chunk) = frame.data_ref() {
            bytes.extend_from_slice(chunk);
            if let Some(limit) = max_body_bytes
                && (bytes.len() as u64) > limit
            {
                anyhow::bail!(
                    "response exceeds max-bytes limit ({} > {})",
                    bytes.len(),
                    limit
                );
            }
        }
    }

    Ok(HttpResponse {
        status: parts.status,
        headers: parts.headers,
        body: bytes,
    })
}
