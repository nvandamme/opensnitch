use reqwest::{StatusCode, header};
use tracing::{info, warn};

use super::SubscriptionRecord;
use super::SubscriptionService;
use super::refresh_timing::next_refresh_success;
pub(super) use crate::models::subscription_refresh::RefreshOutcome;
use crate::services::storage::StorageService;
use crate::utils::http_response::{header_value, summarize_http_error};
use crate::utils::time_nonce::now_rfc3339_utc;

impl SubscriptionService {
    pub(super) async fn refresh_subscription(
        &self,
        record: &mut SubscriptionRecord,
    ) -> std::result::Result<RefreshOutcome, String> {
        if record.url.trim().is_empty() {
            let message = "subscription url is empty".to_string();
            self.mark_refresh_error(record, &message);
            return Err(message);
        }

        info!(name = %record.name, url = %record.url, "subscription refresh: started");

        let mut request = self
            .http
            .get(&record.url)
            .timeout(std::time::Duration::from_secs(u64::from(
                record.timeout_seconds.max(1),
            )));
        if !record.etag.is_empty() {
            request = request.header(header::IF_NONE_MATCH, &record.etag);
        }
        if !record.last_modified.is_empty() {
            request = request.header(header::IF_MODIFIED_SINCE, &record.last_modified);
        }

        let retry = request.try_clone();
        let response = match request.send().await {
            Ok(response) => response,
            Err(err) => match retry {
                Some(retry_request) => {
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    match retry_request.send().await {
                        Ok(response) => response,
                        Err(retry_err) => {
                            let message =
                                format!("request failed: {err}; retry failed: {retry_err}");
                            self.mark_refresh_error(record, &message);
                            return Err(message);
                        }
                    }
                }
                None => {
                    let message = format!("request failed: {err}");
                    self.mark_refresh_error(record, &message);
                    return Err(message);
                }
            },
        };

        match response.status() {
            StatusCode::OK => {
                let etag = header_value(response.headers().get(header::ETAG));
                let last_modified = header_value(response.headers().get(header::LAST_MODIFIED));
                if let Err(err) = self
                    .write_source_file(&record.filename, &record.format, record.max_bytes, response)
                    .await
                {
                    let message = err.to_string();
                    self.mark_refresh_error(record, &message);
                    warn!(name = %record.name, error = %message, "subscription refresh: failed");
                    return Err(message);
                }

                record.status = "ready".to_string();
                record.last_error.clear();
                record.last_updated = now_rfc3339_utc();
                record.etag = etag;
                record.last_modified = last_modified;
                record.consecutive_failures = 0;
                record.next_refresh_after = next_refresh_success(record.interval_seconds);
                info!(name = %record.name, url = %record.url, "subscription refresh: updated");
                Ok(RefreshOutcome::Downloaded)
            }
            StatusCode::NOT_MODIFIED => {
                let source_path = self.source_path_for(record);
                let has_source = StorageService::global()
                    .path_exists("subscription", source_path.as_path())
                    .await
                    .unwrap_or(false);
                if !has_source {
                    let message =
                        "server returned 304 but cached source file is missing".to_string();
                    self.mark_refresh_error(record, &message);
                    warn!(name = %record.name, error = %message, "subscription refresh: failed");
                    return Err(message);
                }

                let etag = header_value(response.headers().get(header::ETAG));
                let last_modified = header_value(response.headers().get(header::LAST_MODIFIED));
                if !etag.is_empty() {
                    record.etag = etag;
                }
                if !last_modified.is_empty() {
                    record.last_modified = last_modified;
                }
                record.status = "ready".to_string();
                record.last_error.clear();
                record.last_updated = now_rfc3339_utc();
                record.consecutive_failures = 0;
                record.next_refresh_after = next_refresh_success(record.interval_seconds);
                info!(name = %record.name, url = %record.url, "subscription refresh: not-modified (up to date)");
                Ok(RefreshOutcome::NotModified)
            }
            status => {
                let message = summarize_http_error(status, response).await;
                self.mark_refresh_error(record, &message);
                warn!(name = %record.name, error = %message, "subscription refresh: failed");
                Err(message)
            }
        }
    }
}
