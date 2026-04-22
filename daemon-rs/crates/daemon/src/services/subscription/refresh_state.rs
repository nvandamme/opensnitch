use std::sync::Arc;

use opensnitch_proto::pb;
use tokio::sync::Mutex as AsyncMutex;

use super::SubscriptionService;
use super::refresh_timing::next_refresh_failure;
use super::{SubscriptionRecord, subscription_status_to_str};
use crate::utils::time_nonce::unix_timestamp_now_utc;

impl SubscriptionService {
    pub(super) fn is_refresh_due(&self, record: &SubscriptionRecord) -> bool {
        record.next_refresh_after <= unix_timestamp_now_utc()
    }

    pub(super) fn mark_refresh_error(&self, record: &mut SubscriptionRecord, message: &str) {
        record.status = subscription_status_to_str(pb::SubscriptionStatus::Error);
        record.last_error = message.to_string();
        record.consecutive_failures = record.consecutive_failures.saturating_add(1);
        record.next_refresh_after = next_refresh_failure(
            &record.id,
            record.interval_seconds,
            record.consecutive_failures,
        );
    }

    pub(super) fn per_sub_lock(&self, id: &str) -> Arc<AsyncMutex<()>> {
        self.locks
            .entry(id.to_owned())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }
}
