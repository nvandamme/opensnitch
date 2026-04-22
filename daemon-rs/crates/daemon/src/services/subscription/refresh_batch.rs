use tracing::debug;
use transport_wire_core::WireSubscriptionAction;

use super::SubscriptionService;
use super::labels::subscription_label;
use super::{SubscriptionRecord, wire_subscription_from_record};
pub(super) use crate::models::subscription_refresh::RefreshBatchResult;
use crate::models::subscription_refresh::RefreshOutcome;

impl SubscriptionService {
    pub(super) async fn process_refresh_records(
        &self,
        selected: Vec<SubscriptionRecord>,
        force: bool,
    ) -> RefreshBatchResult {
        let mut refreshed = 0usize;
        let mut unchanged = 0usize;
        let mut skipped = 0usize;
        let mut errors = Vec::new();
        let mut updated = Vec::with_capacity(selected.len());
        let mut sync_layout = false;

        for mut record in selected {
            if !force && !self.is_refresh_due(&record) {
                skipped += 1;
                debug!(name = %record.name, "subscription refresh: skipped (not due yet)");
                updated.push(record);
                continue;
            }

            let sub_lock = self.per_sub_lock(&record.id);
            let _guard = sub_lock.lock().await;

            match self.refresh_subscription(&mut record).await {
                Ok(RefreshOutcome::Downloaded) => {
                    refreshed += 1;
                    sync_layout = true;
                    self.refresh_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let wire = wire_subscription_from_record(&record);
                    self.push_event(wire, WireSubscriptionAction::Refresh);
                }
                Ok(RefreshOutcome::NotModified) => {
                    unchanged += 1;
                    sync_layout = true;
                }
                Err(err) => {
                    errors.push(format!("{}: {err}", subscription_label(&record)));
                    self.refresh_errors
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let wire = wire_subscription_from_record(&record);
                    self.push_event(wire, WireSubscriptionAction::Refresh);
                }
            }

            updated.push(self.storage.put_record(record));
        }

        RefreshBatchResult {
            refreshed,
            unchanged,
            skipped,
            errors,
            updated,
            sync_layout,
        }
    }
}
