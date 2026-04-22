use opensnitch_proto::pb;

use crate::models::subscription_storage::SubscriptionRecord;

use super::SubscriptionService;
use super::refresh_batch::RefreshBatchResult;
use super::refresh_reply::{empty_refresh_reply, finalize_refresh_reply};
use super::refresh_selection::{RefreshSelection, select_refresh_targets};

impl SubscriptionService {
    pub(super) async fn handle_refresh(
        &self,
        items: Vec<SubscriptionRecord>,
        targets: Vec<String>,
        force: bool,
    ) -> pb::SubscriptionReply {
        let RefreshSelection {
            explicit_targeting,
            selected,
        } = select_refresh_targets(self.storage.list_records(), &items, &targets);
        if selected.is_empty() {
            return empty_refresh_reply(explicit_targeting);
        }

        let RefreshBatchResult {
            refreshed,
            unchanged,
            skipped,
            mut errors,
            updated,
            sync_layout,
        } = self.process_refresh_records(selected, force).await;

        self.apply_refresh_postprocess(sync_layout, &mut errors)
            .await;
        finalize_refresh_reply(updated, errors, refreshed, unchanged, skipped)
    }
}
