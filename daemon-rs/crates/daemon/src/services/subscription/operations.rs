use opensnitch_proto::pb;

use super::SubscriptionService;
use super::reply::{base_reply, reply_with};
use crate::utils::stable_id::hex_id_from_pair;

impl SubscriptionService {
    pub(super) fn handle_list(&self) -> pb::SubscriptionReply {
        let items = self.storage.list();
        reply_with(
            pb::SubscriptionOperation::List,
            "subscriptions loaded",
            true,
            items,
            Vec::new(),
        )
    }

    pub(super) async fn handle_apply(&self, raw: Vec<pb::Subscription>) -> pb::SubscriptionReply {
        if raw.is_empty() {
            return base_reply(
                pb::SubscriptionOperation::Apply,
                "no subscriptions supplied",
                false,
            );
        }
        let normalized: Vec<pb::Subscription> = raw
            .into_iter()
            .filter_map(|item| {
                if item.url.is_empty() && item.name.is_empty() {
                    return None;
                }
                Some(super::format::normalize_subscription(item))
            })
            .collect();
        if normalized.is_empty() {
            return base_reply(
                pb::SubscriptionOperation::Apply,
                "no valid subscriptions supplied",
                false,
            );
        }
        let updated = self.storage.apply(normalized);
        let sync_err = self.sync_layout_error().await;
        self.flush_storage_best_effort().await;
        reply_with(
            pb::SubscriptionOperation::Apply,
            "subscriptions stored",
            true,
            updated,
            sync_err.into_iter().collect(),
        )
    }

    pub(super) async fn handle_delete(
        &self,
        items: Vec<pb::Subscription>,
    ) -> pb::SubscriptionReply {
        if items.is_empty() {
            return base_reply(
                pb::SubscriptionOperation::Delete,
                "no subscriptions supplied",
                false,
            );
        }
        let ids: Vec<String> = items
            .iter()
            .map(|item| {
                if !item.id.is_empty() {
                    item.id.clone()
                } else {
                    hex_id_from_pair(&item.url, &item.name)
                }
            })
            .collect();
        self.storage.delete(&ids);
        let sync_err = self.sync_layout_error().await;
        self.flush_storage_best_effort().await;
        reply_with(
            pb::SubscriptionOperation::Delete,
            "subscriptions deleted",
            true,
            Vec::new(),
            sync_err.into_iter().collect(),
        )
    }

    pub(super) async fn handle_deploy(&self) -> pb::SubscriptionReply {
        let sync_err = self.sync_layout_error().await;
        let updated = self.storage.list();
        reply_with(
            pb::SubscriptionOperation::Deploy,
            if sync_err.is_none() {
                "subscription layout deployed"
            } else {
                "subscription layout deploy failed"
            },
            sync_err.is_none(),
            updated,
            sync_err.as_ref().into_iter().cloned().collect(),
        )
    }
}
