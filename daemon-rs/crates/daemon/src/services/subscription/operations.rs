use opensnitch_proto::pb;

use super::SubscriptionService;
use super::record_to_proto;
use super::reply::{base_reply, reply_with};
use crate::models::subscription_rpc::{SubscriptionCommand, SubscriptionOperation};
use crate::models::subscription_storage::SubscriptionRecord;
use crate::utils::stable_id::hex_id_from_pair;

impl SubscriptionService {
    pub(super) async fn handle_command(
        &self,
        command: SubscriptionCommand,
    ) -> pb::SubscriptionReply {
        match command.operation {
            SubscriptionOperation::List => self.handle_list(),
            SubscriptionOperation::Apply => self.handle_apply(command.subscriptions).await,
            SubscriptionOperation::Delete => self.handle_delete(command.subscriptions).await,
            SubscriptionOperation::Refresh => {
                self.handle_refresh(command.subscriptions, command.targets, command.force)
                    .await
            }
            SubscriptionOperation::Deploy => self.handle_deploy().await,
            SubscriptionOperation::Unspecified => base_reply(
                pb::SubscriptionAction::Unspecified,
                "unspecified operation",
                false,
            ),
        }
    }

    pub(super) fn handle_list(&self) -> pb::SubscriptionReply {
        let items = self
            .storage
            .list_records()
            .into_iter()
            .map(|record| record_to_proto(&record))
            .collect();
        reply_with(
            pb::SubscriptionAction::List,
            "subscriptions loaded",
            true,
            items,
            Vec::new(),
        )
    }

    pub(super) async fn handle_apply(&self, raw: Vec<SubscriptionRecord>) -> pb::SubscriptionReply {
        if raw.is_empty() {
            return base_reply(
                pb::SubscriptionAction::Apply,
                "no subscriptions supplied",
                false,
            );
        }
        let normalized: Vec<SubscriptionRecord> = raw
            .into_iter()
            .filter_map(|item| {
                if item.url.is_empty() && item.name.is_empty() {
                    return None;
                }
                Some(super::format::normalize_record(item))
            })
            .collect();
        if normalized.is_empty() {
            return base_reply(
                pb::SubscriptionAction::Apply,
                "no valid subscriptions supplied",
                false,
            );
        }
        let updated: Vec<pb::Subscription> = self
            .storage
            .apply_records(normalized)
            .into_iter()
            .map(|record| record_to_proto(&record))
            .collect();
        let sync_err = self.sync_layout_error().await;
        self.flush_storage_best_effort().await;
        reply_with(
            pb::SubscriptionAction::Apply,
            "subscriptions stored",
            true,
            updated,
            sync_err.into_iter().collect(),
        )
    }

    pub(super) async fn handle_delete(
        &self,
        items: Vec<SubscriptionRecord>,
    ) -> pb::SubscriptionReply {
        if items.is_empty() {
            return base_reply(
                pb::SubscriptionAction::Delete,
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
            pb::SubscriptionAction::Delete,
            "subscriptions deleted",
            true,
            Vec::new(),
            sync_err.into_iter().collect(),
        )
    }

    pub(super) async fn handle_deploy(&self) -> pb::SubscriptionReply {
        let sync_err = self.sync_layout_error().await;
        let updated = self
            .storage
            .list_records()
            .into_iter()
            .map(|record| record_to_proto(&record))
            .collect();
        reply_with(
            pb::SubscriptionAction::Deploy,
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
