use opensnitch_proto::pb;

use super::wire::{encode_subscription_reply_data, parse_subscription_request_data};
use crate::{
    services::{client::Client, stats::StatsService, subscription::SubscriptionService},
    utils::notification_reply::build_notification_reply,
};

#[derive(Clone, Default)]
pub(crate) struct SubscriptionCommandService;

impl SubscriptionCommandService {
    pub(crate) async fn handle_notification_rpc_first(
        &self,
        client: &mut Client,
        id: u64,
        request_json: &str,
        subscriptions: &SubscriptionService,
        stats: &StatsService,
    ) -> pb::NotificationReply {
        let request = match parse_subscription_request_data(request_json) {
            Ok(request) => request,
            Err(err) => {
                return build_notification_reply(id, pb::NotificationReplyCode::Error, err);
            }
        };

        let operation = pb::SubscriptionOperation::try_from(request.operation)
            .unwrap_or(pb::SubscriptionOperation::Unspecified);

        let explicit_rpc = match operation {
            pb::SubscriptionOperation::List => client.subscription_list(request.clone()).await,
            pb::SubscriptionOperation::Apply => client.subscription_apply(request.clone()).await,
            pb::SubscriptionOperation::Delete => client.subscription_delete(request.clone()).await,
            pb::SubscriptionOperation::Refresh => client.subscription_refresh(request.clone()).await,
            pb::SubscriptionOperation::Deploy => client.subscription_deploy(request.clone()).await,
            pb::SubscriptionOperation::Unspecified => {
                // Keep unspecified routed to compatibility command endpoint.
                client.subscription_command(request.clone()).await
            }
        };

        match explicit_rpc {
            Ok(reply) => {
                return Self::subscription_reply_as_notification(id, reply);
            }
            Err(err) => {
                tracing::debug!(
                    notification_id = id,
                    operation = ?operation,
                    "explicit subscription rpc failed, falling back to command rpc: {err}"
                );
            }
        }

        match client.subscription_command(request.clone()).await {
            Ok(reply) => {
                return Self::subscription_reply_as_notification(id, reply);
            }
            Err(err) => {
                tracing::debug!(
                    notification_id = id,
                    "subscription command rpc unavailable, falling back to notification compatibility path: {err}"
                );
            }
        }

        // Compatibility fallback: keep handling over notification command path.
        self.handle_notification(id, request_json, subscriptions, stats)
            .await
    }

    pub(crate) async fn handle_notification(
        &self,
        id: u64,
        request_json: &str,
        subscriptions: &SubscriptionService,
        stats: &StatsService,
    ) -> pb::NotificationReply {
        let request = match parse_subscription_request_data(request_json) {
            Ok(request) => request,
            Err(err) => {
                return build_notification_reply(id, pb::NotificationReplyCode::Error, err);
            }
        };

        let reply = subscriptions.handle_request(request).await;
        let (total, ready, error) = subscriptions.counts();
        stats.update_subscription_counts(total, ready, error);

        Self::subscription_reply_as_notification(id, reply)
    }

    fn subscription_reply_as_notification(id: u64, reply: pb::SubscriptionReply) -> pb::NotificationReply {
        let data = match encode_subscription_reply_data(&reply) {
            Ok(data) => data,
            Err(err) => {
                return build_notification_reply(
                    id,
                    pb::NotificationReplyCode::Error,
                    format!("failed to serialize subscription reply: {err}"),
                );
            }
        };

        build_notification_reply(
            id,
            if reply.accepted {
                pb::NotificationReplyCode::Ok
            } else {
                pb::NotificationReplyCode::Error
            },
            data,
        )
    }
}
