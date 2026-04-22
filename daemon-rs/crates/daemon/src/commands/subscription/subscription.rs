use opensnitch_proto::pb;

use crate::{
    models::command_rpc::IncomingSubscriptionNotification,
    services::{client::ClientService, subscription::SubscriptionService},
};

#[derive(Clone)]
pub(crate) struct SubscriptionCommandService {
    subscriptions: SubscriptionService,
}

impl SubscriptionCommandService {
    pub(crate) fn new(subscriptions: SubscriptionService) -> Self {
        Self { subscriptions }
    }

    /// Process a `SubscriptionCommand` received from the `Subscriptions.Commands`
    /// bidi stream and return the `SubscriptionCommandAck` to send back to the UI.
    pub(crate) async fn handle_command(
        &self,
        cmd: pb::SubscriptionCommand,
        client_service: &mut ClientService,
    ) -> pb::SubscriptionCommandAck {
        let action = pb::SubscriptionAction::try_from(cmd.action)
            .unwrap_or(pb::SubscriptionAction::Unspecified);

        let ParsedData {
            subscriptions,
            targets,
            force,
        } = parse_command_data(&cmd.data);

        let req = match action {
            pb::SubscriptionAction::List => pb::SubscriptionRequest {
                operation: pb::SubscriptionAction::List as i32,
                subscriptions: self.subscriptions.list(),
                ..Default::default()
            },
            pb::SubscriptionAction::Apply => pb::SubscriptionRequest {
                operation: pb::SubscriptionAction::Apply as i32,
                subscriptions,
                ..Default::default()
            },
            pb::SubscriptionAction::Delete => pb::SubscriptionRequest {
                operation: pb::SubscriptionAction::Delete as i32,
                subscriptions,
                ..Default::default()
            },
            pb::SubscriptionAction::Refresh => pb::SubscriptionRequest {
                operation: pb::SubscriptionAction::Refresh as i32,
                targets,
                force,
                ..Default::default()
            },
            pb::SubscriptionAction::Deploy => pb::SubscriptionRequest {
                operation: pb::SubscriptionAction::Deploy as i32,
                ..Default::default()
            },
            pb::SubscriptionAction::Unspecified => {
                return pb::SubscriptionCommandAck {
                    id: cmd.id,
                    action: cmd.action,
                    accepted: false,
                    message: "unspecified action".to_string(),
                };
            }
        };

        let reply = self.subscriptions.handle_request(req.clone()).await;

        // Sync the outcome back to the Python UI via the individual named RPCs.
        // List always syncs (carries the full subscription set); others only sync
        // when the local operation was accepted.
        let should_sync = reply.accepted || matches!(action, pb::SubscriptionAction::List);
        if should_sync {
            let sync_result = match action {
                pb::SubscriptionAction::List => client_service.subscription_list(req).await,
                pb::SubscriptionAction::Apply => client_service.subscription_apply(req).await,
                pb::SubscriptionAction::Delete => client_service.subscription_delete(req).await,
                pb::SubscriptionAction::Refresh => client_service.subscription_refresh(req).await,
                pb::SubscriptionAction::Deploy => client_service.subscription_deploy(req).await,
                pb::SubscriptionAction::Unspecified => Ok(pb::SubscriptionReply::default()),
            };
            if let Err(err) = sync_result {
                tracing::debug!(
                    cmd_id = cmd.id,
                    "subscription command: UI sync failed: {err}"
                );
            }
        }

        pb::SubscriptionCommandAck {
            id: cmd.id,
            action: cmd.action,
            accepted: reply.accepted,
            message: reply.message,
        }
    }
}

struct ParsedData {
    subscriptions: Vec<pb::Subscription>,
    targets: Vec<String>,
    force: bool,
}

fn parse_command_data(raw_data: &str) -> ParsedData {
    let data =
        serde_json::from_str::<IncomingSubscriptionNotification>(raw_data).unwrap_or_default();
    ParsedData {
        subscriptions: data
            .subscriptions
            .into_iter()
            .map(|item| pb::Subscription {
                id: item.id,
                name: item.name,
                url: item.url,
                enabled: item.enabled,
                ..Default::default()
            })
            .collect(),
        targets: data.targets,
        force: data.force,
    }
}
