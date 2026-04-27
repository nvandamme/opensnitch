use transport_wire_core::{
    WireSubscription, WireSubscriptionAction, WireSubscriptionCommand, WireSubscriptionCommandAck,
    WireSubscriptionRequest, decode_json_notification_payload,
};

use crate::{
    models::command::rpc::IncomingSubscriptionNotification,
    models::subscription::rpc::{SubscriptionCommand, SubscriptionOperation},
    models::subscription::storage::SubscriptionRecord,
    services::{
        client::ClientService,
        subscription::{
            SubscriptionService, operation_from_wire_action, wire_subscription_action_from_i32,
        },
    },
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
    /// bidi stream and return the `SubscriptionCommandAck` to send back to the client.
    pub(crate) async fn handle_command(
        &self,
        cmd: WireSubscriptionCommand,
        client_service: &mut ClientService,
    ) -> WireSubscriptionCommandAck {
        let action = wire_subscription_action_from_i32(cmd.action);

        let ParsedData {
            subscriptions,
            targets,
            force,
        } = parse_command_data(&cmd.data);

        let operation = operation_from_wire_action(action);

        if matches!(operation, SubscriptionOperation::Unspecified) {
            return WireSubscriptionCommandAck {
                id: cmd.id,
                action: cmd.action,
                accepted: false,
                message: "unspecified action".to_string(),
            };
        }

        let command = SubscriptionCommand {
            operation,
            subscriptions,
            targets,
            force,
        };

        let reply = self
            .subscriptions
            .handle_wire_command(command.clone())
            .await;

        // Sync the outcome back to the Python client via the individual named RPCs.
        // List always syncs (carries the full subscription set); others only sync
        // when the local operation was accepted.
        let should_sync = reply.accepted || matches!(action, WireSubscriptionAction::List);
        if should_sync {
            let wire_req = wire_subscription_request_from_command(command, &reply);
            let sync_result = match action {
                WireSubscriptionAction::List => client_service.subscription_list(wire_req).await,
                WireSubscriptionAction::Apply => client_service.subscription_apply(wire_req).await,
                WireSubscriptionAction::Delete => {
                    client_service.subscription_delete(wire_req).await
                }
                WireSubscriptionAction::Refresh => {
                    client_service.subscription_refresh(wire_req).await
                }
                WireSubscriptionAction::Deploy => {
                    client_service.subscription_deploy(wire_req).await
                }
                WireSubscriptionAction::Unspecified => Ok(Default::default()),
            };
            if let Err(err) = sync_result {
                tracing::debug!(
                    cmd_id = cmd.id,
                    "subscription command: client sync failed: {err}"
                );
            }
        }

        WireSubscriptionCommandAck {
            id: cmd.id,
            action: cmd.action,
            accepted: reply.accepted,
            message: reply.message,
        }
    }
}

fn wire_subscription_request_from_command(
    command: SubscriptionCommand,
    reply: &transport_wire_core::WireSubscriptionReply,
) -> WireSubscriptionRequest {
    let operation = match command.operation {
        SubscriptionOperation::Unspecified => WireSubscriptionAction::Unspecified as i32,
        SubscriptionOperation::List => WireSubscriptionAction::List as i32,
        SubscriptionOperation::Apply => WireSubscriptionAction::Apply as i32,
        SubscriptionOperation::Delete => WireSubscriptionAction::Delete as i32,
        SubscriptionOperation::Refresh => WireSubscriptionAction::Refresh as i32,
        SubscriptionOperation::Deploy => WireSubscriptionAction::Deploy as i32,
    };

    let subscriptions = if matches!(command.operation, SubscriptionOperation::List) {
        reply.subscriptions.clone()
    } else {
        command
            .subscriptions
            .into_iter()
            .map(subscription_record_to_wire)
            .collect()
    };

    WireSubscriptionRequest {
        operation,
        subscriptions,
        targets: command.targets,
        force: command.force,
    }
}

struct ParsedData {
    subscriptions: Vec<SubscriptionRecord>,
    targets: Vec<String>,
    force: bool,
}

fn parse_command_data(raw_data: &str) -> ParsedData {
    let data = decode_json_notification_payload::<IncomingSubscriptionNotification>(raw_data)
        .unwrap_or_default();
    ParsedData {
        subscriptions: data
            .subscriptions
            .into_iter()
            .map(|item| SubscriptionRecord {
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

fn subscription_record_to_wire(record: SubscriptionRecord) -> WireSubscription {
    WireSubscription {
        id: record.id,
        name: record.name,
        url: record.url,
        filename: record.filename,
        groups: record.groups,
        enabled: record.enabled,
        format: record.format,
        interval_seconds: record.interval_seconds,
        timeout_seconds: record.timeout_seconds,
        max_bytes: record.max_bytes,
        node: record.node,
        status: 0,
        last_updated: record.last_updated,
        last_error: record.last_error,
        refresh_meta: Some(transport_wire_core::WireSubscriptionRefreshMetadata {
            next_refresh_after: record.next_refresh_after,
            consecutive_failures: record.consecutive_failures,
            etag: record.etag,
            last_modified: record.last_modified,
        }),
    }
}
