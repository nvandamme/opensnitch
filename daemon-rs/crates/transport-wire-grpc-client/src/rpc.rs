use anyhow::Result;
use opensnitch_proto::pb;
#[cfg(feature = "subscriptions")]
use opensnitch_transport_wire_core::SubscriptionCommandInboundPort;
use opensnitch_transport_wire_core::{NotificationInboundPort, PortFuture};
use opensnitch_transport_wire_core::{
    WireAlertReply, WireConnection, WireNotification, WirePingReply, WirePingRequest, WireRule,
    WireSubscribeConfig,
};
use tokio::sync::mpsc;
#[cfg(feature = "subscriptions")]
use tokio::sync::mpsc as subscriptions_mpsc;
use tokio_stream::wrappers::ReceiverStream;
pub use tonic::codec::CompressionEncoding as GrpcCompressionEncoding;

use crate::wire_protos::{
    pb_connection_from_wire, pb_ping_request_from_wire, pb_subscribe_config_from_wire,
    wire_alert_reply_from_proto, wire_alert_to_proto, wire_notification_from_proto,
    wire_ping_reply_from_proto, wire_rule_from_pb, wire_subscribe_config_from_proto,
};
#[cfg(feature = "subscriptions")]
use crate::wire_protos::{
    pb_subscription_ack_from_wire, pb_subscription_request_from_wire,
    wire_subscription_command_from_proto, wire_subscription_reply_from_pb,
};
use crate::{GrpcChannel, WireAlertRequest, WireNotificationReply};
#[cfg(feature = "subscriptions")]
use crate::{
    WireSubscriptionCommand, WireSubscriptionCommandAck, WireSubscriptionReply,
    WireSubscriptionRequest,
};

pub type GrpcStreaming<T> = tonic::Streaming<T>;

struct WireNotificationInbound {
    inner: GrpcStreaming<pb::Notification>,
}

impl NotificationInboundPort for WireNotificationInbound {
    fn recv<'a>(&'a mut self) -> PortFuture<'a, Option<WireNotification>> {
        Box::pin(async move {
            let next = self.inner.message().await?;
            Ok(next.map(wire_notification_from_proto))
        })
    }
}

#[cfg(feature = "subscriptions")]
struct WireSubscriptionCommandInbound {
    inner: GrpcStreaming<pb::SubscriptionCommand>,
}

#[cfg(feature = "subscriptions")]
impl SubscriptionCommandInboundPort for WireSubscriptionCommandInbound {
    fn recv_command<'a>(&'a mut self) -> PortFuture<'a, Option<WireSubscriptionCommand>> {
        Box::pin(async move {
            let next = self.inner.message().await?;
            Ok(next.map(wire_subscription_command_from_proto))
        })
    }
}

pub async fn ui_subscribe(
    client: &mut pb::ui_client::UiClient<GrpcChannel>,
    cfg: WireSubscribeConfig,
) -> Result<WireSubscribeConfig, tonic::Status> {
    Ok(wire_subscribe_config_from_proto(
        client
            .subscribe(pb_subscribe_config_from_wire(cfg))
            .await?
            .into_inner(),
    ))
}

pub async fn ui_ping(
    client: &mut pb::ui_client::UiClient<GrpcChannel>,
    req: WirePingRequest,
) -> Result<WirePingReply, tonic::Status> {
    Ok(wire_ping_reply_from_proto(
        client
            .ping(pb_ping_request_from_wire(req))
            .await?
            .into_inner(),
    ))
}

pub async fn ui_ask_rule(
    client: &mut pb::ui_client::UiClient<GrpcChannel>,
    conn: WireConnection,
) -> Result<WireRule, tonic::Status> {
    Ok(wire_rule_from_pb(
        client
            .ask_rule(pb_connection_from_wire(conn))
            .await?
            .into_inner(),
    ))
}

pub async fn ui_post_alert(
    client: &mut pb::ui_client::UiClient<GrpcChannel>,
    alert: WireAlertRequest,
) -> Result<WireAlertReply, tonic::Status> {
    let alert = wire_alert_to_proto(alert);
    Ok(wire_alert_reply_from_proto(
        client
            .clone()
            .send_compressed(GrpcCompressionEncoding::Gzip)
            .post_alert(alert)
            .await?
            .into_inner(),
    ))
}

pub async fn ui_open_notifications(
    client: &mut pb::ui_client::UiClient<GrpcChannel>,
) -> Result<
    (
        Box<dyn NotificationInboundPort>,
        mpsc::Sender<WireNotificationReply>,
    ),
    tonic::Status,
> {
    let (reply_tx, mut reply_rx) = mpsc::channel::<WireNotificationReply>(64);
    let (pb_reply_tx, pb_reply_rx) = mpsc::channel::<pb::NotificationReply>(64);
    tokio::spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            if pb_reply_tx
                .send(pb::NotificationReply {
                    id: reply.id,
                    code: reply.code,
                    data: reply.data,
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let outbound = ReceiverStream::new(pb_reply_rx);
    let response = client.notifications(outbound).await?;
    Ok((
        Box::new(WireNotificationInbound {
            inner: response.into_inner(),
        }),
        reply_tx,
    ))
}

#[cfg(feature = "subscriptions")]
pub async fn subscriptions_open_commands(
    client: &mut pb::subscriptions_client::SubscriptionsClient<GrpcChannel>,
) -> Result<
    (
        Box<dyn SubscriptionCommandInboundPort>,
        subscriptions_mpsc::Sender<WireSubscriptionCommandAck>,
    ),
    tonic::Status,
> {
    let (ack_tx, mut ack_rx) = subscriptions_mpsc::channel::<WireSubscriptionCommandAck>(16);
    let (pb_ack_tx, pb_ack_rx) = subscriptions_mpsc::channel::<pb::SubscriptionCommandAck>(16);
    tokio::spawn(async move {
        while let Some(ack) = ack_rx.recv().await {
            if pb_ack_tx
                .send(pb_subscription_ack_from_wire(ack))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let ack_stream = ReceiverStream::new(pb_ack_rx);
    let stream = client.commands(ack_stream).await?.into_inner();
    Ok((
        Box::new(WireSubscriptionCommandInbound { inner: stream }),
        ack_tx,
    ))
}

#[cfg(feature = "subscriptions")]
pub async fn subscriptions_list(
    client: &mut pb::subscriptions_client::SubscriptionsClient<GrpcChannel>,
    req: WireSubscriptionRequest,
) -> Result<WireSubscriptionReply, tonic::Status> {
    Ok(wire_subscription_reply_from_pb(
        client
            .list(pb_subscription_request_from_wire(req))
            .await?
            .into_inner(),
    ))
}

#[cfg(feature = "subscriptions")]
pub async fn subscriptions_apply(
    client: &mut pb::subscriptions_client::SubscriptionsClient<GrpcChannel>,
    req: WireSubscriptionRequest,
) -> Result<WireSubscriptionReply, tonic::Status> {
    Ok(wire_subscription_reply_from_pb(
        client
            .apply(pb_subscription_request_from_wire(req))
            .await?
            .into_inner(),
    ))
}

#[cfg(feature = "subscriptions")]
pub async fn subscriptions_delete(
    client: &mut pb::subscriptions_client::SubscriptionsClient<GrpcChannel>,
    req: WireSubscriptionRequest,
) -> Result<WireSubscriptionReply, tonic::Status> {
    Ok(wire_subscription_reply_from_pb(
        client
            .delete(pb_subscription_request_from_wire(req))
            .await?
            .into_inner(),
    ))
}

#[cfg(feature = "subscriptions")]
pub async fn subscriptions_refresh(
    client: &mut pb::subscriptions_client::SubscriptionsClient<GrpcChannel>,
    req: WireSubscriptionRequest,
) -> Result<WireSubscriptionReply, tonic::Status> {
    Ok(wire_subscription_reply_from_pb(
        client
            .refresh(pb_subscription_request_from_wire(req))
            .await?
            .into_inner(),
    ))
}

#[cfg(feature = "subscriptions")]
pub async fn subscriptions_deploy(
    client: &mut pb::subscriptions_client::SubscriptionsClient<GrpcChannel>,
    req: WireSubscriptionRequest,
) -> Result<WireSubscriptionReply, tonic::Status> {
    Ok(wire_subscription_reply_from_pb(
        client
            .deploy(pb_subscription_request_from_wire(req))
            .await?
            .into_inner(),
    ))
}
