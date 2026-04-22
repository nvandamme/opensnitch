use anyhow::Result;
use opensnitch_proto::pb;
#[cfg(feature = "subscriptions")]
use opensnitch_transport_wire_core::SubscriptionCommandInboundPort;
use opensnitch_transport_wire_core::{
    NotificationInboundPort, WireAlert, WireAlertReply, WireConnection, WirePingReply,
    WirePingRequest, WireRule, WireSubscribeConfig,
};
#[cfg(feature = "subscriptions")]
use tokio::sync::mpsc as subscriptions_mpsc;

#[cfg(feature = "subscriptions")]
use crate::rpc::{
    subscriptions_apply, subscriptions_delete, subscriptions_deploy, subscriptions_list,
    subscriptions_open_commands, subscriptions_refresh,
};
use crate::rpc::{ui_ask_rule, ui_open_notifications, ui_ping, ui_post_alert, ui_subscribe};
#[cfg(feature = "subscriptions")]
use crate::subscriptions_client_from_channel;
use crate::{WireSession, ui_client_from_channel};

pub type WireAlertRequest = WireAlert;
pub type WireNotificationReply = opensnitch_transport_wire_core::WireNotificationReply;
#[cfg(feature = "subscriptions")]
pub type WireSubscriptionAction = opensnitch_transport_wire_core::WireSubscriptionAction;
#[cfg(feature = "subscriptions")]
pub type WireSubscriptionCommand = opensnitch_transport_wire_core::WireSubscriptionCommand;
#[cfg(feature = "subscriptions")]
pub type WireSubscriptionCommandAck = opensnitch_transport_wire_core::WireSubscriptionCommandAck;
#[cfg(feature = "subscriptions")]
pub type WireSubscriptionReply = opensnitch_transport_wire_core::WireSubscriptionReply;
#[cfg(feature = "subscriptions")]
pub type WireSubscriptionRequest = opensnitch_transport_wire_core::WireSubscriptionRequest;

#[derive(Clone)]
pub struct WireClient {
    ui: pb::ui_client::UiClient<crate::GrpcChannel>,
    #[cfg(feature = "subscriptions")]
    subscriptions: pb::subscriptions_client::SubscriptionsClient<crate::GrpcChannel>,
}

impl WireClient {
    pub fn from_session(channel: WireSession) -> Self {
        Self {
            ui: ui_client_from_channel(channel.clone()),
            #[cfg(feature = "subscriptions")]
            subscriptions: subscriptions_client_from_channel(channel),
        }
    }

    pub async fn subscribe(
        &mut self,
        cfg: WireSubscribeConfig,
    ) -> Result<WireSubscribeConfig, tonic::Status> {
        ui_subscribe(&mut self.ui, cfg).await
    }

    pub async fn ping(&mut self, req: WirePingRequest) -> Result<WirePingReply, tonic::Status> {
        ui_ping(&mut self.ui, req).await
    }

    pub async fn ask_rule(&mut self, conn: WireConnection) -> Result<WireRule, tonic::Status> {
        ui_ask_rule(&mut self.ui, conn).await
    }

    pub async fn post_alert(
        &mut self,
        alert: WireAlertRequest,
    ) -> Result<WireAlertReply, tonic::Status> {
        ui_post_alert(&mut self.ui, alert).await
    }

    pub async fn open_notifications(
        &mut self,
    ) -> Result<
        (
            Box<dyn NotificationInboundPort>,
            tokio::sync::mpsc::Sender<WireNotificationReply>,
        ),
        tonic::Status,
    > {
        ui_open_notifications(&mut self.ui).await
    }

    #[cfg(feature = "subscriptions")]
    pub async fn subscription_commands_open(
        &mut self,
    ) -> Result<
        (
            Box<dyn SubscriptionCommandInboundPort>,
            subscriptions_mpsc::Sender<WireSubscriptionCommandAck>,
        ),
        tonic::Status,
    > {
        subscriptions_open_commands(&mut self.subscriptions).await
    }

    #[cfg(feature = "subscriptions")]
    pub async fn subscription_list(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply, tonic::Status> {
        subscriptions_list(&mut self.subscriptions, req).await
    }

    #[cfg(feature = "subscriptions")]
    pub async fn subscription_apply(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply, tonic::Status> {
        subscriptions_apply(&mut self.subscriptions, req).await
    }

    #[cfg(feature = "subscriptions")]
    pub async fn subscription_delete(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply, tonic::Status> {
        subscriptions_delete(&mut self.subscriptions, req).await
    }

    #[cfg(feature = "subscriptions")]
    pub async fn subscription_refresh(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply, tonic::Status> {
        subscriptions_refresh(&mut self.subscriptions, req).await
    }

    #[cfg(feature = "subscriptions")]
    pub async fn subscription_deploy(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply, tonic::Status> {
        subscriptions_deploy(&mut self.subscriptions, req).await
    }
}
