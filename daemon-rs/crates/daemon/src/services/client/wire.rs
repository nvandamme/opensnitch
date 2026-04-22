use super::transport::{
    ClientAlertReply, ClientPingReply, ClientPingRequest, ClientSubscribeConfig,
};
#[cfg(feature = "client-transport")]
use super::transport::{ClientTransportSession, TransportRuntimeClient};
use anyhow::Result;
use tokio::sync::mpsc;
use transport_wire_core::PortFuture;
use transport_wire_core::{
    NotificationInboundPort, WireAlert, WireConnection, WireNotification, WireNotificationReply,
    WireRule,
};
#[cfg(feature = "subscriptions")]
use transport_wire_core::{
    SubscriptionCommandInboundPort, WireSubscriptionCommand, WireSubscriptionCommandAck,
    WireSubscriptionReply, WireSubscriptionRequest,
};

// Future transport profiles may run daemon in server or peer-to-peer mode;
// keep all role variants explicit now for profile-shape stability.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClientTransportRole {
    Client,
    Server,
    PeerToPeer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClientTransportKind {
    Stub,
    #[cfg(feature = "client-transport")]
    Http2,
    #[cfg(not(feature = "client-transport"))]
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClientWireCodecKind {
    Stub,
    #[cfg(feature = "client-transport")]
    ProtobufGrpc,
    #[cfg(not(feature = "client-transport"))]
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClientWireProfile {
    pub(super) role: ClientTransportRole,
    pub(super) transport: ClientTransportKind,
    pub(super) codec: ClientWireCodecKind,
}

pub(super) fn select_wire_profile(client_addr: &str) -> ClientWireProfile {
    if client_addr.starts_with("stub://") {
        return ClientWireProfile {
            role: ClientTransportRole::Client,
            transport: ClientTransportKind::Stub,
            codec: ClientWireCodecKind::Stub,
        };
    }

    #[cfg(feature = "client-transport")]
    {
        ClientWireProfile {
            role: ClientTransportRole::Client,
            transport: ClientTransportKind::Http2,
            codec: ClientWireCodecKind::ProtobufGrpc,
        }
    }

    #[cfg(not(feature = "client-transport"))]
    {
        ClientWireProfile {
            role: ClientTransportRole::Client,
            transport: ClientTransportKind::Disabled,
            codec: ClientWireCodecKind::Disabled,
        }
    }
}

#[derive(Clone, Default)]
pub(super) enum ClientWire {
    #[cfg(feature = "client-transport")]
    GrpcClient(TransportRuntimeClient),
    Stub(StubClientWire),
    #[default]
    Disabled,
}

impl ClientWire {
    #[cfg(feature = "client-transport")]
    pub(super) fn from_session(session: ClientTransportSession) -> Self {
        Self::GrpcClient(TransportRuntimeClient::from_session(session))
    }

    pub(super) fn from_stub() -> Self {
        Self::Stub(StubClientWire::default())
    }

    pub(super) async fn subscribe(
        &mut self,
        cfg: ClientSubscribeConfig,
    ) -> Result<ClientSubscribeConfig> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.subscribe(cfg).await;
        }
        if let Self::Stub(inner) = self {
            return inner.subscribe(cfg).await;
        }

        let _ = cfg;
        anyhow::bail!("client-transport feature disabled: subscribe transport is not available")
    }

    pub(super) async fn ping(&mut self, req: ClientPingRequest) -> Result<ClientPingReply> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.ping(req).await;
        }
        if let Self::Stub(inner) = self {
            return inner.ping(req).await;
        }

        let _ = req;
        anyhow::bail!("client-transport feature disabled: ping transport is not available")
    }

    pub(super) async fn ask_rule(&mut self, conn: WireConnection) -> Result<WireRule> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.ask_rule(conn).await;
        }
        if let Self::Stub(inner) = self {
            return inner.ask_rule(conn).await;
        }

        let _ = conn;
        anyhow::bail!("client-transport feature disabled: ask_rule transport is not available")
    }

    pub(super) async fn post_alert(&mut self, alert: WireAlert) -> Result<ClientAlertReply> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.post_alert(alert).await;
        }
        if let Self::Stub(inner) = self {
            return inner.post_alert(alert).await;
        }

        let _ = alert;
        anyhow::bail!("client-transport feature disabled: alert transport is not available")
    }

    pub(super) async fn open_notifications(
        &mut self,
    ) -> Result<(
        Box<dyn NotificationInboundPort>,
        mpsc::Sender<WireNotificationReply>,
    )> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.open_notifications().await;
        }
        if let Self::Stub(inner) = self {
            return inner.open_notifications().await;
        }

        anyhow::bail!(
            "client-transport feature disabled: Notifications stream transport is not available"
        )
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_commands_open(
        &mut self,
    ) -> Result<(
        Box<dyn SubscriptionCommandInboundPort>,
        mpsc::Sender<WireSubscriptionCommandAck>,
    )> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.subscription_commands_open().await;
        }
        if let Self::Stub(inner) = self {
            return inner.subscription_commands_open().await;
        }

        anyhow::bail!(
            "client-transport feature disabled: subscription Commands stream transport is not available"
        )
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_list(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.subscription_list(req).await;
        }
        if let Self::Stub(inner) = self {
            return inner.subscription_list(req).await;
        }

        let _ = req;
        anyhow::bail!("client-transport feature disabled: subscriptions transport is not available")
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_apply(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.subscription_apply(req).await;
        }
        if let Self::Stub(inner) = self {
            return inner.subscription_apply(req).await;
        }

        let _ = req;
        anyhow::bail!("client-transport feature disabled: subscriptions transport is not available")
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_delete(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.subscription_delete(req).await;
        }
        if let Self::Stub(inner) = self {
            return inner.subscription_delete(req).await;
        }

        let _ = req;
        anyhow::bail!("client-transport feature disabled: subscriptions transport is not available")
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_refresh(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.subscription_refresh(req).await;
        }
        if let Self::Stub(inner) = self {
            return inner.subscription_refresh(req).await;
        }

        let _ = req;
        anyhow::bail!("client-transport feature disabled: subscriptions transport is not available")
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_deploy(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        #[cfg(feature = "client-transport")]
        if let Self::GrpcClient(inner) = self {
            return inner.subscription_deploy(req).await;
        }
        if let Self::Stub(inner) = self {
            return inner.subscription_deploy(req).await;
        }

        let _ = req;
        anyhow::bail!("client-transport feature disabled: subscriptions transport is not available")
    }
}

#[derive(Clone, Default)]
pub(super) struct StubClientWire;

impl StubClientWire {
    async fn subscribe(&mut self, cfg: ClientSubscribeConfig) -> Result<ClientSubscribeConfig> {
        Ok(cfg)
    }

    async fn ping(&mut self, req: ClientPingRequest) -> Result<ClientPingReply> {
        Ok(ClientPingReply { id: req.id })
    }

    async fn ask_rule(&mut self, _conn: WireConnection) -> Result<WireRule> {
        Ok(WireRule::default())
    }

    async fn post_alert(&mut self, alert: WireAlert) -> Result<ClientAlertReply> {
        Ok(ClientAlertReply { id: alert.id })
    }

    async fn open_notifications(
        &mut self,
    ) -> Result<(
        Box<dyn NotificationInboundPort>,
        mpsc::Sender<WireNotificationReply>,
    )> {
        let (reply_tx, _reply_rx) = mpsc::channel::<WireNotificationReply>(64);
        let (inbound_tx, inbound_rx) = mpsc::channel::<WireNotification>(1);
        let inbound = Box::new(StubNotificationInbound {
            inbound_rx,
            _inbound_tx_guard: inbound_tx,
        });
        Ok((inbound, reply_tx))
    }

    #[cfg(feature = "subscriptions")]
    async fn subscription_commands_open(
        &mut self,
    ) -> Result<(
        Box<dyn SubscriptionCommandInboundPort>,
        mpsc::Sender<WireSubscriptionCommandAck>,
    )> {
        let (ack_tx, _ack_rx) = mpsc::channel::<WireSubscriptionCommandAck>(16);
        let (inbound_tx, inbound_rx) = mpsc::channel::<WireSubscriptionCommand>(1);
        let inbound = Box::new(StubSubscriptionCommandInbound {
            inbound_rx,
            _inbound_tx_guard: inbound_tx,
        });
        Ok((inbound, ack_tx))
    }

    #[cfg(feature = "subscriptions")]
    async fn subscription_list(
        &mut self,
        _req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        Ok(WireSubscriptionReply::default())
    }

    #[cfg(feature = "subscriptions")]
    async fn subscription_apply(
        &mut self,
        _req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        Ok(WireSubscriptionReply::default())
    }

    #[cfg(feature = "subscriptions")]
    async fn subscription_delete(
        &mut self,
        _req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        Ok(WireSubscriptionReply::default())
    }

    #[cfg(feature = "subscriptions")]
    async fn subscription_refresh(
        &mut self,
        _req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        Ok(WireSubscriptionReply::default())
    }

    #[cfg(feature = "subscriptions")]
    async fn subscription_deploy(
        &mut self,
        _req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        Ok(WireSubscriptionReply::default())
    }
}

struct StubNotificationInbound {
    inbound_rx: mpsc::Receiver<WireNotification>,
    _inbound_tx_guard: mpsc::Sender<WireNotification>,
}

impl NotificationInboundPort for StubNotificationInbound {
    fn recv<'a>(&'a mut self) -> PortFuture<'a, Option<WireNotification>> {
        Box::pin(async move { Ok(self.inbound_rx.recv().await) })
    }
}

#[cfg(feature = "subscriptions")]
struct StubSubscriptionCommandInbound {
    inbound_rx: mpsc::Receiver<WireSubscriptionCommand>,
    _inbound_tx_guard: mpsc::Sender<WireSubscriptionCommand>,
}

#[cfg(feature = "subscriptions")]
impl SubscriptionCommandInboundPort for StubSubscriptionCommandInbound {
    fn recv_command<'a>(&'a mut self) -> PortFuture<'a, Option<WireSubscriptionCommand>> {
        Box::pin(async move { Ok(self.inbound_rx.recv().await) })
    }
}
