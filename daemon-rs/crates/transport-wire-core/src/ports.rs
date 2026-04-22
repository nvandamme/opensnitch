use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

#[cfg(feature = "subscriptions")]
use crate::wire_helpers::WireSubscriptionCommand;
use crate::wire_helpers::{WireAlert, WireNotification};

pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait NotificationInboundPort: Send {
    fn recv<'a>(&'a mut self) -> PortFuture<'a, Option<WireNotification>>;
}

#[cfg(feature = "subscriptions")]
pub trait SubscriptionCommandInboundPort: Send {
    fn recv_command<'a>(&'a mut self) -> PortFuture<'a, Option<WireSubscriptionCommand>>;
}

pub trait ClientTransportPort {
    type SubscribeConfig;
    type PingRequest;
    type PingReply;
    type AskRuleRequest;
    type RuleReply;
    type AlertReply;

    fn subscribe<'a>(
        &'a mut self,
        cfg: Self::SubscribeConfig,
    ) -> PortFuture<'a, Self::SubscribeConfig>;
    fn ping<'a>(&'a mut self, req: Self::PingRequest) -> PortFuture<'a, Self::PingReply>;
    fn ask_rule<'a>(&'a mut self, conn: Self::AskRuleRequest) -> PortFuture<'a, Self::RuleReply>;
    fn post_alert<'a>(&'a mut self, alert: WireAlert) -> PortFuture<'a, Self::AlertReply>;
}

pub trait ClientTransportConnectorPort<Cfg> {
    type Client: ClientTransportPort;

    fn connect_or_reuse<'a>(&'a self, config: &'a Cfg) -> PortFuture<'a, Self::Client>;

    fn invalidate(&self);
}

/// Factory for establishing a reusable transport session from runtime config.
///
/// The session is transport-specific (for example HTTP pool, WebSocket handle,
/// MQTT client session, gRPC channel), but callers depend only on this generic
/// factory contract.
pub trait ClientTransportSessionFactoryPort<Cfg> {
    type Session: Clone + Send + Sync + 'static;

    fn fingerprint(&self, config: &Cfg) -> u64;

    fn connect_session<'a>(&'a self, config: &'a Cfg) -> PortFuture<'a, Self::Session>;
}

/// Factory for building a transport client from a reusable transport session.
pub trait ClientTransportClientFactoryPort<Session> {
    type Client: ClientTransportPort;

    fn client_from_session(&self, session: Session) -> Self::Client;
}
