// This service surface is shared across profiles; several fields/helpers are only
// exercised by `client-transport` builds.
#![cfg(feature = "client-transport")]

use anyhow::Result;
use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::sync::mpsc;
use transport_wire_core;
#[cfg(feature = "client-transport")]
use transport_wire_core::{ClientTransportClientFactoryPort, ClientTransportSessionFactoryPort};
use transport_wire_core::{
    ClientTransportConnectorPort, ClientTransportPort, NotificationInboundPort, PortFuture,
    WireAlert, WireConnection, WireNotificationReply, WireRule, WireSysFirewall,
};
#[cfg(feature = "subscriptions")]
use transport_wire_core::{
    WireSubscriptionAction, WireSubscriptionCommandAck, WireSubscriptionReply,
    WireSubscriptionRequest,
};

use super::session::{
    CLIENT_SESSION_ID, ClientPrincipal, ClientSession, ClientSessionSnapshot, SessionState,
};
#[cfg(not(feature = "client-transport"))]
use super::transport::CapturedServerCertIdentity;
#[cfg(feature = "client-transport")]
use super::transport::{
    CapturedServerCertIdentity, SocketTarget, classify_socket_target,
    connect_unix_abstract_channel, connect_unix_channel, connect_with_skip_verify,
    connect_with_verified_tls, endpoint_with_keepalive,
};
use super::transport::{
    ClientAlertReply, ClientPingReply, ClientPingRequest, ClientSubscribeConfig,
    ClientTransportSession,
};
#[cfg(feature = "client-transport")]
use super::wire::{ClientTransportKind, ClientTransportRole, ClientWireCodecKind};
use super::wire::{ClientWire, ClientWireProfile, select_wire_profile};
#[cfg(feature = "client-transport")]
use crate::config::ClientAuthType;
use crate::config::Config;
#[cfg(feature = "subscriptions")]
use crate::models::subscription::rpc::{SubscriptionCommand, SubscriptionOperation};
#[cfg(feature = "subscriptions")]
use transport_wire_core::SubscriptionCommandInboundPort;
#[cfg(feature = "subscriptions")]
use transport_wire_core::{WireSubscription, WireSubscriptionRefreshMetadata};

/// Shared cache for a transport session keyed on a config fingerprint.
///
/// Reusing an existing session avoids setup overhead on every
/// RPC call. The cache is lock-free (`ArcSwap`) and safe to share across
/// concurrent tasks.
#[derive(Clone)]
pub struct WireSessionCache {
    inner: Arc<ArcSwap<Option<CachedSession>>>,
}

struct CachedSession {
    fingerprint: u64,
    session: ClientTransportSession,
}

impl Default for WireSessionCache {
    fn default() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(None)),
        }
    }
}

impl WireSessionCache {
    fn fingerprint(config: &Config) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        config.client_addr.hash(&mut h);
        config.client_auth.auth_type.as_name().hash(&mut h);
        h.finish()
    }

    fn load(&self, fp: u64) -> Option<ClientTransportSession> {
        let guard = self.inner.load();
        guard
            .as_ref()
            .as_ref()
            .filter(|c| c.fingerprint == fp)
            .map(|c| c.session.clone())
    }

    fn store(&self, fp: u64, session: ClientTransportSession) {
        self.inner.store(Arc::new(Some(CachedSession {
            fingerprint: fp,
            session,
        })));
    }

    pub fn invalidate(&self) {
        self.inner.store(Arc::new(None));
    }
}

#[cfg(feature = "client-transport")]
#[derive(Clone, Copy, Default)]
struct DaemonWireSessionFactory;

#[cfg(feature = "client-transport")]
impl ClientTransportSessionFactoryPort<Config> for DaemonWireSessionFactory {
    type Session = ClientTransportSession;

    fn fingerprint(&self, config: &Config) -> u64 {
        WireSessionCache::fingerprint(config)
    }

    fn connect_session<'a>(&'a self, config: &'a Config) -> PortFuture<'a, Self::Session> {
        Box::pin(async move {
            let (session, _) = ClientService::connect_session_with_identity(config).await?;
            Ok(session)
        })
    }
}

#[cfg(feature = "client-transport")]
#[derive(Clone, Copy, Default)]
struct DaemonWireClientFactory;

#[cfg(feature = "client-transport")]
impl ClientTransportClientFactoryPort<ClientTransportSession> for DaemonWireClientFactory {
    type Client = ClientService;

    fn client_from_session(&self, session: ClientTransportSession) -> Self::Client {
        ClientService::from_session(session)
    }
}

#[derive(Clone, Default)]
pub struct ClientTransportConnector {
    cache: WireSessionCache,
}

impl ClientTransportConnector {
    pub fn new(cache: WireSessionCache) -> Self {
        Self { cache }
    }
}

impl ClientTransportConnectorPort<Config> for ClientTransportConnector {
    type Client = ClientService;

    fn connect_or_reuse<'a>(&'a self, config: &'a Config) -> PortFuture<'a, Self::Client> {
        Box::pin(async move { ClientService::connect_or_reuse(config, &self.cache).await })
    }

    fn invalidate(&self) {
        self.cache.invalidate();
    }
}

#[derive(Clone)]
pub struct ClientService {
    wire: ClientWire,
    session: Arc<SessionState>,
}

// ---------------------------------------------------------------------------
// Session management — delegates to SessionState
// ---------------------------------------------------------------------------

impl Default for ClientService {
    fn default() -> Self {
        Self {
            wire: ClientWire::default(),
            session: Arc::new(SessionState::new()),
        }
    }
}

impl ClientService {
    fn modify_snapshot(&self, f: impl FnOnce(&mut ClientSessionSnapshot)) {
        self.session.modify_snapshot(f);
    }

    pub fn upsert_session(&self, session: ClientSession) {
        self.modify_snapshot(|s| {
            s.sessions.insert(session.id.clone(), session);
        });
    }
    // Session-injection helper retained for test and profile-specific ingress paths.
    #[allow(dead_code)]
    pub fn connect_local_uid_session(&self, uid: u32) {
        let default_action = self.session.snapshot_rx.borrow().connected_default_action;
        self.upsert_session(ClientSession::for_local_uid(uid, default_action));
    }
    // Session-injection helper retained for test and profile-specific ingress paths.
    #[allow(dead_code)]
    pub fn connect_network_identity_session(&self, identity: impl Into<String>) {
        let default_action = self.session.snapshot_rx.borrow().connected_default_action;
        self.upsert_session(ClientSession::for_network_identity(
            identity,
            default_action,
        ));
    }
    // Session-injection helper retained for test and profile-specific ingress paths.
    #[allow(dead_code)]
    pub fn connect_ip_fallback_session(&self, ip: std::net::IpAddr) {
        let default_action = self.session.snapshot_rx.borrow().connected_default_action;
        self.upsert_session(ClientSession::for_ip_fallback(ip, default_action));
    }

    pub fn disconnect_session(&self, session_id: &str) {
        self.modify_snapshot(|s| {
            s.sessions.remove(session_id);
        });
    }
    // Snapshot helper retained for diagnostics and profile-specific surfaces.
    #[allow(dead_code)]
    pub fn connected_sessions(&self) -> Vec<ClientSession> {
        self.session
            .snapshot_rx
            .borrow()
            .sessions
            .values()
            .cloned()
            .collect()
    }

    pub fn connected_sessions_count(&self) -> usize {
        self.session.snapshot_rx.borrow().sessions.len()
    }

    pub fn primary_owner(&self) -> Option<ClientPrincipal> {
        let snapshot = self.session.snapshot_rx.borrow();
        if let Some(client_session) = snapshot.sessions.get(CLIENT_SESSION_ID) {
            return Some(client_session.owner.clone());
        }
        snapshot
            .sessions
            .values()
            .min_by(|left, right| {
                let left_rank = SessionState::principal_rank(&left.owner);
                let right_rank = SessionState::principal_rank(&right.owner);
                left_rank
                    .cmp(&right_rank)
                    .then_with(|| left.id.cmp(&right.id))
            })
            .map(|session| session.owner.clone())
    }
    // Session mutation helper retained for profile-specific control paths.
    #[allow(dead_code)]
    pub fn set_session_default_action(
        &self,
        session_id: &str,
        action: crate::config::DefaultAction,
    ) {
        self.modify_snapshot(|s| {
            if let Some(session) = s.sessions.get_mut(session_id) {
                session.default_action = action;
            }
        });
    }
    // Session mutation helper retained for profile-specific control paths.
    #[allow(dead_code)]
    pub fn set_connected(&self, connected: bool) {
        if connected {
            let default_action = self.session.snapshot_rx.borrow().connected_default_action;
            self.upsert_session(ClientSession {
                id: CLIENT_SESSION_ID.to_string(),
                owner: ClientPrincipal::NetworkIdentity(CLIENT_SESSION_ID.to_string()),
                default_action,
                capabilities: Vec::new(),
            });
        } else {
            self.disconnect_session(CLIENT_SESSION_ID);
        }
    }
    pub fn is_connected(&self) -> bool {
        !self.session.snapshot_rx.borrow().sessions.is_empty()
    }

    pub fn set_connected_default_action(&self, action: crate::config::DefaultAction) {
        self.modify_snapshot(|s| {
            if let Some(client_session) = s.sessions.get_mut(CLIENT_SESSION_ID) {
                client_session.default_action = action;
            }
            s.connected_default_action = action;
        });
    }

    pub fn connected_default_action(&self) -> crate::config::DefaultAction {
        self.session.snapshot_rx.borrow().connected_default_action
    }

    pub fn effective_default_action(
        &self,
        disconnected_default_action: crate::config::DefaultAction,
    ) -> crate::config::DefaultAction {
        let snapshot = self.session.snapshot_rx.borrow();
        if let Some(client_session) = snapshot.sessions.get(CLIENT_SESSION_ID) {
            return client_session.default_action;
        }
        snapshot
            .sessions
            .values()
            .min_by(|left, right| {
                let left_rank = SessionState::principal_rank(&left.owner);
                let right_rank = SessionState::principal_rank(&right.owner);
                left_rank
                    .cmp(&right_rank)
                    .then_with(|| left.id.cmp(&right.id))
            })
            .map(|session| session.default_action)
            .unwrap_or(disconnected_default_action)
    }

    pub fn effective_default_duration(
        &self,
        disconnected_default_duration: crate::config::DefaultDuration,
    ) -> crate::config::DefaultDuration {
        disconnected_default_duration
    }

    pub fn effective_defaults(
        &self,
        disconnected_default_action: crate::config::DefaultAction,
        disconnected_default_duration: crate::config::DefaultDuration,
    ) -> (crate::config::DefaultAction, crate::config::DefaultDuration) {
        let action = self.effective_default_action(disconnected_default_action);
        let duration = self.effective_default_duration(disconnected_default_duration);
        (action, duration)
    }
}

// ---------------------------------------------------------------------------
// gRPC transport — connection and RPC methods
// ---------------------------------------------------------------------------

impl ClientService {
    fn selected_wire_profile(config: &Config) -> ClientWireProfile {
        select_wire_profile(config.client_addr.as_str())
    }

    fn nonempty_server_identity(
        identity: Arc<CapturedServerCertIdentity>,
    ) -> Option<Arc<CapturedServerCertIdentity>> {
        if identity.fingerprint_sha256.is_some()
            || identity.subject.is_some()
            || identity.san_dns.is_some()
        {
            Some(identity)
        } else {
            None
        }
    }
    #[cfg(feature = "client-transport")]
    #[allow(dead_code)]
    pub async fn connect(addr: &str) -> Result<Self> {
        let channel = match classify_socket_target(addr) {
            SocketTarget::Tcp(target) => endpoint_with_keepalive(target)?.connect().await?,
            SocketTarget::UnixPath(path) => connect_unix_channel(path.to_string()).await?,
            SocketTarget::UnixAbstract(name) => {
                connect_unix_abstract_channel(name.to_string()).await?
            }
        };
        Ok(Self::from_session(channel))
    }
    #[cfg(not(feature = "client-transport"))]
    #[allow(dead_code)]
    pub async fn connect(_addr: &str) -> Result<Self> {
        Ok(Self::default())
    }

    #[cfg(feature = "client-transport")]
    pub async fn connect_with_config(config: &Config) -> Result<Self> {
        let (service, _) = Self::connect_with_config_and_server_identity(config).await?;
        Ok(service)
    }

    #[cfg(not(feature = "client-transport"))]
    pub async fn connect_with_config(_config: &Config) -> Result<Self> {
        Ok(Self::default())
    }

    #[cfg(feature = "client-transport")]
    pub async fn connect_with_config_and_server_identity(
        config: &Config,
    ) -> Result<(Self, Option<Arc<CapturedServerCertIdentity>>)> {
        let profile = Self::selected_wire_profile(config);
        match (profile.role, profile.transport, profile.codec) {
            (ClientTransportRole::Client, ClientTransportKind::Stub, ClientWireCodecKind::Stub) => {
                return Ok((Self::from_stub_wire(), None));
            }
            #[cfg(feature = "client-transport")]
            (
                ClientTransportRole::Client,
                ClientTransportKind::Http2,
                ClientWireCodecKind::ProtobufGrpc,
            ) => {}
            #[cfg(not(feature = "client-transport"))]
            (
                ClientTransportRole::Client,
                ClientTransportKind::Disabled,
                ClientWireCodecKind::Disabled,
            ) => {
                return Ok((Self::default(), None));
            }
            _ => anyhow::bail!("invalid client transport/wire profile selection"),
        }

        let (session, server_identity) = Self::connect_session_with_identity(config).await?;
        Ok((Self::from_session(session), server_identity))
    }

    #[cfg(not(feature = "client-transport"))]
    pub async fn connect_with_config_and_server_identity(
        _config: &Config,
    ) -> Result<(Self, Option<Arc<CapturedServerCertIdentity>>)> {
        Ok((Self::default(), None))
    }

    /// Reuse a cached transport session when the config fingerprint matches,
    /// falling back to a fresh connection on cache miss or config change.
    #[cfg(feature = "client-transport")]
    pub async fn connect_or_reuse(config: &Config, cache: &WireSessionCache) -> Result<Self> {
        let profile = Self::selected_wire_profile(config);
        match (profile.role, profile.transport, profile.codec) {
            (ClientTransportRole::Client, ClientTransportKind::Stub, ClientWireCodecKind::Stub) => {
                return Ok(Self::from_stub_wire());
            }
            (
                ClientTransportRole::Client,
                ClientTransportKind::Http2,
                ClientWireCodecKind::ProtobufGrpc,
            ) => {}
            #[cfg(not(feature = "client-transport"))]
            (
                ClientTransportRole::Client,
                ClientTransportKind::Disabled,
                ClientWireCodecKind::Disabled,
            ) => {
                return Ok(Self::default());
            }
            _ => anyhow::bail!("invalid client transport/wire profile selection"),
        }

        let session_factory = DaemonWireSessionFactory;
        let client_factory = DaemonWireClientFactory;

        let fp = session_factory.fingerprint(config);
        if let Some(session) = cache.load(fp) {
            return Ok(client_factory.client_from_session(session));
        }
        let session = session_factory.connect_session(config).await?;
        cache.store(fp, session.clone());
        Ok(client_factory.client_from_session(session))
    }

    #[cfg(not(feature = "client-transport"))]
    pub async fn connect_or_reuse(_config: &Config, _cache: &WireSessionCache) -> Result<Self> {
        Ok(Self::default())
    }

    #[cfg(feature = "client-transport")]
    fn from_session(session: ClientTransportSession) -> Self {
        let mut service = Self::default();
        service.wire = ClientWire::from_session(session);
        service
    }

    fn from_stub_wire() -> Self {
        let mut service = Self::default();
        service.wire = ClientWire::from_stub();
        service
    }

    #[cfg(feature = "client-transport")]
    async fn connect_session_with_identity(
        config: &Config,
    ) -> Result<(
        ClientTransportSession,
        Option<Arc<CapturedServerCertIdentity>>,
    )> {
        if matches!(config.client_auth.auth_type, ClientAuthType::Simple) {
            let session = match classify_socket_target(&config.client_addr) {
                SocketTarget::Tcp(target) => endpoint_with_keepalive(target)?.connect().await?,
                SocketTarget::UnixPath(path) => connect_unix_channel(path.to_string()).await?,
                SocketTarget::UnixAbstract(name) => {
                    connect_unix_abstract_channel(name.to_string()).await?
                }
            };
            return Ok((session, None));
        }

        let addr = if config.client_addr.starts_with("http://") {
            format!("https://{}", &config.client_addr[7..])
        } else {
            config.client_addr.clone()
        };

        let endpoint = endpoint_with_keepalive(&addr)?;

        let (session, server_identity) = if config.client_auth.tls_options.skip_verify {
            connect_with_skip_verify(&endpoint, config).await?
        } else {
            connect_with_verified_tls(&endpoint, config).await?
        };

        Ok((session, Self::nonempty_server_identity(server_identity)))
    }

    pub(crate) fn runtime_identity() -> (String, String) {
        let name = crate::utils::proc_fs::proc_sys_kernel_value("hostname")
            .unwrap_or_else(|| "opensnitchd-rs".to_string());

        let version = crate::utils::proc_fs::proc_sys_kernel_value("osrelease")
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

        (name, version)
    }

    pub(crate) fn build_subscribe_config_from_snapshots(
        config: &Config,
        rules: &[WireRule],
        is_firewall_running: bool,
        system_firewall: &Arc<Option<crate::platform::firewall::config::FirewallConfig>>,
    ) -> ClientSubscribeConfig {
        let (name, version) = Self::runtime_identity();

        // Protobuf request messages are owned values. At the gRPC boundary,
        // clone once from Arc snapshots to preserve immutable runtime snapshots.
        // Convert domain FirewallConfig -> WireSysFirewall here at the transport egress boundary.
        ClientSubscribeConfig {
            id: 1,
            name,
            version,
            is_firewall_running,
            config: config.raw_json.clone(),
            log_level: config.log_level,
            rules: rules.to_vec(),
            system_firewall: system_firewall
                .as_ref()
                .as_ref()
                .map(|firewall| WireSysFirewall::from(firewall)),
        }
    }

    pub async fn subscribe(&mut self, cfg: ClientSubscribeConfig) -> Result<ClientSubscribeConfig> {
        self.wire.subscribe(cfg).await
    }

    pub async fn ping(&mut self, req: ClientPingRequest) -> Result<ClientPingReply> {
        self.wire.ping(req).await
    }

    pub async fn ask_rule(&mut self, conn: WireConnection) -> Result<WireRule> {
        self.wire.ask_rule(conn).await
    }

    pub async fn post_alert(&mut self, alert: WireAlert) -> Result<ClientAlertReply> {
        self.wire.post_alert(alert).await
    }

    pub async fn notification_stream_channels(
        &mut self,
    ) -> Result<(
        Box<dyn NotificationInboundPort>,
        mpsc::Sender<WireNotificationReply>,
    )> {
        self.wire.open_notifications().await
    }
}

/// Outbound transport client methods for the `Subscriptions` service hosted by the
/// Python client on the same socket as the client service.  All calls go through
/// `SubscriptionFlow` which owns its own `WireSessionCache` and reconnect loop.
#[cfg(feature = "subscriptions")]
impl ClientService {
    pub async fn subscription_commands_open(
        &mut self,
    ) -> Result<(
        Box<dyn SubscriptionCommandInboundPort>,
        mpsc::Sender<WireSubscriptionCommandAck>,
    )> {
        self.wire.subscription_commands_open().await
    }

    fn subscription_request_from_command(command: SubscriptionCommand) -> WireSubscriptionRequest {
        let operation = match command.operation {
            SubscriptionOperation::List => WireSubscriptionAction::List,
            SubscriptionOperation::Apply => WireSubscriptionAction::Apply,
            SubscriptionOperation::Delete => WireSubscriptionAction::Delete,
            SubscriptionOperation::Refresh => WireSubscriptionAction::Refresh,
            SubscriptionOperation::Deploy => WireSubscriptionAction::Deploy,
            SubscriptionOperation::Unspecified => WireSubscriptionAction::Unspecified,
        };

        WireSubscriptionRequest {
            operation: operation as i32,
            subscriptions: command
                .subscriptions
                .iter()
                .map(wire_subscription_from_record)
                .collect(),
            targets: command.targets,
            force: command.force,
        }
    }

    pub async fn subscription_execute(
        &mut self,
        command: SubscriptionCommand,
    ) -> Result<WireSubscriptionReply> {
        let req = Self::subscription_request_from_command(command);
        self.subscription_list(req).await
    }

    #[cfg(feature = "client-transport")]
    pub async fn subscription_list(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        self.wire.subscription_list(req).await
    }

    #[cfg(not(feature = "client-transport"))]
    pub async fn subscription_list(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        self.wire.subscription_list(req).await
    }

    #[cfg(feature = "client-transport")]
    pub async fn subscription_apply(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        self.wire.subscription_apply(req).await
    }

    #[cfg(not(feature = "client-transport"))]
    pub async fn subscription_apply(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        self.wire.subscription_apply(req).await
    }

    #[cfg(feature = "client-transport")]
    pub async fn subscription_delete(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        self.wire.subscription_delete(req).await
    }

    #[cfg(not(feature = "client-transport"))]
    pub async fn subscription_delete(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        self.wire.subscription_delete(req).await
    }

    #[cfg(feature = "client-transport")]
    pub async fn subscription_refresh(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        self.wire.subscription_refresh(req).await
    }

    #[cfg(not(feature = "client-transport"))]
    pub async fn subscription_refresh(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        self.wire.subscription_refresh(req).await
    }

    #[cfg(feature = "client-transport")]
    pub async fn subscription_deploy(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        self.wire.subscription_deploy(req).await
    }

    #[cfg(not(feature = "client-transport"))]
    pub async fn subscription_deploy(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        self.wire.subscription_deploy(req).await
    }
}

#[cfg(feature = "subscriptions")]
fn wire_subscription_from_record(
    sub: &crate::models::subscription::storage::SubscriptionRecord,
) -> WireSubscription {
    WireSubscription {
        id: sub.id.clone(),
        name: sub.name.clone(),
        url: sub.url.clone(),
        filename: sub.filename.clone(),
        groups: sub.groups.clone(),
        enabled: sub.enabled,
        format: sub.format.clone(),
        interval_seconds: sub.interval_seconds,
        timeout_seconds: sub.timeout_seconds,
        max_bytes: sub.max_bytes,
        node: sub.node.clone(),
        status: match sub.status.as_str() {
            "pending" => 1,
            "ready" => 2,
            "syncing" => 3,
            "error" => 4,
            _ => 0,
        },
        last_updated: sub.last_updated.clone(),
        last_error: sub.last_error.clone(),
        refresh_meta: Some(WireSubscriptionRefreshMetadata {
            next_refresh_after: sub.next_refresh_after,
            consecutive_failures: sub.consecutive_failures,
            etag: sub.etag.clone(),
            last_modified: sub.last_modified.clone(),
        }),
    }
}

impl ClientTransportPort for ClientService {
    type SubscribeConfig = ClientSubscribeConfig;
    type PingRequest = ClientPingRequest;
    type PingReply = ClientPingReply;
    type AskRuleRequest = WireConnection;
    type RuleReply = WireRule;
    type AlertReply = ClientAlertReply;

    fn subscribe<'a>(
        &'a mut self,
        cfg: Self::SubscribeConfig,
    ) -> PortFuture<'a, Self::SubscribeConfig> {
        Box::pin(async move { ClientService::subscribe(self, cfg).await })
    }

    fn ping<'a>(&'a mut self, req: Self::PingRequest) -> PortFuture<'a, Self::PingReply> {
        Box::pin(async move { ClientService::ping(self, req).await })
    }

    fn ask_rule<'a>(&'a mut self, conn: Self::AskRuleRequest) -> PortFuture<'a, Self::RuleReply> {
        Box::pin(async move { ClientService::ask_rule(self, conn).await })
    }

    fn post_alert<'a>(&'a mut self, alert: WireAlert) -> PortFuture<'a, Self::AlertReply> {
        Box::pin(async move { ClientService::post_alert(self, alert).await })
    }
}
