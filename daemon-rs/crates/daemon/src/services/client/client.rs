use anyhow::Result;
use arc_swap::ArcSwap;
use opensnitch_proto::pb;
#[cfg(feature = "subscriptions")]
use pb::subscriptions_client::SubscriptionsClient;
use pb::ui_client::UiClient;
use std::net::IpAddr;
use std::sync::Arc;
#[cfg(feature = "grpc-ui")]
use tonic::codec::CompressionEncoding;
use tonic::transport::Channel;

use super::session::{
    CLIENT_SESSION_ID, ClientPrincipal, ClientSession, ClientSessionSnapshot, SessionState,
};
#[cfg(feature = "grpc-ui")]
use super::transport::{
    CapturedServerCertIdentity, SocketTarget, classify_socket_target,
    connect_unix_abstract_channel, connect_unix_channel, connect_with_skip_verify,
    connect_with_verified_tls, endpoint_with_keepalive,
};
#[cfg(not(feature = "grpc-ui"))]
use super::transport::CapturedServerCertIdentity;
#[cfg(feature = "grpc-ui")]
use crate::config::ClientAuthType;
use crate::config::Config;
#[cfg(feature = "subscriptions")]
use crate::models::subscription_rpc::{SubscriptionCommand, SubscriptionOperation};
#[cfg(feature = "subscriptions")]
use crate::services::subscription::record_to_proto;

/// Shared cache for a gRPC `Channel` keyed on a config fingerprint.
///
/// Reusing an existing channel avoids TCP+TLS handshake overhead on every
/// RPC call. The cache is lock-free (`ArcSwap`) and safe to share across
/// concurrent tasks.
#[derive(Clone)]
pub struct GrpcChannelCache {
    inner: Arc<ArcSwap<Option<CachedChannel>>>,
}

struct CachedChannel {
    fingerprint: u64,
    channel: Channel,
}

impl Default for GrpcChannelCache {
    fn default() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(None)),
        }
    }
}

impl GrpcChannelCache {
    fn fingerprint(config: &Config) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        config.client_addr.hash(&mut h);
        config.client_auth.auth_type.as_name().hash(&mut h);
        h.finish()
    }

    fn load(&self, fp: u64) -> Option<Channel> {
        let guard = self.inner.load();
        guard
            .as_ref()
            .as_ref()
            .filter(|c| c.fingerprint == fp)
            .map(|c| c.channel.clone())
    }

    fn store(&self, fp: u64, channel: Channel) {
        self.inner.store(Arc::new(Some(CachedChannel {
            fingerprint: fp,
            channel,
        })));
    }

    pub fn invalidate(&self) {
        self.inner.store(Arc::new(None));
    }
}

#[derive(Clone)]
pub struct ClientService {
    grpc: Option<UiClient<Channel>>,
    #[cfg(feature = "subscriptions")]
    subscriptions_grpc: Option<SubscriptionsClient<Channel>>,
    session: Arc<SessionState>,
}

// ---------------------------------------------------------------------------
// Session management — delegates to SessionState
// ---------------------------------------------------------------------------

impl Default for ClientService {
    fn default() -> Self {
        Self {
            grpc: None,
            #[cfg(feature = "subscriptions")]
            subscriptions_grpc: None,
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn connect_local_uid_session(&self, uid: u32) {
        let default_action = self.session.snapshot_rx.borrow().connected_default_action;
        self.upsert_session(ClientSession::for_local_uid(uid, default_action));
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn connect_network_identity_session(&self, identity: impl Into<String>) {
        let default_action = self.session.snapshot_rx.borrow().connected_default_action;
        self.upsert_session(ClientSession::for_network_identity(
            identity,
            default_action,
        ));
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn connect_ip_fallback_session(&self, ip: IpAddr) {
        let default_action = self.session.snapshot_rx.borrow().connected_default_action;
        self.upsert_session(ClientSession::for_ip_fallback(ip, default_action));
    }

    pub fn disconnect_session(&self, session_id: &str) {
        self.modify_snapshot(|s| {
            s.sessions.remove(session_id);
        });
    }

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

    #[cfg_attr(not(test), allow(dead_code))]
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

    #[cfg_attr(not(test), allow(dead_code))]
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

    #[cfg_attr(not(test), allow(dead_code))]
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

    #[allow(dead_code)]
    #[cfg(feature = "grpc-ui")]
    pub async fn connect(addr: &str) -> Result<Self> {
        let channel = match classify_socket_target(addr) {
            SocketTarget::Tcp(target) => endpoint_with_keepalive(target)?.connect().await?,
            SocketTarget::UnixPath(path) => connect_unix_channel(path.to_string()).await?,
            SocketTarget::UnixAbstract(name) => {
                connect_unix_abstract_channel(name.to_string()).await?
            }
        };
        Ok(Self::from_channel(channel))
    }

    #[allow(dead_code)]
    #[cfg(not(feature = "grpc-ui"))]
    pub async fn connect(_addr: &str) -> Result<Self> {
        Ok(Self::default())
    }

    #[cfg(feature = "grpc-ui")]
    pub async fn connect_with_config(config: &Config) -> Result<Self> {
        let (service, _) = Self::connect_with_config_and_server_identity(config).await?;
        Ok(service)
    }

    #[cfg(not(feature = "grpc-ui"))]
    pub async fn connect_with_config(_config: &Config) -> Result<Self> {
        Ok(Self::default())
    }

    #[cfg(feature = "grpc-ui")]
    pub async fn connect_with_config_and_server_identity(
        config: &Config,
    ) -> Result<(Self, Option<Arc<CapturedServerCertIdentity>>)> {
        let (channel, server_identity) = Self::connect_channel(config).await?;
        Ok((Self::from_channel(channel), server_identity))
    }

    #[cfg(not(feature = "grpc-ui"))]
    pub async fn connect_with_config_and_server_identity(
        _config: &Config,
    ) -> Result<(Self, Option<Arc<CapturedServerCertIdentity>>)> {
        Ok((Self::default(), None))
    }

    /// Reuse a cached gRPC channel when the config fingerprint matches,
    /// falling back to a fresh connection on cache miss or config change.
    #[cfg(feature = "grpc-ui")]
    pub async fn connect_or_reuse(config: &Config, cache: &GrpcChannelCache) -> Result<Self> {
        let fp = GrpcChannelCache::fingerprint(config);
        if let Some(channel) = cache.load(fp) {
            return Ok(Self::from_channel(channel));
        }
        let (channel, _) = Self::connect_channel(config).await?;
        cache.store(fp, channel.clone());
        Ok(Self::from_channel(channel))
    }

    #[cfg(not(feature = "grpc-ui"))]
    pub async fn connect_or_reuse(_config: &Config, _cache: &GrpcChannelCache) -> Result<Self> {
        Ok(Self::default())
    }

    #[cfg(feature = "grpc-ui")]
    fn from_channel(channel: Channel) -> Self {
        let grpc = UiClient::new(channel.clone());
        #[cfg(feature = "subscriptions")]
        let subscriptions_grpc = SubscriptionsClient::new(channel);
        let mut service = Self::default();
        service.grpc = Some(grpc);
        #[cfg(feature = "subscriptions")]
        {
            service.subscriptions_grpc = Some(subscriptions_grpc);
        }
        service
    }

    #[cfg(feature = "grpc-ui")]
    async fn connect_channel(
        config: &Config,
    ) -> Result<(Channel, Option<Arc<CapturedServerCertIdentity>>)> {
        if matches!(config.client_auth.auth_type, ClientAuthType::Simple) {
            let channel = match classify_socket_target(&config.client_addr) {
                SocketTarget::Tcp(target) => endpoint_with_keepalive(target)?.connect().await?,
                SocketTarget::UnixPath(path) => connect_unix_channel(path.to_string()).await?,
                SocketTarget::UnixAbstract(name) => {
                    connect_unix_abstract_channel(name.to_string()).await?
                }
            };
            return Ok((channel, None));
        }

        let addr = if config.client_addr.starts_with("http://") {
            format!("https://{}", &config.client_addr[7..])
        } else {
            config.client_addr.clone()
        };

        let endpoint = endpoint_with_keepalive(&addr)?;

        let (channel, server_identity) = if config.client_auth.tls_options.skip_verify {
            connect_with_skip_verify(&endpoint, config).await?
        } else {
            connect_with_verified_tls(&endpoint, config).await?
        };

        Ok((channel, Self::nonempty_server_identity(server_identity)))
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
        rules: &Arc<Vec<pb::Rule>>,
        is_firewall_running: bool,
        system_firewall: &Arc<Option<crate::models::firewall_config::FirewallConfig>>,
    ) -> pb::ClientConfig {
        let (name, version) = Self::runtime_identity();

        // Protobuf request messages are owned values. At the gRPC boundary,
        // clone once from Arc snapshots to preserve immutable runtime snapshots.
        // Convert domain FirewallConfig → pb::SysFirewall here at the gRPC egress boundary.
        pb::ClientConfig {
            id: 1,
            name,
            version,
            is_firewall_running,
            config: config.raw_json.clone(),
            log_level: config.log_level,
            rules: rules.as_ref().clone(),
            system_firewall: system_firewall.as_ref().as_ref().map(pb::SysFirewall::from),
        }
    }

    pub async fn subscribe(&mut self, cfg: pb::ClientConfig) -> Result<pb::ClientConfig> {
        #[cfg(not(feature = "grpc-ui"))]
        {
            let _ = cfg;
            anyhow::bail!("grpc-ui feature disabled: subscribe transport is not available")
        }
        #[cfg(feature = "grpc-ui")]
        Ok(self.grpc_mut().subscribe(cfg).await?.into_inner())
    }

    pub async fn ping(&mut self, req: pb::PingRequest) -> Result<pb::PingReply> {
        #[cfg(not(feature = "grpc-ui"))]
        {
            let _ = req;
            anyhow::bail!("grpc-ui feature disabled: ping transport is not available")
        }
        #[cfg(feature = "grpc-ui")]
        Ok(self.grpc_mut().ping(req).await?.into_inner())
    }

    pub async fn ask_rule(&mut self, conn: pb::Connection) -> Result<pb::Rule> {
        #[cfg(not(feature = "grpc-ui"))]
        {
            let _ = conn;
            anyhow::bail!("grpc-ui feature disabled: ask_rule transport is not available")
        }
        #[cfg(feature = "grpc-ui")]
        Ok(self.grpc_mut().ask_rule(conn).await?.into_inner())
    }

    pub async fn post_alert(&mut self, alert: pb::Alert) -> Result<pb::MsgResponse> {
        #[cfg(not(feature = "grpc-ui"))]
        {
            let _ = alert;
            anyhow::bail!("grpc-ui feature disabled: alert transport is not available")
        }
        #[cfg(feature = "grpc-ui")]
        Ok(self
            .grpc_mut()
            .clone()
            .send_compressed(CompressionEncoding::Gzip)
            .post_alert(alert)
            .await?
            .into_inner())
    }

    #[cfg(feature = "grpc-ui")]
    pub fn grpc_mut(&mut self) -> &mut UiClient<Channel> {
        self.grpc
            .as_mut()
            .expect("ClientService transport not initialized; connect first")
    }
}

/// Outbound gRPC client methods for the `Subscriptions` service hosted by the
/// Python UI on the same socket as the UI service.  All calls go through
/// `SubscriptionFlow` which owns its own `GrpcChannelCache` and reconnect loop.
#[cfg(feature = "subscriptions")]
impl ClientService {
    fn subscription_request_from_command(command: SubscriptionCommand) -> pb::SubscriptionRequest {
        let operation = match command.operation {
            SubscriptionOperation::List => pb::SubscriptionAction::List,
            SubscriptionOperation::Apply => pb::SubscriptionAction::Apply,
            SubscriptionOperation::Delete => pb::SubscriptionAction::Delete,
            SubscriptionOperation::Refresh => pb::SubscriptionAction::Refresh,
            SubscriptionOperation::Deploy => pb::SubscriptionAction::Deploy,
            SubscriptionOperation::Unspecified => pb::SubscriptionAction::Unspecified,
        };

        pb::SubscriptionRequest {
            operation: operation as i32,
            subscriptions: command
                .subscriptions
                .iter()
                .map(record_to_proto)
                .collect(),
            targets: command.targets,
            force: command.force,
        }
    }

    pub async fn subscription_execute(
        &mut self,
        command: SubscriptionCommand,
    ) -> Result<pb::SubscriptionReply> {
        let req = Self::subscription_request_from_command(command);
        self.subscription_list(req).await
    }

    #[cfg(feature = "grpc-ui")]
    pub async fn subscription_list(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self.subscriptions_grpc_mut().list(req).await?.into_inner())
    }

    #[cfg(not(feature = "grpc-ui"))]
    pub async fn subscription_list(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        let _ = req;
        anyhow::bail!("grpc-ui feature disabled: subscriptions transport is not available")
    }

    #[cfg(feature = "grpc-ui")]
    pub async fn subscription_apply(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self.subscriptions_grpc_mut().apply(req).await?.into_inner())
    }

    #[cfg(not(feature = "grpc-ui"))]
    pub async fn subscription_apply(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        let _ = req;
        anyhow::bail!("grpc-ui feature disabled: subscriptions transport is not available")
    }

    #[cfg(feature = "grpc-ui")]
    pub async fn subscription_delete(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc_mut()
            .delete(req)
            .await?
            .into_inner())
    }

    #[cfg(not(feature = "grpc-ui"))]
    pub async fn subscription_delete(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        let _ = req;
        anyhow::bail!("grpc-ui feature disabled: subscriptions transport is not available")
    }

    #[cfg(feature = "grpc-ui")]
    pub async fn subscription_refresh(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc_mut()
            .refresh(req)
            .await?
            .into_inner())
    }

    #[cfg(not(feature = "grpc-ui"))]
    pub async fn subscription_refresh(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        let _ = req;
        anyhow::bail!("grpc-ui feature disabled: subscriptions transport is not available")
    }

    #[cfg(feature = "grpc-ui")]
    pub async fn subscription_deploy(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc_mut()
            .deploy(req)
            .await?
            .into_inner())
    }

    #[cfg(not(feature = "grpc-ui"))]
    pub async fn subscription_deploy(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        let _ = req;
        anyhow::bail!("grpc-ui feature disabled: subscriptions transport is not available")
    }

    #[cfg(feature = "grpc-ui")]
    pub async fn subscription_commands(
        &mut self,
        acks: impl tonic::IntoStreamingRequest<Message = pb::SubscriptionCommandAck>,
    ) -> Result<tonic::Streaming<pb::SubscriptionCommand>> {
        Ok(self
            .subscriptions_grpc_mut()
            .commands(acks)
            .await?
            .into_inner())
    }

    #[cfg(not(feature = "grpc-ui"))]
    pub async fn subscription_commands(
        &mut self,
        acks: impl tonic::IntoStreamingRequest<Message = pb::SubscriptionCommandAck>,
    ) -> Result<tonic::Streaming<pb::SubscriptionCommand>> {
        let _ = acks;
        anyhow::bail!("grpc-ui feature disabled: subscriptions transport is not available")
    }

    #[cfg(feature = "grpc-ui")]
    fn subscriptions_grpc_mut(&mut self) -> &mut SubscriptionsClient<Channel> {
        self.subscriptions_grpc
            .as_mut()
            .expect("ClientService transport not initialized; connect first")
    }
}
