use anyhow::Result;
use opensnitch_proto::pb;
use pb::subscriptions_client::SubscriptionsClient;
use pb::ui_client::UiClient;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tonic::codec::CompressionEncoding;
use tonic::transport::Channel;

use super::transport::{
    SocketTarget, build_tls_config, classify_socket_target, connect_unix_abstract_channel,
    connect_unix_channel, connect_with_skip_verify, endpoint_with_keepalive,
};
use crate::config::{ClientAuthType, Config};

#[derive(Clone)]
pub struct ClientService {
    grpc: Option<UiClient<Channel>>,
    subscriptions_grpc: Option<SubscriptionsClient<Channel>>,
    snapshot_tx: watch::Sender<Arc<ClientSessionSnapshot>>,
    snapshot_rx: watch::Receiver<Arc<ClientSessionSnapshot>>,
}

impl From<ClientPrincipal> for crate::models::policy_tx::PolicyOwner {
    fn from(value: ClientPrincipal) -> Self {
        match value {
            ClientPrincipal::LocalUid(uid) => Self::LocalUid(uid),
            ClientPrincipal::UnixAbstractName(name) => Self::UnixAbstractName(name),
            ClientPrincipal::NetworkIdentity(identity) => Self::NetworkIdentity(identity),
            ClientPrincipal::IpFallback(ip) => Self::IpFallback(ip.to_string()),
        }
    }
}

const CONTROL_SESSION_ID: &str = "control-plane";

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClientPrincipal {
    LocalUid(u32),
    UnixAbstractName(String),
    NetworkIdentity(String),
    IpFallback(IpAddr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSession {
    pub id: String,
    pub owner: ClientPrincipal,
    pub default_action: crate::config::DefaultAction,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ClientSession {
    pub fn for_local_uid(
        uid: u32,
        default_action: crate::config::DefaultAction,
    ) -> Self {
        Self {
            id: format!("uid:{uid}"),
            owner: ClientPrincipal::LocalUid(uid),
            default_action,
        }
    }

    pub fn for_network_identity(
        identity: impl Into<String>,
        default_action: crate::config::DefaultAction,
    ) -> Self {
        let identity = identity.into();
        Self {
            id: format!("net:{identity}"),
            owner: ClientPrincipal::NetworkIdentity(identity),
            default_action,
        }
    }

    pub fn for_unix_abstract_name(
        name: impl Into<String>,
        default_action: crate::config::DefaultAction,
    ) -> Self {
        let name = name.into();
        Self {
            id: format!("abs:{name}"),
            owner: ClientPrincipal::UnixAbstractName(name),
            default_action,
        }
    }

    pub fn for_ip_fallback(
        ip: IpAddr,
        default_action: crate::config::DefaultAction,
    ) -> Self {
        Self {
            id: format!("ip:{ip}"),
            owner: ClientPrincipal::IpFallback(ip),
            default_action,
        }
    }
}

#[derive(Clone)]
struct ClientSessionSnapshot {
    sessions: BTreeMap<String, ClientSession>,
    connected_default_action: crate::config::DefaultAction,
}

impl Default for ClientService {
    fn default() -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(Arc::new(ClientSessionSnapshot {
            sessions: BTreeMap::new(),
            connected_default_action: crate::config::DefaultAction::Deny,
        }));
        Self {
            grpc: None,
            subscriptions_grpc: None,
            snapshot_tx,
            snapshot_rx,
        }
    }
}

impl ClientService {
    fn principal_rank(owner: &ClientPrincipal) -> u8 {
        match owner {
            ClientPrincipal::LocalUid(_) => 0,
            ClientPrincipal::UnixAbstractName(_) => 1,
            ClientPrincipal::NetworkIdentity(_) => 2,
            ClientPrincipal::IpFallback(_) => 3,
        }
    }

    fn publish_snapshot(&self, next: ClientSessionSnapshot) {
        let _ = self.snapshot_tx.send_replace(Arc::new(next));
    }

    pub fn upsert_session(&self, session: ClientSession) {
        let (mut sessions, connected_default_action) = {
            let snapshot = self.snapshot_rx.borrow();
            (snapshot.sessions.clone(), snapshot.connected_default_action)
        };
        sessions.insert(session.id.clone(), session);
        let next = ClientSessionSnapshot {
            sessions,
            connected_default_action,
        };
        self.publish_snapshot(next);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn connect_session(&self, session_id: impl Into<String>) {
        let session_id = session_id.into();
        let default_action = self.snapshot_rx.borrow().connected_default_action;
        self.upsert_session(ClientSession {
            id: session_id,
            owner: ClientPrincipal::NetworkIdentity("legacy-session".to_string()),
            default_action,
        });
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn connect_local_uid_session(&self, uid: u32) {
        let default_action = self.snapshot_rx.borrow().connected_default_action;
        self.upsert_session(ClientSession::for_local_uid(uid, default_action));
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn connect_network_identity_session(&self, identity: impl Into<String>) {
        let default_action = self.snapshot_rx.borrow().connected_default_action;
        self.upsert_session(ClientSession::for_network_identity(identity, default_action));
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn connect_ip_fallback_session(&self, ip: IpAddr) {
        let default_action = self.snapshot_rx.borrow().connected_default_action;
        self.upsert_session(ClientSession::for_ip_fallback(ip, default_action));
    }

    pub fn disconnect_session(&self, session_id: &str) {
        let (mut sessions, connected_default_action) = {
            let snapshot = self.snapshot_rx.borrow();
            (snapshot.sessions.clone(), snapshot.connected_default_action)
        };
        sessions.remove(session_id);
        let next = ClientSessionSnapshot {
            sessions,
            connected_default_action,
        };
        self.publish_snapshot(next);
    }

    pub fn connected_sessions(&self) -> Vec<ClientSession> {
        self.snapshot_rx
            .borrow()
            .sessions
            .values()
            .cloned()
            .collect()
    }

    pub fn primary_owner(&self) -> Option<ClientPrincipal> {
        let snapshot = self.snapshot_rx.borrow();
        if let Some(control_session) = snapshot.sessions.get(CONTROL_SESSION_ID) {
            return Some(control_session.owner.clone());
        }
        snapshot
            .sessions
            .values()
            .min_by(|left, right| {
                let left_rank = Self::principal_rank(&left.owner);
                let right_rank = Self::principal_rank(&right.owner);
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
        let (mut sessions, connected_default_action) = {
            let snapshot = self.snapshot_rx.borrow();
            (snapshot.sessions.clone(), snapshot.connected_default_action)
        };
        if let Some(session) = sessions.get_mut(session_id) {
            session.default_action = action;
        }
        let next = ClientSessionSnapshot {
            sessions,
            connected_default_action,
        };
        self.publish_snapshot(next);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn set_connected(&self, connected: bool) {
        if connected {
            let default_action = self.snapshot_rx.borrow().connected_default_action;
            self.upsert_session(ClientSession {
                id: CONTROL_SESSION_ID.to_string(),
                owner: ClientPrincipal::NetworkIdentity(CONTROL_SESSION_ID.to_string()),
                default_action,
            });
        } else {
            self.disconnect_session(CONTROL_SESSION_ID);
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_connected(&self) -> bool {
        !self.snapshot_rx.borrow().sessions.is_empty()
    }

    pub fn set_connected_default_action(&self, action: crate::config::DefaultAction) {
        let mut sessions = {
            let snapshot = self.snapshot_rx.borrow();
            snapshot.sessions.clone()
        };
        if let Some(control_session) = sessions.get_mut(CONTROL_SESSION_ID) {
            control_session.default_action = action;
        }
        let next = ClientSessionSnapshot {
            sessions,
            connected_default_action: action,
        };
        self.publish_snapshot(next);
    }

    pub fn connected_default_action(&self) -> crate::config::DefaultAction {
        self.snapshot_rx.borrow().connected_default_action
    }

    pub fn effective_default_action(
        &self,
        disconnected_default_action: crate::config::DefaultAction,
    ) -> crate::config::DefaultAction {
        let snapshot = self.snapshot_rx.borrow();
        if let Some(control_session) = snapshot.sessions.get(CONTROL_SESSION_ID) {
            return control_session.default_action;
        }

        snapshot
            .sessions
            .values()
            .min_by(|left, right| {
                let left_rank = Self::principal_rank(&left.owner);
                let right_rank = Self::principal_rank(&right.owner);
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

impl ClientService {
    pub async fn connect(addr: &str) -> Result<Self> {
        let channel = match classify_socket_target(addr) {
            SocketTarget::Tcp(target) => endpoint_with_keepalive(target)?.connect().await?,
            SocketTarget::UnixPath(path) => connect_unix_channel(path.to_string()).await?,
            SocketTarget::UnixAbstract(name) => {
                connect_unix_abstract_channel(name.to_string()).await?
            }
        };
        let grpc = UiClient::new(channel.clone());
        let subscriptions_grpc = SubscriptionsClient::new(channel);
        let mut service = Self::default();
        service.grpc = Some(grpc);
        service.subscriptions_grpc = Some(subscriptions_grpc);
        Ok(service)
    }

    pub async fn connect_with_config(config: &Config) -> Result<Self> {
        if matches!(config.client_auth.auth_type, ClientAuthType::Simple) {
            return Self::connect(&config.client_addr).await;
        }

        let addr = if config.client_addr.starts_with("http://") {
            format!("https://{}", &config.client_addr[7..])
        } else {
            config.client_addr.clone()
        };

        let endpoint = endpoint_with_keepalive(&addr)?;

        let channel = if config.client_auth.tls_options.skip_verify {
            connect_with_skip_verify(&endpoint, config).await?
        } else {
            endpoint
                .clone()
                .tls_config(build_tls_config(config)?)?
                .connect()
                .await?
        };

        let grpc = UiClient::new(channel.clone());
        let subscriptions_grpc = SubscriptionsClient::new(channel);
        let mut service = Self::default();
        service.grpc = Some(grpc);
        service.subscriptions_grpc = Some(subscriptions_grpc);
        Ok(service)
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
        system_firewall: &Arc<Option<pb::SysFirewall>>,
    ) -> pb::ClientConfig {
        let (name, version) = Self::runtime_identity();

        // Protobuf request messages are owned values. At the gRPC boundary,
        // clone once from Arc snapshots to preserve immutable runtime snapshots.
        pb::ClientConfig {
            id: 1,
            name,
            version,
            is_firewall_running,
            config: config.raw_json.clone(),
            log_level: config.log_level,
            rules: rules.as_ref().clone(),
            system_firewall: system_firewall.as_ref().clone(),
        }
    }


    pub async fn subscribe(&mut self, cfg: pb::ClientConfig) -> Result<pb::ClientConfig> {
        Ok(self.grpc_mut().subscribe(cfg).await?.into_inner())
    }

    pub async fn ping(&mut self, req: pb::PingRequest) -> Result<pb::PingReply> {
        Ok(self.grpc_mut().ping(req).await?.into_inner())
    }

    pub async fn ask_rule(&mut self, conn: pb::Connection) -> Result<pb::Rule> {
        Ok(self.grpc_mut().ask_rule(conn).await?.into_inner())
    }

    pub async fn post_alert(&mut self, alert: pb::Alert) -> Result<pb::MsgResponse> {
        Ok(self
            .grpc_mut()
            .clone()
            .send_compressed(CompressionEncoding::Gzip)
            .post_alert(alert)
            .await?
            .into_inner())
    }

    pub async fn subscription_command(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc_mut()
            .command(req)
            .await?
            .into_inner())
    }

    pub async fn subscription_list(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc_mut()
            .list(req)
            .await?
            .into_inner())
    }

    pub async fn subscription_apply(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc_mut()
            .apply(req)
            .await?
            .into_inner())
    }

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

    pub fn grpc_mut(&mut self) -> &mut UiClient<Channel> {
        self.grpc
            .as_mut()
            .expect("ClientService transport not initialized; connect first")
    }

    fn subscriptions_grpc_mut(&mut self) -> &mut SubscriptionsClient<Channel> {
        self.subscriptions_grpc
            .as_mut()
            .expect("ClientService transport not initialized; connect first")
    }
}
