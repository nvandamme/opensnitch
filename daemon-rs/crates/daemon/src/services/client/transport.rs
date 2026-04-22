// Transport boundary facade: adapter/protocol internals live in
// opensnitch-transport-wire-grpc-client.
#![cfg_attr(not(feature = "client-transport"), allow(dead_code))]

#[cfg(feature = "client-transport")]
use anyhow::Result;
#[cfg(feature = "client-transport")]
use tokio::sync::mpsc;
#[cfg(feature = "client-transport")]
use transport_wire_core::NotificationInboundPort;
#[cfg(all(feature = "subscriptions", feature = "client-transport"))]
use transport_wire_core::SubscriptionCommandInboundPort;
#[cfg(feature = "client-transport")]
use transport_wire_core::{
    WireAlert, WireConnection, WireNotificationReply, WirePingRequest as TransportWirePingRequest,
    WireSubscribeConfig as TransportWireSubscribeConfig,
};
use transport_wire_core::{WireRule, WireStatistics, WireSysFirewall};
#[cfg(all(feature = "subscriptions", feature = "client-transport"))]
use transport_wire_core::{
    WireSubscriptionCommandAck, WireSubscriptionReply, WireSubscriptionRequest,
};
#[cfg(feature = "client-transport")]
use transport_wire_grpc_client;
#[cfg(feature = "client-transport")]
use transport_wire_grpc_client::{
    WireEndpoint as Endpoint, WireTlsClientIdentityPem, WireTlsConfig,
};

#[cfg(feature = "client-transport")]
use crate::config::{ClientAuthType, Config};
#[cfg(feature = "client-transport")]
use crate::services::storage::StorageService;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClientPingRequest {
    pub(crate) id: u64,
    pub(crate) stats: Option<WireStatistics>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientPingReply {
    pub(crate) id: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClientSubscribeConfig {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) is_firewall_running: bool,
    pub(crate) config: String,
    pub(crate) log_level: u32,
    pub(crate) rules: Vec<WireRule>,
    pub(crate) system_firewall: Option<WireSysFirewall>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientAlertReply {
    pub(crate) id: u64,
}

#[cfg(feature = "client-transport")]
pub(super) use transport_wire_grpc_client::{
    WireSession as ClientTransportSession, WireSocketTarget as SocketTarget,
    wire_classify_socket_target as classify_socket_target,
    wire_connect_unix_abstract_session as connect_unix_abstract_channel,
    wire_connect_unix_session as connect_unix_channel,
    wire_endpoint_with_keepalive as endpoint_with_keepalive,
};

#[cfg(feature = "client-transport")]
pub(crate) use transport_wire_grpc_client::{
    WireServerCertIdentity as CapturedServerCertIdentity,
    wire_extract_identity_from_pem as extract_identity_from_pem,
};

#[cfg(feature = "client-transport")]
#[derive(Clone)]
pub(super) struct TransportRuntimeClient {
    inner: transport_wire_grpc_client::WireClient,
}

#[cfg(feature = "client-transport")]
impl TransportRuntimeClient {
    pub(super) fn from_session(session: ClientTransportSession) -> Self {
        Self {
            inner: transport_wire_grpc_client::WireClient::from_session(session),
        }
    }

    pub(super) async fn subscribe(
        &mut self,
        cfg: ClientSubscribeConfig,
    ) -> Result<ClientSubscribeConfig> {
        let req = TransportWireSubscribeConfig {
            id: cfg.id,
            name: cfg.name,
            version: cfg.version,
            is_firewall_running: cfg.is_firewall_running,
            config: cfg.config,
            log_level: cfg.log_level,
            rules: cfg.rules.into_iter().map(Into::into).collect(),
            system_firewall: cfg.system_firewall,
        };
        let reply = self.inner.subscribe(req).await?;
        Ok(ClientSubscribeConfig {
            id: reply.id,
            name: reply.name,
            version: reply.version,
            is_firewall_running: reply.is_firewall_running,
            config: reply.config,
            log_level: reply.log_level,
            rules: reply.rules.into_iter().map(Into::into).collect(),
            system_firewall: reply.system_firewall,
        })
    }

    pub(super) async fn ping(&mut self, req: ClientPingRequest) -> Result<ClientPingReply> {
        let reply = self
            .inner
            .ping(TransportWirePingRequest {
                id: req.id,
                stats: req.stats.map(Into::into),
            })
            .await?;
        Ok(ClientPingReply { id: reply.id })
    }

    pub(super) async fn ask_rule(&mut self, conn: WireConnection) -> Result<WireRule> {
        Ok(self.inner.ask_rule(conn).await?)
    }

    pub(super) async fn post_alert(&mut self, alert: WireAlert) -> Result<ClientAlertReply> {
        let reply = self.inner.post_alert(alert).await?;
        Ok(ClientAlertReply { id: reply.id })
    }

    pub(super) async fn open_notifications(
        &mut self,
    ) -> Result<(
        Box<dyn NotificationInboundPort>,
        mpsc::Sender<WireNotificationReply>,
    )> {
        Ok(self.inner.open_notifications().await?)
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_commands_open(
        &mut self,
    ) -> Result<(
        Box<dyn SubscriptionCommandInboundPort>,
        mpsc::Sender<WireSubscriptionCommandAck>,
    )> {
        Ok(self.inner.subscription_commands_open().await?)
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_list(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        Ok(self.inner.subscription_list(req).await?)
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_apply(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        Ok(self.inner.subscription_apply(req).await?)
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_delete(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        Ok(self.inner.subscription_delete(req).await?)
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_refresh(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        Ok(self.inner.subscription_refresh(req).await?)
    }

    #[cfg(feature = "subscriptions")]
    pub(super) async fn subscription_deploy(
        &mut self,
        req: WireSubscriptionRequest,
    ) -> Result<WireSubscriptionReply> {
        Ok(self.inner.subscription_deploy(req).await?)
    }
}

#[cfg(not(feature = "client-transport"))]
pub(super) type ClientTransportSession = ();

#[cfg(not(feature = "client-transport"))]
#[derive(Clone, Debug, Default)]
pub(crate) struct CapturedServerCertIdentity {
    pub(crate) fingerprint_sha256: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) san_dns: Option<String>,
}

#[cfg(not(feature = "client-transport"))]
pub(crate) fn extract_identity_from_pem(pem_bytes: &[u8]) -> Option<CapturedServerCertIdentity> {
    let _ = pem_bytes;
    None
}

#[cfg(feature = "client-transport")]
pub(super) async fn connect_with_skip_verify(
    endpoint: &Endpoint,
    config: &Config,
) -> Result<(
    ClientTransportSession,
    std::sync::Arc<CapturedServerCertIdentity>,
)> {
    let tls = WireTlsConfig {
        skip_verify: true,
        trust_root_pem: read_trust_root_pem(config)?,
        client_identity: load_client_identity_material(config)?,
    };

    let (session, identity) =
        transport_wire_grpc_client::wire_connect_tls_session(endpoint, &tls).await?;
    Ok((session, std::sync::Arc::new(identity)))
}

#[cfg(feature = "client-transport")]
pub(super) async fn connect_with_verified_tls(
    endpoint: &Endpoint,
    config: &Config,
) -> Result<(
    ClientTransportSession,
    std::sync::Arc<CapturedServerCertIdentity>,
)> {
    let tls = WireTlsConfig {
        skip_verify: false,
        trust_root_pem: read_trust_root_pem(config)?,
        client_identity: load_client_identity_material(config)?,
    };

    let (session, identity) =
        transport_wire_grpc_client::wire_connect_tls_session(endpoint, &tls).await?;
    Ok((session, std::sync::Arc::new(identity)))
}

#[cfg(feature = "client-transport")]
fn read_trust_root_pem(config: &Config) -> Result<Vec<u8>> {
    let tls_opts = &config.client_auth.tls_options;
    let mut root_pem = Vec::<u8>::new();
    if !tls_opts.ca_cert.trim().is_empty() {
        match StorageService::global()
            .read_bytes_sync_and_notify("client", std::path::Path::new(tls_opts.ca_cert.trim()))
        {
            Ok(raw) => root_pem.extend(raw),
            Err(err) => tracing::warn!(
                "reading client auth CA certificate ({}): {err}",
                config.client_auth.auth_type.as_name()
            ),
        }
    }
    if !tls_opts.server_cert.trim().is_empty() {
        match StorageService::global()
            .read_bytes_sync_and_notify("client", std::path::Path::new(tls_opts.server_cert.trim()))
        {
            Ok(raw) => root_pem.extend(raw),
            Err(err) => tracing::warn!(
                "reading client auth server cert ({}): {err}",
                config.client_auth.auth_type.as_name()
            ),
        }
    }

    if root_pem.is_empty() {
        anyhow::bail!(
            "client auth {} requires explicit trust material: set TLSOptions.CACert or TLSOptions.ServerCert (self-signed certs are supported when provided here)",
            config.client_auth.auth_type.as_name()
        );
    }

    Ok(root_pem)
}

#[cfg(feature = "client-transport")]
fn load_client_identity_material(config: &Config) -> Result<Option<WireTlsClientIdentityPem>> {
    let tls_opts = &config.client_auth.tls_options;
    if !matches!(config.client_auth.auth_type, ClientAuthType::TlsMutual) {
        return Ok(None);
    }

    let cert_pem = StorageService::global()
        .read_bytes_sync_and_notify("client", std::path::Path::new(tls_opts.client_cert.trim()))?;
    let key_pem = StorageService::global()
        .read_bytes_sync_and_notify("client", std::path::Path::new(tls_opts.client_key.trim()))?;

    Ok(Some(WireTlsClientIdentityPem { cert_pem, key_pem }))
}
