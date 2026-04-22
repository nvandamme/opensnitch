use std::net::IpAddr;
use std::time::Instant;

use tokio::sync::mpsc;
use transport_wire_core::WireNotificationReply;

use super::notification::NotificationFlow;
use crate::{
    config::{Config, DefaultAction},
    models::command_rpc::ClientCommand,
    services::client::{ClientPrincipal, ClientSession, transport::CapturedServerCertIdentity},
    utils::channel_send::send_with_backpressure,
};

#[derive(Debug)]
pub(super) struct ReconnectState {
    pub(super) started_at: Instant,
    pub(super) failures: u64,
    pub(super) last_warn_at: Option<Instant>,
    pub(super) suppressed_warns: u64,
}

impl Default for ReconnectState {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            failures: 0,
            last_warn_at: None,
            suppressed_warns: 0,
        }
    }
}

impl NotificationFlow {
    pub(crate) fn session_binding_from_client_addr(
        client_addr: &str,
        config: &Config,
    ) -> ClientSession {
        Self::session_binding_from_client_addr_and_server_identity(client_addr, config, None)
    }

    pub(crate) fn session_binding_from_client_addr_and_server_identity(
        client_addr: &str,
        config: &Config,
        server_identity: Option<&CapturedServerCertIdentity>,
    ) -> ClientSession {
        if let Some(peer) = Self::try_unix_peer_credentials(client_addr) {
            let bind_local_uid = matches!(config.auth_mode, crate::config::AuthMode::Legacy)
                || Self::unix_principal_allowed(config, peer);
            if bind_local_uid {
                return ClientSession::for_local_uid(peer.uid, DefaultAction::Deny);
            }
        }

        if let Some((uid, _inode)) = Self::try_loopback_tcp_listen_socket(client_addr) {
            let bind_local_uid = matches!(config.auth_mode, crate::config::AuthMode::Legacy)
                || Self::loopback_tcp_principal_allowed(config, client_addr);
            if bind_local_uid {
                return ClientSession::for_local_uid(uid, DefaultAction::Deny);
            }
        }

        if let Some(path) = client_addr.strip_prefix("unix:") {
            return ClientSession::for_network_identity(
                format!("unix:{path}"),
                DefaultAction::Deny,
            );
        }

        if let Some(name) = client_addr.strip_prefix("unix-abstract:") {
            return ClientSession::for_unix_abstract_name(name, DefaultAction::Deny);
        }

        // For remote (non-local) endpoints, prefer live TLS handshake identity when
        // available, and fall back to configured server-cert extraction only when
        // no live identity was supplied.
        if let Some(identity) = server_identity {
            if let Some(resolved) = Self::resolve_remote_principal_binding(
                config,
                identity.fingerprint_sha256.as_deref(),
                identity.subject.as_deref(),
                identity.san_dns.as_deref(),
            ) {
                return resolved;
            }
        } else if let Some(resolved) = Self::try_resolve_remote_principal_from_config(config) {
            return resolved;
        }

        let endpoint = client_addr
            .strip_prefix("http://")
            .or_else(|| client_addr.strip_prefix("https://"))
            .unwrap_or(client_addr)
            .split('/')
            .next()
            .unwrap_or(client_addr);

        let host = if let Some(stripped) = endpoint.strip_prefix('[') {
            stripped.split(']').next().unwrap_or(endpoint)
        } else {
            endpoint
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(endpoint)
        };

        if let Ok(ip) = host.parse::<IpAddr>() {
            return ClientSession::for_ip_fallback(ip, DefaultAction::Deny);
        }

        ClientSession::for_network_identity(host.to_string(), DefaultAction::Deny)
    }

    /// Attempt to resolve a remote principal binding from the configured server cert.
    ///
    /// When TLS is configured with a server cert and `RemotePrincipalBindings` exist,
    /// this extracts the cert identity (fingerprint, subject, SAN) and resolves it
    /// against the bindings to produce a `ClientSession` with capabilities.
    fn try_resolve_remote_principal_from_config(config: &Config) -> Option<ClientSession> {
        use crate::config::ClientAuthType;
        use crate::services::client::transport::extract_identity_from_pem;
        use crate::services::storage::StorageService;

        if config
            .remote_principal_bindings
            .as_ref()
            .is_none_or(|b| b.is_empty())
        {
            return None;
        }

        if !matches!(
            config.client_auth.auth_type,
            ClientAuthType::TlsSimple | ClientAuthType::TlsMutual
        ) {
            return None;
        }

        let server_cert_path = config.client_auth.tls_options.server_cert.trim();
        if server_cert_path.is_empty() {
            return None;
        }

        let pem_bytes = StorageService::global()
            .read_bytes_sync_and_notify(
                "remote-principal-binding",
                std::path::Path::new(server_cert_path),
            )
            .ok()?;

        let identity = extract_identity_from_pem(&pem_bytes)?;

        Self::resolve_remote_principal_binding(
            config,
            identity.fingerprint_sha256.as_deref(),
            identity.subject.as_deref(),
            identity.san_dns.as_deref(),
        )
    }

    pub(super) fn client_origin(owner: &ClientPrincipal) -> String {
        match owner {
            ClientPrincipal::LocalUid(uid) => format!("local-uid:{uid}"),
            ClientPrincipal::UnixAbstractName(name) => {
                format!("unix-abstract:{name}")
            }
            ClientPrincipal::NetworkIdentity(identity) => {
                format!("network:{identity}")
            }
            ClientPrincipal::IpFallback(ip) => format!("ip:{ip}"),
            ClientPrincipal::RemoteCert {
                binding_name,
                mapped_uid,
            } => {
                format!("remote-cert:{binding_name}(uid:{mapped_uid})")
            }
        }
    }

    pub(super) fn connect_owner_bound_session(&self, session_template: &ClientSession) {
        let default_action = self.client_service.connected_default_action();
        let owner = session_template.owner.clone();
        let capabilities = session_template.capabilities.clone();
        match owner {
            ClientPrincipal::LocalUid(uid) => {
                self.client_service
                    .upsert_session(ClientSession::for_local_uid(uid, default_action));
            }
            ClientPrincipal::UnixAbstractName(name) => {
                self.client_service
                    .upsert_session(ClientSession::for_unix_abstract_name(name, default_action));
            }
            ClientPrincipal::NetworkIdentity(identity) => {
                self.client_service
                    .upsert_session(ClientSession::for_network_identity(
                        identity,
                        default_action,
                    ));
            }
            ClientPrincipal::IpFallback(ip) => {
                self.client_service
                    .upsert_session(ClientSession::for_ip_fallback(ip, default_action));
            }
            ClientPrincipal::RemoteCert {
                binding_name,
                mapped_uid,
            } => {
                self.client_service
                    .upsert_session(ClientSession::for_remote_principal(
                        binding_name,
                        mapped_uid,
                        capabilities,
                        default_action,
                    ));
            }
        }
    }

    pub(super) async fn do_reconnect(
        &self,
        task_reply_rx: &mpsc::Receiver<WireNotificationReply>,
        reconnect_state: &mut ReconnectState,
        active_session_id: &mut Option<String>,
        client_id: &str,
        client_origin: &str,
        warning: Option<&str>,
    ) -> bool {
        if let Some(session_id) = active_session_id.take() {
            self.client_service.disconnect_session(&session_id);
        }
        if let Some(msg) = warning {
            reconnect_state.failures = reconnect_state.failures.saturating_add(1);
            let now = Instant::now();
            let should_warn = reconnect_state
                .last_warn_at
                .map(|last| now.duration_since(last) >= Self::RECONNECT_WARN_THROTTLE)
                .unwrap_or(true);
            if should_warn {
                tracing::warn!(
                    client_id,
                    client_origin,
                    attempt = reconnect_state.failures,
                    suppressed = reconnect_state.suppressed_warns,
                    elapsed_secs = reconnect_state.started_at.elapsed().as_secs(),
                    "{msg}; retrying"
                );
                reconnect_state.last_warn_at = Some(now);
                reconnect_state.suppressed_warns = 0;
            } else {
                reconnect_state.suppressed_warns =
                    reconnect_state.suppressed_warns.saturating_add(1);
            }
        }
        if task_reply_rx.is_closed() {
            return true;
        }
        tokio::time::sleep(Self::RECONNECT_DELAY).await;
        false
    }

    pub(super) async fn request_runtime_task_teardown(&self, client_id: &str, client_origin: &str) {
        tracing::info!(
            client_id,
            client_origin,
            "notification flow: requesting temporary runtime task teardown"
        );
        if !send_with_backpressure(&self.bus.client_cmd_tx, ClientCommand::StopRuntimeTasks).await {
            tracing::warn!(
                client_id,
                client_origin,
                "failed to queue temporary task teardown after notification disconnect"
            );
        }
    }
}
