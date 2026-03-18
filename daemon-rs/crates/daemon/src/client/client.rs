use anyhow::Result;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::rt::TokioIo;
use opensnitch_proto::pb;
use pb::ui_client::UiClient;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, SignatureScheme};
use std::{os::fd::AsRawFd, sync::Arc, time::Duration};
use tokio::net::UnixStream;
use tonic::codec::CompressionEncoding;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Uri};
use tower::service_fn;

use crate::config::{ClientAuthType, Config};

#[derive(Clone)]
pub struct Client {
    grpc: UiClient<Channel>,
}

enum SocketTarget<'a> {
    Tcp(&'a str),
    UnixPath(&'a str),
    UnixAbstract(&'a str),
}

fn classify_socket_target(addr: &str) -> SocketTarget<'_> {
    if let Some(path) = addr.strip_prefix("unix:") {
        return SocketTarget::UnixPath(path);
    }
    if let Some(name) = addr.strip_prefix("unix-abstract:") {
        return SocketTarget::UnixAbstract(name);
    }
    SocketTarget::Tcp(addr)
}

fn endpoint_with_keepalive(addr: &str) -> Result<Endpoint> {
    Ok(Endpoint::from_shared(addr.to_string())?
        .http2_keep_alive_interval(Duration::from_secs(5))
        .keep_alive_timeout(Duration::from_secs(22))
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(Duration::from_secs(20))))
}

async fn connect_unix_channel(path: String) -> Result<Channel> {
    let endpoint = Endpoint::try_from("http://[::]:50051")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await?;
    Ok(channel)
}

async fn connect_abstract_unix_stream(name: String) -> std::io::Result<TokioIo<UnixStream>> {
    let std_stream =
        tokio::task::spawn_blocking(move || -> std::io::Result<std::os::unix::net::UnixStream> {
            let fd = nix::sys::socket::socket(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::Stream,
                nix::sys::socket::SockFlag::SOCK_CLOEXEC,
                None,
            )
            .map_err(|err| std::io::Error::other(err.to_string()))?;
            let addr = nix::sys::socket::UnixAddr::new_abstract(name.as_bytes())
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            nix::sys::socket::connect(fd.as_raw_fd(), &addr)
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            Ok(std::os::unix::net::UnixStream::from(fd))
        })
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))??;

    std_stream.set_nonblocking(true)?;
    UnixStream::from_std(std_stream).map(TokioIo::new)
}

async fn connect_unix_abstract_channel(name: String) -> Result<Channel> {
    let endpoint = Endpoint::try_from("http://[::]:50051")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let name = name.clone();
            async move { connect_abstract_unix_stream(name).await }
        }))
        .await?;
    Ok(channel)
}

impl Client {
    pub async fn connect(addr: &str) -> Result<Self> {
        let channel = match classify_socket_target(addr) {
            SocketTarget::Tcp(target) => endpoint_with_keepalive(target)?.connect().await?,
            SocketTarget::UnixPath(path) => connect_unix_channel(path.to_string()).await?,
            SocketTarget::UnixAbstract(name) => {
                connect_unix_abstract_channel(name.to_string()).await?
            }
        };
        let grpc = UiClient::new(channel);
        Ok(Self { grpc })
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
            Self::connect_with_skip_verify(&endpoint, config).await?
        } else {
            endpoint
                .clone()
                .tls_config(Self::build_tls_config(config)?)?
                .connect()
                .await?
        };

        let grpc = UiClient::new(channel);
        Ok(Self { grpc })
    }

    async fn connect_with_skip_verify(endpoint: &Endpoint, config: &Config) -> Result<Channel> {
        tracing::warn!(
            "UI auth SkipVerify=true: certificate verification is disabled for this UI channel"
        );

        let tls_opts = &config.client_auth.tls_options;
        let mut rustls = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        if matches!(config.client_auth.auth_type, ClientAuthType::TlsMutual)
            && !tls_opts.client_cert.trim().is_empty()
            && !tls_opts.client_key.trim().is_empty()
        {
            let cert_raw = std::fs::read(tls_opts.client_cert.trim())?;
            let key_raw = std::fs::read(tls_opts.client_key.trim())?;
            let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(cert_raw))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key_raw))?
                .ok_or_else(|| anyhow::anyhow!("missing private key in {}", tls_opts.client_key))?;
            rustls = RustlsClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_client_auth_cert(certs, key)?;
        }

        rustls.alpn_protocols = vec![b"h2".to_vec()];

        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(rustls)
            .https_or_http()
            .enable_all_versions()
            .build();

        Ok(endpoint.clone().connect_with_connector(connector).await?)
    }

    fn build_tls_config(config: &Config) -> Result<ClientTlsConfig> {
        let tls_opts = &config.client_auth.tls_options;
        let mut tls = ClientTlsConfig::new();

        let mut root_pem = Vec::<u8>::new();
        if !tls_opts.ca_cert.trim().is_empty() {
            match std::fs::read(tls_opts.ca_cert.trim()) {
                Ok(raw) => root_pem.extend(raw),
                Err(err) => tracing::warn!(
                    "reading UI auth CA certificate ({}): {err}",
                    config.client_auth.auth_type.as_name()
                ),
            }
        }
        if !tls_opts.server_cert.trim().is_empty() {
            match std::fs::read(tls_opts.server_cert.trim()) {
                Ok(raw) => root_pem.extend(raw),
                Err(err) => tracing::warn!(
                    "reading UI auth server cert ({}): {err}",
                    config.client_auth.auth_type.as_name()
                ),
            }
        }

        if !root_pem.is_empty() {
            tls = tls.ca_certificate(Certificate::from_pem(root_pem));
        }

        if matches!(config.client_auth.auth_type, ClientAuthType::TlsMutual) {
            let cert = std::fs::read(tls_opts.client_cert.trim())?;
            let key = std::fs::read(tls_opts.client_key.trim())?;
            tls = tls.identity(Identity::from_pem(cert, key));
        }

        Ok(tls)
    }

    #[cfg(test)]
    pub(crate) fn with_grpc(grpc: UiClient<Channel>) -> Self {
        Self { grpc }
    }

    pub(crate) fn runtime_identity() -> (String, String) {
        let name = Self::read_text_file_trimmed("/proc/sys/kernel/hostname")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "opensnitchd-rs".to_string());

        let version = Self::read_text_file_trimmed("/proc/sys/kernel/osrelease")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

        (name, version)
    }

    fn read_text_file_trimmed(path: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()
            .map(|value| value.trim().to_string())
    }

    pub fn build_subscribe_config(
        &self,
        config: &Config,
        rules: Vec<pb::Rule>,
        is_firewall_running: bool,
        system_firewall: Option<pb::SysFirewall>,
    ) -> pb::ClientConfig {
        let (name, version) = Self::runtime_identity();

        pb::ClientConfig {
            id: 1,
            name,
            version,
            is_firewall_running,
            config: config.raw_json.clone(),
            log_level: config.log_level,
            rules,
            system_firewall,
        }
    }

    pub async fn subscribe(&mut self, cfg: pb::ClientConfig) -> Result<pb::ClientConfig> {
        Ok(self.grpc.subscribe(cfg).await?.into_inner())
    }

    pub async fn ping(&mut self, req: pb::PingRequest) -> Result<pb::PingReply> {
        Ok(self.grpc.ping(req).await?.into_inner())
    }

    pub async fn ask_rule(&mut self, conn: pb::Connection) -> Result<pb::Rule> {
        Ok(self.grpc.ask_rule(conn).await?.into_inner())
    }

    pub async fn post_alert(&mut self, alert: pb::Alert) -> Result<pb::MsgResponse> {
        Ok(self
            .grpc
            .clone()
            .send_compressed(CompressionEncoding::Gzip)
            .post_alert(alert)
            .await?
            .into_inner())
    }

    pub fn grpc_mut(&mut self) -> &mut UiClient<Channel> {
        &mut self.grpc
    }
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
