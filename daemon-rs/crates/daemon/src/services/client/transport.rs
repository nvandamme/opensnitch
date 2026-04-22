use anyhow::Result;
#[cfg(feature = "grpc-ui")]
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::rt::TokioIo;
#[cfg(feature = "grpc-ui")]
use rustls::client::{WebPkiServerVerifier, danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier}};
#[cfg(feature = "grpc-ui")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
#[cfg(feature = "grpc-ui")]
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
#[cfg(feature = "grpc-ui")]
use rustls_pki_types::pem::PemObject;
#[cfg(feature = "grpc-ui")]
use sha2::{Digest as _, Sha256};
use std::path::Path;
use std::{os::fd::AsRawFd, sync::Arc, time::Duration};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
#[cfg(feature = "grpc-ui")]
use x509_cert::der::{Decode as _, oid::AssociatedOid as _};

#[cfg(feature = "grpc-ui")]
use crate::config::{ClientAuthType, Config};
#[cfg(feature = "grpc-ui")]
use crate::services::storage::StorageService;

pub(super) enum SocketTarget<'a> {
    Tcp(&'a str),
    UnixPath(&'a str),
    UnixAbstract(&'a str),
}

pub(super) fn classify_socket_target(addr: &str) -> SocketTarget<'_> {
    if let Some(path) = addr.strip_prefix("unix:") {
        return SocketTarget::UnixPath(path);
    }
    if let Some(name) = addr.strip_prefix("unix-abstract:") {
        return SocketTarget::UnixAbstract(name);
    }
    SocketTarget::Tcp(addr)
}

pub(super) fn endpoint_with_keepalive(addr: &str) -> Result<Endpoint> {
    Ok(Endpoint::from_shared(addr.to_string())?
        .http2_keep_alive_interval(Duration::from_secs(5))
        .keep_alive_timeout(Duration::from_secs(22))
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(Duration::from_secs(20))))
}

pub(super) async fn connect_unix_channel(path: String) -> Result<Channel> {
    let endpoint = Endpoint::try_from("http://[::]:50051")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await?;
    Ok(channel)
}

pub(super) async fn connect_unix_abstract_channel(name: String) -> Result<Channel> {
    let endpoint = Endpoint::try_from("http://[::]:50051")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let name = name.clone();
            async move { connect_abstract_unix_stream(name).await }
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

#[cfg(feature = "grpc-ui")]
pub(super) async fn connect_with_skip_verify(
    endpoint: &Endpoint,
    config: &Config,
) -> Result<(Channel, Arc<CapturedServerCertIdentity>)> {
    tracing::warn!(
        "UI auth SkipVerify=true: certificate verification is disabled for this UI channel"
    );

    let verifier = cert_capturing_no_verifier();
    let rustls = build_rustls_config(config, verifier.clone())?;
    let channel = connect_https_channel(endpoint, rustls).await?;
    Ok((channel, verifier.captured_identity()))
}

#[cfg(feature = "grpc-ui")]
pub(super) async fn connect_with_verified_tls(
    endpoint: &Endpoint,
    config: &Config,
) -> Result<(Channel, Arc<CapturedServerCertIdentity>)> {
    let verifier = cert_capturing_webpki_verifier(config)?;
    let rustls = build_rustls_config(config, verifier.clone())?;
    let channel = connect_https_channel(endpoint, rustls).await?;
    Ok((channel, verifier.captured_identity()))
}

#[cfg(feature = "grpc-ui")]
fn read_trust_root_pem(config: &Config) -> Result<Vec<u8>> {
    let tls_opts = &config.client_auth.tls_options;
    let mut root_pem = Vec::<u8>::new();
    if !tls_opts.ca_cert.trim().is_empty() {
        match StorageService::global()
            .read_bytes_sync_and_notify("client", Path::new(tls_opts.ca_cert.trim()))
        {
            Ok(raw) => root_pem.extend(raw),
            Err(err) => tracing::warn!(
                "reading UI auth CA certificate ({}): {err}",
                config.client_auth.auth_type.as_name()
            ),
        }
    }
    if !tls_opts.server_cert.trim().is_empty() {
        match StorageService::global()
            .read_bytes_sync_and_notify("client", Path::new(tls_opts.server_cert.trim()))
        {
            Ok(raw) => root_pem.extend(raw),
            Err(err) => tracing::warn!(
                "reading UI auth server cert ({}): {err}",
                config.client_auth.auth_type.as_name()
            ),
        }
    }

    if root_pem.is_empty() {
        anyhow::bail!(
            "UI auth {} requires explicit trust material: set TLSOptions.CACert or TLSOptions.ServerCert (self-signed certs are supported when provided here)",
            config.client_auth.auth_type.as_name()
        );
    }

    Ok(root_pem)
}

#[cfg(feature = "grpc-ui")]
fn load_client_identity_material(
    config: &Config,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
    let tls_opts = &config.client_auth.tls_options;
    if !matches!(config.client_auth.auth_type, ClientAuthType::TlsMutual) {
        return Ok(None);
    }

    let cert = StorageService::global()
        .read_bytes_sync_and_notify("client", Path::new(tls_opts.client_cert.trim()))?;
    let key = StorageService::global()
        .read_bytes_sync_and_notify("client", Path::new(tls_opts.client_key.trim()))?;
    let certs = CertificateDer::pem_slice_iter(&cert)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&key).map_err(|e| {
        anyhow::anyhow!(
            "missing/invalid private key in {}: {e}",
            tls_opts.client_key
        )
    })?;
    Ok(Some((certs, key)))
}

#[cfg(feature = "grpc-ui")]
fn build_rustls_config(
    config: &Config,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<RustlsClientConfig> {
    let mut rustls = if let Some((certs, key)) = load_client_identity_material(config)? {
        RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(certs, key)?
    } else {
        RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    };

    rustls.alpn_protocols = vec![b"h2".to_vec()];
    Ok(rustls)
}

#[cfg(feature = "grpc-ui")]
async fn connect_https_channel(endpoint: &Endpoint, rustls: RustlsClientConfig) -> Result<Channel> {
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(rustls)
        .https_or_http()
        .enable_all_versions()
        .build();

    Ok(endpoint.clone().connect_with_connector(connector).await?)
}

#[cfg(feature = "grpc-ui")]
fn cert_capturing_webpki_verifier(config: &Config) -> Result<Arc<CertCapturingVerifier>> {
    let root_pem = read_trust_root_pem(config)?;
    let certs = CertificateDer::pem_slice_iter(&root_pem)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        anyhow::bail!(
            "UI auth {} trust material did not yield any usable root certificates",
            config.client_auth.auth_type.as_name()
        );
    }
    if ignored > 0 {
        tracing::debug!(added, ignored, "ignored invalid TLS trust anchors while building UI client verifier");
    }

    let inner: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|err| anyhow::anyhow!("building UI TLS verifier: {err}"))?;
    Ok(CertCapturingVerifier::new(inner))
}

#[cfg(feature = "grpc-ui")]
#[derive(Debug)]
struct NoVerifier;

#[cfg(feature = "grpc-ui")]
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

#[cfg(feature = "grpc-ui")]
#[allow(dead_code)] // Used when CertCapturingVerifier is wired into live TLS handshake path.
const NO_VERIFIER_SCHEMES: &[SignatureScheme] = &[
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
];

/// Captured server-certificate identity from a TLS handshake.
///
/// Populated by `CertCapturingVerifier` during `verify_server_cert` and consumed
/// by session-binding logic to resolve against `RemotePrincipalBindings`.
#[derive(Clone, Debug, Default)]
pub(crate) struct CapturedServerCertIdentity {
    /// SHA-256 fingerprint of the DER-encoded end-entity certificate (lowercase hex).
    pub(crate) fingerprint_sha256: Option<String>,
    /// Subject distinguished name (e.g. `CN=ui.example.test,O=Org`).
    pub(crate) subject: Option<String>,
    /// First DNS SAN entry, if present.
    pub(crate) san_dns: Option<String>,
}

/// A `ServerCertVerifier` wrapper that delegates real verification to an inner
/// verifier but also captures the server certificate's identity for
/// `RemotePrincipalBinding` resolution.
///
/// Thread-safety: the captured identity is stored in an `ArcSwap` so it can be
/// read concurrently from non-TLS code after the handshake completes.
#[cfg(feature = "grpc-ui")]
#[derive(Debug)]
pub(super) struct CertCapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    captured: arc_swap::ArcSwap<CapturedServerCertIdentity>,
}

#[cfg(feature = "grpc-ui")]
impl CertCapturingVerifier {
    pub(super) fn new(inner: Arc<dyn ServerCertVerifier>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            captured: arc_swap::ArcSwap::new(Arc::new(CapturedServerCertIdentity::default())),
        })
    }

    /// Read the most recently captured server cert identity (if any).
    pub(super) fn captured_identity(&self) -> Arc<CapturedServerCertIdentity> {
        self.captured.load_full()
    }

    fn extract_identity(cert_der: &CertificateDer<'_>) -> CapturedServerCertIdentity {
        let fingerprint = {
            let digest = Sha256::digest(cert_der.as_ref());
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            Some(hex)
        };

        let (subject, san_dns) = match x509_cert::Certificate::from_der(cert_der.as_ref()) {
            Ok(parsed) => {
                let subject_str = parsed.tbs_certificate.subject.to_string();
                let subject = if subject_str.is_empty() {
                    None
                } else {
                    Some(subject_str)
                };

                let san = parsed
                    .tbs_certificate
                    .extensions
                    .as_ref()
                    .and_then(|exts| {
                        exts.iter()
                            .find(|ext| ext.extn_id == x509_cert::ext::pkix::SubjectAltName::OID)
                    })
                    .and_then(|ext| {
                        x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes())
                            .ok()
                    })
                    .and_then(|san| {
                        san.0.iter().find_map(|name| match name {
                            x509_cert::ext::pkix::name::GeneralName::DnsName(dns) => {
                                Some(dns.to_string())
                            }
                            _ => None,
                        })
                    });

                (subject, san)
            }
            Err(err) => {
                tracing::debug!(
                    "failed to parse server certificate for identity extraction: {err}"
                );
                (None, None)
            }
        };

        CapturedServerCertIdentity {
            fingerprint_sha256: fingerprint,
            subject,
            san_dns,
        }
    }
}

#[cfg(feature = "grpc-ui")]
impl ServerCertVerifier for CertCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let identity = Self::extract_identity(end_entity);
        tracing::debug!(
            fingerprint = identity.fingerprint_sha256.as_deref().unwrap_or("-"),
            subject = identity.subject.as_deref().unwrap_or("-"),
            san_dns = identity.san_dns.as_deref().unwrap_or("-"),
            "captured server certificate identity for remote principal resolution"
        );
        self.captured.store(Arc::new(identity));

        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A `CertCapturingVerifier` that wraps `NoVerifier` (skip-verify mode) and
/// still captures the server certificate identity for binding resolution.
#[cfg(feature = "grpc-ui")]
pub(super) fn cert_capturing_no_verifier() -> Arc<CertCapturingVerifier> {
    CertCapturingVerifier::new(Arc::new(NoVerifier))
}

/// Extract `CapturedServerCertIdentity` from a PEM-encoded certificate file.
///
/// Used to resolve remote principal bindings from the configured server cert
/// (when the daemon knows the expected server identity via config rather than
/// extracting it from a live handshake).
pub(crate) fn extract_identity_from_pem(pem_bytes: &[u8]) -> Option<CapturedServerCertIdentity> {
    #[cfg(feature = "grpc-ui")]
    {
    let cert_der = CertificateDer::pem_slice_iter(pem_bytes).next()?.ok()?;
    let identity = CertCapturingVerifier::extract_identity(&cert_der);
    if identity.fingerprint_sha256.is_none()
        && identity.subject.is_none()
        && identity.san_dns.is_none()
    {
        return None;
    }
    Some(identity)
    }

    #[cfg(not(feature = "grpc-ui"))]
    {
        let _ = pem_bytes;
        None
    }
}
