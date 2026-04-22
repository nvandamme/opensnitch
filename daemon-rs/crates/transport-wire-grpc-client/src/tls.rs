use std::sync::{Arc, Mutex};

use anyhow::Result;
use rustls::client::{
    WebPkiServerVerifier,
    danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use rustls_pki_types::pem::PemObject;
use sha2::{Digest as _, Sha256};
use x509_cert::der::Decode;

use crate::{WireEndpoint, WireSession, wire_connect_https_session};

#[derive(Clone, Debug, Default)]
pub struct WireServerCertIdentity {
    pub fingerprint_sha256: Option<String>,
    pub subject: Option<String>,
    pub san_dns: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct WireTlsClientIdentityPem {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct WireTlsConfig {
    pub skip_verify: bool,
    pub trust_root_pem: Vec<u8>,
    pub client_identity: Option<WireTlsClientIdentityPem>,
}

pub async fn wire_connect_tls_session(
    endpoint: &WireEndpoint,
    tls: &WireTlsConfig,
) -> Result<(WireSession, WireServerCertIdentity)> {
    if tls.skip_verify {
        let verifier = cert_capturing_no_verifier();
        let rustls = build_rustls_config(tls, verifier.clone())?;
        let channel = wire_connect_https_session(endpoint, rustls).await?;
        return Ok((channel, verifier.captured_identity()));
    }

    let verifier = cert_capturing_webpki_verifier(tls)?;
    let rustls = build_rustls_config(tls, verifier.clone())?;
    let channel = wire_connect_https_session(endpoint, rustls).await?;
    Ok((channel, verifier.captured_identity()))
}

pub fn wire_extract_identity_from_pem(pem_bytes: &[u8]) -> Option<WireServerCertIdentity> {
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

fn cert_capturing_webpki_verifier(tls: &WireTlsConfig) -> Result<Arc<CertCapturingVerifier>> {
    if tls.trust_root_pem.is_empty() {
        anyhow::bail!("wire TLS verification requires non-empty trust roots");
    }
    let certs = CertificateDer::pem_slice_iter(&tls.trust_root_pem)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        anyhow::bail!("wire TLS trust material did not yield any usable root certificates");
    }

    let inner: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|err| anyhow::anyhow!("building wire TLS verifier: {err}"))?;
    Ok(CertCapturingVerifier::new(inner))
}

fn build_rustls_config(
    tls: &WireTlsConfig,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<RustlsClientConfig> {
    let mut rustls = if let Some(identity) = tls.client_identity.as_ref() {
        let certs = CertificateDer::pem_slice_iter(&identity.cert_pem)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_slice(&identity.key_pem)
            .map_err(|err| anyhow::anyhow!("missing/invalid client private key: {err}"))?;

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

#[derive(Debug)]
struct CertCapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    captured: Mutex<WireServerCertIdentity>,
}

impl CertCapturingVerifier {
    fn new(inner: Arc<dyn ServerCertVerifier>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            captured: Mutex::new(WireServerCertIdentity::default()),
        })
    }

    fn captured_identity(&self) -> WireServerCertIdentity {
        self.captured
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn extract_identity(cert_der: &CertificateDer<'_>) -> WireServerCertIdentity {
        let fingerprint = {
            let digest = Sha256::digest(cert_der.as_ref());
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
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
                    .and_then(|exts: &x509_cert::ext::Extensions| {
                        exts.iter()
                            .find(|ext| ext.extn_id == x509_cert::ext::pkix::ID_CE_SUBJECT_ALT_NAME)
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
            Err(_) => (None, None),
        };

        WireServerCertIdentity {
            fingerprint_sha256: fingerprint,
            subject,
            san_dns,
        }
    }
}

impl ServerCertVerifier for CertCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut slot) = self.captured.lock() {
            *slot = Self::extract_identity(end_entity);
        }

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

fn cert_capturing_no_verifier() -> Arc<CertCapturingVerifier> {
    CertCapturingVerifier::new(Arc::new(NoVerifier))
}
