use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use time::{Duration, OffsetDateTime};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertRole {
    Server,
    Client,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertGenRequest {
    pub role: CertRole,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub common_name: String,
    pub san_entries: Vec<String>,
    pub valid_days: u64,
}

impl CertRole {
    fn default_common_name(self) -> &'static str {
        match self {
            Self::Server => "opensnitch-server",
            Self::Client => "opensnitch-client",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
        }
    }
}

pub fn parse_self_signed_request_from_args(args: &[String]) -> Result<Option<CertGenRequest>> {
    if args.is_empty() {
        return Ok(None);
    }

    let mut role: Option<CertRole> = None;
    let mut cert_path: Option<PathBuf> = None;
    let mut key_path: Option<PathBuf> = None;
    let mut common_name: Option<String> = None;
    let mut san_entries: Vec<String> = Vec::new();
    let mut valid_days: u64 = 365;

    let mut idx = 0usize;
    while idx < args.len() {
        let arg = &args[idx];
        if let Some(val) = arg.strip_prefix("--gen-self-signed-server-cert=") {
            ensure_single_role(role, CertRole::Server)?;
            role = Some(CertRole::Server);
            cert_path = Some(PathBuf::from(val));
            idx += 1;
            continue;
        }
        if arg == "--gen-self-signed-server-cert" {
            ensure_single_role(role, CertRole::Server)?;
            role = Some(CertRole::Server);
            cert_path = Some(PathBuf::from(take_value(args, &mut idx, arg)?));
            idx += 1;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--gen-self-signed-server-key=") {
            ensure_single_role(role, CertRole::Server)?;
            role = Some(CertRole::Server);
            key_path = Some(PathBuf::from(val));
            idx += 1;
            continue;
        }
        if arg == "--gen-self-signed-server-key" {
            ensure_single_role(role, CertRole::Server)?;
            role = Some(CertRole::Server);
            key_path = Some(PathBuf::from(take_value(args, &mut idx, arg)?));
            idx += 1;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--gen-self-signed-client-cert=") {
            ensure_single_role(role, CertRole::Client)?;
            role = Some(CertRole::Client);
            cert_path = Some(PathBuf::from(val));
            idx += 1;
            continue;
        }
        if arg == "--gen-self-signed-client-cert" {
            ensure_single_role(role, CertRole::Client)?;
            role = Some(CertRole::Client);
            cert_path = Some(PathBuf::from(take_value(args, &mut idx, arg)?));
            idx += 1;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--gen-self-signed-client-key=") {
            ensure_single_role(role, CertRole::Client)?;
            role = Some(CertRole::Client);
            key_path = Some(PathBuf::from(val));
            idx += 1;
            continue;
        }
        if arg == "--gen-self-signed-client-key" {
            ensure_single_role(role, CertRole::Client)?;
            role = Some(CertRole::Client);
            key_path = Some(PathBuf::from(take_value(args, &mut idx, arg)?));
            idx += 1;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--gen-self-signed-cn=") {
            common_name = Some(val.to_owned());
            idx += 1;
            continue;
        }
        if arg == "--gen-self-signed-cn" {
            common_name = Some(take_value(args, &mut idx, arg)?);
            idx += 1;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--gen-self-signed-san=") {
            san_entries.push(val.to_owned());
            idx += 1;
            continue;
        }
        if arg == "--gen-self-signed-san" {
            san_entries.push(take_value(args, &mut idx, arg)?);
            idx += 1;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--gen-self-signed-days=") {
            valid_days = parse_valid_days(val, arg)?;
            idx += 1;
            continue;
        }
        if arg == "--gen-self-signed-days" {
            valid_days = parse_valid_days(&take_value(args, &mut idx, arg)?, arg)?;
            idx += 1;
            continue;
        }
        idx += 1;
    }

    let Some(selected_role) = role else {
        return Ok(None);
    };

    let cert_path = cert_path.ok_or_else(|| {
        anyhow!(
            "missing cert output path for {} certificate generation",
            selected_role.as_str()
        )
    })?;
    let key_path = key_path.ok_or_else(|| {
        anyhow!(
            "missing key output path for {} certificate generation",
            selected_role.as_str()
        )
    })?;

    let common_name = common_name
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| selected_role.default_common_name().to_owned());

    Ok(Some(CertGenRequest {
        role: selected_role,
        cert_path,
        key_path,
        common_name,
        san_entries,
        valid_days,
    }))
}

pub fn generate_self_signed_pair(req: &CertGenRequest) -> Result<()> {
    if req.valid_days == 0 {
        bail!("--gen-self-signed-days must be >= 1");
    }

    ensure_parent_dir(&req.cert_path)?;
    ensure_parent_dir(&req.key_path)?;

    let key = KeyPair::generate().context("failed to generate private key")?;
    let mut params = CertificateParams::new(Vec::new())?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, req.common_name.clone());
    params.distinguished_name = dn;

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(req.valid_days as i64);

    if !req.san_entries.is_empty() {
        params.subject_alt_names = req
            .san_entries
            .iter()
            .map(|entry| -> Result<SanType> {
                if let Ok(ip) = entry.parse() {
                    Ok(SanType::IpAddress(ip))
                } else {
                    let dns = entry
                        .clone()
                        .try_into()
                        .with_context(|| format!("invalid DNS SAN entry: {entry}"))?;
                    Ok(SanType::DnsName(dns))
                }
            })
            .collect::<Result<Vec<_>>>()?;
    }

    let cert = params
        .self_signed(&key)
        .context("failed to build self-signed certificate")?;

    fs::write(&req.cert_path, cert.pem()).with_context(|| {
        format!(
            "failed writing certificate to {}",
            req.cert_path.to_string_lossy()
        )
    })?;
    fs::write(&req.key_path, key.serialize_pem())
        .with_context(|| format!("failed writing key to {}", req.key_path.to_string_lossy()))?;

    set_private_file_permissions(&req.key_path)?;
    Ok(())
}

fn ensure_single_role(current: Option<CertRole>, incoming: CertRole) -> Result<()> {
    if let Some(existing) = current {
        if existing != incoming {
            bail!("cannot mix server and client generation flags in a single invocation");
        }
    }
    Ok(())
}

fn take_value(args: &[String], idx: &mut usize, flag: &str) -> Result<String> {
    let next = *idx + 1;
    if next >= args.len() {
        bail!("missing value for {flag}");
    }
    *idx = next;
    Ok(args[next].clone())
}

fn parse_valid_days(raw: &str, flag: &str) -> Result<u64> {
    let days: u64 = raw
        .parse()
        .with_context(|| format!("invalid value for {flag}: {raw}"))?;
    if days == 0 {
        bail!("{flag} must be >= 1");
    }
    Ok(days)
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create parent directory {}", parent.display())
            })?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(path)
        .with_context(|| format!("failed to read permissions for {}", path.display()))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
        .with_context(|| format!("failed to set permissions for {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
