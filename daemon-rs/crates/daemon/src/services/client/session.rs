/// Client session types and session-state management.
///
/// Extracted from `client.rs` per DESIGN_RULES §3: session-state internals,
/// principal ranking logic, and snapshot machinery are separate concerns from
/// the gRPC transport surface in `client.rs`.
use std::collections::BTreeMap;
use std::net::IpAddr;

use tokio::sync::watch;

use std::sync::Arc;

pub(crate) const CLIENT_SESSION_ID: &str = "client";

impl From<ClientPrincipal> for crate::models::policy_tx_storage::PolicyOwner {
    fn from(value: ClientPrincipal) -> Self {
        match value {
            ClientPrincipal::LocalUid(uid) => Self::LocalUid(uid),
            ClientPrincipal::UnixAbstractName(name) => Self::UnixAbstractName(name),
            ClientPrincipal::NetworkIdentity(identity) => Self::NetworkIdentity(identity),
            ClientPrincipal::IpFallback(ip) => Self::IpFallback(ip.to_string()),
            ClientPrincipal::RemoteCert { binding_name, .. } => {
                Self::NetworkIdentity(format!("remote-cert:{binding_name}"))
            }
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClientPrincipal {
    LocalUid(u32),
    UnixAbstractName(String),
    NetworkIdentity(String),
    IpFallback(IpAddr),
    /// Remote principal resolved from a TLS certificate binding.
    ///
    /// `mapped_uid` is the local UID from the matched `RemotePrincipalBinding`;
    /// it anchors owner-scope checks for remote sessions.
    RemoteCert {
        binding_name: String,
        mapped_uid: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSession {
    pub id: String,
    pub owner: ClientPrincipal,
    pub default_action: crate::config::DefaultAction,
    /// Capability grants for this session (populated from `RemotePrincipalBindings`).
    ///
    /// Empty for local sessions (local authorization uses UID/GID checks).
    /// For remote cert-authenticated sessions, this carries the normalized
    /// capability strings from the matched binding.
    pub capabilities: Vec<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ClientSession {
    pub fn for_local_uid(uid: u32, default_action: crate::config::DefaultAction) -> Self {
        Self {
            id: format!("uid:{uid}"),
            owner: ClientPrincipal::LocalUid(uid),
            default_action,
            capabilities: Vec::new(),
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
            capabilities: Vec::new(),
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
            capabilities: Vec::new(),
        }
    }

    pub fn for_ip_fallback(ip: IpAddr, default_action: crate::config::DefaultAction) -> Self {
        Self {
            id: format!("ip:{ip}"),
            owner: ClientPrincipal::IpFallback(ip),
            default_action,
            capabilities: Vec::new(),
        }
    }

    /// Create a session for a remote principal resolved from a TLS cert binding.
    ///
    /// `binding_name` is the human-readable name from `RemotePrincipalBindings`.
    /// `mapped_uid` is the local UID that owner-scope checks will use.
    /// `capabilities` are the normalized capability grants from the binding.
    pub fn for_remote_principal(
        binding_name: impl Into<String>,
        mapped_uid: u32,
        capabilities: Vec<String>,
        default_action: crate::config::DefaultAction,
    ) -> Self {
        let binding_name = binding_name.into();
        Self {
            id: format!("remote-cert:{binding_name}"),
            owner: ClientPrincipal::RemoteCert {
                binding_name,
                mapped_uid,
            },
            default_action,
            capabilities,
        }
    }

    /// Returns `true` if this session has the given capability grant.
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }
}

#[derive(Clone)]
pub(super) struct ClientSessionSnapshot {
    pub(super) sessions: BTreeMap<String, ClientSession>,
    pub(super) connected_default_action: crate::config::DefaultAction,
}

impl ClientSessionSnapshot {
    pub(super) fn default_snapshot() -> Arc<Self> {
        Arc::new(Self {
            sessions: BTreeMap::new(),
            connected_default_action: crate::config::DefaultAction::Deny,
        })
    }
}

/// Session-state and principal-ranking logic for `ClientService`.
///
/// All session mutation methods live here; gRPC transport methods live
/// in `client.rs`.
pub(super) struct SessionState {
    pub(super) snapshot_tx: watch::Sender<Arc<ClientSessionSnapshot>>,
    pub(super) snapshot_rx: watch::Receiver<Arc<ClientSessionSnapshot>>,
}

impl SessionState {
    pub(super) fn new() -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(ClientSessionSnapshot::default_snapshot());
        Self {
            snapshot_tx,
            snapshot_rx,
        }
    }

    /// Copy-on-write mutation: if no reader currently holds an `Arc` clone of
    /// the snapshot, the inner data is mutated in-place (zero allocation).
    /// Under contention, `Arc::make_mut` clones — the minimum necessary for
    /// concurrent correctness.
    pub(super) fn modify_snapshot(&self, f: impl FnOnce(&mut ClientSessionSnapshot)) {
        self.snapshot_tx.send_modify(|arc| {
            f(Arc::make_mut(arc));
        });
    }

    pub(super) fn principal_rank(owner: &ClientPrincipal) -> u8 {
        match owner {
            ClientPrincipal::LocalUid(_) => 0,
            ClientPrincipal::UnixAbstractName(_) => 1,
            ClientPrincipal::RemoteCert { .. } => 2,
            ClientPrincipal::NetworkIdentity(_) => 3,
            ClientPrincipal::IpFallback(_) => 4,
        }
    }
}
