/// Client session types and session-state management.
///
/// Extracted from `client.rs` per DESIGN_RULES §3: session-state internals,
/// principal ranking logic, and snapshot machinery are separate concerns from
/// the gRPC transport surface in `client.rs`.
use std::collections::BTreeMap;
use std::net::IpAddr;

use tokio::sync::watch;

use std::sync::Arc;

pub(crate) const CONTROL_SESSION_ID: &str = "control-plane";

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
    pub fn for_local_uid(uid: u32, default_action: crate::config::DefaultAction) -> Self {
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

    pub fn for_ip_fallback(ip: IpAddr, default_action: crate::config::DefaultAction) -> Self {
        Self {
            id: format!("ip:{ip}"),
            owner: ClientPrincipal::IpFallback(ip),
            default_action,
        }
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
        let (snapshot_tx, snapshot_rx) =
            watch::channel(ClientSessionSnapshot::default_snapshot());
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
            ClientPrincipal::NetworkIdentity(_) => 2,
            ClientPrincipal::IpFallback(_) => 3,
        }
    }
}
