#[cfg(unix)]
use nix::unistd::{Gid, Uid, User, getgrouplist};

use super::notification::{NotificationFlow, UnixPeerCredentials};
use crate::config::Config;

impl NotificationFlow {
    #[cfg(unix)]
    pub(super) fn try_unix_peer_credentials(client_addr: &str) -> Option<UnixPeerCredentials> {
        use std::os::fd::AsRawFd;

        let fd = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            None,
        )
        .ok()?;

        let addr = if let Some(path) = client_addr.strip_prefix("unix:") {
            nix::sys::socket::UnixAddr::new(path).ok()?
        } else if let Some(name) = client_addr.strip_prefix("unix-abstract:") {
            nix::sys::socket::UnixAddr::new_abstract(name.as_bytes()).ok()?
        } else {
            return None;
        };

        nix::sys::socket::connect(fd.as_raw_fd(), &addr).ok()?;
        let creds =
            nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::PeerCredentials).ok()?;
        Some(UnixPeerCredentials {
            uid: creds.uid(),
            gid: creds.gid(),
            pid: creds.pid(),
        })
    }

    #[cfg(not(unix))]
    pub(super) fn try_unix_peer_credentials(_client_addr: &str) -> Option<UnixPeerCredentials> {
        None
    }

    /// Read the supplementary GIDs of a peer process from `/proc/{pid}/status`.
    /// Look up the LISTEN socket at `client_addr` (must be a loopback TCP URL such as
    /// `http://127.0.0.1:50051`) in `/proc/net/tcp[6]` and return its `(uid, inode)`.
    /// Used to identify who owns the UI gRPC server and to resolve supplementary groups.
    #[cfg(target_os = "linux")]
    pub(super) fn try_loopback_tcp_listen_socket(client_addr: &str) -> Option<(u32, u32)> {
        let endpoint = client_addr
            .strip_prefix("https://")
            .or_else(|| client_addr.strip_prefix("http://"))
            .unwrap_or(client_addr)
            .split('/')
            .next()
            .unwrap_or(client_addr);

        let (host, port_str) = if endpoint.starts_with('[') {
            // IPv6: [::1]:port
            let close = endpoint.find(']')?;
            let port_str = endpoint[close + 1..].strip_prefix(':')?;
            (&endpoint[1..close], port_str)
        } else {
            // IPv4: host:port
            endpoint.rsplit_once(':')?
        };

        let ip: std::net::IpAddr = host.parse().ok()?;
        if !ip.is_loopback() {
            return None;
        }

        let target_port: u16 = port_str.parse().ok()?;
        let proc_file = if ip.is_ipv6() {
            "/proc/net/tcp6"
        } else {
            "/proc/net/tcp"
        };
        let content = std::fs::read_to_string(proc_file).ok()?;

        // Column indices mirror parse_proc_net_row in services/connection/parsing.rs:
        // 0=sl 1=local_addr 2=rem_addr 3=state 4=tx:rx 5=tr:tm 6=retrnsmt 7=uid 8=timeout 9=inode
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            if cols[3] != "0A" {
                continue; // TCP_LISTEN only
            }
            let Some(port_hex) = cols[1].split(':').nth(1) else {
                continue;
            };
            let Ok(local_port) = u16::from_str_radix(port_hex, 16) else {
                continue;
            };
            if local_port != target_port {
                continue;
            }
            let Ok(uid) = cols[7].parse::<u32>() else {
                continue;
            };
            let inode = cols[9].parse::<u32>().unwrap_or(0);
            return Some((uid, inode));
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn try_loopback_tcp_listen_socket(_client_addr: &str) -> Option<(u32, u32)> {
        None
    }

    /// Scan `/proc/{pid}/fd/` symlinks to find which PID owns `inode`.
    /// Enables supplementary group resolution for loopback TCP peers.
    #[cfg(target_os = "linux")]
    pub(super) fn find_pid_for_socket_inode(inode: u32) -> Option<i32> {
        if inode == 0 {
            return None;
        }
        let target = format!("socket:[{inode}]");
        let procs = std::fs::read_dir("/proc").ok()?;
        for entry in procs.flatten() {
            let name = entry.file_name();
            let Ok(pid) = name.to_string_lossy().parse::<i32>() else {
                continue;
            };
            let fd_dir = format!("/proc/{pid}/fd");
            let Ok(fds) = std::fs::read_dir(&fd_dir) else {
                continue;
            };
            for fd_entry in fds.flatten() {
                if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                    if link.to_string_lossy() == target {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn find_pid_for_socket_inode(_inode: u32) -> Option<i32> {
        None
    }

    /// Read the primary/effective and supplementary GIDs of a peer process from
    /// `/proc/{pid}/status`. This keeps group-based local policy as a broad
    /// membership filter instead of binding authorization to one exact primary GID.
    pub(super) fn peer_group_memberships(pid: i32, primary_gid_hint: Option<u32>) -> Vec<u32> {
        let path = format!("/proc/{pid}/status");
        let mut gids = Vec::new();
        if let Some(gid) = primary_gid_hint {
            gids.push(gid);
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            gids.sort_unstable();
            gids.dedup();
            return gids;
        };
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("Gid:\t") {
                gids.extend(
                    rest.split_ascii_whitespace()
                        .filter_map(|s| s.parse::<u32>().ok()),
                );
                continue;
            }
            if let Some(rest) = line.strip_prefix("Groups:\t") {
                gids.extend(
                    rest.split_ascii_whitespace()
                        .filter_map(|s| s.parse::<u32>().ok()),
                );
            }
        }
        gids.sort_unstable();
        gids.dedup();
        gids
    }

    pub(super) fn local_policy_explicitly_configured(config: &Config) -> bool {
        config.local_control_allowed_principals.is_some()
            || config.local_control_allowed_group_gids.is_some()
    }

    pub(super) fn unix_principal_allowed(config: &Config, peer: UnixPeerCredentials) -> bool {
        if !Self::local_policy_explicitly_configured(config) {
            // Hardened local-only mode defaults to root-only when no explicit local policy data exists.
            return peer.uid == 0;
        }

        let peer_gids = Self::peer_group_memberships(peer.pid, Some(peer.gid));

        // UID anchors the local principal identity; GID acts as a coarse group selector.
        let principal_ok = match config.local_control_allowed_principals.as_ref() {
            None => true,
            Some(allowlist) => {
                Self::local_principal_allowlist_matches(allowlist, peer.uid, &peer_gids)
            }
        };

        // Check broad group allowlist.
        let group_ok = match config.local_control_allowed_group_gids.as_ref() {
            None => true,
            Some(allowed_gids) if allowed_gids.is_empty() => false,
            Some(allowed_gids) => Self::allowed_group_selector_matches(allowed_gids, &peer_gids),
        };

        // If either list is configured, the peer must satisfy that list.
        // If both are null → legacy pass-through (both are true above).
        principal_ok && group_ok
    }

    pub(super) fn loopback_tcp_principal_allowed(config: &Config, client_addr: &str) -> bool {
        let Some((uid, inode)) = Self::try_loopback_tcp_listen_socket(client_addr) else {
            return false;
        };

        if !Self::local_policy_explicitly_configured(config) {
            return uid == 0;
        }

        let pid = Self::find_pid_for_socket_inode(inode);
        if pid.is_none()
            && (config.local_control_allowed_principals.is_some()
                || config.local_control_allowed_group_gids.is_some())
        {
            tracing::warn!(
                uid,
                inode,
                "loopback TCP principal check: could not resolve PID from socket inode; group-based local principal enforcement cannot proceed"
            );
        }
        let peer_gids = pid
            .map(|pid| Self::peer_group_memberships(pid, None))
            .unwrap_or_default();

        let principal_ok = match config.local_control_allowed_principals.as_ref() {
            None => true,
            Some(allowlist) => Self::local_principal_allowlist_matches(allowlist, uid, &peer_gids),
        };
        let group_ok = match config.local_control_allowed_group_gids.as_ref() {
            None => true,
            Some(allowed_gids) if allowed_gids.is_empty() => false,
            Some(allowed_gids) => Self::allowed_group_selector_matches(allowed_gids, &peer_gids),
        };
        principal_ok && group_ok
    }

    #[cfg(unix)]
    pub(super) fn username_for_uid(uid: u32) -> Option<String> {
        User::from_uid(Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(|user| user.name)
    }

    #[cfg(not(unix))]
    pub(super) fn username_for_uid(_uid: u32) -> Option<String> {
        None
    }

    #[cfg(unix)]
    pub(super) fn group_memberships_for_uid(uid: u32) -> Vec<u32> {
        let Some(user) = User::from_uid(Uid::from_raw(uid)).ok().flatten() else {
            return Vec::new();
        };

        let Ok(username) = std::ffi::CString::new(user.name) else {
            return vec![user.gid.as_raw()];
        };

        match getgrouplist(username.as_c_str(), Gid::from_raw(user.gid.as_raw())) {
            Ok(groups) => {
                let mut gids: Vec<u32> = groups.into_iter().map(|group| group.as_raw()).collect();
                gids.sort_unstable();
                gids.dedup();
                gids
            }
            Err(_) => vec![user.gid.as_raw()],
        }
    }

    #[cfg(not(unix))]
    pub(super) fn group_memberships_for_uid(_uid: u32) -> Vec<u32> {
        Vec::new()
    }

    /// Resolve a remote endpoint's TLS certificate against the configured
    /// `RemotePrincipalBindings`.
    ///
    /// Returns a `ClientSession` for the first matching binding, carrying the
    /// mapped local principal UID and the binding's capability grants.
    /// Returns `None` when no binding matches or when remote bindings are not
    /// configured.
    ///
    /// Match priority: fingerprint > subject > SAN (first match wins).
    pub(crate) fn resolve_remote_principal_binding(
        config: &Config,
        cert_fingerprint: Option<&str>,
        cert_subject: Option<&str>,
        cert_san: Option<&str>,
    ) -> Option<crate::services::client::ClientSession> {
        use crate::services::client::ClientSession;
        use crate::utils::name_parsing::normalized_name;

        let bindings = config.remote_principal_bindings.as_ref()?;
        if bindings.is_empty() {
            return None;
        }

        let normalized_fingerprint = cert_fingerprint.map(|f| normalized_name(f));

        for binding in bindings {
            let fp_matches = binding
                .cert_fingerprint
                .as_ref()
                .is_some_and(|fp| normalized_fingerprint.as_deref() == Some(fp.as_str()));

            let subject_matches = binding
                .cert_subject
                .as_ref()
                .is_some_and(|s| cert_subject == Some(s.as_str()));

            let san_matches = binding
                .cert_san
                .as_ref()
                .is_some_and(|s| cert_san == Some(s.as_str()));

            if fp_matches || subject_matches || san_matches {
                return Some(ClientSession::for_remote_principal(
                    &binding.name,
                    binding.local_principal.uid,
                    binding.capabilities.clone(),
                    crate::config::DefaultAction::Deny,
                ));
            }
        }

        None
    }
}
