use nix::unistd::{Group, User};

use crate::{
    config::{Config, LocalPrincipal, RemotePrincipalBinding},
    models::config_storage::{RawPrincipalEntry, RawRemotePrincipalBinding, RawServerAuth},
    utils::name_parsing::normalized_name,
};

impl Config {
    pub(super) fn parse_local_control_allowed_principals(
        auth: &RawServerAuth,
    ) -> Option<Vec<LocalPrincipal>> {
        let has_principals = auth.allowed_principals.is_some();
        let has_users = auth.allowed_users.is_some();
        if !has_principals && !has_users {
            // Missing fields preserve legacy behavior.
            return None;
        }

        let mut resolved: Vec<LocalPrincipal> = Vec::new();

        if let Some(entries) = auth.allowed_principals.as_ref() {
            for entry in entries {
                match (entry.uid, entry.gid) {
                    (Some(uid), Some(gid)) => {
                        resolved.push(LocalPrincipal { uid, gid });
                    }
                    _ => {
                        tracing::warn!("ignoring AllowedPrincipals entry without both UID and GID");
                    }
                }
            }
        }

        if let Some(users) = auth.allowed_users.as_ref() {
            for username in users {
                let username = username.trim();
                if username.is_empty() {
                    continue;
                }
                match User::from_name(username) {
                    Ok(Some(user)) => {
                        resolved.push(LocalPrincipal {
                            uid: user.uid.as_raw(),
                            gid: user.gid.as_raw(),
                        });
                    }
                    Ok(None) => {
                        tracing::warn!(
                            username = username,
                            "ignoring AllowedUsers entry that does not resolve to a local account"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            username = username,
                            "ignoring AllowedUsers entry due to account lookup error: {err}"
                        );
                    }
                }
            }
        }

        resolved.sort_unstable_by_key(|p| (p.uid, p.gid));
        resolved.dedup_by_key(|p| (p.uid, p.gid));
        Some(resolved)
    }

    pub(super) fn parse_local_control_allowed_group_gids(auth: &RawServerAuth) -> Option<Vec<u32>> {
        let groups = auth.allowed_groups.as_ref()?;
        // Field present (even if empty list) → activate group-based enforcement.
        let mut gids: Vec<u32> = Vec::new();
        for groupname in groups {
            let groupname = groupname.trim();
            if groupname.is_empty() {
                continue;
            }
            match Group::from_name(groupname) {
                Ok(Some(group)) => {
                    gids.push(group.gid.as_raw());
                }
                Ok(None) => {
                    tracing::warn!(
                        groupname = groupname,
                        "ignoring AllowedGroups entry that does not resolve to a local group"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        groupname = groupname,
                        "ignoring AllowedGroups entry due to group lookup error: {err}"
                    );
                }
            }
        }
        gids.sort_unstable();
        gids.dedup();
        Some(gids)
    }

    pub(super) fn parse_remote_principal_bindings(
        auth: &RawServerAuth,
    ) -> Option<Vec<RemotePrincipalBinding>> {
        let entries = auth.remote_principal_bindings.as_ref()?;
        let mut resolved = Vec::new();

        for entry in entries {
            let cert_fingerprint = Self::trimmed_nonempty(&entry.cert_fingerprint)
                .map(|value| normalized_name(&value));
            let cert_subject = Self::trimmed_nonempty(&entry.cert_subject);
            let cert_san = Self::trimmed_nonempty(&entry.cert_san);
            if cert_fingerprint.is_none() && cert_subject.is_none() && cert_san.is_none() {
                tracing::warn!(
                    name = entry.name.trim(),
                    "ignoring RemotePrincipalBindings entry without any certificate selector"
                );
                continue;
            }

            let Some(local_principal) = Self::resolve_remote_binding_local_principal(entry) else {
                tracing::warn!(
                    name = entry.name.trim(),
                    "ignoring RemotePrincipalBindings entry without a resolvable local principal"
                );
                continue;
            };

            let mut capabilities = entry
                .capabilities
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|capability| normalized_name(&capability))
                .filter(|capability| !capability.is_empty())
                .collect::<Vec<_>>();
            capabilities.sort_unstable();
            capabilities.dedup();

            resolved.push(RemotePrincipalBinding {
                name: entry.name.trim().to_string(),
                cert_fingerprint,
                cert_subject,
                cert_san,
                local_principal,
                capabilities,
            });
        }

        Some(resolved)
    }

    pub(super) fn resolve_remote_binding_local_principal(
        entry: &RawRemotePrincipalBinding,
    ) -> Option<LocalPrincipal> {
        if let Some(principal) = entry.local_principal.as_ref() {
            if let Some(principal) = Self::local_principal_from_raw_entry(principal) {
                return Some(principal);
            }
            tracing::warn!(
                name = entry.name.trim(),
                "ignoring incomplete LocalPrincipal mapping in RemotePrincipalBindings entry"
            );
        }

        let username = entry.local_user.trim();
        if username.is_empty() {
            return None;
        }

        match User::from_name(username) {
            Ok(Some(user)) => Some(LocalPrincipal {
                uid: user.uid.as_raw(),
                gid: user.gid.as_raw(),
            }),
            Ok(None) => {
                tracing::warn!(
                    name = entry.name.trim(),
                    username = username,
                    "ignoring RemotePrincipalBindings LocalUser that does not resolve to a local account"
                );
                None
            }
            Err(err) => {
                tracing::warn!(
                    name = entry.name.trim(),
                    username = username,
                    "ignoring RemotePrincipalBindings LocalUser due to account lookup error: {err}"
                );
                None
            }
        }
    }

    pub(super) fn local_principal_from_raw_entry(
        entry: &RawPrincipalEntry,
    ) -> Option<LocalPrincipal> {
        match (entry.uid, entry.gid) {
            (Some(uid), Some(gid)) => Some(LocalPrincipal { uid, gid }),
            _ => None,
        }
    }

    pub(super) fn trimmed_nonempty(value: &str) -> Option<String> {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    }
}
