use super::notification::{NotificationAuthorizationClass, NotificationFlow};
use crate::{
    config::{AuthMode, Config},
    models::{
        command_action::CommandAction, firewall_config::FirewallConfig, rule_record::RuleRecord,
    },
    services::client::{ClientPrincipal, ClientSession},
};

impl NotificationFlow {
    pub(crate) fn authorization_rule_candidates(
        action: CommandAction,
        rules: &[RuleRecord],
        stored_rules: &[RuleRecord],
    ) -> Vec<RuleRecord> {
        if !Self::is_rule_toggle_or_delete_action(action) {
            return rules.to_vec();
        }

        rules
            .iter()
            .map(|rule| {
                let is_legacy_identity_stub =
                    !rule.name.trim().is_empty() && !Self::rule_has_operand_semantics(rule);

                if !is_legacy_identity_stub {
                    return rule.clone();
                }

                stored_rules
                    .iter()
                    .find(|stored| stored.name == rule.name)
                    .cloned()
                    .unwrap_or_else(|| rule.clone())
            })
            .collect()
    }

    pub(crate) fn normalize_owner_scoped_rule_mutation_rules(
        config: &Config,
        session: &ClientSession,
        action: CommandAction,
        rules: &mut [RuleRecord],
    ) -> std::result::Result<usize, &'static str> {
        if matches!(config.auth_mode, AuthMode::Legacy) || !Self::is_rule_mutation_action(action) {
            return Ok(0);
        }

        let owner_uid = match session.owner {
            ClientPrincipal::LocalUid(uid) => uid,
            ClientPrincipal::RemoteCert { mapped_uid, .. } => mapped_uid,
            _ => return Ok(0),
        };

        if owner_uid == 0 {
            return Ok(0);
        }

        let owner_username = Self::username_for_uid(owner_uid);
        let owner_group_gids = Self::group_memberships_for_uid(owner_uid);
        let mut injected_count = 0usize;
        for rule in rules.iter_mut() {
            if rule.precedence {
                continue;
            }

            if rule.operator.is_empty() {
                continue;
            }

            let mut saw_owner_match = false;
            let conflicts = Self::operator_owner_scope_conflicts(
                &rule.operator,
                owner_uid,
                owner_username.as_deref(),
                owner_group_gids.as_slice(),
                &mut saw_owner_match,
            );
            if conflicts {
                return Err("rule payload owner scope conflicts with authenticated caller");
            }

            if !saw_owner_match {
                Self::inject_owner_uid_scope(rule, owner_uid);
                injected_count = injected_count.saturating_add(1);
            }
        }

        Ok(injected_count)
    }

    pub(crate) fn normalize_owner_scoped_firewall_reload(
        config: &Config,
        session: &ClientSession,
        action: CommandAction,
        firewall: Option<&mut FirewallConfig>,
    ) -> std::result::Result<usize, &'static str> {
        if matches!(config.auth_mode, AuthMode::Legacy) || !Self::is_firewall_reload_action(action)
        {
            return Ok(0);
        }

        let Some(firewall) = firewall else {
            return Ok(0);
        };

        let owner_uid = match session.owner {
            ClientPrincipal::LocalUid(uid) => uid,
            ClientPrincipal::RemoteCert { mapped_uid, .. } => mapped_uid,
            _ => return Ok(0),
        };

        if owner_uid == 0 {
            return Ok(0);
        }

        let owner_group_gids = Self::group_memberships_for_uid(owner_uid);
        let owner_fragment = format!("-m owner --uid-owner {owner_uid}");
        let mut injected_count = 0usize;
        for rule in &mut firewall.rules {
            if Self::firewall_rule_matches_owner_scope(rule, owner_uid, owner_group_gids.as_slice())
            {
                continue;
            }

            if Self::firewall_parameters_have_conflicting_owner_scope(
                rule.parameters.as_str(),
                owner_uid,
                owner_group_gids.as_slice(),
            ) {
                return Err(
                    "system firewall payload owner scope conflicts with authenticated caller",
                );
            }

            if Self::firewall_expressions_have_conflicting_owner_scope(
                &rule.expressions,
                owner_uid,
                owner_group_gids.as_slice(),
            ) {
                return Err(
                    "system firewall payload owner scope conflicts with authenticated caller",
                );
            }

            if !rule.expressions.is_empty() {
                Self::inject_firewall_expression_owner_uid_scope(rule, owner_uid);
                injected_count = injected_count.saturating_add(1);
                continue;
            }

            rule.parameters = if rule.parameters.trim().is_empty() {
                owner_fragment.clone()
            } else {
                format!("{} {}", owner_fragment, rule.parameters.trim())
            };
            injected_count = injected_count.saturating_add(1);
        }

        Ok(injected_count)
    }

    pub(crate) fn notification_action_allowed(config: &Config, action: CommandAction) -> bool {
        if matches!(config.auth_mode, AuthMode::Legacy) {
            return true;
        }

        if !Self::is_privileged_notification_action(action) {
            return true;
        }

        let client_addr = config.client_addr.as_str();
        if client_addr.starts_with("unix:") || client_addr.starts_with("unix-abstract:") {
            return Self::local_peer_principal_allowed(config);
        }
        if Self::try_loopback_tcp_listen_socket(client_addr).is_some() {
            return Self::local_peer_principal_allowed(config);
        }

        // In hardened modes, remote privileged actions are denied by this local-gate
        // path and are only allowed through explicit RemoteCert capability checks.
        false
    }

    pub(crate) fn classify_privileged_notification_action(
        session: &ClientSession,
        action: CommandAction,
        rules: &[RuleRecord],
        firewall: Option<&FirewallConfig>,
    ) -> (NotificationAuthorizationClass, &'static str) {
        let owner_uid = match &session.owner {
            ClientPrincipal::LocalUid(uid) => *uid,
            ClientPrincipal::RemoteCert { mapped_uid, .. } => *mapped_uid,
            _ => {
                return (
                    NotificationAuthorizationClass::AlwaysDenied,
                    "owner scope could not be established for this client",
                );
            }
        };

        match action {
            CommandAction::ChangeRule => {
                if rules.is_empty() {
                    return (
                        NotificationAuthorizationClass::AlwaysDenied,
                        "rule mutation payload is missing",
                    );
                }
                if !rules.iter().all(Self::rule_has_operand_semantics) {
                    return (
                        NotificationAuthorizationClass::AlwaysDenied,
                        "rule mutation payload has no operand semantics",
                    );
                }
                if rules
                    .iter()
                    .all(|rule| Self::rule_matches_owner_scope(rule, owner_uid))
                {
                    (
                        NotificationAuthorizationClass::UserScopedAllowed,
                        "rule mutation payload is provably owner-scoped",
                    )
                } else {
                    (
                        NotificationAuthorizationClass::ElevatedRequired,
                        "rule mutation payload is not provably scoped to the caller",
                    )
                }
            }
            CommandAction::EnableRule | CommandAction::DisableRule | CommandAction::DeleteRule => {
                if rules.is_empty() {
                    return (
                        NotificationAuthorizationClass::AlwaysDenied,
                        "rule mutation payload is missing",
                    );
                }
                if rules
                    .iter()
                    .all(|rule| Self::rule_matches_owner_scope(rule, owner_uid))
                {
                    (
                        NotificationAuthorizationClass::UserScopedAllowed,
                        "rule mutation payload is provably owner-scoped",
                    )
                } else {
                    (
                        NotificationAuthorizationClass::ElevatedRequired,
                        "rule mutation payload is not provably scoped to the caller",
                    )
                }
            }
            CommandAction::ReloadFwRules => {
                let Some(firewall) = firewall else {
                    return (
                        NotificationAuthorizationClass::AlwaysDenied,
                        "system firewall payload is missing",
                    );
                };
                if Self::firewall_matches_owner_scope(firewall, owner_uid) {
                    (
                        NotificationAuthorizationClass::UserScopedAllowed,
                        "system firewall payload is provably owner-scoped",
                    )
                } else {
                    (
                        NotificationAuthorizationClass::ElevatedRequired,
                        "system firewall payload is not provably scoped to the caller",
                    )
                }
            }
            CommandAction::EnableFirewall
            | CommandAction::DisableFirewall
            | CommandAction::EnableInterception
            | CommandAction::DisableInterception
            | CommandAction::ChangeConfig
            | CommandAction::TaskStart
            | CommandAction::TaskStop
            | CommandAction::LogLevel
            | CommandAction::Stop => (
                NotificationAuthorizationClass::ElevatedRequired,
                "requested command remains elevated in hardened authorization modes",
            ),
            _ => (
                NotificationAuthorizationClass::AlwaysAllowed,
                "notification action is always allowed",
            ),
        }
    }

    pub(crate) fn notification_command_allowed(
        config: &Config,
        session: &ClientSession,
        action: CommandAction,
        rules: &[RuleRecord],
        firewall: Option<&FirewallConfig>,
    ) -> std::result::Result<(), &'static str> {
        if matches!(config.auth_mode, AuthMode::Legacy)
            || !Self::is_privileged_notification_action(action)
        {
            return Ok(());
        }

        // Remote principal sessions are always authorized through capability policy,
        // independent of mapped UID or capability-list size.
        let is_remote_session = matches!(session.owner, ClientPrincipal::RemoteCert { .. });

        if !is_remote_session && !Self::notification_action_allowed(config, action) {
            return Err("auth mode / local principal policy denied the command");
        }

        let (class, reason) =
            Self::classify_privileged_notification_action(session, action, rules, firewall);

        if matches!(session.owner, ClientPrincipal::LocalUid(0)) {
            return match class {
                NotificationAuthorizationClass::AlwaysDenied => Err(reason),
                NotificationAuthorizationClass::AlwaysAllowed
                | NotificationAuthorizationClass::UserScopedAllowed
                | NotificationAuthorizationClass::ElevatedRequired => Ok(()),
            };
        }

        // Remote sessions require explicit capability grants for privileged
        // classes and do not inherit local-root bypass semantics.
        if is_remote_session {
            return Self::check_remote_capability_authorization(session, action, class, reason);
        }

        match class {
            NotificationAuthorizationClass::AlwaysAllowed
            | NotificationAuthorizationClass::UserScopedAllowed => Ok(()),
            NotificationAuthorizationClass::ElevatedRequired
            | NotificationAuthorizationClass::AlwaysDenied => Err(reason),
        }
    }

    fn check_remote_capability_authorization(
        session: &ClientSession,
        action: CommandAction,
        class: NotificationAuthorizationClass,
        reason: &'static str,
    ) -> std::result::Result<(), &'static str> {
        use crate::models::auth_capability::required_capability;

        match class {
            NotificationAuthorizationClass::AlwaysAllowed => Ok(()),
            NotificationAuthorizationClass::AlwaysDenied => Err(reason),
            NotificationAuthorizationClass::UserScopedAllowed
            | NotificationAuthorizationClass::ElevatedRequired => {
                let Some(cap) = required_capability(action, class) else {
                    return Err(reason);
                };
                if session.has_capability(cap) {
                    Ok(())
                } else {
                    Err("remote session lacks required capability for this command")
                }
            }
        }
    }

    pub(super) fn log_privileged_authorization_allow(
        config: &Config,
        session: &ClientSession,
        notification_id: u64,
        action: CommandAction,
    ) {
        if !Self::is_privileged_notification_action(action) {
            return;
        }

        let (nfqueue_overload_policy, ask_timeout_policy) =
            Self::verdict_fallback_log_context(config);

        if matches!(config.auth_mode, AuthMode::Legacy) {
            tracing::warn!(
                notification_id,
                action = action.as_name(),
                auth_mode = config.auth_mode.as_name(),
                nfqueue_overload_policy,
                ask_timeout_policy,
                owner = ?session.owner,
                "privileged notification command allowed in legacy compatibility mode"
            );
            return;
        }

        tracing::info!(
            notification_id,
            action = action.as_name(),
            auth_mode = config.auth_mode.as_name(),
            nfqueue_overload_policy,
            ask_timeout_policy,
            owner = ?session.owner,
            "privileged notification command authorized by local hardened policy"
        );
    }
}
