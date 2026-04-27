/// Canonical capability names for privileged client authorization.
///
/// Each capability string corresponds to a specific class of daemon mutation.
/// Capabilities are granted via `RemotePrincipalBindings` in daemon config and
/// checked at notification ingress when a remote session attempts a privileged
/// command.
///
/// See DESIGN_RULES §8 — Remote Node Authorization Rule for the capability model.

/// Owner-scoped rule mutations (update/enable/disable/delete rules that are
/// provably scoped to the mapped local principal's UID/GID).
pub const CAP_RULES_OWNER_WRITE: &str = "rules.owner.write";

/// Global/shared rule mutations (rules that affect all users or cannot be proven
/// owner-scoped). Requires explicit elevated authorization.
pub const CAP_RULES_GLOBAL_WRITE: &str = "rules.global.write";

/// Owner-scoped firewall mutations (firewall rules containing socket-owner
/// matches that target only the mapped local principal's UID/GID).
pub const CAP_FIREWALL_OWNER_WRITE: &str = "firewall.owner.write";

/// Global/shared firewall mutations (chain policy edits, table management, or
/// rules that affect all traffic). Requires explicit elevated authorization.
pub const CAP_FIREWALL_GLOBAL_WRITE: &str = "firewall.global.write";

/// Daemon runtime configuration mutations (`ChangeConfig`).
pub const CAP_CONFIG_WRITE: &str = "config.write";

/// Daemon lifecycle control (stop/shutdown).
pub const CAP_DAEMON_CONTROL_STOP: &str = "daemon.control.stop";

/// Task lifecycle control (start/stop managed tasks).
pub const CAP_TASK_CONTROL: &str = "task.control";

/// Log-level runtime mutation.
pub const CAP_LOG_LEVEL: &str = "log.level";

/// Firewall enable/disable toggle.
pub const CAP_FIREWALL_TOGGLE: &str = "firewall.toggle";

/// Interception enable/disable toggle.
pub const CAP_INTERCEPTION_TOGGLE: &str = "interception.toggle";

use crate::flows::notification::notification::NotificationAuthorizationClass;
use crate::models::command::action::CommandAction;

/// Returns the capability required for a given command action and authorization class.
///
/// For `UserScopedAllowed` mutations, the owner-scoped capability is returned.
/// For `ElevatedRequired` mutations, the global/elevated capability is returned.
/// Returns `None` for `AlwaysAllowed` or `AlwaysDenied` classifications (those
/// are handled without capability checks).
pub fn required_capability(
    action: CommandAction,
    class: NotificationAuthorizationClass,
) -> Option<&'static str> {
    match (action, class) {
        (_, NotificationAuthorizationClass::AlwaysAllowed)
        | (_, NotificationAuthorizationClass::AlwaysDenied) => None,

        // Rule mutations
        (CommandAction::ChangeRule, NotificationAuthorizationClass::UserScopedAllowed)
        | (CommandAction::EnableRule, NotificationAuthorizationClass::UserScopedAllowed)
        | (CommandAction::DisableRule, NotificationAuthorizationClass::UserScopedAllowed)
        | (CommandAction::DeleteRule, NotificationAuthorizationClass::UserScopedAllowed) => {
            Some(CAP_RULES_OWNER_WRITE)
        }
        (CommandAction::ChangeRule, NotificationAuthorizationClass::ElevatedRequired)
        | (CommandAction::EnableRule, NotificationAuthorizationClass::ElevatedRequired)
        | (CommandAction::DisableRule, NotificationAuthorizationClass::ElevatedRequired)
        | (CommandAction::DeleteRule, NotificationAuthorizationClass::ElevatedRequired) => {
            Some(CAP_RULES_GLOBAL_WRITE)
        }

        // Firewall reload
        (CommandAction::ReloadFwRules, NotificationAuthorizationClass::UserScopedAllowed) => {
            Some(CAP_FIREWALL_OWNER_WRITE)
        }
        (CommandAction::ReloadFwRules, NotificationAuthorizationClass::ElevatedRequired) => {
            Some(CAP_FIREWALL_GLOBAL_WRITE)
        }

        // Always-elevated commands
        (CommandAction::EnableFirewall, NotificationAuthorizationClass::ElevatedRequired)
        | (CommandAction::DisableFirewall, NotificationAuthorizationClass::ElevatedRequired) => {
            Some(CAP_FIREWALL_TOGGLE)
        }
        (CommandAction::EnableInterception, NotificationAuthorizationClass::ElevatedRequired)
        | (CommandAction::DisableInterception, NotificationAuthorizationClass::ElevatedRequired) => {
            Some(CAP_INTERCEPTION_TOGGLE)
        }
        (CommandAction::ChangeConfig, NotificationAuthorizationClass::ElevatedRequired) => {
            Some(CAP_CONFIG_WRITE)
        }
        (CommandAction::Stop, NotificationAuthorizationClass::ElevatedRequired) => {
            Some(CAP_DAEMON_CONTROL_STOP)
        }
        (CommandAction::TaskStart, NotificationAuthorizationClass::ElevatedRequired)
        | (CommandAction::TaskStop, NotificationAuthorizationClass::ElevatedRequired) => {
            Some(CAP_TASK_CONTROL)
        }
        (CommandAction::LogLevel, NotificationAuthorizationClass::ElevatedRequired) => {
            Some(CAP_LOG_LEVEL)
        }

        // Remaining cases — conservatively require elevated config.write
        (_, NotificationAuthorizationClass::UserScopedAllowed)
        | (_, NotificationAuthorizationClass::ElevatedRequired) => Some(CAP_CONFIG_WRITE),
    }
}
