use super::notification::NotificationFlow;
use crate::models::command::action::CommandAction;

impl NotificationFlow {
    pub(super) fn is_privileged_notification_action(action: CommandAction) -> bool {
        matches!(
            action,
            CommandAction::EnableInterception
                | CommandAction::DisableInterception
                | CommandAction::EnableFirewall
                | CommandAction::DisableFirewall
                | CommandAction::ReloadFwRules
                | CommandAction::ChangeConfig
                | CommandAction::EnableRule
                | CommandAction::DisableRule
                | CommandAction::DeleteRule
                | CommandAction::ChangeRule
                | CommandAction::TaskStart
                | CommandAction::TaskStop
                | CommandAction::LogLevel
                | CommandAction::Stop
        )
    }

    pub(super) fn is_rule_mutation_action(action: CommandAction) -> bool {
        matches!(
            action,
            CommandAction::ChangeRule | CommandAction::EnableRule | CommandAction::DisableRule
        )
    }

    pub(super) fn is_rule_toggle_or_delete_action(action: CommandAction) -> bool {
        matches!(
            action,
            CommandAction::EnableRule | CommandAction::DisableRule | CommandAction::DeleteRule
        )
    }

    pub(super) fn is_firewall_reload_action(action: CommandAction) -> bool {
        matches!(action, CommandAction::ReloadFwRules)
    }
}
