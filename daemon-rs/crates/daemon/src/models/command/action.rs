/// Canonical domain discriminant for a daemon control command.
///
/// All notification flow policy logic (authorization, classification, owner-scope
/// normalization) operates on this type rather than the wire-level `pb::Action`
/// proto enum.  Mapping between wire types and this domain enum lives in the
/// notification ingress code (`flows/notification/`) — this model is proto-free.
///
/// The name is intentionally transport-neutral: these are **commands** directed at
/// the daemon, not "notifications" (which is the UI-transport framing).  The type
/// acts as a discriminant (`CommandAction`) that drives policy before the full
/// `ClientCommand` (with payload) is assembled and dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandAction {
    None,
    EnableInterception,
    DisableInterception,
    EnableFirewall,
    DisableFirewall,
    ReloadFwRules,
    ChangeConfig,
    EnableRule,
    DisableRule,
    DeleteRule,
    ChangeRule,
    TaskStart,
    TaskStop,
    LogLevel,
    Stop,
}

impl CommandAction {
    /// Returns a stable human-readable name suitable for structured logging.
    pub fn as_name(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::EnableInterception => "ENABLE_INTERCEPTION",
            Self::DisableInterception => "DISABLE_INTERCEPTION",
            Self::EnableFirewall => "ENABLE_FIREWALL",
            Self::DisableFirewall => "DISABLE_FIREWALL",
            Self::ReloadFwRules => "RELOAD_FW_RULES",
            Self::ChangeConfig => "CHANGE_CONFIG",
            Self::EnableRule => "ENABLE_RULE",
            Self::DisableRule => "DISABLE_RULE",
            Self::DeleteRule => "DELETE_RULE",
            Self::ChangeRule => "CHANGE_RULE",
            Self::TaskStart => "TASK_START",
            Self::TaskStop => "TASK_STOP",
            Self::LogLevel => "LOG_LEVEL",
            Self::Stop => "STOP",
        }
    }
}
