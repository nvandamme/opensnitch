use std::sync::Arc;

use crate::platform::firewall::config::FirewallConfig;
use crate::platform::firewall::state::FirewallState;

#[derive(Debug, Clone)]
pub(crate) struct FirewallRuntime {
    pub(crate) state: FirewallState,
    pub(crate) queue_num: u16,
    pub(crate) queue_bypass: bool,
    pub(crate) interception_enabled: bool,
    pub(crate) system_firewall: Arc<Option<FirewallConfig>>,
}
