use std::sync::Arc;

use crate::models::firewall_state::FirewallState;

#[derive(Debug, Clone)]
pub(crate) struct FirewallRuntime {
    pub(crate) state: FirewallState,
    pub(crate) queue_num: u16,
    pub(crate) queue_bypass: bool,
    pub(crate) interception_enabled: bool,
    pub(crate) system_firewall: Arc<Option<opensnitch_proto::pb::SysFirewall>>,
}