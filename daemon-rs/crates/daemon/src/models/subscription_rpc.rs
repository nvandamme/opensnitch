use crate::models::subscription_storage::SubscriptionRecord;

// Shared subscription command model kept available across build profiles so the
// enabled and disabled subscription services expose the same API surface.
#[cfg_attr(not(feature = "subscriptions"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionOperation {
    Unspecified,
    List,
    Apply,
    Delete,
    Refresh,
    Deploy,
}

impl Default for SubscriptionOperation {
    fn default() -> Self {
        Self::Unspecified
    }
}

// Shared subscription command model kept available across build profiles so the
// enabled and disabled subscription services expose the same API surface.
#[cfg_attr(not(feature = "subscriptions"), allow(dead_code))]
#[derive(Clone, Debug, Default)]
pub struct SubscriptionCommand {
    pub operation: SubscriptionOperation,
    pub subscriptions: Vec<SubscriptionRecord>,
    pub targets: Vec<String>,
    pub force: bool,
}
