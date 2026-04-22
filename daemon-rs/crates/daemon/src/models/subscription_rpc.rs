use crate::models::subscription_storage::SubscriptionRecord;

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

#[derive(Clone, Debug, Default)]
pub struct SubscriptionCommand {
    pub operation: SubscriptionOperation,
    pub subscriptions: Vec<SubscriptionRecord>,
    pub targets: Vec<String>,
    pub force: bool,
}
