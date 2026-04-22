use crate::models::subscription_storage::SubscriptionRecord;

// Subscription refresh planning type used by the optional subscriptions runtime.
#[allow(dead_code)]
pub(crate) struct RefreshSelection {
    pub explicit_targeting: bool,
    pub selected: Vec<SubscriptionRecord>,
}

// Subscription refresh execution summary used by the optional subscriptions runtime.
#[allow(dead_code)]
pub(crate) struct RefreshBatchResult {
    pub refreshed: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
    pub updated: Vec<SubscriptionRecord>,
    pub sync_layout: bool,
}

// Subscription refresh outcome contract used by the optional subscriptions runtime.
#[allow(dead_code)]
pub(crate) enum RefreshOutcome {
    Downloaded,
    NotModified,
}
