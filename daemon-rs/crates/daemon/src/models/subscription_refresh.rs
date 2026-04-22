use opensnitch_proto::pb;

use crate::models::subscription_storage::SubscriptionRecord;

pub(crate) struct RefreshSelection {
    pub explicit_targeting: bool,
    pub selected: Vec<SubscriptionRecord>,
}

pub(crate) struct RefreshBatchResult {
    pub refreshed: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
    pub updated: Vec<pb::Subscription>,
    pub sync_layout: bool,
}

pub(crate) enum RefreshOutcome {
    Downloaded,
    NotModified,
}
