#![cfg_attr(not(feature = "subscriptions"), allow(dead_code))]

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
    pub updated: Vec<SubscriptionRecord>,
    pub sync_layout: bool,
}

pub(crate) enum RefreshOutcome {
    Downloaded,
    NotModified,
}
