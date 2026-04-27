use transport_wire_core::{WireSubscriptionAction, WireSubscriptionReply};

use super::record_to_wire;
use super::refresh_timing::build_refresh_message;
use super::reply::{base_reply, reply_with};
use crate::models::subscription::storage::SubscriptionRecord;
use crate::utils::sort_key::sort_by_string_key;

pub(super) fn empty_refresh_reply(explicit_targeting: bool) -> WireSubscriptionReply {
    base_reply(
        WireSubscriptionAction::Refresh,
        if explicit_targeting {
            "no matching subscriptions supplied"
        } else {
            "no subscriptions available"
        },
        false,
    )
}

pub(super) fn finalize_refresh_reply(
    mut subscriptions: Vec<SubscriptionRecord>,
    errors: Vec<String>,
    refreshed: usize,
    unchanged: usize,
    skipped: usize,
) -> WireSubscriptionReply {
    sort_by_string_key(&mut subscriptions, |sub| sub.id.as_str());
    let subscriptions = subscriptions.into_iter().map(record_to_wire).collect();
    let error_count = errors.len();
    let accepted = errors.is_empty();

    reply_with(
        WireSubscriptionAction::Refresh,
        build_refresh_message(refreshed, unchanged, skipped, error_count),
        accepted,
        subscriptions,
        errors,
    )
}
