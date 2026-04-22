use opensnitch_proto::pb;

use super::reply::{base_reply, reply_with};
use super::refresh_timing::build_refresh_message;
use crate::utils::sort_key::sort_by_string_key;

pub(super) fn empty_refresh_reply(explicit_targeting: bool) -> pb::SubscriptionReply {
    base_reply(
        pb::SubscriptionOperation::Refresh,
        if explicit_targeting {
            "no matching subscriptions supplied"
        } else {
            "no subscriptions available"
        },
        false,
    )
}

pub(super) fn finalize_refresh_reply(
    mut subscriptions: Vec<pb::Subscription>,
    errors: Vec<String>,
    refreshed: usize,
    unchanged: usize,
    skipped: usize,
) -> pb::SubscriptionReply {
    sort_by_string_key(&mut subscriptions, |sub| sub.id.as_str());
    let error_count = errors.len();
    let accepted = errors.is_empty();

    reply_with(
        pb::SubscriptionOperation::Refresh,
        build_refresh_message(refreshed, unchanged, skipped, error_count),
        accepted,
        subscriptions,
        errors,
    )
}
