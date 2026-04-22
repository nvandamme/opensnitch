use std::collections::HashSet;

use opensnitch_proto::pb;

use super::SubscriptionRecord;
use crate::utils::stable_id::hex_id_from_pair;
use crate::utils::string_iter::trimmed_non_empty;

fn subscription_selector_id(item: &pb::Subscription) -> Option<String> {
    let id = item.id.trim();
    if !id.is_empty() {
        return Some(id.to_string());
    }

    let url = item.url.trim();
    let name = item.name.trim();
    if url.is_empty() && name.is_empty() {
        return None;
    }

    Some(hex_id_from_pair(url, name))
}

pub(crate) fn has_refresh_targeting(items: &[pb::Subscription], targets: &[String]) -> bool {
    trimmed_non_empty(targets.iter().map(String::as_str)).next().is_some()
        || items
            .iter()
            .any(|item| subscription_selector_id(item).is_some())
}

pub(crate) fn resolve_refresh_targets(
    all_records: Vec<SubscriptionRecord>,
    items: &[pb::Subscription],
    targets: &[String],
) -> Vec<SubscriptionRecord> {
    let mut ids: HashSet<String> =
        trimmed_non_empty(targets.iter().map(String::as_str)).map(ToOwned::to_owned).collect();
    ids.extend(items.iter().filter_map(subscription_selector_id));

    if ids.is_empty() {
        return all_records;
    }

    all_records
        .into_iter()
        .filter(|record| ids.contains(&record.id))
        .collect()
}
