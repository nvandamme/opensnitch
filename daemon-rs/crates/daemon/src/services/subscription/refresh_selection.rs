use super::SubscriptionRecord;
use super::refresh_targets::{has_refresh_targeting, resolve_refresh_targets};
pub(super) use crate::models::subscription::refresh::RefreshSelection;

pub(super) fn select_refresh_targets(
    all_records: Vec<SubscriptionRecord>,
    items: &[SubscriptionRecord],
    targets: &[String],
) -> RefreshSelection {
    RefreshSelection {
        explicit_targeting: has_refresh_targeting(items, targets),
        selected: resolve_refresh_targets(all_records, items, targets),
    }
}
