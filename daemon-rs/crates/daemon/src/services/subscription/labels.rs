use super::SubscriptionRecord;

pub(super) fn subscription_label(record: &SubscriptionRecord) -> &str {
    [record.name.as_str(), record.filename.as_str()]
        .into_iter()
        .find(|value| !value.is_empty())
        .unwrap_or(record.id.as_str())
}
