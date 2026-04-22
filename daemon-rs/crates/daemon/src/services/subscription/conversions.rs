use transport_wire_core::{
    WireSubscription, WireSubscriptionAction, WireSubscriptionRefreshMetadata,
};

use super::defaults::{DEFAULT_INTERVAL_SECONDS, DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_SECONDS};
use super::format::normalize_format;
pub(crate) use crate::models::subscription_storage::SubscriptionRecord;
use crate::utils::name_parsing::sanitize_ascii_name;
use crate::utils::stable_id::hex_id_from_pair;
use crate::utils::time_nonce::now_rfc3339_utc;

const SUBSCRIPTION_STATUS_UNSPECIFIED: i32 = 0;
const SUBSCRIPTION_STATUS_PENDING: i32 = 1;
const SUBSCRIPTION_STATUS_READY: i32 = 2;
const SUBSCRIPTION_STATUS_SYNCING: i32 = 3;
const SUBSCRIPTION_STATUS_ERROR: i32 = 4;

pub(crate) fn record_to_wire(record: SubscriptionRecord) -> WireSubscription {
    WireSubscription {
        id: record.id,
        name: record.name,
        url: record.url,
        filename: record.filename,
        groups: record.groups,
        enabled: record.enabled,
        format: record.format,
        interval_seconds: record.interval_seconds,
        timeout_seconds: record.timeout_seconds,
        max_bytes: record.max_bytes,
        node: record.node,
        status: subscription_status_code_from_str(&record.status),
        last_updated: record.last_updated,
        last_error: record.last_error,
        refresh_meta: Some(WireSubscriptionRefreshMetadata {
            next_refresh_after: record.next_refresh_after,
            consecutive_failures: record.consecutive_failures,
            etag: record.etag,
            last_modified: record.last_modified,
        }),
    }
}

pub(crate) fn wire_subscription_from_record(record: &SubscriptionRecord) -> WireSubscription {
    record_to_wire(record.clone())
}

pub(crate) fn record_from_wire(subscription: WireSubscription) -> SubscriptionRecord {
    let id = ensure_id(&subscription);
    let filename = ensure_filename(&subscription);
    let WireSubscription {
        id: _,
        name,
        url,
        filename: _,
        groups,
        enabled,
        format,
        interval_seconds,
        timeout_seconds,
        max_bytes,
        node,
        status,
        last_updated,
        last_error,
        refresh_meta,
    } = subscription;
    let refresh_meta = refresh_meta.unwrap_or_default();

    SubscriptionRecord {
        id,
        name,
        url,
        filename,
        groups,
        enabled,
        format: normalize_format(&format),
        interval_seconds: if interval_seconds == 0 {
            DEFAULT_INTERVAL_SECONDS
        } else {
            interval_seconds
        },
        timeout_seconds: if timeout_seconds == 0 {
            DEFAULT_TIMEOUT_SECONDS
        } else {
            timeout_seconds
        },
        max_bytes: if max_bytes == 0 {
            DEFAULT_MAX_BYTES
        } else {
            max_bytes
        },
        node,
        status: subscription_status_to_str(status),
        last_updated: if last_updated.is_empty() {
            now_rfc3339_utc()
        } else {
            last_updated
        },
        last_error,
        etag: refresh_meta.etag,
        last_modified: refresh_meta.last_modified,
        next_refresh_after: refresh_meta.next_refresh_after,
        consecutive_failures: refresh_meta.consecutive_failures,
    }
}

pub(crate) fn subscription_status_to_str(status: i32) -> String {
    match status {
        SUBSCRIPTION_STATUS_PENDING => "pending",
        SUBSCRIPTION_STATUS_READY => "ready",
        SUBSCRIPTION_STATUS_SYNCING => "syncing",
        SUBSCRIPTION_STATUS_ERROR => "error",
        _ => "unspecified",
    }
    .to_string()
}

pub(crate) fn subscription_status_code_from_str(status: &str) -> i32 {
    match status {
        "pending" => SUBSCRIPTION_STATUS_PENDING,
        "ready" => SUBSCRIPTION_STATUS_READY,
        "syncing" => SUBSCRIPTION_STATUS_SYNCING,
        "error" => SUBSCRIPTION_STATUS_ERROR,
        _ => SUBSCRIPTION_STATUS_UNSPECIFIED,
    }
}

pub(crate) fn wire_subscription_action_from_i32(value: i32) -> WireSubscriptionAction {
    match value {
        x if x == WireSubscriptionAction::List as i32 => WireSubscriptionAction::List,
        x if x == WireSubscriptionAction::Apply as i32 => WireSubscriptionAction::Apply,
        x if x == WireSubscriptionAction::Delete as i32 => WireSubscriptionAction::Delete,
        x if x == WireSubscriptionAction::Refresh as i32 => WireSubscriptionAction::Refresh,
        x if x == WireSubscriptionAction::Deploy as i32 => WireSubscriptionAction::Deploy,
        _ => WireSubscriptionAction::Unspecified,
    }
}

pub(crate) fn operation_from_wire_action(
    action: WireSubscriptionAction,
) -> crate::models::subscription_rpc::SubscriptionOperation {
    use crate::models::subscription_rpc::SubscriptionOperation;

    match action {
        WireSubscriptionAction::Unspecified => SubscriptionOperation::Unspecified,
        WireSubscriptionAction::List => SubscriptionOperation::List,
        WireSubscriptionAction::Apply => SubscriptionOperation::Apply,
        WireSubscriptionAction::Delete => SubscriptionOperation::Delete,
        WireSubscriptionAction::Refresh => SubscriptionOperation::Refresh,
        WireSubscriptionAction::Deploy => SubscriptionOperation::Deploy,
    }
}

fn ensure_id(subscription: &WireSubscription) -> String {
    if !subscription.id.is_empty() {
        subscription.id.clone()
    } else {
        hex_id_from_pair(&subscription.url, &subscription.name)
    }
}

fn ensure_filename(subscription: &WireSubscription) -> String {
    if !subscription.filename.is_empty() {
        return subscription.filename.clone();
    }
    derive_filename(subscription)
}

fn derive_filename(subscription: &WireSubscription) -> String {
    if !subscription.name.is_empty() {
        return sanitize_ascii_name(&subscription.name);
    }
    let path = subscription
        .url
        .split('?')
        .next()
        .unwrap_or(&subscription.url)
        .trim_end_matches('/');
    let last = path.rsplit('/').next().unwrap_or(path);
    if !last.is_empty() {
        return sanitize_ascii_name(last);
    }
    hex_id_from_pair(&subscription.url, &subscription.name)
}
