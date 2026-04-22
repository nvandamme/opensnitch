use opensnitch_proto::pb;

use super::defaults::{DEFAULT_INTERVAL_SECONDS, DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_SECONDS};
use super::format::normalize_format;
pub(crate) use crate::models::subscription_storage::SubscriptionRecord;
use crate::utils::name_parsing::sanitize_ascii_name;
use crate::utils::stable_id::hex_id_from_pair;
use crate::utils::time_nonce::now_rfc3339_utc;

pub(crate) fn record_to_proto(r: &SubscriptionRecord) -> pb::Subscription {
    pb::Subscription {
        id: r.id.clone(),
        name: r.name.clone(),
        url: r.url.clone(),
        filename: r.filename.clone(),
        groups: r.groups.clone(),
        enabled: r.enabled,
        format: r.format.clone(),
        interval_seconds: r.interval_seconds,
        timeout_seconds: r.timeout_seconds,
        max_bytes: r.max_bytes,
        node: r.node.clone(),
        status: subscription_status_from_str(&r.status) as i32,
        last_updated: r.last_updated.clone(),
        last_error: r.last_error.clone(),
        refresh_meta: Some(pb::SubscriptionRefreshMetadata {
            next_refresh_after: r.next_refresh_after,
            consecutive_failures: r.consecutive_failures,
            etag: r.etag.clone(),
            last_modified: r.last_modified.clone(),
        }),
    }
}

pub(crate) fn proto_to_record(p: &pb::Subscription) -> SubscriptionRecord {
    let status =
        pb::SubscriptionStatus::try_from(p.status).unwrap_or(pb::SubscriptionStatus::Unspecified);
    SubscriptionRecord {
        id: ensure_id(p),
        name: p.name.clone(),
        url: p.url.clone(),
        filename: ensure_filename(p),
        groups: p.groups.clone(),
        enabled: p.enabled,
        format: normalize_format(&p.format),
        interval_seconds: if p.interval_seconds == 0 {
            DEFAULT_INTERVAL_SECONDS
        } else {
            p.interval_seconds
        },
        timeout_seconds: if p.timeout_seconds == 0 {
            DEFAULT_TIMEOUT_SECONDS
        } else {
            p.timeout_seconds
        },
        max_bytes: if p.max_bytes == 0 {
            DEFAULT_MAX_BYTES
        } else {
            p.max_bytes
        },
        node: p.node.clone(),
        status: subscription_status_to_str(status),
        last_updated: if p.last_updated.is_empty() {
            now_rfc3339_utc()
        } else {
            p.last_updated.clone()
        },
        last_error: p.last_error.clone(),
        etag: p
            .refresh_meta
            .as_ref()
            .map(|m| m.etag.clone())
            .unwrap_or_default(),
        last_modified: p
            .refresh_meta
            .as_ref()
            .map(|m| m.last_modified.clone())
            .unwrap_or_default(),
        next_refresh_after: p
            .refresh_meta
            .as_ref()
            .map(|m| m.next_refresh_after)
            .unwrap_or_default(),
        consecutive_failures: p
            .refresh_meta
            .as_ref()
            .map(|m| m.consecutive_failures)
            .unwrap_or_default(),
    }
}

pub(crate) fn subscription_status_to_str(status: pb::SubscriptionStatus) -> String {
    match status {
        pb::SubscriptionStatus::Pending => "pending",
        pb::SubscriptionStatus::Ready => "ready",
        pb::SubscriptionStatus::Syncing => "syncing",
        pb::SubscriptionStatus::Error => "error",
        pb::SubscriptionStatus::Unspecified => "unspecified",
    }
    .to_string()
}

pub(crate) fn subscription_status_from_str(s: &str) -> pb::SubscriptionStatus {
    match s {
        "pending" => pb::SubscriptionStatus::Pending,
        "ready" => pb::SubscriptionStatus::Ready,
        "syncing" => pb::SubscriptionStatus::Syncing,
        "error" => pb::SubscriptionStatus::Error,
        _ => pb::SubscriptionStatus::Unspecified,
    }
}

fn ensure_id(p: &pb::Subscription) -> String {
    if !p.id.is_empty() {
        p.id.clone()
    } else {
        hex_id_from_pair(&p.url, &p.name)
    }
}

fn ensure_filename(p: &pb::Subscription) -> String {
    if !p.filename.is_empty() {
        return p.filename.clone();
    }
    derive_filename(p)
}

fn derive_filename(p: &pb::Subscription) -> String {
    if !p.name.is_empty() {
        return sanitize_ascii_name(&p.name);
    }
    let path = p
        .url
        .split('?')
        .next()
        .unwrap_or(&p.url)
        .trim_end_matches('/');
    let last = path.rsplit('/').next().unwrap_or(path);
    if !last.is_empty() {
        return sanitize_ascii_name(last);
    }
    hex_id_from_pair(&p.url, &p.name)
}
