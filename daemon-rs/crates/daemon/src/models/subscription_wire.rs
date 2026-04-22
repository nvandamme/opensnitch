use opensnitch_proto::pb;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubscriptionRefreshMetaWire {
    #[serde(default)]
    next_refresh_after: i64,
    #[serde(default)]
    consecutive_failures: u32,
    #[serde(default)]
    etag: String,
    #[serde(default)]
    last_modified: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubscriptionWire {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    format: String,
    #[serde(default)]
    interval_seconds: u32,
    #[serde(default)]
    timeout_seconds: u32,
    #[serde(default)]
    max_bytes: u64,
    #[serde(default)]
    node: String,
    #[serde(default)]
    status: i32,
    #[serde(default)]
    last_updated: String,
    #[serde(default)]
    last_error: String,
    #[serde(default)]
    refresh_meta: Option<SubscriptionRefreshMetaWire>,
}

impl SubscriptionWire {
    fn into_proto(self) -> pb::Subscription {
        pb::Subscription {
            id: self.id,
            name: self.name,
            url: self.url,
            filename: self.filename,
            groups: self.groups,
            enabled: self.enabled,
            format: self.format,
            interval_seconds: self.interval_seconds,
            timeout_seconds: self.timeout_seconds,
            max_bytes: self.max_bytes,
            node: self.node,
            status: self.status,
            last_updated: self.last_updated,
            last_error: self.last_error,
            refresh_meta: self
                .refresh_meta
                .map(|meta| pb::SubscriptionRefreshMetadata {
                    next_refresh_after: meta.next_refresh_after,
                    consecutive_failures: meta.consecutive_failures,
                    etag: meta.etag,
                    last_modified: meta.last_modified,
                }),
        }
    }

    fn from_proto(subscription: pb::Subscription) -> Self {
        Self {
            id: subscription.id,
            name: subscription.name,
            url: subscription.url,
            filename: subscription.filename,
            groups: subscription.groups,
            enabled: subscription.enabled,
            format: subscription.format,
            interval_seconds: subscription.interval_seconds,
            timeout_seconds: subscription.timeout_seconds,
            max_bytes: subscription.max_bytes,
            node: subscription.node,
            status: subscription.status,
            last_updated: subscription.last_updated,
            last_error: subscription.last_error,
            refresh_meta: subscription
                .refresh_meta
                .map(|meta| SubscriptionRefreshMetaWire {
                    next_refresh_after: meta.next_refresh_after,
                    consecutive_failures: meta.consecutive_failures,
                    etag: meta.etag,
                    last_modified: meta.last_modified,
                }),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SubscriptionRequestWire {
    #[serde(default)]
    operation: i32,
    #[serde(default)]
    subscriptions: Vec<SubscriptionWire>,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    force: bool,
}

impl SubscriptionRequestWire {
    pub(crate) fn into_proto(self) -> pb::SubscriptionRequest {
        pb::SubscriptionRequest {
            operation: self.operation,
            subscriptions: self
                .subscriptions
                .into_iter()
                .map(SubscriptionWire::into_proto)
                .collect(),
            targets: self.targets,
            force: self.force,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SubscriptionReplyWire {
    #[serde(default)]
    operation: i32,
    #[serde(default)]
    subscriptions: Vec<SubscriptionWire>,
    #[serde(default)]
    errors: Vec<String>,
    #[serde(default)]
    message: String,
    #[serde(default)]
    accepted: bool,
}

impl SubscriptionReplyWire {
    pub(crate) fn from_proto(reply: pb::SubscriptionReply) -> Self {
        Self {
            operation: reply.operation,
            subscriptions: reply
                .subscriptions
                .into_iter()
                .map(SubscriptionWire::from_proto)
                .collect(),
            errors: reply.errors,
            message: reply.message,
            accepted: reply.accepted,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn into_proto(self) -> pb::SubscriptionReply {
        pb::SubscriptionReply {
            operation: self.operation,
            subscriptions: self
                .subscriptions
                .into_iter()
                .map(SubscriptionWire::into_proto)
                .collect(),
            errors: self.errors,
            message: self.message,
            accepted: self.accepted,
        }
    }
}
