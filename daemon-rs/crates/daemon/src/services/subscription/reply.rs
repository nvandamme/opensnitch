use transport_wire_core::{WireSubscription, WireSubscriptionAction, WireSubscriptionReply};

pub(super) fn base_reply(
    operation: WireSubscriptionAction,
    message: impl Into<String>,
    accepted: bool,
) -> WireSubscriptionReply {
    WireSubscriptionReply {
        operation: operation as i32,
        message: message.into(),
        accepted,
        ..Default::default()
    }
}

pub(super) fn reply_with(
    operation: WireSubscriptionAction,
    message: impl Into<String>,
    accepted: bool,
    subscriptions: Vec<WireSubscription>,
    errors: Vec<String>,
) -> WireSubscriptionReply {
    WireSubscriptionReply {
        operation: operation as i32,
        message: message.into(),
        accepted,
        subscriptions,
        errors,
        ..Default::default()
    }
}
