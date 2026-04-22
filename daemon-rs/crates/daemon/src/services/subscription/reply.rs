use opensnitch_proto::pb;

pub(super) fn base_reply(
    operation: pb::SubscriptionOperation,
    message: impl Into<String>,
    accepted: bool,
) -> pb::SubscriptionReply {
    pb::SubscriptionReply {
        operation: operation as i32,
        message: message.into(),
        accepted,
        ..Default::default()
    }
}

pub(super) fn reply_with(
    operation: pb::SubscriptionOperation,
    message: impl Into<String>,
    accepted: bool,
    subscriptions: Vec<pb::Subscription>,
    errors: Vec<String>,
) -> pb::SubscriptionReply {
    pb::SubscriptionReply {
        operation: operation as i32,
        message: message.into(),
        accepted,
        subscriptions,
        errors,
        ..Default::default()
    }
}