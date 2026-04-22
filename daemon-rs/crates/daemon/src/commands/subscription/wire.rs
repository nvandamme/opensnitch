use opensnitch_proto::pb;
use crate::models::subscription_wire::{SubscriptionReplyWire, SubscriptionRequestWire};

pub(crate) fn parse_subscription_request_data(
    raw_data: &str,
) -> Result<pb::SubscriptionRequest, String> {
    let wire = serde_json::from_str::<SubscriptionRequestWire>(raw_data)
        .map_err(|err| format!("invalid subscription request payload: {err}"))?;
    Ok(wire.into_proto())
}

pub(crate) fn encode_subscription_reply_data(
    reply: &pb::SubscriptionReply,
) -> Result<String, String> {
    let wire = SubscriptionReplyWire::from_proto(reply.clone());
    serde_json::to_string(&wire).map_err(|err| err.to_string())
}
