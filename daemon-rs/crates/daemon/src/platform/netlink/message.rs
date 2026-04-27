//! Netlink message types and consumer-facing traits.
//!
//! This module defines the trait hierarchy that consumers implement to
//! participate in the shared netlink infrastructure:
//!
//! - [`NetlinkMessage`] — stateful, non-cloneable wrapper around a decoded
//!   netlink message, exposing header fields and payload.
//! - [`NetlinkResponse`] — decode contract for structured reply messages
//!   received during request/reply iteration (zero-copy, borrows from buffer).
//! - [`NetlinkEvent`] — decode contract for multicast event messages received
//!   on subscription sockets.  Includes built-in control-message filtering.
//!
//! For the request side, consumers implement
//! [`netlink_bindings::traits::NetlinkRequest`] directly (re-exported from
//! [`super::io`] as [`NetlinkRequest`](super::io::NetlinkRequest)).

use anyhow::Result;

use super::control::classify_nlmsg_control;

// ─── NetlinkMessage ───────────────────────────────────────────────────────────

/// A decoded netlink message exposing header fields and payload.
///
/// Not `Clone` — consumers borrow from the underlying receive buffer.
/// Produced by [`NlmsgIter`](super::wire::NlmsgIter) when iterating over
/// raw netlink datagrams.
#[allow(dead_code)]
pub(crate) struct NetlinkMessage<'buf> {
    pub(crate) msg_type: u16,
    pub(crate) flags: u16,
    pub(crate) seq: u32,
    pub(crate) payload: &'buf [u8],
}

// ─── NetlinkResponse ──────────────────────────────────────────────────────────

/// Decode contract for structured netlink reply messages.
///
/// Protocol adapters implement this on their response types to provide
/// zero-copy decode from a [`NetlinkMessage`].  The netlink module's
/// iteration helpers work with any `NetlinkResponse` implementor.
///
/// ## Message type hierarchy
///
/// Response handling follows one of three paths (in preference order):
///
/// 1. **Binding families** — reply types provided directly by
///    `netlink-bindings` feature modules (`rt_link`, `rt_addr`, `inet_diag`,
///    `nftables`, …).  Already fully typed; no `NetlinkResponse` impl needed.
/// 2. **`NetlinkResponse` implementors** — protocol adapters define their own
///    response types and implement this trait for structured zero-copy decode.
/// 3. **`RawNetlinkPayload`** — zero-copy byte-slice passthrough for payloads
///    that require fully internal parsing.  Discouraged; prefer adding a
///    structured impl or binding coverage instead.
pub(crate) trait NetlinkResponse<'buf>: Sized {
    /// Decode a structured message from a [`NetlinkMessage`].
    ///
    /// Returns `None` when the message does not contain a valid payload
    /// of this type (length too short, missing mandatory attributes, wrong
    /// message type, etc.).
    fn decode(msg: &NetlinkMessage<'buf>) -> Option<Self>;
}

/// Decode a [`NetlinkMessage`] into a structured [`NetlinkResponse`] type.
///
/// Convenience wrapper that dispatches to the implementor's
/// [`NetlinkResponse::decode`].
#[inline]
#[allow(dead_code)]
pub(crate) fn decode_response<'buf, R: NetlinkResponse<'buf>>(
    msg: &NetlinkMessage<'buf>,
) -> Option<R> {
    R::decode(msg)
}

// ─── RawNetlinkPayload ────────────────────────────────────────────────────────

/// Raw netlink payload wrapper.  Implements [`NetlinkResponse`] as a trivial
/// passthrough — prefer a typed impl when possible.
#[derive(Debug)]
pub(crate) struct RawNetlinkPayload<'a> {
    pub(crate) payload: &'a [u8],
}

impl<'a> RawNetlinkPayload<'a> {
    pub(crate) fn load(payload: &'a [u8]) -> Self {
        Self { payload }
    }
}

impl<'buf> NetlinkResponse<'buf> for RawNetlinkPayload<'buf> {
    fn decode(msg: &NetlinkMessage<'buf>) -> Option<Self> {
        Some(Self {
            payload: msg.payload,
        })
    }
}

// ─── NetlinkEvent ─────────────────────────────────────────────────────────────

/// Decode contract for multicast netlink event messages.
///
/// Consumers implement this on their owned event types to participate in
/// the shared multicast receive infrastructure.  Unlike [`NetlinkResponse`],
/// event types produce owned values (no lifetime parameter) and include
/// built-in control-message filtering via the default
/// [`decode_from_raw`](NetlinkEvent::decode_from_raw) method.
///
/// ## Required
///
/// Implement [`decode_event`](NetlinkEvent::decode_event) with the
/// protocol-specific decode logic.  The method receives a message type and
/// payload that have already passed control-message filtering.
///
/// ## Provided
///
/// [`decode_from_raw`](NetlinkEvent::decode_from_raw) handles NLMSG_ERROR /
/// NLMSG_NOOP / NLMSG_DONE filtering, then delegates to `decode_event`.
/// Consumers typically call this entry point and don't override it.
pub(crate) trait NetlinkEvent: Sized {
    /// Decode an event from a netlink message that has already passed
    /// control-message filtering.
    ///
    /// Returns `Ok(None)` for message types that are valid but not relevant
    /// to this event type.
    fn decode_event(msg_type: u16, payload: &[u8]) -> Result<Option<Self>>;

    /// Decode an event from a raw netlink datagram message.
    ///
    /// Filters out control messages (NLMSG_ERROR, NLMSG_NOOP, NLMSG_DONE)
    /// before delegating to [`decode_event`](NetlinkEvent::decode_event).
    fn decode_from_raw(msg_type: u16, payload: &[u8]) -> Result<Option<Self>> {
        use super::control::NetlinkControlFlow;

        match classify_nlmsg_control(msg_type, payload)? {
            NetlinkControlFlow::Process => Self::decode_event(msg_type, payload),
            NetlinkControlFlow::Ignore => Ok(None),
        }
    }
}
