use std::time::Duration;

use anyhow::{Result, anyhow};

pub(crate) use netlink_socket2::{MulticastSocketRaw, NetlinkSocket, ReplyError};

pub(crate) use netlink_bindings::traits::{NetlinkRequest, Protocol};

#[allow(unused_imports)]
pub(crate) use super::message::{
    NetlinkEvent, NetlinkMessage, NetlinkResponse, RawNetlinkPayload, decode_response,
};

pub(crate) async fn recv_with_timeout<T, E>(
    timeout: Duration,
    recv: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<Option<T>>
where
    E: Into<anyhow::Error>,
{
    match tokio::time::timeout(timeout, recv).await {
        Ok(Ok(value)) => Ok(Some(value)),
        Ok(Err(err)) => Err(err.into()),
        Err(_) => Ok(None),
    }
}

pub(crate) async fn request_with_ack_timeout<R>(
    sock: &mut NetlinkSocket,
    request: &R,
    timeout: Duration,
    request_timeout_message: &'static str,
    ack_timeout_message: &'static str,
) -> Result<()>
where
    R: NetlinkRequest,
{
    let mut iter = tokio::time::timeout(timeout, sock.request(request))
        .await
        .map_err(|_| anyhow!(request_timeout_message))??;
    tokio::time::timeout(timeout, iter.recv_ack())
        .await
        .map_err(|_| anyhow!(ack_timeout_message))?
        .map_err(anyhow::Error::new)?;
    Ok(())
}

pub(crate) async fn request_with_ack<R, MapIo, MapReply>(
    sock: &mut NetlinkSocket,
    request: &R,
    map_io: MapIo,
    map_reply: MapReply,
) -> Result<()>
where
    R: NetlinkRequest,
    MapIo: FnOnce(std::io::Error) -> anyhow::Error,
    MapReply: Fn(ReplyError) -> anyhow::Error,
{
    let mut reply = sock.request(request).await.map_err(map_io)?;
    reply.recv_ack().await.map_err(map_reply)?;
    Ok(())
}

pub(crate) fn open_multicast_socket(protocol: u16) -> Result<MulticastSocketRaw> {
    MulticastSocketRaw::new(protocol).map_err(anyhow::Error::new)
}

pub(crate) fn open_and_listen_multicast_socket(
    protocol: u16,
    group: u32,
) -> Result<MulticastSocketRaw> {
    let mut sock = open_multicast_socket(protocol)?;
    sock.listen(group).map_err(anyhow::Error::new)?;
    Ok(sock)
}

pub(crate) fn reply_errno(err: &ReplyError) -> i32 {
    err.as_io_error().raw_os_error().unwrap_or_default()
}

pub(crate) fn reply_extack_message(err: &ReplyError) -> String {
    err.ext_ack()
        .and_then(|attrs| attrs.get_msg().ok())
        .map(|msg| msg.to_string_lossy().into_owned())
        .unwrap_or_else(|| "-".to_string())
}

macro_rules! netlink_map_io_error {
    ($action:expr, $message:expr $(, $field:ident = $value:expr )* $(,)?) => {
        |err: std::io::Error| {
            tracing::warn!(
                action = $action,
                $( $field = $value, )*
                detail = %err,
                $message
            );
            anyhow::Error::new(err)
        }
    };
}

macro_rules! netlink_map_reply_error {
    ($action:expr, $message:expr $(, $field:ident = $value:expr )* $(,)?) => {
        |err: crate::platform::netlink::io::ReplyError| {
            tracing::warn!(
                action = $action,
                $( $field = $value, )*
                errno = crate::platform::netlink::io::reply_errno(&err),
                extack = %crate::platform::netlink::io::reply_extack_message(&err),
                detail = %err,
                $message
            );
            anyhow::Error::new(err)
        }
    };
}

pub(crate) use netlink_map_io_error;
pub(crate) use netlink_map_reply_error;

pub(crate) async fn for_each_reply<R, OnReply, MapIo, MapReply>(
    sock: &mut NetlinkSocket,
    request: &R,
    map_io: MapIo,
    map_reply: MapReply,
    mut on_reply: OnReply,
) -> Result<()>
where
    R: NetlinkRequest,
    for<'buf> OnReply: FnMut(R::ReplyType<'buf>) -> Result<()>,
    MapIo: FnOnce(std::io::Error) -> anyhow::Error,
    MapReply: Fn(ReplyError) -> anyhow::Error,
{
    let mut iter = sock.request(request).await.map_err(map_io)?;
    while let Some(reply) = iter.recv().await {
        let decoded = reply.map_err(&map_reply)?;
        on_reply(decoded)?;
    }
    Ok(())
}

pub(crate) enum ReplyVisit<T> {
    Continue,
    Break(T),
}

pub(crate) async fn for_each_reply_until<R, OnReply, MapIo, MapReply, T>(
    sock: &mut NetlinkSocket,
    request: &R,
    map_io: MapIo,
    map_reply: MapReply,
    mut on_reply: OnReply,
) -> Result<Option<T>>
where
    R: NetlinkRequest,
    for<'buf> OnReply: FnMut(R::ReplyType<'buf>) -> Result<ReplyVisit<T>>,
    MapIo: FnOnce(std::io::Error) -> anyhow::Error,
    MapReply: Fn(ReplyError) -> anyhow::Error,
{
    let mut iter = sock.request(request).await.map_err(map_io)?;
    while let Some(reply) = iter.recv().await {
        let decoded = reply.map_err(&map_reply)?;
        match on_reply(decoded)? {
            ReplyVisit::Continue => {}
            ReplyVisit::Break(value) => return Ok(Some(value)),
        }
    }
    Ok(None)
}

/// Collect reply items into a pre-allocated `Vec`.
/// Avoids the closure-capture pattern for simple accumulation loops.
#[allow(dead_code)]
pub(crate) async fn collect_replies<R, T, MapIo, MapReply, MapItem>(
    sock: &mut NetlinkSocket,
    request: &R,
    map_io: MapIo,
    map_reply: MapReply,
    mut map_item: MapItem,
) -> Result<Vec<T>>
where
    R: NetlinkRequest,
    for<'buf> MapItem: FnMut(R::ReplyType<'buf>) -> Option<T>,
    MapIo: FnOnce(std::io::Error) -> anyhow::Error,
    MapReply: Fn(ReplyError) -> anyhow::Error,
{
    let mut out = Vec::new();
    let mut iter = sock.request(request).await.map_err(map_io)?;
    while let Some(reply) = iter.recv().await {
        let decoded = reply.map_err(&map_reply)?;
        if let Some(item) = map_item(decoded) {
            out.push(item);
        }
    }
    Ok(out)
}

/// Commit a chained nftables batch transaction. Centralizes the
/// `request_chained().recv_all()` pattern for all firewall netlink
/// callers.
pub(crate) async fn commit_chained_transaction(
    sock: &mut NetlinkSocket,
    chained: &netlink_bindings::nftables::ChainedFinal<'_>,
) -> Result<()> {
    sock.request_chained(chained).await?.recv_all().await?;
    Ok(())
}

/// Helper: create a fresh `NetlinkSocket`. Centralizes construction
/// so callers don't import `netlink_socket2` directly.
pub(crate) fn new_request_socket() -> NetlinkSocket {
    NetlinkSocket::new()
}
