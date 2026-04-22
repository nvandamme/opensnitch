use std::os::fd::AsRawFd;
use std::time::Duration;

use anyhow::Result;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::rt::TokioIo;
use opensnitch_proto::pb;
use rustls::ClientConfig as RustlsClientConfig;
use tokio::net::UnixStream;
pub use tonic::transport::{Channel as GrpcChannel, Endpoint as GrpcEndpoint, Uri as GrpcUri};
use tower::service_fn;

pub type WireChannel = GrpcChannel;
pub type WireEndpoint = GrpcEndpoint;
pub type WireUri = GrpcUri;
pub type WireSession = WireChannel;

pub const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(22);
pub const TCP_KEEPALIVE: Duration = Duration::from_secs(20);

pub enum WireSocketTarget<'a> {
    Tcp(&'a str),
    UnixPath(&'a str),
    UnixAbstract(&'a str),
}

pub fn wire_classify_socket_target(addr: &str) -> WireSocketTarget<'_> {
    if let Some(path) = addr.strip_prefix("unix:") {
        return WireSocketTarget::UnixPath(path);
    }
    if let Some(name) = addr.strip_prefix("unix-abstract:") {
        return WireSocketTarget::UnixAbstract(name);
    }
    WireSocketTarget::Tcp(addr)
}

pub fn wire_endpoint_with_keepalive(addr: &str) -> Result<WireEndpoint> {
    Ok(WireEndpoint::from_shared(addr.to_string())?
        .http2_keep_alive_interval(HTTP2_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(TCP_KEEPALIVE)))
}

pub async fn wire_connect_unix_session(path: String) -> Result<WireSession> {
    let endpoint = WireEndpoint::try_from("http://[::]:50051")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: WireUri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await?;
    Ok(channel)
}

pub async fn wire_connect_unix_abstract_session(name: String) -> Result<WireSession> {
    let endpoint = WireEndpoint::try_from("http://[::]:50051")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: WireUri| {
            let name = name.clone();
            async move { connect_abstract_unix_stream(name).await }
        }))
        .await?;
    Ok(channel)
}

pub async fn wire_connect_https_session(
    endpoint: &WireEndpoint,
    rustls: RustlsClientConfig,
) -> Result<WireSession> {
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(rustls)
        .https_or_http()
        .enable_all_versions()
        .build();

    Ok(endpoint.clone().connect_with_connector(connector).await?)
}

pub fn ui_client_from_channel(channel: GrpcChannel) -> pb::ui_client::UiClient<GrpcChannel> {
    pb::ui_client::UiClient::new(channel)
}

#[cfg(feature = "subscriptions")]
pub fn subscriptions_client_from_channel(
    channel: GrpcChannel,
) -> pb::subscriptions_client::SubscriptionsClient<GrpcChannel> {
    pb::subscriptions_client::SubscriptionsClient::new(channel)
}

async fn connect_abstract_unix_stream(name: String) -> std::io::Result<TokioIo<UnixStream>> {
    let std_stream =
        tokio::task::spawn_blocking(move || -> std::io::Result<std::os::unix::net::UnixStream> {
            let fd = nix::sys::socket::socket(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::Stream,
                nix::sys::socket::SockFlag::SOCK_CLOEXEC,
                None,
            )
            .map_err(|err| std::io::Error::other(err.to_string()))?;
            let addr = nix::sys::socket::UnixAddr::new_abstract(name.as_bytes())
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            nix::sys::socket::connect(fd.as_raw_fd(), &addr)
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            Ok(std::os::unix::net::UnixStream::from(fd))
        })
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))??;

    std_stream.set_nonblocking(true)?;
    UnixStream::from_std(std_stream).map(TokioIo::new)
}
