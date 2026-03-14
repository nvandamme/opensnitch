mod daemon;
mod bus;
mod client;
mod flows;
mod services;
mod workers;
mod models;
mod adapters;
mod ffi;
mod config;
mod error;
mod runtime;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let client_addr = std::env::var("OPENSNITCH_CLIENT_ADDR").ok();

    daemon::Daemon::run(client_addr.as_deref()).await
}
