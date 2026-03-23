mod bus;
mod commands;
mod config;
mod daemon;
mod flows;
mod logging;
mod models;
mod platform;
mod services;
#[cfg(test)]
mod tests;
mod tunables;
mod utils;
mod workers;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    logging::LoggingState::init();

    let client_addr = std::env::var("OPENSNITCH_CLIENT_ADDR").ok();

    daemon::Daemon::run(client_addr.as_deref()).await
}
