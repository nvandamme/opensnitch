mod adapters;
mod bus;
mod client;
mod commands;
mod config;
mod daemon;
mod ffi;
mod flows;
#[cfg(all(test, feature = "integration-kernel-tests"))]
mod integration_kernel_tests;
mod logging;
mod models;
mod services;
mod utils;
mod workers;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    logging::init();

    let client_addr = std::env::var("OPENSNITCH_CLIENT_ADDR").ok();

    daemon::Daemon::run(client_addr.as_deref()).await
}
