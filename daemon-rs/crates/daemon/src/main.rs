mod adapters;
mod bus;
mod client;
mod commands;
mod config;
mod daemon;
mod ffi;
mod flows;
mod logging;
mod models;
mod services;
#[cfg(test)]
mod tests;
mod tunables;
mod utils;
mod workers;

use anyhow::Result;

#[cfg(test)]
mod probe_bootstrap {
    #[ctor::ctor]
    fn init_logging_for_all_tests() {
        crate::tests::support::init_test_logging();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::LoggingState::init();

    let client_addr = std::env::var("OPENSNITCH_CLIENT_ADDR").ok();

    daemon::Daemon::run(client_addr.as_deref()).await
}
