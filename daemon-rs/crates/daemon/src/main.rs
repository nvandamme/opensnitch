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

use daemon::CliOverrides;

/// Parse a minimal set of CLI flags from argv, mirroring the Go daemon's flag package:
///
///   --rules-path  <path>   Override the rules directory from config.
///   --config-file <path>   Override the config file path.
///   --ui-socket   <addr>   Override the UI gRPC socket address.
///
/// All other argv tokens (unknown flags, positional args) are silently ignored
/// so that `cargo run -- --rules-path ...` and direct binary invocations both
/// work without requiring a dedicated arg-parsing crate.
fn parse_cli_overrides() -> CliOverrides {
    let mut overrides = CliOverrides::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let (flag, value) = if let Some(rest) = arg.strip_prefix("--") {
            if let Some((name, val)) = rest.split_once('=') {
                (name.to_string(), Some(val.to_string()))
            } else {
                (rest.to_string(), args.next())
            }
        } else {
            continue;
        };
        match flag.as_str() {
            "rules-path"  => overrides.rules_path  = value.map(std::path::PathBuf::from),
            "config-file" => overrides.config_file = value.map(std::path::PathBuf::from),
            "ui-socket"   => overrides.ui_socket   = value,
            _ => {}
        }
    }
    overrides
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::LoggingState::init();

    let client_addr = std::env::var("OPENSNITCH_CLIENT_ADDR").ok();
    let mut overrides = parse_cli_overrides();
    // OPENSNITCH_CLIENT_ADDR env var takes lower precedence than --ui-socket flag.
    if overrides.ui_socket.is_none() {
        overrides.ui_socket = client_addr;
    }

    daemon::Daemon::start(overrides).await
}
