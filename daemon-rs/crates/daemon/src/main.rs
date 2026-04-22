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
            // Core daemon flags
            "rules-path"  => overrides.rules_path  = value.map(std::path::PathBuf::from),
            "config-file" => overrides.config_file = value.map(std::path::PathBuf::from),
            "ui-socket"   => overrides.ui_socket   = value,
            // Metrics flags (§7: CLI overrides env vars and metrics.json baseline)
            "metrics-prometheus-addr" => overrides.metrics.prometheus_addr = value,
            "metrics-push-url"        => overrides.metrics.push_url        = value,
            "metrics-push-format"     => overrides.metrics.push_format     = value,
            "metrics-push-job"        => overrides.metrics.push_job        = value,
            "metrics-push-token"      => overrides.metrics.push_token      = value,
            "metrics-push-gzip"       => overrides.metrics.push_gzip       = Some(true),
            _ => {}
        }
    }
    overrides
}

#[tokio::main]
async fn main() -> Result<()> {
    // --check-caps: run kernel capability diagnostic and exit.
    // Handled before logging init so output goes cleanly to stdout/stderr.
    if std::env::args().any(|a| a == "--check-caps") {
        let diag = crate::utils::kernel_caps::run();
        diag.print_report();
        std::process::exit(if diag.all_pass { 0 } else { 1 });
    }

    logging::LoggingState::init();

    let client_addr = std::env::var("OPENSNITCH_CLIENT_ADDR").ok();
    let mut overrides = parse_cli_overrides();
    // §7: --ui-socket CLI has highest precedence; env var fills when CLI absent.
    if overrides.ui_socket.is_none() {
        overrides.ui_socket = client_addr;
    }

    daemon::Daemon::start(overrides).await
}
