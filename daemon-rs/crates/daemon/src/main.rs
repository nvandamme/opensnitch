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

#[cfg(all(feature = "openwrt", not(feature = "storage-format-uci")))]
compile_error!("feature `openwrt` requires feature `storage-format-uci`");

use daemon::CliOverrides;

/// Parse a minimal set of CLI flags from argv, mirroring the Go daemon's flag package:
///
///   --rules-path  <path>   Override the rules directory from config.
///   --config-file <path>   Override the config file path.
///   --ui-socket   <addr>   Override the UI gRPC socket address.
///   --auth-mode   <mode>   Override client authorization mode.
///   --firewall-persistence-mode <mode> Override firewall persistence mode (live-only|durable).
///   --main-storage-format <format> Override main storage format (json|yaml|toml).
///   --migrate-ownerless-rules        Run one-shot legacy ownerless rule migration.
///   --migrate-owner-uid <uid>        Target owner UID for migration mode.
///   --migrate-write                  Persist migration changes (default is dry-run).
///
/// Certificate generation flags (feature-gated; requires `cert-gen`):
///   --gen-self-signed-server-cert <path>   Generate self-signed server cert and exit.
///   --gen-self-signed-server-key  <path>   Output private key path for server cert mode.
///   --gen-self-signed-client-cert <path>   Generate self-signed client cert and exit.
///   --gen-self-signed-client-key  <path>   Output private key path for client cert mode.
///   --gen-self-signed-cn <name>            Optional subject CN override.
///   --gen-self-signed-san <entry>          Optional SAN entry (repeatable; DNS or IP).
///   --gen-self-signed-days <days>          Optional cert validity period (default 365).
///
/// Audit sink flags (additive; any combination may be used):
///   --audit-sink-file <path>  Append NDJSON audit records to this file path.
///   --audit-sink-syslog       Enable local syslog as an audit sink.
///   --audit-sink-log          Enable tracing log-line audit sink (on by default).
///
/// Metrics syslog flags (§7: CLI overrides env vars and metrics.json baseline):
///   --metrics-syslog-server   <host:port>   Remote syslog target; absent keeps local syslog mode.
///   --metrics-syslog-protocol <udp|tcp>     Remote syslog transport.
///   --metrics-syslog-format   <rfc3164|rfc5424>  Remote syslog framing.
///   --metrics-syslog-tag      <name>        Syslog app-name/tag.
///
/// Corresponding env vars (lower priority than CLI flags, higher than config file):
///   OPENSNITCH_AUDIT_SINK_FILE=<path>
///   OPENSNITCH_AUDIT_SINK_SYSLOG=1
///   OPENSNITCH_AUDIT_SINK_LOG=1
///   OPENSNITCH_AUDIT_VERBOSE_HOT_PATH=1
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
            "rules-path" => overrides.rules_path = value.map(std::path::PathBuf::from),
            "config-file" => overrides.config_file = value.map(std::path::PathBuf::from),
            "ui-socket" => overrides.ui_socket = value,
            "auth-mode" => overrides.auth_mode = value,
            "firewall-persistence-mode" => overrides.firewall_persistence_mode = value,
            "main-storage-format" => overrides.main_storage_format = value,
            "migrate-ownerless-rules" => overrides.rule_migration.ownerless_rules = true,
            "migrate-owner-uid" => overrides.rule_migration.owner_uid = value,
            "migrate-write" => overrides.rule_migration.write = true,
            // Metrics flags (§7: CLI overrides env vars and metrics.json baseline)
            "metrics-prometheus-addr" => overrides.metrics.prometheus_addr = value,
            "metrics-push-url" => overrides.metrics.push_url = value,
            "metrics-push-format" => overrides.metrics.push_format = value,
            "metrics-push-job" => overrides.metrics.push_job = value,
            "metrics-push-token" => overrides.metrics.push_token = value,
            "metrics-push-gzip" => overrides.metrics.push_gzip = Some(true),
            "metrics-syslog-server" => overrides.metrics.syslog_server = value,
            "metrics-syslog-protocol" => overrides.metrics.syslog_protocol = value,
            "metrics-syslog-format" => overrides.metrics.syslog_format = value,
            "metrics-syslog-tag" => overrides.metrics.syslog_tag = value,
            // Audit sink flags (§7: CLI > env > config file)
            "audit-sink-file" => overrides.audit.sink_file = value.map(std::path::PathBuf::from),
            "audit-sink-syslog" => overrides.audit.sink_syslog = Some(true),
            "audit-sink-log" | "audit-sink-log-lines" => {
                overrides.audit.sink_log_lines = Some(true)
            }
            "audit-verbose-hot-path" => overrides.audit.verbose_hot_path = Some(true),
            _ => {}
        }
    }
    overrides
}

#[cfg(not(feature = "cert-gen"))]
fn has_cert_gen_args(argv: &[String]) -> bool {
    argv.iter().any(|arg| arg.starts_with("--gen-self-signed"))
}

#[cfg(not(feature = "kernel-caps-diag"))]
fn has_check_caps_arg(argv: &[String]) -> bool {
    argv.iter().any(|arg| arg == "--check-caps")
}

#[tokio::main]
async fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();

    // --check-caps: run kernel capability diagnostic and exit.
    // Handled before logging init so output goes cleanly to stdout/stderr.
    #[cfg(feature = "kernel-caps-diag")]
    if argv.iter().any(|a| a == "--check-caps") {
        let diag = crate::utils::kernel_caps::run();
        diag.print_report();
        std::process::exit(if diag.all_pass { 0 } else { 1 });
    }

    #[cfg(not(feature = "kernel-caps-diag"))]
    if has_check_caps_arg(&argv[1..]) {
        anyhow::bail!(
            "--check-caps requires feature `kernel-caps-diag` (build with: cargo build -p opensnitchd-rs --features kernel-caps-diag)"
        );
    }

    #[cfg(feature = "cert-gen")]
    if let Some(req) = crate::utils::cert_gen::parse_self_signed_request_from_args(&argv[1..])? {
        crate::utils::cert_gen::generate_self_signed_pair(&req)?;
        println!(
            "Generated self-signed {} certificate at {} and key at {}",
            req.role.as_str(),
            req.cert_path.display(),
            req.key_path.display()
        );
        std::process::exit(0);
    }

    #[cfg(not(feature = "cert-gen"))]
    if has_cert_gen_args(&argv[1..]) {
        anyhow::bail!(
            "--gen-self-signed* flags require feature `cert-gen` (build with: cargo build -p opensnitchd-rs --features cert-gen)"
        );
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
