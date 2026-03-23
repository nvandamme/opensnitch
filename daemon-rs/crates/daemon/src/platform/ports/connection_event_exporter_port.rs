use opensnitch_proto::pb;

use crate::models::config_runtime::LoggerSinkConfig;

/// Trait for pluggable per-connection event exporters.
///
/// Implementors are called once per resolved connection verdict, receiving the
/// connection metadata and the matched rule (if any).
///
/// This is the Rust equivalent of the Go `daemon/log/loggers/` pipeline:
/// `LoggerManager.Log(con.Serialize(), action, rname)` is called inside
/// `Statistics.OnConnectionEvent()` for every intercepted connection.
///
/// Go loggers support the following output formats and transports:
/// - RFC5424 / RFC3164 syslog (local or remote UDP/TCP)
/// - JSON (remote TCP/UDP → Loki / any log aggregator)
/// - CSV (remote TCP/UDP)
///
/// Intended adapter targets for Rust:
/// - Loki (Grafana): push JSON log lines over HTTP to `/loki/api/v1/push`.
/// - Remote syslog: RFC5424/RFC3164 over UDP or TCP.
/// - Generic JSON sink: newline-delimited JSON to any remote endpoint.
/// - stdout / file logger: structured tracing output for local inspection.
///
/// Implementations must be non-blocking. Offload I/O to an internal async
/// channel or background task to avoid blocking the verdict hot path.
pub trait ConnectionEventExporterPort: Send + Sync {
    /// Optional hook called before event emission to apply runtime logger config changes.
    ///
    /// Default implementation is a no-op so non-logger exporters are unaffected.
    fn refresh_loggers(&self, _loggers: &[LoggerSinkConfig]) {}

    /// Called on every resolved connection verdict.
    ///
    /// `connection` carries the full connection metadata (process, src/dst
    /// addr/port, protocol, uid, etc.).
    /// `rule` is `Some` when a rule was matched, `None` on missed/default.
    fn on_connection_event(&self, connection: &pb::Connection, rule: Option<&pb::Rule>);
}
