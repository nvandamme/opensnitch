use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;
use syslog::{Facility, Formatter3164};
use tracing::warn;
use transport_wire_core::{WireConnection, WireRule};

use crate::config::LoggerSinkConfig;
use crate::platform::conman::event_exporter::ConnectionEventExporterPort;
use crate::utils::name_parsing::case_folded;

const DEFAULT_TAG: &str = "opensnitchd";
const DEFAULT_WORKERS: usize = 1;
const DEFAULT_QUEUE_CAPACITY: usize = 2048;
const DEFAULT_REOPEN_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkFormat {
    Json,
    Csv,
    Rfc3164,
    Rfc5424,
}

impl SinkFormat {
    fn from_str(raw: &str) -> Self {
        match case_folded(raw).as_str() {
            "json" => Self::Json,
            "csv" => Self::Csv,
            "rfc3164" => Self::Rfc3164,
            _ => Self::Rfc5424,
        }
    }
}

#[derive(Clone)]
struct SinkHandle {
    sender: SyncSender<String>,
    format: SinkFormat,
    tag: Arc<str>,
}

pub struct ConnectionEventLoggerAdapter {
    state: RwLock<LoggerState>,
}

struct LoggerState {
    loggers: Vec<LoggerSinkConfig>,
    sinks: Arc<[SinkHandle]>,
}

impl Default for LoggerState {
    fn default() -> Self {
        Self {
            loggers: Vec::new(),
            sinks: Arc::from([]),
        }
    }
}

impl ConnectionEventLoggerAdapter {
    pub fn new(loggers: &[LoggerSinkConfig]) -> Self {
        let sinks: Arc<[SinkHandle]> = build_sinks(loggers).into();
        Self {
            state: RwLock::new(LoggerState {
                loggers: loggers.to_vec(),
                sinks,
            }),
        }
    }

    pub fn has_sinks(&self) -> bool {
        !self
            .state
            .read()
            .expect("connection-event-logger state poisoned")
            .sinks
            .is_empty()
    }

    pub fn reload_from_loggers(&self, loggers: &[LoggerSinkConfig]) {
        {
            let state = self
                .state
                .read()
                .expect("connection-event-logger state poisoned");
            if state.loggers == loggers {
                return;
            }
        }

        let new_sinks = build_sinks(loggers);
        let mut state = self
            .state
            .write()
            .expect("connection-event-logger state poisoned");
        if state.loggers == loggers {
            return;
        }

        state.loggers = loggers.to_vec();
        state.sinks = new_sinks.into();
    }
}

impl ConnectionEventExporterPort for ConnectionEventLoggerAdapter {
    fn refresh_loggers(&self, loggers: &[LoggerSinkConfig]) {
        self.reload_from_loggers(loggers);
    }

    fn on_connection_event(&self, connection: &WireConnection, rule: Option<&WireRule>) {
        let sinks = Arc::clone(
            &self
                .state
                .read()
                .expect("connection-event-logger state poisoned")
                .sinks,
        );

        if sinks.is_empty() {
            return;
        }

        for sink in sinks.iter() {
            let payload = format_message_enum(sink.format, &sink.tag, connection, rule);
            match sink.sender.try_send(payload) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    // Fail-open by design: never block verdict hot path.
                }
                Err(TrySendError::Disconnected(_)) => {
                    // Worker terminated; fail-open.
                }
            }
        }
    }
}

fn build_sinks(loggers: &[LoggerSinkConfig]) -> Vec<SinkHandle> {
    let mut sinks = Vec::new();

    for logger in loggers {
        if !is_supported_logger(logger) {
            continue;
        }

        let workers = logger.workers.max(DEFAULT_WORKERS);
        for _ in 0..workers {
            let (tx, rx) = mpsc::sync_channel::<String>(DEFAULT_QUEUE_CAPACITY);
            let cfg = logger.clone();
            thread::spawn(move || run_sink_worker(cfg, rx));

            sinks.push(SinkHandle {
                sender: tx,
                format: SinkFormat::from_str(&logger.format),
                tag: if logger.tag.trim().is_empty() {
                    Arc::from(DEFAULT_TAG)
                } else {
                    Arc::from(logger.tag.as_str())
                },
            });
        }
    }

    sinks
}

fn run_sink_worker(cfg: LoggerSinkConfig, rx: Receiver<String>) {
    let protocol = normalized_protocol(&cfg.protocol);

    match protocol {
        Protocol::Udp => run_udp_worker(&cfg, rx),
        Protocol::Tcp => run_tcp_worker(&cfg, rx),
    }
}

fn run_udp_worker(cfg: &LoggerSinkConfig, rx: Receiver<String>) {
    if is_local_syslog_mode(cfg) {
        run_local_syslog_worker(cfg, rx);
        return;
    }

    let server = cfg.server.trim();
    if server.is_empty() {
        run_local_tracing_sink(cfg, rx);
        return;
    }

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(err) => {
            warn!(logger_name = %cfg.name, logger_server = %cfg.server, "siem-export udp bind failed: {err}");
            return;
        }
    };

    let write_timeout = parse_duration(&cfg.write_timeout, Duration::from_secs(1));
    let _ = socket.set_write_timeout(Some(write_timeout));

    for msg in rx {
        let _ = socket.send_to(msg.as_bytes(), server);
    }
}

fn run_tcp_worker(cfg: &LoggerSinkConfig, rx: Receiver<String>) {
    if is_local_syslog_mode(cfg) {
        run_local_syslog_worker(cfg, rx);
        return;
    }

    let server = cfg.server.trim();
    if server.is_empty() {
        run_local_tracing_sink(cfg, rx);
        return;
    }

    let connect_timeout = parse_duration(&cfg.connect_timeout, Duration::from_secs(5));
    let write_timeout = parse_duration(&cfg.write_timeout, Duration::from_secs(1));
    let max_attempts = cfg.max_connect_attempts;
    let mut stream: Option<TcpStream> = None;

    for msg in rx {
        if stream.is_none() {
            stream = connect_with_retry_policy(cfg, connect_timeout, max_attempts);
        }

        let Some(mut active_stream) = stream.take() else {
            continue;
        };

        let _ = active_stream.set_write_timeout(Some(write_timeout));
        match active_stream.write_all(msg.as_bytes()) {
            Ok(()) => {
                stream = Some(active_stream);
            }
            Err(err) => {
                warn!(logger_name = %cfg.name, logger_server = %cfg.server, "siem-export tcp write failed; reconnecting: {err}");
                stream = connect_with_retry_policy(cfg, connect_timeout, max_attempts);
            }
        }
    }
}

fn connect_with_retry_policy(
    cfg: &LoggerSinkConfig,
    connect_timeout: Duration,
    max_attempts: u16,
) -> Option<TcpStream> {
    let server = cfg.server.trim();
    let mut attempts: u16 = 0;

    loop {
        match connect_tcp(server, connect_timeout) {
            Ok(stream) => return Some(stream),
            Err(err) => {
                attempts = attempts.saturating_add(1);
                warn!(
                    logger_name = %cfg.name,
                    logger_server = %cfg.server,
                    attempt = attempts,
                    max_attempts = max_attempts,
                    "siem-export tcp connect failed: {err}"
                );

                if !should_retry_connect(max_attempts, attempts) {
                    warn!(
                        logger_name = %cfg.name,
                        logger_server = %cfg.server,
                        max_attempts = max_attempts,
                        "siem-export max connect attempts reached; dropping current message"
                    );
                    return None;
                }

                thread::sleep(DEFAULT_REOPEN_INTERVAL);
            }
        }
    }
}

fn run_local_tracing_sink(cfg: &LoggerSinkConfig, rx: Receiver<String>) {
    for msg in rx {
        tracing::info!(
            target: "opensnitch.siem",
            logger_name = %cfg.name,
            logger_format = %cfg.format,
            event = %msg.trim_end(),
            "siem-export local sink"
        );
    }
}

fn run_local_syslog_worker(cfg: &LoggerSinkConfig, rx: Receiver<String>) {
    let process = if cfg.tag.trim().is_empty() {
        DEFAULT_TAG.to_string()
    } else {
        cfg.tag.clone()
    };

    let formatter = Formatter3164 {
        facility: Facility::LOG_DAEMON,
        hostname: None,
        process,
        pid: 0,
    };

    let mut writer = match syslog::unix(formatter) {
        Ok(writer) => writer,
        Err(err) => {
            warn!(logger_name = %cfg.name, "siem-export local syslog init failed; falling back to tracing sink: {err}");
            run_local_tracing_sink(cfg, rx);
            return;
        }
    };

    for msg in rx {
        if let Err(err) = writer.notice(msg.as_str()) {
            warn!(logger_name = %cfg.name, "siem-export local syslog write failed: {err}");
        }
    }
}

fn should_retry_connect(max_attempts: u16, attempts: u16) -> bool {
    max_attempts == 0 || attempts < max_attempts
}

fn connect_tcp(server: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    let addrs = server.to_socket_addrs()?;
    let mut last_err = None;

    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no tcp addresses resolved",
        )
    }))
}

fn format_message_enum(
    format: SinkFormat,
    tag: &str,
    connection: &WireConnection,
    rule: Option<&WireRule>,
) -> String {
    let ts = now_unix_seconds();
    match format {
        SinkFormat::Json => format_json(ts, tag, connection, rule),
        SinkFormat::Csv => format_csv(ts, connection, rule),
        SinkFormat::Rfc3164 => format_rfc3164(ts, tag, connection, rule),
        SinkFormat::Rfc5424 => format_rfc5424(ts, tag, connection, rule),
    }
}

/// Convenience wrapper for tests: accepts a format string and dispatches via [`SinkFormat`].
#[cfg(test)]
pub(crate) fn format_message(
    format: &str,
    tag: &str,
    connection: &WireConnection,
    rule: Option<&WireRule>,
) -> String {
    format_message_enum(SinkFormat::from_str(format), tag, connection, rule)
}

fn format_json(ts: u64, tag: &str, connection: &WireConnection, rule: Option<&WireRule>) -> String {
    let process_tree = connection
        .process_tree
        .iter()
        .map(|item| json!({ "key": item.key, "value": item.value }))
        .collect::<Vec<_>>();

    let doc = json!({
        "@timestamp": ts,
        "tag": tag,
        "event": {
            "protocol": connection.protocol,
            "src_ip": connection.src_ip,
            "src_port": connection.src_port,
            "dst_ip": connection.dst_ip,
            "dst_host": connection.dst_host,
            "dst_port": connection.dst_port,
            "user_id": connection.user_id,
            "process_id": connection.process_id,
            "process_path": connection.process_path,
            "process_cwd": connection.process_cwd,
            "process_args": connection.process_args,
            "process_env": connection.process_env,
            "process_checksums": connection.process_checksums,
            "process_tree": process_tree,
        },
        "rule": rule.map(|r| {
            json!({
                "name": r.name,
                "action": r.action,
                "duration": r.duration,
                "nolog": r.nolog,
                "enabled": r.enabled,
            })
        }),
    });

    format!("{}\n", doc)
}

fn format_csv(ts: u64, connection: &WireConnection, rule: Option<&WireRule>) -> String {
    let rule_name = rule.map(|r| r.name.as_str()).unwrap_or("");
    let rule_action = rule.map(|r| r.action.as_str()).unwrap_or("");

    format!(
        "{ts},{proto},{src_ip},{src_port},{dst_ip},{dst_port},{uid},{pid},{proc_path},{rule_name},{rule_action}\n",
        proto = csv_escape(&connection.protocol),
        src_ip = csv_escape(&connection.src_ip),
        src_port = connection.src_port,
        dst_ip = csv_escape(&connection.dst_ip),
        dst_port = connection.dst_port,
        uid = connection.user_id,
        pid = connection.process_id,
        proc_path = csv_escape(&connection.process_path),
        rule_name = csv_escape(rule_name),
        rule_action = csv_escape(rule_action),
    )
}

fn format_rfc5424(
    ts: u64,
    tag: &str,
    connection: &WireConnection,
    rule: Option<&WireRule>,
) -> String {
    let rule_name = rule.map(|r| r.name.as_str()).unwrap_or("");
    let rule_action = rule.map(|r| r.action.as_str()).unwrap_or("");
    format!(
        "<14>1 {ts} localhost {tag} - - - protocol={proto} src_ip={src_ip} src_port={src_port} dst_ip={dst_ip} dst_port={dst_port} user_id={uid} process_id={pid} process_path=\"{proc_path}\" rule=\"{rule_name}\" action={rule_action}\n",
        proto = connection.protocol,
        src_ip = connection.src_ip,
        src_port = connection.src_port,
        dst_ip = connection.dst_ip,
        dst_port = connection.dst_port,
        uid = connection.user_id,
        pid = connection.process_id,
        proc_path = sanitize_kv(&connection.process_path),
        rule_name = sanitize_kv(rule_name),
        rule_action = rule_action,
    )
}

fn format_rfc3164(
    ts: u64,
    tag: &str,
    connection: &WireConnection,
    rule: Option<&WireRule>,
) -> String {
    let rule_name = rule.map(|r| r.name.as_str()).unwrap_or("");
    let rule_action = rule.map(|r| r.action.as_str()).unwrap_or("");
    format!(
        "<14>{ts} localhost {tag}: proto={proto} src={src_ip}:{src_port} dst={dst_ip}:{dst_port} uid={uid} pid={pid} proc=\"{proc_path}\" rule=\"{rule_name}\" action={rule_action}\n",
        proto = connection.protocol,
        src_ip = connection.src_ip,
        src_port = connection.src_port,
        dst_ip = connection.dst_ip,
        dst_port = connection.dst_port,
        uid = connection.user_id,
        pid = connection.process_id,
        proc_path = sanitize_kv(&connection.process_path),
        rule_name = sanitize_kv(rule_name),
        rule_action = rule_action,
    )
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

fn sanitize_kv(value: &str) -> String {
    value.replace('\n', " ").replace('"', "")
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

enum Protocol {
    Tcp,
    Udp,
}

fn normalized_protocol(raw: &str) -> Protocol {
    if case_folded(raw) == "tcp" {
        Protocol::Tcp
    } else {
        Protocol::Udp
    }
}

fn is_supported_logger(cfg: &LoggerSinkConfig) -> bool {
    let name = case_folded(&cfg.name);
    matches!(name.as_str(), "syslog" | "remote" | "remote_syslog")
}

fn is_local_syslog_mode(cfg: &LoggerSinkConfig) -> bool {
    case_folded(&cfg.name) == "syslog" && cfg.server.trim().is_empty()
}

fn parse_duration(raw: &str, default: Duration) -> Duration {
    let value = raw.trim();
    if value.is_empty() {
        return default;
    }

    if let Some(ms) = value.strip_suffix("ms") {
        if let Ok(parsed) = ms.parse::<u64>() {
            return Duration::from_millis(parsed);
        }
    }
    if let Some(s) = value.strip_suffix('s') {
        if let Ok(parsed) = s.parse::<u64>() {
            return Duration::from_secs(parsed);
        }
    }
    if let Some(m) = value.strip_suffix('m') {
        if let Ok(parsed) = m.parse::<u64>() {
            return Duration::from_secs(parsed.saturating_mul(60));
        }
    }
    if let Some(h) = value.strip_suffix('h') {
        if let Ok(parsed) = h.parse::<u64>() {
            return Duration::from_secs(parsed.saturating_mul(3600));
        }
    }

    default
}

#[cfg(test)]
#[path = "../../tests/parsing/connection_event_logger.rs"]
mod connection_event_logger_tests;
