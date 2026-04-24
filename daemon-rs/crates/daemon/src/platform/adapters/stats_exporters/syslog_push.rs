use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use syslog::{Facility, Formatter3164};
use tracing::{debug, warn};

use crate::models::metrics_snapshot::{MetricsExportSnapshot, MetricsSnapshot};
use crate::platform::ports::stats_exporter_port::StatsExporterPort;

pub const SYSLOG_SERVER_ENV: &str = "OPENSNITCH_METRICS_SYSLOG_SERVER";
pub const SYSLOG_PROTOCOL_ENV: &str = "OPENSNITCH_METRICS_SYSLOG_PROTOCOL";
pub const SYSLOG_FORMAT_ENV: &str = "OPENSNITCH_METRICS_SYSLOG_FORMAT";
pub const SYSLOG_TAG_ENV: &str = "OPENSNITCH_METRICS_SYSLOG_TAG";

const DEFAULT_TAG: &str = "opensnitchd-rs-metrics";
const CHANNEL_CAPACITY: usize = 4;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const TCP_REOPEN_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyslogProtocol {
    #[default]
    Udp,
    Tcp,
}

impl SyslogProtocol {
    pub fn from_str(raw: &str) -> Self {
        if raw.trim().eq_ignore_ascii_case("tcp") {
            Self::Tcp
        } else {
            Self::Udp
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyslogFormat {
    Rfc3164,
    #[default]
    Rfc5424,
}

impl SyslogFormat {
    pub fn from_str(raw: &str) -> Self {
        if raw.trim().eq_ignore_ascii_case("rfc3164") {
            Self::Rfc3164
        } else {
            Self::Rfc5424
        }
    }
}

#[derive(Clone, Debug)]
pub struct SyslogConfig {
    pub server: Option<String>,
    pub protocol: SyslogProtocol,
    pub format: SyslogFormat,
    pub tag: String,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            server: None,
            protocol: SyslogProtocol::Udp,
            format: SyslogFormat::Rfc5424,
            tag: DEFAULT_TAG.to_string(),
        }
    }
}

/// Syslog-backed metrics exporter.
///
/// Local syslog remains the default when no remote server is configured. When a
/// remote target is configured, records are framed as RFC3164 or RFC5424 and sent
/// over UDP or TCP using a bounded background worker.
pub struct SyslogStatsExporter {
    tx: SyncSender<Arc<MetricsExportSnapshot>>,
}

impl SyslogStatsExporter {
    pub fn new(config: SyslogConfig) -> Arc<Self> {
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        thread::spawn(move || run_worker(config, rx));
        Arc::new(Self { tx })
    }
}

impl StatsExporterPort for SyslogStatsExporter {
    fn export_snapshot(&self, snapshot: &MetricsSnapshot) {
        match self.tx.try_send(snapshot.export_view()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                debug!("metrics syslog exporter: channel full; snapshot dropped")
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!("metrics syslog exporter: worker disconnected; snapshot dropped")
            }
        }
    }
}

fn run_worker(config: SyslogConfig, rx: Receiver<Arc<MetricsExportSnapshot>>) {
    match config
        .server
        .as_deref()
        .map(str::trim)
        .filter(|server| !server.is_empty())
    {
        Some(server) => match config.protocol {
            SyslogProtocol::Udp => run_udp_worker(&config, server, rx),
            SyslogProtocol::Tcp => run_tcp_worker(&config, server, rx),
        },
        None => run_local_worker(&config, rx),
    }
}

fn run_local_worker(config: &SyslogConfig, rx: Receiver<Arc<MetricsExportSnapshot>>) {
    let formatter = Formatter3164 {
        facility: Facility::LOG_DAEMON,
        hostname: None,
        process: config.tag.clone(),
        pid: 0,
    };

    let mut writer = match syslog::unix(formatter) {
        Ok(writer) => writer,
        Err(err) => {
            debug!("metrics syslog exporter: local syslog connect failed: {err}");
            return;
        }
    };

    for snapshot in rx {
        for message in super::encoder_syslog::encode_syslog_metrics(&snapshot) {
            if let Err(err) = writer.info(message.as_str()) {
                warn!("metrics syslog exporter: local syslog write failed: {err}");
            }
        }
    }
}

fn run_udp_worker(config: &SyslogConfig, server: &str, rx: Receiver<Arc<MetricsExportSnapshot>>) {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(err) => {
            warn!(server, "metrics syslog exporter: udp bind failed: {err}");
            return;
        }
    };
    let _ = socket.set_write_timeout(Some(TCP_WRITE_TIMEOUT));

    for snapshot in rx {
        for body in super::encoder_syslog::encode_syslog_metrics(&snapshot) {
            let message = frame_remote_message(config.format, &config.tag, &body);
            let _ = socket.send_to(message.as_bytes(), server);
        }
    }
}

fn run_tcp_worker(config: &SyslogConfig, server: &str, rx: Receiver<Arc<MetricsExportSnapshot>>) {
    let mut stream: Option<TcpStream> = None;

    for snapshot in rx {
        for body in super::encoder_syslog::encode_syslog_metrics(&snapshot) {
            if stream.is_none() {
                stream = connect_tcp(server);
            }

            let Some(mut active_stream) = stream.take() else {
                continue;
            };

            let _ = active_stream.set_write_timeout(Some(TCP_WRITE_TIMEOUT));
            let message = frame_remote_message(config.format, &config.tag, &body);
            match active_stream.write_all(message.as_bytes()) {
                Ok(()) => {
                    stream = Some(active_stream);
                }
                Err(err) => {
                    warn!(
                        server,
                        "metrics syslog exporter: tcp write failed; reconnecting: {err}"
                    );
                    stream = connect_tcp(server);
                }
            }
        }
    }
}

fn connect_tcp(server: &str) -> Option<TcpStream> {
    loop {
        match connect_tcp_once(server) {
            Ok(stream) => return Some(stream),
            Err(err) => {
                warn!(server, "metrics syslog exporter: tcp connect failed: {err}");
                thread::sleep(TCP_REOPEN_INTERVAL);
            }
        }
    }
}

fn connect_tcp_once(server: &str) -> std::io::Result<TcpStream> {
    let addrs = server.to_socket_addrs()?;
    let mut last_err = None;

    for addr in addrs {
        match TcpStream::connect_timeout(&addr, TCP_CONNECT_TIMEOUT) {
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

fn frame_remote_message(format: SyslogFormat, tag: &str, body: &str) -> String {
    let ts = now_unix_seconds();
    match format {
        SyslogFormat::Rfc3164 => format!("<14>{ts} localhost {tag}: {}\n", sanitize_value(body)),
        SyslogFormat::Rfc5424 => format!(
            "<14>1 {ts} localhost {tag} - - - {}\n",
            sanitize_value(body)
        ),
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn sanitize_value(value: &str) -> String {
    value.replace('\n', " ")
}

#[cfg(test)]
#[path = "../../../tests/metrics/stats_exporter_syslog.rs"]
mod syslog_exporter_tests;
