use std::{
    env,
    fs::OpenOptions,
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    path::PathBuf,
    sync::{
        OnceLock, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};
use time::{OffsetDateTime, macros::format_description};
use tracing::warn;
use tracing_subscriber::{
    EnvFilter, Registry,
    fmt::{format::Writer, time::FormatTime, writer::MakeWriter},
    layer::SubscriberExt,
    reload,
    util::SubscriberInitExt,
};

pub(crate) static LOG_FILTER_HANDLE: OnceLock<reload::Handle<EnvFilter, Registry>> =
    OnceLock::new();
static LOG_SINK_OPTIONS: OnceLock<RwLock<LogSinkOptions>> = OnceLock::new();

// Atomic fast-path flags updated in sync with LOG_SINK_OPTIONS so that
// make_writer() and format_time() avoid an RwLock acquisition in the common
// case (stdout-only, UTC, second-precision timestamps).
static LOG_SINK_HAS_FILE: AtomicBool = AtomicBool::new(false);
static LOG_SINK_HAS_UDP: AtomicBool = AtomicBool::new(false);
static LOG_SINK_UTC: AtomicBool = AtomicBool::new(true);
static LOG_SINK_MICRO: AtomicBool = AtomicBool::new(false);

const TS_BASE: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
const TS_MICRO: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:6]");

#[derive(Debug, Clone, Default)]
struct LogSinkOptions {
    log_file: Option<PathBuf>,
    log_utc: bool,
    log_micro: bool,
    udp_target: Option<SocketAddr>,
}

struct OpensnitchTimer;

impl FormatTime for OpensnitchTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        // Fast path: read atomics instead of acquiring the RwLock.
        let utc = LOG_SINK_UTC.load(Ordering::Relaxed);
        let micro = LOG_SINK_MICRO.load(Ordering::Relaxed);

        let now = if utc {
            OffsetDateTime::now_utc()
        } else {
            OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
        };

        match now.format(if micro { TS_MICRO } else { TS_BASE }) {
            Ok(ts) => write!(w, "{ts}"),
            Err(_) => {
                let fallback = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                write!(w, "{fallback}")
            }
        }
    }
}

#[derive(Clone, Copy)]
struct OpensnitchMakeWriter;

struct OpensnitchWriter {
    stdout: io::Stdout,
    file: Option<std::fs::File>,
    udp_socket: Option<UdpSocket>,
    udp_target: Option<SocketAddr>,
}

impl<'a> MakeWriter<'a> for OpensnitchMakeWriter {
    type Writer = OpensnitchWriter;

    fn make_writer(&'a self) -> Self::Writer {
        // Fast path: if no file or UDP sink is configured, skip the RwLock
        // entirely and return a stdout-only writer. This is the common case and
        // runs on every emitted tracing event, so avoiding the lock matters.
        if !LOG_SINK_HAS_FILE.load(Ordering::Relaxed) && !LOG_SINK_HAS_UDP.load(Ordering::Relaxed) {
            return OpensnitchWriter {
                stdout: io::stdout(),
                file: None,
                udp_socket: None,
                udp_target: None,
            };
        }

        let options = LoggingState::sink_options()
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default();

        let file = options
            .log_file
            .as_ref()
            .and_then(|path| OpenOptions::new().create(true).append(true).open(path).ok());

        let udp_socket = options
            .udp_target
            .and_then(|_| UdpSocket::bind("0.0.0.0:0").ok());

        OpensnitchWriter {
            stdout: io::stdout(),
            file,
            udp_socket,
            udp_target: options.udp_target,
        }
    }
}

impl Write for OpensnitchWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stdout.write_all(buf)?;
        if let Some(file) = self.file.as_mut() {
            let _ = file.write_all(buf);
        }
        if let (Some(socket), Some(target)) = (self.udp_socket.as_ref(), self.udp_target) {
            let _ = socket.send_to(buf, target);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stdout.flush()?;
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
        Ok(())
    }
}

pub struct LoggingState;

impl LoggingState {
    fn sink_options() -> &'static RwLock<LogSinkOptions> {
        LOG_SINK_OPTIONS.get_or_init(|| {
            RwLock::new(LogSinkOptions {
                log_file: None,
                log_utc: true,
                log_micro: false,
                udp_target: None,
            })
        })
    }

    fn parse_udp_target(server: &str) -> Option<SocketAddr> {
        let value = server.trim();
        if value.is_empty() {
            return None;
        }
        value.to_socket_addrs().ok()?.next()
    }

    pub fn apply_config(config: &crate::config::Config) -> Result<()> {
        let override_log_file = env::var("OPENSNITCH_DAEMON_RS_LOG_FILE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let effective_log_file = override_log_file.or_else(|| config.log_file.clone());

        let udp_target = config
            .loggers
            .iter()
            .find(|logger| {
                logger.protocol.eq_ignore_ascii_case("udp") && !logger.server.trim().is_empty()
            })
            .and_then(|logger| Self::parse_udp_target(&logger.server));

        if let Ok(mut guard) = Self::sink_options().write() {
            guard.log_file = effective_log_file.clone();
            guard.log_utc = config.log_utc;
            guard.log_micro = config.log_micro;
            guard.udp_target = udp_target;
        }

        LOG_SINK_HAS_FILE.store(effective_log_file.is_some(), Ordering::Relaxed);
        LOG_SINK_HAS_UDP.store(udp_target.is_some(), Ordering::Relaxed);
        LOG_SINK_UTC.store(config.log_utc, Ordering::Relaxed);
        LOG_SINK_MICRO.store(config.log_micro, Ordering::Relaxed);

        for logger in &config.loggers {
            if logger.name.trim().is_empty() {
                continue;
            }
            let supported =
                logger.protocol.eq_ignore_ascii_case("udp") && !logger.server.is_empty();
            warn!(
                logger_name = %logger.name,
                logger_format = %logger.format,
                logger_protocol = %logger.protocol,
                logger_server = %logger.server,
                logger_tag = %logger.tag,
                logger_write_timeout = %logger.write_timeout,
                logger_connect_timeout = %logger.connect_timeout,
                logger_workers = logger.workers,
                logger_max_connect_attempts = logger.max_connect_attempts,
                logger_supported = supported,
                "configured log sink detected"
            );
        }

        Self::set_opensnitch_log_level(config.log_level as i32)
    }

    pub fn init() {
        let (filter_layer, handle) = reload::Layer::new(EnvFilter::from_default_env());
        let _ = LOG_FILTER_HANDLE.set(handle);

        tracing_subscriber::registry()
            .with(filter_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_timer(OpensnitchTimer)
                    .with_writer(OpensnitchMakeWriter),
            )
            .init();
    }

    pub fn set_opensnitch_log_level(level: i32) -> Result<()> {
        let directive = match level {
            i if i <= -1 => "trace",
            0 => "debug",
            1 => "info",
            2 => "info",
            3 => "warn",
            _ => "error",
        };

        let handle = LOG_FILTER_HANDLE
            .get()
            .ok_or_else(|| anyhow!("logging subsystem is not initialized"))?;
        handle.reload(EnvFilter::new(directive))?;
        Ok(())
    }

    pub fn forward_task_notification(task_name: &str, data: &str, is_error: bool) {
        let payload = serde_json::json!({
            "Name": task_name,
            "Data": data,
        })
        .to_string();

        if is_error {
            tracing::error!(
                target: "opensnitch.task",
                task = %task_name,
                task_notification = %payload,
                "forwarding task notification"
            );
        } else {
            tracing::info!(
                target: "opensnitch.task",
                task = %task_name,
                task_notification = %payload,
                "forwarding task notification"
            );
        }
    }
}
