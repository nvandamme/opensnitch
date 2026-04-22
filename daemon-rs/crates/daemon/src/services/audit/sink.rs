//! Audit event sink routing.
//!
//! [`AuditSinks`] is the multiplexing layer between the broadcast subscriber
//! in `spawn_audit_sink_task` and the three independent, additive destinations:
//!
//! | Sink          | Default | Config key        | CLI flag              | Env var                       |
//! |---------------|---------|-------------------|-----------------------|-------------------------------|
//! | log-lines     | **on**  | `SinkLogLines`    | `--audit-sink-log`    | `OPENSNITCH_AUDIT_SINK_LOG`   |
//! | syslog        | off     | `SinkSyslog`      | `--audit-sink-syslog` | `OPENSNITCH_AUDIT_SINK_SYSLOG`|
//! | NDJSON file   | off     | `SinkFile`        | `--audit-sink-file`   | `OPENSNITCH_AUDIT_SINK_FILE`  |
//!
//! Sinks are independent: all enabled sinks receive every event. The file and
//! syslog sinks each run on a dedicated `std::thread`; their channels are
//! fail-open (events are silently dropped if the queue is full).
//!
//! **File sink format** — one NDJSON line per event:
//! ```json
//! {"ts":"2026-03-29T12:34:56.000000000Z","path":"hot","level":"info","event":"VerdictAction/AskTimeoutFallback[rid=1]"}
//! ```
//!
//! **Syslog sink** — uses `LOG_DAEMON` facility.  Severity is mapped from the
//! event's [`AuditSeverity`]:
//! - `Error`   → `syslog::err()` (LOG_ERR)
//! - `Warning` → `syslog::warning()` (LOG_WARNING)
//! - `Info`    → `syslog::notice()` (LOG_NOTICE)
//! - `Debug`   → `syslog::debug()` (LOG_DEBUG)
//!
//! On systems without syslog (e.g. minimal containers), the worker falls back
//! to tracing output.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, sync_channel};

use syslog::{Facility, Formatter3164};

use crate::config::AuditSinkConfig;
use crate::models::audit::{AuditEvent, AuditEventFamily, AuditSeverity};

const SINK_QUEUE_CAPACITY: usize = 1024;
const AUDIT_SYSLOG_TAG: &str = "opensnitchd-audit";

// ── Public API ───────────────────────────────────────────────────────────────

/// Multiplexes [`AuditEvent`]s to the configured set of independent sinks.
///
/// Cheap `Clone`: all clones share the same inner state behind an [`Arc`].
/// Background worker threads are started at construction and automatically
/// stop when the last `AuditSinks` clone is dropped (channel close).
#[derive(Clone)]
pub struct AuditSinks {
    inner: Arc<AuditSinksInner>,
}

struct AuditSinksInner {
    file_tx: Option<SyncSender<String>>,
    syslog_tx: Option<SyncSender<(String, AuditSeverity)>>,
    log_lines: bool,
    min_severity: AuditSeverity,
}

impl AuditSinks {
    /// Build sinks from a resolved [`AuditSinkConfig`].
    ///
    /// File and syslog workers are spawned immediately if their respective
    /// sinks are enabled. Worker threads are detached; they exit cleanly when
    /// the channel's sending end is closed (i.e. when the last `AuditSinks`
    /// clone is dropped).
    pub fn from_config(cfg: &AuditSinkConfig) -> Self {
        let file_tx = cfg.sink_file.as_ref().map(|path| {
            let (tx, rx) = sync_channel::<String>(SINK_QUEUE_CAPACITY);
            let path = path.clone();
            if let Err(err) = std::thread::Builder::new()
                .name("audit-file-sink".to_string())
                .spawn(move || run_file_sink_worker(path, rx))
            {
                tracing::warn!("audit file sink thread spawn failed: {err}");
            }
            tx
        });

        let syslog_tx = if cfg.sink_syslog {
            let (tx, rx) = sync_channel::<(String, AuditSeverity)>(SINK_QUEUE_CAPACITY);
            if let Err(err) = std::thread::Builder::new()
                .name("audit-syslog-sink".to_string())
                .spawn(move || run_syslog_sink_worker(rx))
            {
                tracing::warn!("audit syslog sink thread spawn failed: {err}");
            }
            Some(tx)
        } else {
            None
        };

        Self {
            inner: Arc::new(AuditSinksInner {
                file_tx,
                syslog_tx,
                log_lines: cfg.sink_log_lines,
                min_severity: cfg.min_severity,
            }),
        }
    }

    /// `true` if the log-line (tracing) sink is enabled.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn log_lines_enabled(&self) -> bool {
        self.inner.log_lines
    }

    /// `true` if the tracing log-line sink is enabled for this event severity.
    pub fn log_lines_enabled_for(&self, severity: AuditSeverity) -> bool {
        self.inner.log_lines && severity_rank(severity) >= severity_rank(self.inner.min_severity)
    }

    /// Dispatch an event to all non-log sinks (file + syslog).
    ///
    /// Call this once per event regardless of `log_lines_enabled`; the
    /// tracing sink path is handled separately by the task so it can enter
    /// the right span context before calling `tracing::info!` / `warn!`.
    pub fn dispatch(&self, event: &AuditEvent) {
        if severity_rank(event.severity) < severity_rank(self.inner.min_severity) {
            return;
        }

        if let Some(tx) = &self.inner.file_tx {
            let line = render_ndjson(event);
            let _ = tx.try_send(line);
        }
        if let Some(tx) = &self.inner.syslog_tx {
            let msg = render_syslog_message(event);
            let _ = tx.try_send((msg, event.severity));
        }
    }
}

fn severity_rank(sev: AuditSeverity) -> u8 {
    match sev {
        AuditSeverity::Debug => 0,
        AuditSeverity::Info => 1,
        AuditSeverity::Warning => 2,
        AuditSeverity::Error => 3,
    }
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// Escape a string for embedding in a JSON string value.
///
/// Covers the mandatory JSON escapes only (no Unicode surrogate handling
/// needed — AuditEventKind Display output uses ASCII tokens).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn level_label(sev: AuditSeverity) -> &'static str {
    match sev {
        AuditSeverity::Error => "error",
        AuditSeverity::Warning => "warn",
        AuditSeverity::Info => "info",
        AuditSeverity::Debug => "debug",
    }
}

fn render_ndjson(event: &AuditEvent) -> String {
    let ts = event.timestamp_iso8601();
    let path = match event.family {
        AuditEventFamily::HotPath => "hot",
        AuditEventFamily::ColdPath => "cold",
    };
    let level = level_label(event.severity);
    let kind = json_escape(&format!("{}", event.kind));
    format!("{{\"ts\":\"{ts}\",\"path\":\"{path}\",\"level\":\"{level}\",\"event\":\"{kind}\"}}\n")
}

fn render_syslog_message(event: &AuditEvent) -> String {
    // Include timestamp so the record is unambiguous even when syslogd
    // re-stamps with its own wall-clock time.
    let ts = event.timestamp_iso8601();
    format!("{ts} {}", event.kind)
}

// ── Worker threads ────────────────────────────────────────────────────────────

fn run_file_sink_worker(path: PathBuf, rx: std::sync::mpsc::Receiver<String>) {
    use std::fs::OpenOptions;

    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(err) => {
            tracing::warn!(path = %path.display(), "audit file sink: open failed: {err}");
            return;
        }
    };

    for line in rx {
        if let Err(err) = file.write_all(line.as_bytes()) {
            tracing::warn!(path = %path.display(), "audit file sink: write failed: {err}");
            // Attempt reopen (handles logrotate copytruncate / ext rename).
            match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(f) => {
                    file = f;
                    // Retry the line on the freshly reopened file.
                    let _ = file.write_all(line.as_bytes());
                }
                Err(err) => {
                    tracing::warn!(path = %path.display(), "audit file sink: reopen failed: {err}");
                }
            }
        }
    }
}

fn run_syslog_sink_worker(rx: std::sync::mpsc::Receiver<(String, AuditSeverity)>) {
    let formatter = Formatter3164 {
        facility: Facility::LOG_DAEMON,
        hostname: None,
        process: AUDIT_SYSLOG_TAG.to_string(),
        pid: 0,
    };

    let mut writer = match syslog::unix(formatter) {
        Ok(w) => w,
        Err(err) => {
            tracing::warn!("audit syslog sink: init failed, falling back to tracing: {err}");
            for (msg, sev) in rx {
                match sev {
                    AuditSeverity::Error => tracing::error!(
                        target: "opensnitch.audit.syslog", event = %msg,
                        "audit event (syslog sink unavailable)"
                    ),
                    AuditSeverity::Warning => tracing::warn!(
                        target: "opensnitch.audit.syslog", event = %msg,
                        "audit event (syslog sink unavailable)"
                    ),
                    AuditSeverity::Info => tracing::info!(
                        target: "opensnitch.audit.syslog", event = %msg,
                        "audit event (syslog sink unavailable)"
                    ),
                    AuditSeverity::Debug => tracing::debug!(
                        target: "opensnitch.audit.syslog", event = %msg,
                        "audit event (syslog sink unavailable)"
                    ),
                }
            }
            return;
        }
    };

    for (msg, sev) in rx {
        // Map AuditSeverity to the appropriate syslog level:
        //   Error   → LOG_ERR     (hard daemon failures)
        //   Warning → LOG_WARNING (auth denials, recoverable failures)
        //   Info    → LOG_NOTICE  (normal but significant conditions)
        let result = match sev {
            AuditSeverity::Error => writer.err(msg.as_str()),
            AuditSeverity::Warning => writer.warning(msg.as_str()),
            AuditSeverity::Info => writer.notice(msg.as_str()),
            AuditSeverity::Debug => writer.debug(msg.as_str()),
        };
        if let Err(err) = result {
            tracing::warn!("audit syslog sink: write failed: {err}");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "../../tests/services/audit_sink.rs"]
mod tests;
