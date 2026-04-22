use super::*;
use crate::models::{
    audit::{AuditEvent, AuditEventKind, AuditLifecycle, AuditSeverity},
    config_runtime::AuditSinkConfig,
};

#[test]
fn render_ndjson_produces_valid_line() {
    let event = AuditEvent::cold(AuditEventKind::AuditLifecycle(AuditLifecycle::Initialized));
    let line = render_ndjson(&event);
    assert!(line.starts_with("{\"ts\":\""), "missing ts: {line}");
    assert!(line.contains("\"path\":\"cold\""), "wrong path: {line}");
    assert!(line.contains("\"level\":\"info\""), "missing level: {line}");
    assert!(line.contains("\"event\":\""), "missing event: {line}");
    assert!(line.ends_with("}\n"), "missing trailing newline: {line}");

    // Must be valid JSON.
    let parsed: serde_json::Value =
        transport_wire_core::decode_json_notification_payload(line.trim_end())
            .expect("ndjson line is not valid JSON");
    assert_eq!(parsed["path"], "cold");
    assert_eq!(parsed["level"], "info");
}

#[test]
fn render_ndjson_severity_error_label() {
    use crate::models::audit::{AuditEventKind, ConnectionLifecycle};
    let event = AuditEvent::cold(AuditEventKind::ConnectionLifecycle(
        ConnectionLifecycle::Failed { reason: "test" },
    ));
    assert_eq!(event.severity, AuditSeverity::Error);
    let line = render_ndjson(&event);
    assert!(
        line.contains("\"level\":\"error\""),
        "expected error level: {line}"
    );
}

#[test]
fn render_ndjson_severity_warning_label() {
    use crate::models::audit::{AuditEventKind, RuleAction};
    let event = AuditEvent::cold(AuditEventKind::RuleAction(RuleAction::RuleCommandFailed {
        notification_id: 1,
        reason: "conflict".into(),
    }));
    assert_eq!(event.severity, AuditSeverity::Warning);
    let line = render_ndjson(&event);
    assert!(
        line.contains("\"level\":\"warn\""),
        "expected warn level: {line}"
    );
}

#[test]
fn render_ndjson_escapes_special_chars() {
    let raw = r#"has "quotes" and \backslash"#;
    let escaped = json_escape(raw);
    assert!(!escaped.contains('"') || escaped.contains("\\\""));
    assert!(!escaped.contains('\\') || escaped.contains("\\\\") || escaped.contains("\\\""));
}

#[test]
fn render_syslog_message_no_debug_trait() {
    let event = AuditEvent::hot(AuditEventKind::AuditLifecycle(AuditLifecycle::SinkStarted));
    let msg = render_syslog_message(&event);
    // Must contain the Display output of the event kind, not Debug punctuation like curly braces
    assert!(
        msg.contains("AuditLifecycle/SinkStarted"),
        "unexpected: {msg}"
    );
    assert!(
        !msg.contains("AuditLifecycle(SinkStarted"),
        "Debug leak: {msg}"
    );
}

#[test]
fn from_config_disabled_sinks_creates_no_threads() {
    let cfg = AuditSinkConfig {
        sink_file: None,
        sink_syslog: false,
        sink_log_lines: true,
        verbose_hot_path: false,
        min_severity: AuditSeverity::Debug,
    };
    let sinks = AuditSinks::from_config(&cfg);
    assert!(sinks.inner.file_tx.is_none());
    assert!(sinks.inner.syslog_tx.is_none());
    assert!(sinks.log_lines_enabled());
}

#[test]
fn dispatch_to_file_sink_roundtrip() {
    use std::io::Read;

    let path = std::env::temp_dir().join(format!(
        "opensnitch-audit-sink-test-{}.ndjson",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    let cfg = AuditSinkConfig {
        sink_file: Some(path.clone()),
        sink_syslog: false,
        sink_log_lines: false,
        verbose_hot_path: false,
        min_severity: AuditSeverity::Debug,
    };
    let sinks = AuditSinks::from_config(&cfg);
    let event = AuditEvent::hot(AuditEventKind::AuditLifecycle(AuditLifecycle::SinkStarted));
    sinks.dispatch(&event);

    // Drain the sender so the worker thread flushes.
    drop(sinks);

    // Give the thread a moment to write and exit.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut content = String::new();
    std::fs::File::open(&path)
        .expect("file not created")
        .read_to_string(&mut content)
        .expect("read failed");

    let _ = std::fs::remove_file(&path);

    assert!(
        content.contains("\"path\":\"hot\""),
        "unexpected content: {content}"
    );
    assert!(
        content.contains("AuditLifecycle/SinkStarted"),
        "unexpected content: {content}"
    );
    assert!(
        content.contains("\"level\":\"info\""),
        "unexpected content: {content}"
    );
}

#[test]
fn dispatch_filters_events_below_min_severity() {
    use std::io::Read;

    let path = std::env::temp_dir().join(format!(
        "opensnitch-audit-sink-threshold-test-{}.ndjson",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    let cfg = AuditSinkConfig {
        sink_file: Some(path.clone()),
        sink_syslog: false,
        sink_log_lines: true,
        verbose_hot_path: false,
        min_severity: AuditSeverity::Info,
    };
    let sinks = AuditSinks::from_config(&cfg);

    let debug_event = AuditEvent::hot(AuditEventKind::ConnectFlowAction(
        crate::models::audit::ConnectFlowAction::ConnectionTracked,
    ));
    assert_eq!(debug_event.severity, AuditSeverity::Debug);
    sinks.dispatch(&debug_event);
    assert!(!sinks.log_lines_enabled_for(debug_event.severity));

    let warn_event = AuditEvent::cold(AuditEventKind::RuleAction(
        crate::models::audit::RuleAction::RuleCommandFailed {
            notification_id: 7,
            reason: "denied".into(),
        },
    ));
    assert_eq!(warn_event.severity, AuditSeverity::Warning);
    sinks.dispatch(&warn_event);
    assert!(sinks.log_lines_enabled_for(warn_event.severity));

    drop(sinks);
    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut content = String::new();
    std::fs::File::open(&path)
        .expect("file not created")
        .read_to_string(&mut content)
        .expect("read failed");

    let _ = std::fs::remove_file(&path);

    assert!(
        !content.contains("ConnectFlowAction/ConnectionTracked"),
        "debug event must be filtered: {content}"
    );
    assert!(
        content.contains("RuleAction/RuleCommandFailed"),
        "warning event should pass threshold: {content}"
    );
}
