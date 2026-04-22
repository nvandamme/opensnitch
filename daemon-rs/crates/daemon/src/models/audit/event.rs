use std::time::SystemTime;

use super::{AuditEventFamily, AuditEventKind, AuditSeverity};

/// Audit service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum AuditLifecycle {
    Initialized,
    SinkStarted,
    Stopped,
}

/// Domain audit record produced by service boundaries.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Wall-clock time at which the event was emitted, in UTC.
    /// Stamped at the call site so it reflects when the decision occurred,
    /// not when the dispatcher thread processed the ingress queue.
    pub timestamp: SystemTime,
    pub family: AuditEventFamily,
    /// Operational severity: derived automatically from the event kind.
    pub severity: AuditSeverity,
    pub kind: AuditEventKind,
}

impl AuditEvent {
    /// Tag an event as emitted on the hot (latency-sensitive) path.
    pub fn hot(kind: AuditEventKind) -> Self {
        let severity = AuditSeverity::from_kind(&kind);
        Self {
            timestamp: SystemTime::now(),
            family: AuditEventFamily::HotPath,
            severity,
            kind,
        }
    }

    /// Tag an event as emitted on the cold (administrative/observability) path.
    pub fn cold(kind: AuditEventKind) -> Self {
        let severity = AuditSeverity::from_kind(&kind);
        Self {
            timestamp: SystemTime::now(),
            family: AuditEventFamily::ColdPath,
            severity,
            kind,
        }
    }

    /// Format the timestamp as an ISO 8601 / RFC 3339 string (UTC, nanosecond precision).
    /// No external crate dependency — used by the NDJSON file sink.
    pub fn timestamp_iso8601(&self) -> String {
        let dur = self
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = dur.as_secs();
        let nanos = dur.subsec_nanos();

        // Decompose Unix timestamp into calendar fields (proleptic Gregorian, UTC).
        let s = secs % 60;
        let m = (secs / 60) % 60;
        let h = (secs / 3600) % 24;
        let days = secs / 86400; // days since 1970-01-01

        // Shift to a cycle starting at year 1 to simplify leap-year math.
        // Uses the 400-year Gregorian cycle: 97 leap years per 400 years.
        let z = days + 719_468;
        let era = z / 146_097;
        let doe = z % 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let mo = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if mo <= 2 { y + 1 } else { y };

        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{nanos:09}Z")
    }
}
