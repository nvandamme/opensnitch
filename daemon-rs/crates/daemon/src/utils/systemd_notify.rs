use std::{
    env,
    os::unix::net::UnixDatagram,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use tracing::{debug, info, warn};

static FALLBACK_NOTICE_EMITTED: AtomicBool = AtomicBool::new(false);

pub enum NotifyState<'a> {
    Status(&'a str),
    ExtendTimeout(Duration),
    Ready(Option<&'a str>),
    Stopping(Option<&'a str>),
    Reloading(Option<&'a str>),
}

fn notify_socket_path() -> Option<String> {
    env::var("NOTIFY_SOCKET")
        .ok()
        .filter(|value| !value.is_empty())
}

fn emit_fallback_notice(reason: &str) {
    if FALLBACK_NOTICE_EMITTED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        info!(
            "systemd notify unavailable ({}); using log-based lifecycle state fallback",
            reason
        );
    }
}

fn log_payload_fallback(payload: &str) {
    for line in payload.lines() {
        if let Some(message) = line.strip_prefix("STATUS=") {
            info!("service status: {message}");
            continue;
        }

        if line == "READY=1" {
            info!("service state: ready");
            continue;
        }

        if line == "STOPPING=1" {
            info!("service state: stopping");
            continue;
        }

        if line == "RELOADING=1" {
            info!("service state: reloading");
            continue;
        }

        if let Some(micros) = line.strip_prefix("EXTEND_TIMEOUT_USEC=") {
            debug!("service timeout extension requested: {} usec", micros);
        }
    }
}

fn try_send_payload(payload: &str) -> std::io::Result<bool> {
    let Some(socket_path) = notify_socket_path() else {
        emit_fallback_notice("NOTIFY_SOCKET is not set");
        return Ok(false);
    };

    if socket_path.starts_with('@') {
        emit_fallback_notice("abstract NOTIFY_SOCKET is not supported by this notifier");
        return Ok(false);
    }

    let socket = UnixDatagram::unbound()?;
    socket.send_to(payload.as_bytes(), Path::new(&socket_path))?;
    Ok(true)
}

fn send_payload(payload: &str) {
    match try_send_payload(payload) {
        Ok(true) => {}
        Ok(false) => log_payload_fallback(payload),
        Err(err) => {
            emit_fallback_notice("failed to send sd_notify payload");
            warn!("failed to send sd_notify payload: {err}");
            log_payload_fallback(payload);
        }
    }
}

pub fn notify(state: NotifyState<'_>) {
    match state {
        NotifyState::Status(message) => send_payload(&format!("STATUS={message}")),
        NotifyState::ExtendTimeout(duration) => {
            let micros = duration.as_micros();
            send_payload(&format!("EXTEND_TIMEOUT_USEC={micros}"));
        }
        NotifyState::Ready(Some(message)) => send_payload(&format!("READY=1\nSTATUS={message}")),
        NotifyState::Ready(None) => send_payload("READY=1"),
        NotifyState::Stopping(Some(message)) => {
            send_payload(&format!("STOPPING=1\nSTATUS={message}"));
        }
        NotifyState::Stopping(None) => send_payload("STOPPING=1"),
        NotifyState::Reloading(Some(message)) => {
            send_payload(&format!("RELOADING=1\nSTATUS={message}"));
        }
        NotifyState::Reloading(None) => send_payload("RELOADING=1"),
    }
}
