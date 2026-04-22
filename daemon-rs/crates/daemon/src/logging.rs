use std::sync::OnceLock;

use anyhow::{Result, anyhow};
use tracing_subscriber::{
    EnvFilter, Registry, layer::SubscriberExt, reload, util::SubscriberInitExt,
};

static LOG_FILTER_HANDLE: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

pub fn init() {
    let (filter_layer, handle) = reload::Layer::new(EnvFilter::from_default_env());
    let _ = LOG_FILTER_HANDLE.set(handle);

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
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
