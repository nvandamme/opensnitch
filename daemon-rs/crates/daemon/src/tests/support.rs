#![cfg(test)]

use std::{fs, path::PathBuf, sync::Once};

use crate::utils::time_nonce::unique_name;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, reload};

pub(crate) struct TestDir {
    pub(crate) path: PathBuf,
}

impl TestDir {
    pub(crate) fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(unique_name(prefix));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn init_test_logging() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,opensnitchd_rs=debug"));
        let (filter_layer, handle) = reload::Layer::new(filter);
        let _ = crate::logging::LOG_FILTER_HANDLE.set(handle);

        let _ = tracing_subscriber::registry()
            .with(filter_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .without_time()
                    .with_target(false)
                    .with_test_writer(),
            )
            .try_init();
    });
}
