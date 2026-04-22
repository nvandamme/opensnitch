use std::collections::HashMap;

use tokio_util::sync::CancellationToken;

pub(crate) struct TaskStorageRuntime {
    pub(crate) handle: tokio::task::JoinHandle<()>,
    pub(crate) token: CancellationToken,
    pub(crate) fingerprint: String,
}

impl TaskStorageRuntime {
    pub(crate) fn runtime(handle: tokio::task::JoinHandle<()>, token: CancellationToken) -> Self {
        Self {
            handle,
            token,
            fingerprint: String::new(),
        }
    }

    pub(crate) fn disk(
        handle: tokio::task::JoinHandle<()>,
        token: CancellationToken,
        fingerprint: String,
    ) -> Self {
        Self {
            handle,
            token,
            fingerprint,
        }
    }

    pub(crate) fn stop(self) {
        self.token.cancel();
        self.handle.abort();
    }
}

pub(crate) type RuntimeTaskHandles = HashMap<String, TaskStorageRuntime>;
