use std::sync::{OnceLock, RwLock};

use tokio::sync::watch;

use super::storage::StorageService;
use crate::services::lifecycle::{ServiceFactory, ServiceRuntimeControl};

pub(super) struct StorageRuntimeLifecycle {
    singleton: RwLock<StorageService>,
    reload_generation: RwLock<u64>,
    reload_tx: watch::Sender<u64>,
}

impl StorageRuntimeLifecycle {
    fn new() -> Self {
        let (reload_tx, _) = watch::channel(0_u64);
        Self {
            singleton: RwLock::new(StorageService::new()),
            reload_generation: RwLock::new(0),
            reload_tx,
        }
    }

    pub(super) fn global() -> &'static Self {
        static GLOBAL: OnceLock<StorageRuntimeLifecycle> = OnceLock::new();
        GLOBAL.get_or_init(Self::new)
    }

    pub(super) fn service_snapshot(&self) -> StorageService {
        self.singleton
            .read()
            .expect("storage singleton rwlock poisoned")
            .clone()
    }

    pub(super) fn replace_service(&self, next: StorageService) -> StorageService {
        let mut guard = self
            .singleton
            .write()
            .expect("storage singleton rwlock poisoned");
        *guard = next.clone();

        let next_generation = {
            let mut generation = self
                .reload_generation
                .write()
                .expect("storage reload generation rwlock poisoned");
            *generation = generation.saturating_add(1);
            *generation
        };
        let _ = self.reload_tx.send(next_generation);
        next
    }

    pub(super) fn subscribe_reload(&self) -> watch::Receiver<u64> {
        self.reload_tx.subscribe()
    }
}

pub(super) fn global_storage_service() -> StorageService {
    StorageRuntimeLifecycle::global().service_snapshot()
}

pub(super) fn subscribe_global_storage_reload() -> watch::Receiver<u64> {
    StorageRuntimeLifecycle::global().subscribe_reload()
}
pub(super) fn replace_global_storage_service(next: StorageService) -> StorageService {
    StorageRuntimeLifecycle::global().replace_service(next)
}
pub(super) fn reload_global_storage_service() -> StorageService {
    let current = global_storage_service();
    let audit = current.audit_handle();
    let verbose_hot_path = current.verbose_hot_path_audit_enabled();
    let main_storage_format = current.main_storage_format();
    replace_global_storage_service(
        StorageService::new()
            .with_optional_audit(audit)
            .with_verbose_hot_path_audit(verbose_hot_path)
            .with_main_storage_format(main_storage_format),
    )
}

impl ServiceFactory for StorageService {
    type FactoryInput = ();

    async fn init(_input: Self::FactoryInput) -> anyhow::Result<Self> {
        Ok(StorageService::new())
    }
}

impl ServiceRuntimeControl for StorageService {
    type ReloadInput = ();

    async fn reload(&mut self, _input: Self::ReloadInput) -> anyhow::Result<()> {
        *self = reload_global_storage_service();
        Ok(())
    }
}
