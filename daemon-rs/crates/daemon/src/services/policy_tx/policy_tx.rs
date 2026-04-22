use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use storage_format_core::StorageFormatCodec;
use storage_format_json::JsonStorageFormat;
use tokio::sync::Mutex;

pub use crate::models::policy_tx_storage::{PolicyChangeSet, PolicyOwner, TxPhase};

#[derive(Clone, Debug)]
pub struct PolicyTxRequest {
    pub idempotency_key: String,
    pub owner: PolicyOwner,
    pub expected_revision: Option<u64>,
    pub operations: Vec<String>,
}

#[derive(Debug)]
pub enum PolicyTxError {
    Conflict {
        expected: u64,
        actual: u64,
    },
    DuplicateInFlight {
        tx_id: String,
    },
    DuplicateCommitted {
        tx_id: String,
        revision: u64,
    },
    ApplyFailed {
        error: String,
    },
    RollbackFailed {
        apply_error: String,
        rollback_error: String,
    },
    PersistFailed(String),
}

impl std::fmt::Display for PolicyTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { expected, actual } => {
                write!(
                    f,
                    "transaction conflict: expected revision {expected}, got {actual}"
                )
            }
            Self::DuplicateInFlight { tx_id } => {
                write!(f, "duplicate in-flight transaction: {tx_id}")
            }
            Self::DuplicateCommitted { tx_id, revision } => {
                write!(
                    f,
                    "duplicate committed transaction: {tx_id} at revision {revision}"
                )
            }
            Self::ApplyFailed { error } => write!(f, "apply failed: {error}"),
            Self::RollbackFailed {
                apply_error,
                rollback_error,
            } => {
                write!(
                    f,
                    "rollback failed (apply: {apply_error}; rollback: {rollback_error})"
                )
            }
            Self::PersistFailed(msg) => write!(f, "persist failed: {msg}"),
        }
    }
}

#[derive(Clone, Debug)]
enum IdempotencyState {
    InFlight { tx_id: String },
    Committed { tx_id: String, revision: u64 },
}

#[derive(Clone)]
pub struct PolicyTxCoordinator {
    revision: Arc<AtomicU64>,
    apply_lock: Arc<Mutex<()>>,
    idempotency: Arc<Mutex<HashMap<String, IdempotencyState>>>,
    tx_counter: Arc<AtomicU64>,
    base_dir: Arc<PathBuf>,
}

impl Default for PolicyTxCoordinator {
    fn default() -> Self {
        let base_dir = std::env::temp_dir().join("opensnitchd-rs/policy-tx");
        Self::new(base_dir)
    }
}

impl PolicyTxCoordinator {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            revision: Arc::new(AtomicU64::new(0)),
            apply_lock: Arc::new(Mutex::new(())),
            idempotency: Arc::new(Mutex::new(HashMap::new())),
            tx_counter: Arc::new(AtomicU64::new(1)),
            base_dir: Arc::new(base_dir),
        }
    }

    pub async fn execute<AFut, RFut, A, R>(
        &self,
        req: PolicyTxRequest,
        apply: A,
        rollback: R,
    ) -> Result<u64, PolicyTxError>
    where
        A: FnOnce() -> AFut,
        AFut: Future<Output = Result<(), String>>,
        R: FnOnce() -> RFut,
        RFut: Future<Output = Result<(), String>>,
    {
        let now = crate::utils::time_nonce::unix_epoch_nanos() as i64;

        {
            let idempotency = self.idempotency.lock().await;
            if let Some(state) = idempotency.get(&req.idempotency_key) {
                match state {
                    IdempotencyState::InFlight { tx_id } => {
                        return Err(PolicyTxError::DuplicateInFlight {
                            tx_id: tx_id.clone(),
                        });
                    }
                    IdempotencyState::Committed { tx_id, revision } => {
                        return Err(PolicyTxError::DuplicateCommitted {
                            tx_id: tx_id.clone(),
                            revision: *revision,
                        });
                    }
                }
            }
        }

        let tx_id = format!(
            "tx-{}-{}",
            now,
            self.tx_counter.fetch_add(1, Ordering::Relaxed)
        );

        let mut change_set = PolicyChangeSet {
            tx_id: tx_id.clone(),
            idempotency_key: req.idempotency_key.clone(),
            owner: req.owner,
            expected_revision: req.expected_revision,
            base_revision: self.revision.load(Ordering::Relaxed),
            committed_revision: None,
            created_at_unix_nano: now,
            phase: TxPhase::Planned,
            operations: req.operations,
            outcome: None,
        };

        self.persist_audit_record(&change_set).await?;

        let _guard = self.apply_lock.lock().await;

        {
            let idempotency = self.idempotency.lock().await;
            if let Some(state) = idempotency.get(&req.idempotency_key) {
                match state {
                    IdempotencyState::InFlight { tx_id } => {
                        return Err(PolicyTxError::DuplicateInFlight {
                            tx_id: tx_id.clone(),
                        });
                    }
                    IdempotencyState::Committed { tx_id, revision } => {
                        return Err(PolicyTxError::DuplicateCommitted {
                            tx_id: tx_id.clone(),
                            revision: *revision,
                        });
                    }
                }
            }
        }

        let current_revision = self.revision.load(Ordering::Relaxed);
        if let Some(expected) = change_set.expected_revision
            && expected != current_revision
        {
            return Err(PolicyTxError::Conflict {
                expected,
                actual: current_revision,
            });
        }

        change_set.base_revision = current_revision;
        change_set.phase = TxPhase::IntentPersisted;
        self.persist_change_set(&change_set).await?;
        self.persist_audit_record(&change_set).await?;

        {
            let mut idempotency = self.idempotency.lock().await;
            idempotency.insert(
                change_set.idempotency_key.clone(),
                IdempotencyState::InFlight {
                    tx_id: tx_id.clone(),
                },
            );
        }

        match apply().await {
            Ok(()) => {
                let committed_revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
                change_set.phase = TxPhase::Committed;
                change_set.committed_revision = Some(committed_revision);
                change_set.outcome = Some("ok".to_string());
                self.persist_change_set(&change_set).await?;
                self.persist_audit_record(&change_set).await?;

                let mut idempotency = self.idempotency.lock().await;
                idempotency.insert(
                    change_set.idempotency_key.clone(),
                    IdempotencyState::Committed {
                        tx_id,
                        revision: committed_revision,
                    },
                );

                Ok(committed_revision)
            }
            Err(apply_error) => match rollback().await {
                Ok(()) => {
                    change_set.phase = TxPhase::RolledBack;
                    change_set.outcome = Some(apply_error.clone());
                    self.persist_change_set(&change_set).await?;
                    self.persist_audit_record(&change_set).await?;
                    let mut idempotency = self.idempotency.lock().await;
                    idempotency.remove(&change_set.idempotency_key);
                    Err(PolicyTxError::ApplyFailed { error: apply_error })
                }
                Err(rollback_error) => {
                    change_set.phase = TxPhase::Failed;
                    change_set.outcome = Some(format!(
                        "apply failed: {apply_error}; rollback failed: {rollback_error}"
                    ));
                    self.persist_change_set(&change_set).await?;
                    self.persist_audit_record(&change_set).await?;
                    let mut idempotency = self.idempotency.lock().await;
                    idempotency.remove(&change_set.idempotency_key);
                    Err(PolicyTxError::RollbackFailed {
                        apply_error,
                        rollback_error,
                    })
                }
            },
        }
    }

    async fn ensure_base_dirs(&self) -> Result<(), PolicyTxError> {
        tokio::fs::create_dir_all(self.base_dir.join("audit"))
            .await
            .map_err(|err| PolicyTxError::PersistFailed(err.to_string()))?;
        Ok(())
    }

    async fn persist_change_set(&self, change_set: &PolicyChangeSet) -> Result<(), PolicyTxError> {
        let path = self
            .base_dir
            .join("changesets")
            .join(format!("{}.json", change_set.tx_id));
        crate::services::storage::StorageService::global()
            .convert_and_write_with_storage_format_to_path_and_notify(
                "policy-tx",
                &path,
                change_set,
                true,
            )
            .await
            .map_err(|err| PolicyTxError::PersistFailed(err.to_string()))
    }

    async fn persist_audit_record(
        &self,
        change_set: &PolicyChangeSet,
    ) -> Result<(), PolicyTxError> {
        self.ensure_base_dirs().await?;
        let path = self.base_dir.join("audit").join("policy_tx.jsonl");
        // APPROVED(json): append-only JSONL audit trail — format is explicitly JSON
        // by design (not loadable-state format-pluggable); StorageService has no append path.
        let line = JsonStorageFormat
            .convert_to_storage(change_set)
            .map_err(|err| PolicyTxError::PersistFailed(err.to_string()))?
            + "\n";

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(|err| PolicyTxError::PersistFailed(err.to_string()))?;
        use tokio::io::AsyncWriteExt;
        file.write_all(line.as_bytes())
            .await
            .map_err(|err| PolicyTxError::PersistFailed(err.to_string()))
    }
}

#[cfg(test)]
#[path = "../../tests/services/policy_tx.rs"]
mod tests;
