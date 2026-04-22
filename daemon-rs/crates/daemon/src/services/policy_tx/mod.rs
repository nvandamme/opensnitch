mod runtime_lifecycle;

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Mutex;

pub use crate::models::policy_tx::{PolicyChangeSet, PolicyOwner, TxPhase};

pub use runtime_lifecycle::global_policy_tx;

#[derive(Clone, Debug)]
pub struct PolicyTxRequest {
    pub idempotency_key: String,
    pub owner: PolicyOwner,
    pub expected_revision: Option<u64>,
    pub operations: Vec<String>,
}

#[derive(Debug)]
pub enum PolicyTxError {
    Conflict { expected: u64, actual: u64 },
    DuplicateInFlight { tx_id: String },
    DuplicateCommitted { tx_id: String, revision: u64 },
    ApplyFailed { error: String },
    RollbackFailed { apply_error: String, rollback_error: String },
    PersistFailed(String),
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
        Self {
            revision: Arc::new(AtomicU64::new(0)),
            apply_lock: Arc::new(Mutex::new(())),
            idempotency: Arc::new(Mutex::new(HashMap::new())),
            tx_counter: Arc::new(AtomicU64::new(1)),
            base_dir: Arc::new(base_dir),
        }
    }
}

impl PolicyTxCoordinator {
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
        tokio::fs::create_dir_all(self.base_dir.join("changesets"))
            .await
            .map_err(|err| PolicyTxError::PersistFailed(err.to_string()))?;
        tokio::fs::create_dir_all(self.base_dir.join("audit"))
            .await
            .map_err(|err| PolicyTxError::PersistFailed(err.to_string()))?;
        Ok(())
    }

    async fn persist_change_set(&self, change_set: &PolicyChangeSet) -> Result<(), PolicyTxError> {
        self.ensure_base_dirs().await?;
        let path = self
            .base_dir
            .join("changesets")
            .join(format!("{}.json", change_set.tx_id));
        let payload = serde_json::to_vec_pretty(change_set)
            .map_err(|err| PolicyTxError::PersistFailed(err.to_string()))?;
        tokio::fs::write(path, payload)
            .await
            .map_err(|err| PolicyTxError::PersistFailed(err.to_string()))
    }

    async fn persist_audit_record(&self, change_set: &PolicyChangeSet) -> Result<(), PolicyTxError> {
        self.ensure_base_dirs().await?;
        let path = self.base_dir.join("audit").join("policy_tx.jsonl");
        let line = serde_json::to_string(change_set)
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
mod tests {
    use super::{PolicyOwner, PolicyTxCoordinator, PolicyTxError, PolicyTxRequest};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn duplicate_committed_request_is_rejected() {
        let tx = PolicyTxCoordinator::default();

        let request = PolicyTxRequest {
            idempotency_key: "same-key".to_string(),
            owner: PolicyOwner::LocalUid(1000),
            expected_revision: None,
            operations: vec!["noop".to_string()],
        };

        let first = tx
            .execute(request.clone(), || async { Ok(()) }, || async { Ok(()) })
            .await;
        assert!(first.is_ok());

        let second = tx
            .execute(request, || async { Ok(()) }, || async { Ok(()) })
            .await;

        assert!(matches!(
            second,
            Err(PolicyTxError::DuplicateCommitted { .. })
        ));
    }

    #[tokio::test]
    async fn duplicate_inflight_request_is_rejected() {
        let tx = PolicyTxCoordinator::default();

        let (started_tx, started_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();

        let tx_clone = tx.clone();
        let first_handle = tokio::spawn(async move {
            tx_clone
                .execute(
                    PolicyTxRequest {
                        idempotency_key: "inflight-key".to_string(),
                        owner: PolicyOwner::LocalUid(1000),
                        expected_revision: None,
                        operations: vec!["slow-op".to_string()],
                    },
                    || async {
                        let _ = started_tx.send(());
                        let _ = release_rx.await;
                        Ok(())
                    },
                    || async { Ok(()) },
                )
                .await
        });

        let _ = started_rx.await;

        let second = tx
            .execute(
                PolicyTxRequest {
                    idempotency_key: "inflight-key".to_string(),
                    owner: PolicyOwner::LocalUid(1001),
                    expected_revision: None,
                    operations: vec!["slow-op".to_string()],
                },
                || async { Ok(()) },
                || async { Ok(()) },
            )
            .await;

        assert!(matches!(second, Err(PolicyTxError::DuplicateInFlight { .. })));

        let _ = release_tx.send(());
        let first = first_handle.await.expect("first task join");
        assert!(first.is_ok());
    }

    #[tokio::test]
    async fn requests_from_multiple_users_are_serialized() {
        let tx = PolicyTxCoordinator::default();
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for uid in [2000u32, 2001u32, 2002u32] {
            let tx_clone = tx.clone();
            let active_clone = Arc::clone(&active);
            let max_active_clone = Arc::clone(&max_active);
            handles.push(tokio::spawn(async move {
                tx_clone
                    .execute(
                        PolicyTxRequest {
                            idempotency_key: format!("key-{uid}"),
                            owner: PolicyOwner::LocalUid(uid),
                            expected_revision: None,
                            operations: vec![format!("op-{uid}")],
                        },
                        || async move {
                            let current = active_clone.fetch_add(1, Ordering::SeqCst) + 1;
                            loop {
                                let observed = max_active_clone.load(Ordering::SeqCst);
                                if current <= observed {
                                    break;
                                }
                                if max_active_clone
                                    .compare_exchange(
                                        observed,
                                        current,
                                        Ordering::SeqCst,
                                        Ordering::SeqCst,
                                    )
                                    .is_ok()
                                {
                                    break;
                                }
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                            active_clone.fetch_sub(1, Ordering::SeqCst);
                            Ok(())
                        },
                        || async { Ok(()) },
                    )
                    .await
            }));
        }

        for handle in handles {
            let result = handle.await.expect("task join");
            assert!(result.is_ok());
        }

        assert_eq!(max_active.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn apply_failure_is_reported_when_rollback_succeeds() {
        let tx = PolicyTxCoordinator::default();

        let result = tx
            .execute(
                PolicyTxRequest {
                    idempotency_key: "apply-fail".to_string(),
                    owner: PolicyOwner::LocalUid(1000),
                    expected_revision: None,
                    operations: vec!["apply-fails".to_string()],
                },
                || async { Err("apply failed".to_string()) },
                || async { Ok(()) },
            )
            .await;

        assert!(matches!(
            result,
            Err(PolicyTxError::ApplyFailed { ref error }) if error == "apply failed"
        ));
    }

    #[tokio::test]
    async fn rollback_failure_is_reported_when_apply_and_rollback_fail() {
        let tx = PolicyTxCoordinator::default();

        let result = tx
            .execute(
                PolicyTxRequest {
                    idempotency_key: "rollback-fail".to_string(),
                    owner: PolicyOwner::LocalUid(1000),
                    expected_revision: None,
                    operations: vec!["apply-and-rollback-fail".to_string()],
                },
                || async { Err("apply failed".to_string()) },
                || async { Err("rollback failed".to_string()) },
            )
            .await;

        assert!(matches!(
            result,
            Err(PolicyTxError::RollbackFailed {
                ref apply_error,
                ref rollback_error,
            }) if apply_error == "apply failed" && rollback_error == "rollback failed"
        ));
    }
}
