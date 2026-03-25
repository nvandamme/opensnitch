use crate::services::policy_tx::{
    PolicyOwner, PolicyTxCoordinator, PolicyTxError, PolicyTxRequest,
};
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
