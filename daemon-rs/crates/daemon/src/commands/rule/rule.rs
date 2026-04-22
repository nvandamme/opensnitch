use opensnitch_proto::pb;
use std::collections::BTreeSet;

use crate::models::{
    audit::{AuditEvent, AuditEventKind, RuleAction},
    command_rpc::ClientCommand,
    rule_record::RuleRecord,
};
use crate::services::{
    audit::AuditService,
    client::ClientService,
    policy_tx::{
        PolicyOwner, PolicyTxCoordinator, PolicyTxError, PolicyTxRequest, global_policy_tx,
    },
    rule::RuleService,
};
use crate::utils::notification_reply::{send_notification_reply, status_payload};

#[derive(Clone)]
pub(crate) struct RuleCommandService {
    policy_tx: PolicyTxCoordinator,
    audit: AuditService,
}

impl Default for RuleCommandService {
    fn default() -> Self {
        Self::new(global_policy_tx().clone(), AuditService::new(64))
    }
}

impl RuleCommandService {
    pub(crate) fn new(policy_tx: PolicyTxCoordinator, audit: AuditService) -> Self {
        Self { policy_tx, audit }
    }

    #[cfg(test)]
    pub(crate) fn with_base_dir(base_dir: std::path::PathBuf) -> Self {
        Self {
            policy_tx: PolicyTxCoordinator::new(base_dir),
            audit: AuditService::new(64),
        }
    }

    fn policy_tx(&self) -> &PolicyTxCoordinator {
        &self.policy_tx
    }

    fn owner_from_client(client_service: &ClientService) -> PolicyOwner {
        client_service
            .primary_owner()
            .map(PolicyOwner::from)
            .unwrap_or(PolicyOwner::System)
    }

    pub(crate) async fn try_handle_client_command(
        &self,
        cmd: ClientCommand,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
    ) -> Option<ClientCommand> {
        match cmd {
            ClientCommand::EnableRules {
                notification_id,
                rules: updated,
            } => {
                self.enable_rules(
                    notification_id,
                    updated,
                    rules,
                    task_reply_tx,
                    client_service,
                )
                .await;
                None
            }
            ClientCommand::DisableRules {
                notification_id,
                rules: updated,
            } => {
                self.disable_rules(
                    notification_id,
                    updated,
                    rules,
                    task_reply_tx,
                    client_service,
                )
                .await;
                None
            }
            ClientCommand::UpsertRules {
                notification_id,
                rules: updated,
            } => {
                self.upsert_rules(
                    notification_id,
                    updated,
                    rules,
                    task_reply_tx,
                    client_service,
                )
                .await;
                None
            }
            ClientCommand::DeleteRules {
                notification_id,
                rule_names,
            } => {
                self.delete_rules(
                    notification_id,
                    rule_names,
                    rules,
                    task_reply_tx,
                    client_service,
                )
                .await;
                None
            }
            other => Some(other),
        }
    }

    pub(crate) async fn enable_rules(
        &self,
        notification_id: u64,
        updated_rules: Vec<RuleRecord>,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
    ) {
        RuleUpdateMode::Enable
            .apply(
                self.policy_tx(),
                &self.audit,
                notification_id,
                updated_rules,
                rules,
                task_reply_tx,
                client_service,
            )
            .await;
    }

    pub(crate) async fn disable_rules(
        &self,
        notification_id: u64,
        updated_rules: Vec<RuleRecord>,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
    ) {
        RuleUpdateMode::Disable
            .apply(
                self.policy_tx(),
                &self.audit,
                notification_id,
                updated_rules,
                rules,
                task_reply_tx,
                client_service,
            )
            .await;
    }

    pub(crate) async fn upsert_rules(
        &self,
        notification_id: u64,
        updated_rules: Vec<RuleRecord>,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
    ) {
        RuleUpdateMode::Upsert
            .apply(
                self.policy_tx(),
                &self.audit,
                notification_id,
                updated_rules,
                rules,
                task_reply_tx,
                client_service,
            )
            .await;
    }

    pub(crate) async fn delete_rules(
        &self,
        notification_id: u64,
        rule_names: Vec<String>,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
    ) {
        let previous_rules = rules.get_rule_record_snapshot().as_ref().clone();
        let operation_names = rule_names.clone();
        let owner = Self::owner_from_client(client_service);
        let audit_clone = self.audit.clone();
        let tx = self
            .policy_tx()
            .execute(
                PolicyTxRequest {
                    idempotency_key: format!(
                        "rule-delete:{}:{}",
                        notification_id,
                        operation_names.join(",")
                    ),
                    owner,
                    expected_revision: None,
                    operations: operation_names
                        .iter()
                        .map(|name| format!("delete:{name}"))
                        .collect(),
                },
                || async {
                    let mut errors = Vec::new();
                    for rule_name in &rule_names {
                        let name: Box<str> = rule_name.as_str().into();
                        if let Err(err) = rules.delete_by_name(rule_name).await {
                            tracing::error!(rule = %rule_name, "failed to delete rule: {err}");
                            audit_clone.emit(AuditEvent::cold(AuditEventKind::RuleAction(
                                RuleAction::RuleDeleteFailed {
                                    name,
                                    reason: err.to_string().into(),
                                },
                            )));
                            errors.push(format!("{}: {}", rule_name, err));
                        } else {
                            audit_clone.emit(AuditEvent::cold(AuditEventKind::RuleAction(
                                RuleAction::RuleDeleted { name },
                            )));
                        }
                    }
                    if errors.is_empty() {
                        Ok(())
                    } else {
                        Err(format!(
                            "failed to delete some rules: {}",
                            errors.join(", ")
                        ))
                    }
                },
                || async { Self::restore_rules_snapshot(rules, &previous_rules).await },
            )
            .await;

        if tx.is_ok() || matches!(tx, Err(PolicyTxError::DuplicateCommitted { .. })) {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Ok,
                status_payload("ok"),
                "rule command notification",
            )
            .await;
        } else {
            let message = match tx {
                Err(PolicyTxError::ApplyFailed { error }) => error,
                Err(PolicyTxError::RollbackFailed {
                    apply_error,
                    rollback_error,
                }) => format!("{apply_error}; rollback failed: {rollback_error}"),
                Err(PolicyTxError::DuplicateInFlight { tx_id }) => {
                    format!("duplicate in-flight tx {tx_id}")
                }
                Err(PolicyTxError::Conflict { expected, actual }) => {
                    format!("revision conflict: expected {expected}, actual {actual}")
                }
                Err(PolicyTxError::PersistFailed(error)) => {
                    format!("transaction persistence failed: {error}")
                }
                Err(PolicyTxError::DuplicateCommitted { tx_id, revision }) => {
                    format!("duplicate committed tx {tx_id} @ revision {revision}")
                }
                Ok(_) => "ok".to_string(),
            };
            self.audit.emit(AuditEvent::cold(AuditEventKind::RuleAction(
                RuleAction::RuleCommandFailed {
                    notification_id,
                    reason: message.clone().into(),
                },
            )));
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                message,
                "rule command notification",
            )
            .await;
        }
    }

    async fn restore_rules_snapshot(
        rules: &RuleService,
        snapshot: &[RuleRecord],
    ) -> Result<(), String> {
        let target_names = snapshot
            .iter()
            .map(|rule| rule.name.clone())
            .collect::<BTreeSet<_>>();
        let current = rules.get_rule_record_snapshot();

        for rule in current.as_ref() {
            if !target_names.contains(&rule.name) {
                rules
                    .delete_by_name(&rule.name)
                    .await
                    .map_err(|err| format!("rollback delete {}: {err}", rule.name))?;
            }
        }

        for rule in snapshot {
            rules
                .upsert_rule_record(rule.clone())
                .await
                .map_err(|err| format!("rollback upsert {}: {err}", rule.name))?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum RuleUpdateMode {
    Enable,
    Disable,
    Upsert,
}

impl std::fmt::Display for RuleUpdateMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enable => f.write_str("enable"),
            Self::Disable => f.write_str("disable"),
            Self::Upsert => f.write_str("upsert"),
        }
    }
}

impl RuleUpdateMode {
    fn prepare(self, rule: &mut RuleRecord) {
        match self {
            Self::Enable => rule.enabled = true,
            Self::Disable => rule.enabled = false,
            Self::Upsert => {}
        }
    }

    fn error_prefix(self) -> &'static str {
        match self {
            Self::Enable => "failed to enable some rules",
            Self::Disable => "failed to disable some rules",
            Self::Upsert => "failed to update some rules",
        }
    }

    fn log_message(self) -> &'static str {
        match self {
            Self::Enable => "failed to enable rule",
            Self::Disable => "failed to disable rule",
            Self::Upsert => "failed to upsert rule",
        }
    }

    async fn apply(
        self,
        policy_tx: &PolicyTxCoordinator,
        audit: &AuditService,
        notification_id: u64,
        updated_rules: Vec<RuleRecord>,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        client_service: &ClientService,
    ) {
        let previous_rules = rules.get_rule_record_snapshot().as_ref().clone();
        let operation_names: Vec<String> =
            updated_rules.iter().map(|rule| rule.name.clone()).collect();

        let owner = RuleCommandService::owner_from_client(client_service);
        let audit_clone = audit.clone();
        let tx = policy_tx
            .execute(
                PolicyTxRequest {
                    idempotency_key: format!(
                        "rule-{}:{}:{}",
                        self,
                        notification_id,
                        operation_names.join(",")
                    ),
                    owner,
                    expected_revision: None,
                    operations: operation_names
                        .iter()
                        .map(|name| format!("{}:{name}", self))
                        .collect(),
                },
                || async {
                    let mut errors = Vec::new();
                    for mut rule in updated_rules {
                        self.prepare(&mut rule);
                        let name: Box<str> = rule.name.as_str().into();
                        let is_new = !previous_rules.iter().any(|r| r.name == rule.name);
                        if let Err(err) = rules.upsert_rule_record(rule.clone()).await {
                            tracing::error!(rule = %rule.name, "{}: {err}", self.log_message());
                            let action = if is_new {
                                RuleAction::RuleAddFailed {
                                    name,
                                    reason: err.to_string().into(),
                                }
                            } else {
                                RuleAction::RuleUpdateFailed {
                                    name,
                                    reason: err.to_string().into(),
                                }
                            };
                            audit_clone.emit(AuditEvent::cold(AuditEventKind::RuleAction(action)));
                            errors.push(format!("{}: {}", rule.name, err));
                        } else {
                            let action = if is_new {
                                RuleAction::RuleAdded { name }
                            } else {
                                RuleAction::RuleUpdated { name }
                            };
                            audit_clone.emit(AuditEvent::cold(AuditEventKind::RuleAction(action)));
                        }
                    }

                    if errors.is_empty() {
                        Ok(())
                    } else {
                        Err(format!("{}: {}", self.error_prefix(), errors.join(", ")))
                    }
                },
                || async {
                    RuleCommandService::restore_rules_snapshot(rules, &previous_rules).await
                },
            )
            .await;

        if tx.is_ok() || matches!(tx, Err(PolicyTxError::DuplicateCommitted { .. })) {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Ok,
                status_payload("ok"),
                "rule command notification",
            )
            .await;
        } else {
            let message = match tx {
                Err(PolicyTxError::ApplyFailed { error }) => error,
                Err(PolicyTxError::RollbackFailed {
                    apply_error,
                    rollback_error,
                }) => format!("{apply_error}; rollback failed: {rollback_error}"),
                Err(PolicyTxError::DuplicateInFlight { tx_id }) => {
                    format!("duplicate in-flight tx {tx_id}")
                }
                Err(PolicyTxError::Conflict { expected, actual }) => {
                    format!("revision conflict: expected {expected}, actual {actual}")
                }
                Err(PolicyTxError::PersistFailed(error)) => {
                    format!("transaction persistence failed: {error}")
                }
                Err(PolicyTxError::DuplicateCommitted { tx_id, revision }) => {
                    format!("duplicate committed tx {tx_id} @ revision {revision}")
                }
                Ok(_) => "ok".to_string(),
            };
            audit.emit(AuditEvent::cold(AuditEventKind::RuleAction(
                RuleAction::RuleCommandFailed {
                    notification_id,
                    reason: message.clone().into(),
                },
            )));
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                message,
                "rule command notification",
            )
            .await;
        }
    }
}
