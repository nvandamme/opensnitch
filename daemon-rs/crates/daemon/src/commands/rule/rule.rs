use opensnitch_proto::pb;

use crate::models::command_rpc::ClientCommand;
use crate::services::rule::RuleService;
use crate::utils::notification_reply::{send_notification_reply, status_payload};

#[derive(Clone, Default)]
pub(crate) struct RuleCommandService;

impl RuleCommandService {
    pub(crate) async fn try_handle_client_command(
        &self,
        cmd: ClientCommand,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) -> Option<ClientCommand> {
        match cmd {
            ClientCommand::EnableRules {
                notification_id,
                rules: updated,
            } => {
                self.enable_rules(notification_id, updated, rules, task_reply_tx)
                    .await;
                None
            }
            ClientCommand::DisableRules {
                notification_id,
                rules: updated,
            } => {
                self.disable_rules(notification_id, updated, rules, task_reply_tx)
                    .await;
                None
            }
            ClientCommand::UpsertRules {
                notification_id,
                rules: updated,
            } => {
                self.upsert_rules(notification_id, updated, rules, task_reply_tx)
                    .await;
                None
            }
            ClientCommand::DeleteRules {
                notification_id,
                rule_names,
            } => {
                self.delete_rules(notification_id, rule_names, rules, task_reply_tx)
                    .await;
                None
            }
            other => Some(other),
        }
    }

    pub(crate) async fn enable_rules(
        &self,
        notification_id: u64,
        updated_rules: Vec<pb::Rule>,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        RuleUpdateMode::Enable
            .apply(notification_id, updated_rules, rules, task_reply_tx)
            .await;
    }

    pub(crate) async fn disable_rules(
        &self,
        notification_id: u64,
        updated_rules: Vec<pb::Rule>,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        RuleUpdateMode::Disable
            .apply(notification_id, updated_rules, rules, task_reply_tx)
            .await;
    }

    pub(crate) async fn upsert_rules(
        &self,
        notification_id: u64,
        updated_rules: Vec<pb::Rule>,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        RuleUpdateMode::Upsert
            .apply(notification_id, updated_rules, rules, task_reply_tx)
            .await;
    }

    pub(crate) async fn delete_rules(
        &self,
        notification_id: u64,
        rule_names: Vec<String>,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        let mut errors = Vec::new();
        for rule_name in rule_names {
            if let Err(err) = rules.delete_by_name(&rule_name).await {
                tracing::error!(rule = %rule_name, "failed to delete rule: {err}");
                errors.push(format!("{}: {}", rule_name, err));
            }
        }

        if errors.is_empty() {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Ok,
                status_payload("ok"),
                "rule command notification",
            )
            .await;
        } else {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("failed to delete some rules: {}", errors.join(", ")),
                "rule command notification",
            )
            .await;
        }
    }
}

#[derive(Clone, Copy)]
enum RuleUpdateMode {
    Enable,
    Disable,
    Upsert,
}

impl RuleUpdateMode {
    fn prepare(self, rule: &mut pb::Rule) {
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
        notification_id: u64,
        updated_rules: Vec<pb::Rule>,
        rules: &RuleService,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) {
        let mut errors = Vec::new();
        for mut rule in updated_rules {
            self.prepare(&mut rule);
            if let Err(err) = rules.upsert_from_proto(&rule).await {
                tracing::error!(rule = %rule.name, "{}: {err}", self.log_message());
                errors.push(format!("{}: {}", rule.name, err));
            }
        }

        if errors.is_empty() {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Ok,
                status_payload("ok"),
                "rule command notification",
            )
            .await;
        } else {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("{}: {}", self.error_prefix(), errors.join(", ")),
                "rule command notification",
            )
            .await;
        }
    }
}
