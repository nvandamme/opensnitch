use opensnitch_proto::pb;

use crate::{commands::task_runtime::send_task_reply, services::rule_service::RuleService};

pub(crate) async fn enable_rules(
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
        send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Ok,
            serde_json::json!({"status": "ok"}).to_string(),
        )
        .await;
    } else {
        send_task_reply(
            task_reply_tx,
            notification_id,
            pb::NotificationReplyCode::Error,
            format!("failed to delete some rules: {}", errors.join(", ")),
        )
        .await;
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
            send_task_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Ok,
                serde_json::json!({"status": "ok"}).to_string(),
            )
            .await;
        } else {
            send_task_reply(
                task_reply_tx,
                notification_id,
                pb::NotificationReplyCode::Error,
                format!("{}: {}", self.error_prefix(), errors.join(", ")),
            )
            .await;
        }
    }
}
