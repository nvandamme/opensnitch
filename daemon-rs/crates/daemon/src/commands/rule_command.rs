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

#[cfg(test)]
mod tests {
    use super::{delete_rules, disable_rules, enable_rules, upsert_rules};
    use opensnitch_proto::pb;

    use crate::services::rule_service::RuleService;
    use crate::utils::test_support::TestDir;

    #[tokio::test]
    async fn enable_rules_persists_enabled_rules_and_replies_ok() {
        let temp_dir = TestDir::new("opensnitch-rule-command-service");
        let rules = initialized_rule_service(&temp_dir).await;
        let (task_reply_tx, mut task_reply_rx) = tokio::sync::mpsc::channel(4);

        enable_rules(7, vec![sample_rule("allow-ssh")], &rules, &task_reply_tx).await;

        let reply = task_reply_rx.recv().await.expect("reply");
        assert_eq!(reply.id, 7);
        assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);
        assert_eq!(reply.data, serde_json::json!({"status": "ok"}).to_string());

        let rules_list = rules.list_proto().await;
        assert_eq!(rules_list.len(), 1);
        assert!(rules_list[0].enabled);
        assert!(temp_dir.path.join("allow-ssh.json").exists());
    }

    #[tokio::test]
    async fn disable_rules_persists_disabled_rules_and_replies_ok() {
        let temp_dir = TestDir::new("opensnitch-rule-command-service");
        let rules = initialized_rule_service(&temp_dir).await;
        let (task_reply_tx, mut task_reply_rx) = tokio::sync::mpsc::channel(8);

        enable_rules(1, vec![sample_rule("deny-http")], &rules, &task_reply_tx).await;
        let _ = task_reply_rx.recv().await;

        disable_rules(2, vec![sample_rule("deny-http")], &rules, &task_reply_tx).await;

        let reply = task_reply_rx.recv().await.expect("reply");
        assert_eq!(reply.id, 2);
        assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);

        let rules_list = rules.list_proto().await;
        assert_eq!(rules_list.len(), 1);
        assert!(!rules_list[0].enabled);
    }

    #[tokio::test]
    async fn delete_rules_removes_rule_file_and_replies_ok() {
        let temp_dir = TestDir::new("opensnitch-rule-command-service");
        let rules = initialized_rule_service(&temp_dir).await;
        let (task_reply_tx, mut task_reply_rx) = tokio::sync::mpsc::channel(8);

        upsert_rules(3, vec![sample_rule("temp-rule")], &rules, &task_reply_tx).await;
        let _ = task_reply_rx.recv().await;
        assert!(temp_dir.path.join("temp-rule.json").exists());

        delete_rules(4, vec!["temp-rule".to_string()], &rules, &task_reply_tx).await;

        let reply = task_reply_rx.recv().await.expect("reply");
        assert_eq!(reply.id, 4);
        assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);
        assert!(!temp_dir.path.join("temp-rule.json").exists());
        assert!(rules.list_proto().await.is_empty());
    }

    async fn initialized_rule_service(temp_dir: &TestDir) -> RuleService {
        let rules = RuleService::default();
        rules
            .load_path(&temp_dir.path)
            .await
            .expect("load empty rule dir");
        rules
    }

    fn sample_rule(name: &str) -> pb::Rule {
        pb::Rule {
            name: name.to_string(),
            action: "allow".to_string(),
            duration: "always".to_string(),
            enabled: false,
            ..Default::default()
        }
    }
}
