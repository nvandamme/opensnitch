use opensnitch_proto::pb;

use crate::commands::rule_command::RuleCommandService;
use crate::services::rule_service::RuleService;
use crate::tests::support::TestDir;

#[tokio::test]
async fn enable_rules_persists_enabled_rules_and_replies_ok() {
    let svc = RuleCommandService::default();
    let temp_dir = TestDir::new("opensnitch-rule-command-service");
    let rules = initialized_rule_service(&temp_dir).await;
    let (task_reply_tx, mut task_reply_rx) = tokio::sync::mpsc::channel(4);

    svc.enable_rules(7, vec![sample_rule("allow-ssh")], &rules, &task_reply_tx)
        .await;

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
    let svc = RuleCommandService::default();
    let temp_dir = TestDir::new("opensnitch-rule-command-service");
    let rules = initialized_rule_service(&temp_dir).await;
    let (task_reply_tx, mut task_reply_rx) = tokio::sync::mpsc::channel(8);

    svc.enable_rules(1, vec![sample_rule("deny-http")], &rules, &task_reply_tx)
        .await;
    let _ = task_reply_rx.recv().await;

    svc.disable_rules(2, vec![sample_rule("deny-http")], &rules, &task_reply_tx)
        .await;

    let reply = task_reply_rx.recv().await.expect("reply");
    assert_eq!(reply.id, 2);
    assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);

    let rules_list = rules.list_proto().await;
    assert_eq!(rules_list.len(), 1);
    assert!(!rules_list[0].enabled);
}

#[tokio::test]
async fn delete_rules_removes_rule_file_and_replies_ok() {
    let svc = RuleCommandService::default();
    let temp_dir = TestDir::new("opensnitch-rule-command-service");
    let rules = initialized_rule_service(&temp_dir).await;
    let (task_reply_tx, mut task_reply_rx) = tokio::sync::mpsc::channel(8);

    svc.upsert_rules(3, vec![sample_rule("temp-rule")], &rules, &task_reply_tx)
        .await;
    let _ = task_reply_rx.recv().await;
    assert!(temp_dir.path.join("temp-rule.json").exists());

    svc.delete_rules(4, vec!["temp-rule".to_string()], &rules, &task_reply_tx)
        .await;

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
        operator: Some(pb::Operator {
            r#type: "simple".to_string(),
            operand: "true".to_string(),
            data: String::new(),
            sensitive: false,
            list: Vec::new(),
        }),
        ..Default::default()
    }
}
