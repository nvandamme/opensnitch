use transport_wire_core::{WireNotificationReplyCode, WireRule, WireRuleOperator};

use crate::commands::rule::RuleCommandService;
use crate::models::rule_record::RuleRecord;
use crate::services::client::ClientService;
use crate::services::rule::RuleService;
use crate::tests::support::TestDir;

#[tokio::test]
async fn enable_rules_persists_enabled_rules_and_replies_ok() {
    let temp_dir = TestDir::new("opensnitch-rule-command-service");
    let svc = RuleCommandService::with_base_dir(temp_dir.path.join("policy-tx"));
    let client_service = ClientService::default();
    let temp_dir = TestDir::new("opensnitch-rule-command-service");
    let rules = initialized_rule_service(&temp_dir).await;
    let (task_reply_tx, mut task_reply_rx) = tokio::sync::mpsc::channel(4);

    svc.enable_rules(
        7,
        vec![sample_rule("allow-ssh")],
        &rules,
        &task_reply_tx,
        &client_service,
    )
    .await;

    let reply = task_reply_rx.recv().await.expect("reply");
    assert_eq!(reply.id, 7);
    assert_eq!(reply.code, WireNotificationReplyCode::Ok as i32);
    assert_eq!(reply.data, transport_wire_core::status_payload("ok"));

    let rules_list = rules.list_wire().await;
    assert_eq!(rules_list.len(), 1);
    assert!(rules_list[0].enabled);
    assert!(temp_dir.path.join("allow-ssh.json").exists());
}

#[tokio::test]
async fn disable_rules_persists_disabled_rules_and_replies_ok() {
    let temp_dir = TestDir::new("opensnitch-rule-command-service");
    let svc = RuleCommandService::with_base_dir(temp_dir.path.join("policy-tx"));
    let client_service = ClientService::default();
    let temp_dir = TestDir::new("opensnitch-rule-command-service");
    let rules = initialized_rule_service(&temp_dir).await;
    let (task_reply_tx, mut task_reply_rx) = tokio::sync::mpsc::channel(8);

    svc.enable_rules(
        1,
        vec![sample_rule("deny-http")],
        &rules,
        &task_reply_tx,
        &client_service,
    )
    .await;
    let _ = task_reply_rx.recv().await;

    svc.disable_rules(
        2,
        vec![sample_rule("deny-http")],
        &rules,
        &task_reply_tx,
        &client_service,
    )
    .await;

    let reply = task_reply_rx.recv().await.expect("reply");
    assert_eq!(reply.id, 2);
    assert_eq!(reply.code, WireNotificationReplyCode::Ok as i32);

    let rules_list = rules.list_wire().await;
    assert_eq!(rules_list.len(), 1);
    assert!(!rules_list[0].enabled);
}

#[tokio::test]
async fn delete_rules_removes_rule_file_and_replies_ok() {
    let temp_dir = TestDir::new("opensnitch-rule-command-service");
    let svc = RuleCommandService::with_base_dir(temp_dir.path.join("policy-tx"));
    let client_service = ClientService::default();
    let temp_dir = TestDir::new("opensnitch-rule-command-service");
    let rules = initialized_rule_service(&temp_dir).await;
    let (task_reply_tx, mut task_reply_rx) = tokio::sync::mpsc::channel(8);

    svc.upsert_rules(
        3,
        vec![sample_rule("temp-rule")],
        &rules,
        &task_reply_tx,
        &client_service,
    )
    .await;
    let _ = task_reply_rx.recv().await;
    assert!(temp_dir.path.join("temp-rule.json").exists());

    svc.delete_rules(
        4,
        vec!["temp-rule".to_string()],
        &rules,
        &task_reply_tx,
        &client_service,
    )
    .await;

    let reply = task_reply_rx.recv().await.expect("reply");
    assert_eq!(reply.id, 4);
    assert_eq!(reply.code, WireNotificationReplyCode::Ok as i32);
    assert!(!temp_dir.path.join("temp-rule.json").exists());
    assert!(rules.list_wire().await.is_empty());
}

async fn initialized_rule_service(temp_dir: &TestDir) -> RuleService {
    let rules = RuleService::default();
    rules
        .load_path(&temp_dir.path)
        .await
        .expect("load empty rule dir");
    rules
}

fn sample_rule(name: &str) -> RuleRecord {
    RuleRecord {
        name: name.to_string(),
        action: crate::models::rule_record::RuleAction::Allow,
        duration: crate::models::rule_record::RuleDuration::Permanent,
        enabled: false,
        operator: crate::services::rule::rule_record_from_wire(&WireRule {
            operator: Some(WireRuleOperator {
                type_name: "simple".to_string(),
                operand: "true".to_string(),
                data: String::new(),
                sensitive: false,
                list: Vec::new(),
            }),
            ..Default::default()
        })
        .operator,
        ..Default::default()
    }
}
