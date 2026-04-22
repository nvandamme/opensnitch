use std::path::Path;

use crate::{
    daemon::{
        CliOverrides, classify_rule_for_ownerless_migration, load_ownerless_rule_migration_plan,
    },
    models::rule_record::{RuleAction, RuleDuration, RuleOperator, RuleRecord},
    tests::support::{TestDir, read_text, write_text},
};

fn write_rule_file(path: &Path, raw_json: &str) {
    write_text(path, raw_json);
}

fn test_rule(name: &str, operator: RuleOperator) -> RuleRecord {
    RuleRecord {
        created_at: None,
        updated_at: None,
        name: name.to_string(),
        description: String::new(),
        action: RuleAction::Allow,
        duration: RuleDuration::Permanent,
        enabled: true,
        precedence: false,
        nolog: false,
        operator,
    }
}

#[test]
fn ownerless_rule_migration_marks_missing_owner_scope_as_eligible() {
    let record = test_rule(
        "allow-https",
        RuleOperator {
            type_name: "simple".to_string(),
            operand: "dest.port".to_string(),
            data: "443".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    );

    let decision = classify_rule_for_ownerless_migration(&record, 1000, Some("alice"));
    let crate::daemon::RuleMigrationDecision::Eligible(migrated) = decision else {
        panic!("expected eligible migration decision");
    };
    assert_eq!(migrated.operator.type_name, "list");
    assert!(
        migrated
            .operator
            .list
            .iter()
            .any(|item| { item.operand == "user.id" && item.data == "1000" })
    );
}

#[test]
fn ownerless_rule_migration_flags_precedence_rules_as_ambiguous() {
    let mut record = test_rule("global-precedence", RuleOperator::default());
    record.precedence = true;

    let decision = classify_rule_for_ownerless_migration(&record, 1000, Some("alice"));
    assert!(matches!(
        decision,
        crate::daemon::RuleMigrationDecision::Ambiguous(_)
    ));
}

#[test]
fn ownerless_rule_migration_requires_operator_operand_presence() {
    let record = test_rule(
        "list-without-operands",
        RuleOperator {
            type_name: "list".to_string(),
            operand: String::new(),
            data: String::new(),
            sensitive: false,
            scope: None,
            list: vec![RuleOperator {
                type_name: "simple".to_string(),
                operand: String::new(),
                data: "443".to_string(),
                sensitive: false,
                scope: None,
                list: Vec::new(),
            }],
        },
    );

    let decision = classify_rule_for_ownerless_migration(&record, 1000, Some("alice"));
    assert!(matches!(
        decision,
        crate::daemon::RuleMigrationDecision::Ambiguous(_)
    ));
}

#[tokio::test]
async fn ownerless_rule_migration_dry_run_reports_without_rewriting_files() {
    let dir = TestDir::new("opensnitch-rule-migration-dry-run");
    let rules_dir = dir.path.join("rules");
    std::fs::create_dir_all(&rules_dir).expect("create rules dir");
    let config_path = dir.path.join("default-config.json");
    let rule_path = rules_dir.join("allow-https.json");

    write_rule_file(
        &rule_path,
        r#"{
  "name": "allow-https",
  "action": "allow",
  "duration": "always",
  "enabled": true,
  "operator": {
    "type": "simple",
    "operand": "dest.port",
    "data": "443"
  }
}"#,
    );
    write_rule_file(
        &config_path,
        &format!(
            r#"{{
  "Server": {{"Address": "http://127.0.0.1:50051"}},
  "Rules": {{"Path": "{}"}}
}}"#,
            rules_dir.display()
        ),
    );

    let before = read_text(&rule_path);
    let mut cli = CliOverrides::default();
    cli.config_file = Some(config_path);
    cli.rule_migration.ownerless_rules = true;
    cli.rule_migration.owner_uid = Some("1000".to_string());

    crate::daemon::Daemon::run_ownerless_rule_migration(cli)
        .await
        .expect("dry-run migration succeeds");

    assert_eq!(read_text(&rule_path), before);
}

#[tokio::test]
async fn ownerless_rule_migration_write_rewrites_eligible_rule() {
    let dir = TestDir::new("opensnitch-rule-migration-write");
    let rules_dir = dir.path.join("rules");
    std::fs::create_dir_all(&rules_dir).expect("create rules dir");
    let config_path = dir.path.join("default-config.json");
    let rule_path = rules_dir.join("allow-https.json");

    write_rule_file(
        &rule_path,
        r#"{
  "name": "allow-https",
  "action": "allow",
  "duration": "always",
  "enabled": true,
  "operator": {
    "type": "simple",
    "operand": "dest.port",
    "data": "443"
  }
}"#,
    );
    write_rule_file(
        &config_path,
        &format!(
            r#"{{
  "Server": {{"Address": "http://127.0.0.1:50051"}},
  "Rules": {{"Path": "{}"}}
}}"#,
            rules_dir.display()
        ),
    );

    let mut cli = CliOverrides::default();
    cli.config_file = Some(config_path);
    cli.rule_migration.ownerless_rules = true;
    cli.rule_migration.owner_uid = Some("1000".to_string());
    cli.rule_migration.write = true;

    crate::daemon::Daemon::run_ownerless_rule_migration(cli)
        .await
        .expect("write migration succeeds");

    let migrated = read_text(&rule_path);
    assert!(migrated.contains("\"operand\": \"user.id\""));
    assert!(migrated.contains("\"data\": \"1000\""));
}

#[tokio::test]
async fn ownerless_rule_migration_write_fails_closed_when_ambiguous_rules_exist() {
    let dir = TestDir::new("opensnitch-rule-migration-ambiguous");
    let rules_dir = dir.path.join("rules");
    std::fs::create_dir_all(&rules_dir).expect("create rules dir");
    let config_path = dir.path.join("default-config.json");
    let rule_path = rules_dir.join("global-precedence.json");

    write_rule_file(
        &rule_path,
        r#"{
  "name": "global-precedence",
  "action": "allow",
  "duration": "always",
  "enabled": true,
  "precedence": true,
  "operator": {
    "type": "simple",
    "operand": "dest.port",
    "data": "443"
  }
}"#,
    );
    write_rule_file(
        &config_path,
        &format!(
            r#"{{
  "Server": {{"Address": "http://127.0.0.1:50051"}},
  "Rules": {{"Path": "{}"}}
}}"#,
            rules_dir.display()
        ),
    );

    let before = read_text(&rule_path);
    let mut cli = CliOverrides::default();
    cli.config_file = Some(config_path);
    cli.rule_migration.ownerless_rules = true;
    cli.rule_migration.owner_uid = Some("1000".to_string());
    cli.rule_migration.write = true;

    let err = crate::daemon::Daemon::run_ownerless_rule_migration(cli)
        .await
        .expect_err("ambiguous migration must fail closed");
    assert!(
        err.to_string()
            .contains("ambiguous/conflicting rules require manual review")
    );
    assert_eq!(read_text(&rule_path), before);
}

#[test]
fn ownerless_rule_migration_plan_reports_conflicting_existing_owner() {
    let dir = TestDir::new("opensnitch-rule-migration-plan");
    let rules_dir = dir.path.join("rules");
    std::fs::create_dir_all(&rules_dir).expect("create rules dir");
    let rule_path = rules_dir.join("owned.json");

    write_rule_file(
        &rule_path,
        r#"{
  "name": "owned",
  "action": "allow",
  "duration": "always",
  "enabled": true,
  "operator": {
    "type": "simple",
    "operand": "user.id",
    "data": "2000"
  }
}"#,
    );

    let plan = load_ownerless_rule_migration_plan(&rules_dir, 1000).expect("plan loads");
    assert_eq!(plan.conflicting.len(), 1);
    assert_eq!(plan.eligible.len(), 0);
}
