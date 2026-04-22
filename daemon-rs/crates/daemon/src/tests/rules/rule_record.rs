use crate::models::rule_record::{RuleAction, RuleDuration, RuleRecord};
use opensnitch_proto::pb;

#[test]
fn from_proto_maps_core_fields_like_create_invariants() {
    let proto = pb::Rule {
        created: 1_700_000_000,
        name: "000-test-name".to_string(),
        description: "rule description 000".to_string(),
        enabled: true,
        precedence: false,
        nolog: false,
        action: "allow".to_string(),
        duration: "once".to_string(),
        operator: Some(pb::Operator {
            r#type: "simple".to_string(),
            operand: "true".to_string(),
            data: String::new(),
            sensitive: false,
            list: Vec::new(),
        }),
    };

    let record = RuleRecord::from_proto(&proto);
    assert_eq!(record.name, "000-test-name");
    assert_eq!(record.description, "rule description 000");
    assert!(record.enabled);
    assert!(!record.precedence);
    assert!(!record.nolog);
    assert_eq!(record.action, RuleAction::Allow);
    assert_eq!(record.duration, RuleDuration::Once);
    assert!(record.created_at.is_some());
}

#[test]
fn from_proto_list_operator_clears_data_and_keeps_expanded_list() {
    let proto = pb::Rule {
        name: "000-test-serializer-list".to_string(),
        action: "allow".to_string(),
        duration: "once".to_string(),
        enabled: true,
        operator: Some(pb::Operator {
            r#type: "list".to_string(),
            operand: "list".to_string(),
            data: "[\"test\":true]".to_string(),
            sensitive: false,
            list: vec![
                pb::Operator {
                    r#type: "simple".to_string(),
                    operand: "process.path".to_string(),
                    data: "/path/x".to_string(),
                    sensitive: false,
                    list: Vec::new(),
                },
                pb::Operator {
                    r#type: "simple".to_string(),
                    operand: "dest.port".to_string(),
                    data: "23".to_string(),
                    sensitive: false,
                    list: Vec::new(),
                },
            ],
        }),
        ..Default::default()
    };

    let record = RuleRecord::from_proto(&proto);
    assert_eq!(record.operator.type_name, "list");
    assert_eq!(record.operator.operand, "list");
    assert_eq!(record.operator.data, "");
    assert_eq!(record.operator.list.len(), 2);
    assert_eq!(record.operator.list[0].type_name, "simple");
    assert_eq!(record.operator.list[0].operand, "process.path");
    assert_eq!(record.operator.list[0].data, "/path/x");
    assert_eq!(record.operator.list[1].type_name, "simple");
    assert_eq!(record.operator.list[1].operand, "dest.port");
    assert_eq!(record.operator.list[1].data, "23");
}
