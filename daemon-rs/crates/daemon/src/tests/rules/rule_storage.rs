use crate::models::rule_storage::RuleFile;

#[test]
fn operator_list_null_deserializes_as_empty() {
    let raw = r#"
                {
                    "created": "2026-02-16T19:31:13+01:00",
                    "updated": "2026-02-16T19:31:13+01:00",
                    "name": "LocalNet",
                    "description": "",
                    "action": "allow",
                    "duration": "always",
                    "operator": {
                        "operand": "list",
                        "data": "",
                        "type": "list",
                        "list": [
                            {
                                "operand": "source.network",
                                "data": "10.0.0.0/8",
                                "type": "network",
                                "list": null,
                                "sensitive": false
                            }
                        ],
                        "sensitive": false
                    },
                    "enabled": true,
                    "precedence": false,
                    "nolog": false
                }
                "#;

    let parsed: RuleFile = serde_json::from_str(raw).expect("deserialize rule with null list");
    assert_eq!(parsed.operator.list.len(), 1);
    assert!(parsed.operator.list[0].list.is_empty());
}
