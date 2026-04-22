use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::document::{UciDocument, UciEntry, UciSection};
use crate::error::UciCodecError;

/// Convert a parsed [`UciDocument`] into a [`serde_json::Value`].
///
/// Mapping convention (3-level nesting):
/// - Level 1 key = section type
/// - Level 2 key = section name (anonymous sections get `_anon_<N>`)
/// - Level 3 keys = option names → string values, list names → string arrays
pub fn document_to_value(doc: &UciDocument) -> Value {
    let mut root = Map::new();
    let mut anon_counters: HashMap<String, usize> = HashMap::new();

    for section in &doc.sections {
        let type_key = &section.section_type;

        let section_name = match &section.name {
            Some(name) => name.clone(),
            None => {
                let counter = anon_counters.entry(type_key.clone()).or_insert(0);
                let name = format!("_anon_{counter}");
                *counter += 1;
                name
            }
        };

        let type_obj = root
            .entry(type_key.clone())
            .or_insert_with(|| Value::Object(Map::new()));

        let mut section_map = Map::new();
        let mut lists: Vec<(String, Vec<String>)> = Vec::new();

        for entry in &section.entries {
            match entry {
                UciEntry::Option { name, value } => {
                    section_map.insert(name.clone(), Value::String(value.clone()));
                }
                UciEntry::List { name, value } => {
                    if let Some((_, values)) = lists.iter_mut().find(|(k, _)| k == name) {
                        values.push(value.clone());
                    } else {
                        lists.push((name.clone(), vec![value.clone()]));
                    }
                }
            }
        }

        for (name, values) in lists {
            section_map.insert(
                name,
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
        }

        if let Value::Object(map) = type_obj {
            map.insert(section_name, Value::Object(section_map));
        }
    }

    Value::Object(root)
}

/// Convert a [`serde_json::Value`] back into a [`UciDocument`].
///
/// Expects the same 3-level structure produced by [`document_to_value`].
/// Section names starting with `_anon_` are emitted as anonymous sections.
/// Booleans are mapped to `1`/`0`; numbers are stringified.
pub fn value_to_document(value: &Value) -> Result<UciDocument, UciCodecError> {
    let root = value
        .as_object()
        .ok_or_else(|| UciCodecError::Structure("top-level value must be a JSON object".into()))?;

    let mut sections = Vec::new();

    for (section_type, type_value) in root {
        let type_obj = type_value.as_object().ok_or_else(|| {
            UciCodecError::Structure(format!(
                "section type '{section_type}' must be a JSON object"
            ))
        })?;

        for (section_name, section_value) in type_obj {
            let section_obj = section_value.as_object().ok_or_else(|| {
                UciCodecError::Structure(format!(
                    "section '{section_type}.{section_name}' must be a JSON object"
                ))
            })?;

            let is_anon = section_name.starts_with("_anon_");
            let mut entries = Vec::new();

            for (key, val) in section_obj {
                match val {
                    Value::String(s) => {
                        entries.push(UciEntry::Option {
                            name: key.clone(),
                            value: s.clone(),
                        });
                    }
                    Value::Bool(b) => {
                        entries.push(UciEntry::Option {
                            name: key.clone(),
                            value: if *b { "1" } else { "0" }.into(),
                        });
                    }
                    Value::Number(n) => {
                        entries.push(UciEntry::Option {
                            name: key.clone(),
                            value: n.to_string(),
                        });
                    }
                    Value::Array(arr) => {
                        for item in arr {
                            let s = scalar_to_string(item).ok_or_else(|| {
                                UciCodecError::Structure(format!(
                                    "list '{section_type}.{section_name}.{key}' \
                                     contains unsupported value type"
                                ))
                            })?;
                            entries.push(UciEntry::List {
                                name: key.clone(),
                                value: s,
                            });
                        }
                    }
                    _ => {
                        return Err(UciCodecError::Structure(format!(
                            "option '{section_type}.{section_name}.{key}' has \
                             unsupported type (null/nested objects not allowed)"
                        )));
                    }
                }
            }

            sections.push(UciSection {
                section_type: section_type.clone(),
                name: if is_anon {
                    None
                } else {
                    Some(section_name.clone())
                },
                entries,
            });
        }
    }

    Ok(UciDocument { sections })
}

fn scalar_to_string(val: &Value) -> Option<String> {
    match val {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(if *b { "1" } else { "0" }.into()),
        _ => None,
    }
}
