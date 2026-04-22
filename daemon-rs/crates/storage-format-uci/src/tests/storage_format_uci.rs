use std::collections::BTreeMap;
use std::path::PathBuf;

use opensnitch_storage_format_core::StorageFormatCodec;
use serde::{Deserialize, Serialize};

use crate::document::{UciDocument, UciEntry, UciSection};
use crate::{UciStorageFormat, emitter, parser, serde_bridge};

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const BASIC_UCI: &str = "\
config interface 'loopback'
\toption ifname 'lo'
\toption proto 'static'
\toption ipaddr '127.0.0.1'
\toption netmask '255.0.0.0'

config interface 'lan'
\toption ifname 'eth0'
\toption proto 'static'
\toption ipaddr '192.168.1.1'
\toption netmask '255.255.255.0'
\tlist dns '8.8.8.8'
\tlist dns '8.8.4.4'
";

const WITH_COMMENTS: &str = "\
# Network configuration
# Last modified: 2026-04-01

config interface 'loopback'
\t# Loopback adapter
\toption ifname 'lo'
\toption proto 'static'
";

const WITH_PACKAGE: &str = "\
package network

config interface 'loopback'
\toption ifname 'lo'
\toption proto 'static'
";

fn fixture_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(file)
}

fn rule_fixture_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/rules")
        .join(file)
}

fn read_fixture(path: PathBuf) -> String {
    std::fs::read_to_string(path).expect("read uci fixture")
}

// ---------------------------------------------------------------------------
// Parser tests
// ---------------------------------------------------------------------------

#[test]
fn parses_named_sections_and_options() {
    let doc = parser::parse(BASIC_UCI).expect("parse basic uci");
    assert_eq!(doc.sections.len(), 2);

    assert_eq!(doc.sections[0].section_type, "interface");
    assert_eq!(doc.sections[0].name.as_deref(), Some("loopback"));
    assert_eq!(doc.sections[0].entries.len(), 4);

    assert_eq!(doc.sections[1].section_type, "interface");
    assert_eq!(doc.sections[1].name.as_deref(), Some("lan"));
    // 4 options + 2 list entries
    assert_eq!(doc.sections[1].entries.len(), 6);
}

#[test]
fn parses_option_values() {
    let doc = parser::parse(BASIC_UCI).expect("parse");
    if let UciEntry::Option { name, value } = &doc.sections[0].entries[0] {
        assert_eq!(name, "ifname");
        assert_eq!(value, "lo");
    } else {
        panic!("expected option entry");
    }
}

#[test]
fn parses_list_entries() {
    let doc = parser::parse(BASIC_UCI).expect("parse");
    let lists: Vec<_> = doc.sections[1]
        .entries
        .iter()
        .filter(|e| matches!(e, UciEntry::List { .. }))
        .collect();
    assert_eq!(lists.len(), 2);
    if let UciEntry::List { name, value } = &lists[0] {
        assert_eq!(name, "dns");
        assert_eq!(value, "8.8.8.8");
    }
    if let UciEntry::List { name, value } = &lists[1] {
        assert_eq!(name, "dns");
        assert_eq!(value, "8.8.4.4");
    }
}

#[test]
fn parses_anonymous_sections() {
    let input = "config rule\n\toption name 'test'\n\nconfig rule\n\toption name 'test2'\n";
    let doc = parser::parse(input).expect("parse anonymous sections");
    assert_eq!(doc.sections.len(), 2);
    assert!(doc.sections[0].name.is_none());
    assert!(doc.sections[1].name.is_none());
}

#[test]
fn skips_comments_and_empty_lines() {
    let doc = parser::parse(WITH_COMMENTS).expect("parse with comments");
    assert_eq!(doc.sections.len(), 1);
    assert_eq!(doc.sections[0].entries.len(), 2);
}

#[test]
fn skips_package_line() {
    let doc = parser::parse(WITH_PACKAGE).expect("parse with package");
    assert_eq!(doc.sections.len(), 1);
    assert_eq!(doc.sections[0].name.as_deref(), Some("loopback"));
}

#[test]
fn parses_double_quoted_values() {
    let input = "config test \"quoted_name\"\n\toption key \"the value\"\n";
    let doc = parser::parse(input).expect("parse double-quoted");
    assert_eq!(doc.sections[0].name.as_deref(), Some("quoted_name"));
    if let UciEntry::Option { value, .. } = &doc.sections[0].entries[0] {
        assert_eq!(value, "the value");
    }
}

#[test]
fn parses_unquoted_values() {
    let input = "config test bare\n\toption key val\n";
    let doc = parser::parse(input).expect("parse unquoted");
    assert_eq!(doc.sections[0].name.as_deref(), Some("bare"));
    if let UciEntry::Option { value, .. } = &doc.sections[0].entries[0] {
        assert_eq!(value, "val");
    }
}

#[test]
fn parses_empty_quoted_value() {
    let input = "config test 'a'\n\toption key ''\n";
    let doc = parser::parse(input).expect("parse empty value");
    if let UciEntry::Option { value, .. } = &doc.sections[0].entries[0] {
        assert_eq!(value, "");
    }
}

#[test]
fn parses_value_with_spaces() {
    let input = "config test 'a'\n\toption path '/etc/config/my file.conf'\n";
    let doc = parser::parse(input).expect("parse value with spaces");
    if let UciEntry::Option { value, .. } = &doc.sections[0].entries[0] {
        assert_eq!(value, "/etc/config/my file.conf");
    }
}

#[test]
fn rejects_option_outside_section() {
    let result = parser::parse("option key 'val'\n");
    assert!(result.is_err());
}

#[test]
fn rejects_list_outside_section() {
    let result = parser::parse("list dns '8.8.8.8'\n");
    assert!(result.is_err());
}

#[test]
fn rejects_unterminated_single_quote() {
    let result = parser::parse("config test 'unterminated\n");
    assert!(result.is_err());
}

#[test]
fn rejects_unterminated_double_quote() {
    let result = parser::parse("config test \"unterminated\n");
    assert!(result.is_err());
}

#[test]
fn rejects_bare_config_keyword() {
    let result = parser::parse("config\n");
    assert!(result.is_err());
}

#[test]
fn parses_empty_input() {
    let doc = parser::parse("").expect("parse empty");
    assert!(doc.sections.is_empty());
}

#[test]
fn parses_comments_only() {
    let doc = parser::parse("# just a comment\n# another\n").expect("parse comments only");
    assert!(doc.sections.is_empty());
}

// ---------------------------------------------------------------------------
// Emitter tests
// ---------------------------------------------------------------------------

#[test]
fn emit_round_trip_preserves_structure() {
    let doc = parser::parse(BASIC_UCI).expect("parse");
    let emitted = emitter::emit(&doc);
    let reparsed = parser::parse(&emitted).expect("reparse");
    assert_eq!(doc, reparsed);
}

#[test]
fn emit_anonymous_sections_have_no_name() {
    let doc = UciDocument {
        sections: vec![UciSection {
            section_type: "rule".into(),
            name: None,
            entries: vec![UciEntry::Option {
                name: "action".into(),
                value: "allow".into(),
            }],
        }],
    };
    let text = emitter::emit(&doc);
    // Anonymous section: no name after type keyword
    assert!(text.starts_with("config rule\n"));
    assert!(text.contains("\toption action 'allow'\n"));
}

#[test]
fn emit_uses_single_quotes() {
    let doc = parser::parse("config test 'a'\n\toption key 'val'\n").expect("parse");
    let text = emitter::emit(&doc);
    assert!(text.contains("'a'"));
    assert!(text.contains("'val'"));
}

// ---------------------------------------------------------------------------
// Serde bridge tests
// ---------------------------------------------------------------------------

#[test]
fn document_to_value_maps_options_and_lists() {
    let doc = parser::parse(BASIC_UCI).expect("parse");
    let val = serde_bridge::document_to_value(&doc);

    assert_eq!(val["interface"]["loopback"]["ifname"], "lo");
    assert_eq!(val["interface"]["loopback"]["proto"], "static");
    assert_eq!(val["interface"]["lan"]["dns"][0], "8.8.8.8");
    assert_eq!(val["interface"]["lan"]["dns"][1], "8.8.4.4");
}

#[test]
fn anonymous_sections_get_anon_keys() {
    let input = "config rule\n\toption name 'a'\nconfig rule\n\toption name 'b'\n";
    let doc = parser::parse(input).expect("parse");
    let val = serde_bridge::document_to_value(&doc);

    assert_eq!(val["rule"]["_anon_0"]["name"], "a");
    assert_eq!(val["rule"]["_anon_1"]["name"], "b");
}

#[test]
fn value_to_document_round_trip_preserves_content() {
    let doc = parser::parse(BASIC_UCI).expect("parse");
    let val = serde_bridge::document_to_value(&doc);
    let doc2 = serde_bridge::value_to_document(&val).expect("back to doc");

    // Same number of sections
    assert_eq!(doc2.sections.len(), doc.sections.len());

    // All original section types and names are present (order may differ
    // due to BTreeMap key sorting in the JSON bridge)
    for orig in &doc.sections {
        let found = doc2
            .sections
            .iter()
            .any(|s| s.section_type == orig.section_type && s.name == orig.name);
        assert!(
            found,
            "missing section {:?} {:?}",
            orig.section_type, orig.name
        );
    }
}

#[test]
fn value_to_document_maps_booleans_to_uci_convention() {
    let json = serde_json::json!({
        "daemon": {
            "general": {
                "enabled": true,
                "debug": false
            }
        }
    });
    let doc = serde_bridge::value_to_document(&json).expect("bool to doc");
    let entries = &doc.sections[0].entries;

    let find_opt = |name: &str| {
        entries.iter().find_map(|e| match e {
            UciEntry::Option { name: n, value, .. } if n == name => Some(value.as_str()),
            _ => None,
        })
    };

    assert_eq!(find_opt("enabled"), Some("1"));
    assert_eq!(find_opt("debug"), Some("0"));
}

#[test]
fn value_to_document_maps_numbers_to_strings() {
    let json = serde_json::json!({
        "stats": {
            "config": {
                "max_events": 250,
                "workers": 6
            }
        }
    });
    let doc = serde_bridge::value_to_document(&json).expect("num to doc");
    let entries = &doc.sections[0].entries;

    let find_opt = |name: &str| {
        entries.iter().find_map(|e| match e {
            UciEntry::Option { name: n, value, .. } if n == name => Some(value.as_str()),
            _ => None,
        })
    };

    assert_eq!(find_opt("max_events"), Some("250"));
    assert_eq!(find_opt("workers"), Some("6"));
}

#[test]
fn value_to_document_rejects_nested_objects() {
    let json = serde_json::json!({
        "daemon": {
            "general": {
                "nested": { "key": "val" }
            }
        }
    });
    let result = serde_bridge::value_to_document(&json);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// StorageFormatCodec tests
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SimpleNetworkConfig {
    interface: BTreeMap<String, InterfaceSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct InterfaceSection {
    ifname: String,
    proto: String,
}

#[test]
fn codec_round_trip() {
    let config = SimpleNetworkConfig {
        interface: BTreeMap::from([
            (
                "loopback".into(),
                InterfaceSection {
                    ifname: "lo".into(),
                    proto: "static".into(),
                },
            ),
            (
                "lan".into(),
                InterfaceSection {
                    ifname: "eth0".into(),
                    proto: "dhcp".into(),
                },
            ),
        ]),
    };

    let uci_text = UciStorageFormat
        .convert_to_storage(&config)
        .expect("serialize to uci");

    let parsed: SimpleNetworkConfig = UciStorageFormat
        .parse_from_storage(&uci_text)
        .expect("parse from uci");

    assert_eq!(parsed, config);
}

#[test]
fn codec_parses_uci_text_into_typed_struct() {
    let input = "\
config interface 'loopback'
\toption ifname 'lo'
\toption proto 'static'

config interface 'wan'
\toption ifname 'eth1'
\toption proto 'dhcp'
";
    let config: SimpleNetworkConfig = UciStorageFormat
        .parse_from_storage(input)
        .expect("parse uci into typed struct");

    assert_eq!(config.interface["loopback"].proto, "static");
    assert_eq!(config.interface["wan"].proto, "dhcp");
    assert_eq!(config.interface["wan"].ifname, "eth1");
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WithLists {
    interface: BTreeMap<String, InterfaceWithDns>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct InterfaceWithDns {
    proto: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    dns: Vec<String>,
}

#[test]
fn codec_round_trip_with_lists() {
    let config = WithLists {
        interface: BTreeMap::from([(
            "lan".into(),
            InterfaceWithDns {
                proto: "static".into(),
                dns: vec!["8.8.8.8".into(), "1.1.1.1".into()],
            },
        )]),
    };

    let uci_text = UciStorageFormat
        .convert_to_storage(&config)
        .expect("serialize");
    assert!(uci_text.contains("list dns"));

    let parsed: WithLists = UciStorageFormat
        .parse_from_storage(&uci_text)
        .expect("parse");
    assert_eq!(parsed, config);
}

#[test]
fn codec_parse_document_exposes_raw_model() {
    let doc = UciStorageFormat
        .parse_document(BASIC_UCI)
        .expect("parse_document");
    assert_eq!(doc.sections.len(), 2);
    assert_eq!(doc.sections[0].section_type, "interface");
}

#[test]
fn codec_emit_document_produces_valid_uci() {
    let doc = UciStorageFormat
        .parse_document(BASIC_UCI)
        .expect("parse_document");
    let text = UciStorageFormat.emit_document(&doc);
    let reparsed = UciStorageFormat.parse_document(&text).expect("reparse");
    assert_eq!(doc, reparsed);
}

#[test]
fn parses_default_config_uci_fixture() {
    let raw = read_fixture(fixture_path("default-config.example.uci"));
    let doc = UciStorageFormat
        .parse_document(&raw)
        .expect("parse default-config.example.uci");

    assert!(!doc.sections.is_empty());
    assert!(doc.sections.iter().any(|s| s.section_type == "server"));
    assert!(doc.sections.iter().any(|s| s.section_type == "daemon"));
    assert!(doc.sections.iter().any(|s| s.section_type == "stats"));
}

#[test]
fn parses_system_fw_uci_syntax_fixture() {
    let raw = read_fixture(fixture_path("system-fw.example.uci"));
    let doc = UciStorageFormat
        .parse_document(&raw)
        .expect("parse system-fw.example.uci syntax fixture");

    // Syntax-level coverage only: this test validates UCI document shape
    // parsing, not OpenWrt firewall backend runtime/apply semantics.
    assert!(doc.sections.iter().any(|s| s.section_type == "system_fw"));
    assert!(doc.sections.iter().any(|s| s.section_type == "chain"));
    assert!(doc.sections.iter().any(|s| s.section_type == "rule"));
}

#[test]
fn rejects_uci_cli_show_fixture_as_file_syntax() {
    let raw = read_fixture(fixture_path("system-fw.cli-show.example.txt"));
    UciStorageFormat
        .parse_document(&raw)
        .expect_err("uci show-style output is runtime text, not UCI file syntax");
}

#[test]
fn parses_uci_cli_export_fixture_as_file_syntax() {
    let raw = read_fixture(fixture_path("system-fw.cli-export.example.uci"));
    let doc = UciStorageFormat
        .parse_document(&raw)
        .expect("uci export-style output should be valid UCI file syntax");

    assert!(
        !doc.sections.is_empty(),
        "export fixture must contain sections"
    );
    assert!(doc.sections.iter().any(|s| s.section_type == "system_fw"));
    assert!(doc.sections.iter().any(|s| s.section_type == "chain"));
    assert!(doc.sections.iter().any(|s| s.section_type == "rule"));
}

#[test]
fn parses_tasks_metrics_and_tunables_uci_fixtures() {
    for file in [
        "tasks.example.uci",
        "metrics.example.uci",
        "tunables.example.uci",
    ] {
        let raw = read_fixture(fixture_path(file));
        let doc = UciStorageFormat
            .parse_document(&raw)
            .expect("parse fixture");
        assert!(
            !doc.sections.is_empty(),
            "fixture {file} must contain sections"
        );
    }
}

#[test]
fn parses_rule_uci_fixture() {
    let raw = read_fixture(rule_fixture_path("allow-firefox-dns.example.uci"));
    let doc = UciStorageFormat
        .parse_document(&raw)
        .expect("parse rule fixture");

    assert_eq!(doc.sections.len(), 1);
    let section = &doc.sections[0];
    assert_eq!(section.section_type, "rule");
    assert_eq!(section.name.as_deref(), Some("allow_firefox_dns"));
    assert!(
        section
            .entries
            .iter()
            .any(|e| matches!(e, UciEntry::List { name, .. } if name == "match_process_path"))
    );
    assert!(
        section
            .entries
            .iter()
            .any(|e| matches!(e, UciEntry::List { name, .. } if name == "match_dest_port"))
    );
}

#[test]
fn data_examples_have_uci_companions() {
    // Keep this list explicit so fixture additions require a conscious
    // UCI counterpart decision in the same change.
    let required = [
        "default-config.example",
        "system-fw.example",
        "tasks.example",
        "metrics.example",
        "tunables.example",
    ];

    for base in required {
        let json = fixture_path(&format!("{base}.json"));
        let uci = fixture_path(&format!("{base}.uci"));

        assert!(
            json.exists(),
            "missing baseline fixture: {}",
            json.display()
        );
        assert!(
            uci.exists(),
            "missing UCI fixture companion for {base}: {}",
            uci.display()
        );
    }
}

#[test]
fn rule_examples_have_uci_companions() {
    let required = ["allow-firefox-dns.example"];

    for base in required {
        let json = rule_fixture_path(&format!("{base}.json"));
        let uci = rule_fixture_path(&format!("{base}.uci"));

        assert!(
            json.exists(),
            "missing baseline rule fixture: {}",
            json.display()
        );
        assert!(
            uci.exists(),
            "missing UCI rule fixture companion for {base}: {}",
            uci.display()
        );
    }
}
