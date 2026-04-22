use std::path::PathBuf;

use opensnitch_storage_format_core::StorageFormatCodec;

use crate::TomlStorageFormat;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct RoundTrip {
    name: String,
    enabled: bool,
}

fn fixture_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(file)
}

fn parse_json_fixture(file: &str) -> serde_json::Value {
    let raw = std::fs::read_to_string(fixture_path(file)).expect("read json fixture");
    serde_json::from_str::<serde_json::Value>(&raw).expect("parse json fixture")
}

#[test]
fn parses_toml_fixture() {
    let raw = std::fs::read_to_string(fixture_path("default-config.example.toml"))
        .expect("read toml fixture");
    let parsed: toml::Value = TomlStorageFormat
        .parse_from_storage(&raw)
        .expect("parse toml fixture");
    assert!(parsed.is_table(), "toml fixture must decode to table");
}

#[test]
fn converts_and_parses_round_trip() {
    let dto = RoundTrip {
        name: "toml".to_string(),
        enabled: true,
    };

    let pretty = TomlStorageFormat
        .convert_to_storage_pretty(&dto)
        .expect("serialize toml pretty");
    let parsed: RoundTrip = TomlStorageFormat
        .parse_from_storage(&pretty)
        .expect("parse toml pretty");

    assert_eq!(parsed, dto);
}

#[test]
fn default_config_toml_fixture_matches_json_fixture() {
    let toml_raw = std::fs::read_to_string(fixture_path("default-config.example.toml"))
        .expect("read toml config fixture");
    let toml_value: serde_json::Value = TomlStorageFormat
        .parse_from_storage(&toml_raw)
        .expect("parse toml config fixture");

    let json_value = parse_json_fixture("default-config.example.json");
    assert_eq!(toml_value, json_value);
}

#[test]
fn system_fw_toml_fixture_matches_json_fixture() {
    let toml_raw = std::fs::read_to_string(fixture_path("system-fw.example.toml"))
        .expect("read toml firewall fixture");
    let toml_value: serde_json::Value = TomlStorageFormat
        .parse_from_storage(&toml_raw)
        .expect("parse toml firewall fixture");

    let json_value = parse_json_fixture("system-fw.example.json");
    assert_eq!(toml_value, json_value);
}
