use std::path::PathBuf;

use opensnitch_storage_format_core::StorageFormatCodec;

use crate::YamlStorageFormat;

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
fn parses_yaml_fixture() {
    let raw = std::fs::read_to_string(fixture_path("default-config.example.yaml"))
        .expect("read yaml fixture");
    let parsed: serde_yaml::Value = YamlStorageFormat
        .parse_from_storage(&raw)
        .expect("parse yaml fixture");
    assert!(parsed.is_mapping(), "yaml fixture must decode to mapping");
}

#[test]
fn converts_and_parses_round_trip() {
    let dto = RoundTrip {
        name: "yaml".to_string(),
        enabled: true,
    };

    let pretty = YamlStorageFormat
        .convert_to_storage_pretty(&dto)
        .expect("serialize yaml");
    let parsed: RoundTrip = YamlStorageFormat
        .parse_from_storage(&pretty)
        .expect("parse yaml");

    assert_eq!(parsed, dto);
}

#[test]
fn default_config_yaml_fixture_matches_json_fixture() {
    let yaml_raw = std::fs::read_to_string(fixture_path("default-config.example.yaml"))
        .expect("read yaml config fixture");
    let yaml_value: serde_json::Value = YamlStorageFormat
        .parse_from_storage(&yaml_raw)
        .expect("parse yaml config fixture");

    let json_value = parse_json_fixture("default-config.example.json");
    assert_eq!(yaml_value, json_value);
}

#[test]
fn system_fw_yaml_fixture_matches_json_fixture() {
    let yaml_raw = std::fs::read_to_string(fixture_path("system-fw.example.yaml"))
        .expect("read yaml firewall fixture");
    let yaml_value: serde_json::Value = YamlStorageFormat
        .parse_from_storage(&yaml_raw)
        .expect("parse yaml firewall fixture");

    let json_value = parse_json_fixture("system-fw.example.json");
    assert_eq!(yaml_value, json_value);
}
