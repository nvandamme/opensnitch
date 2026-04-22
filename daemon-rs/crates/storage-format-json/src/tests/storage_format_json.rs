use std::path::PathBuf;

use opensnitch_storage_format_core::StorageFormatCodec;

use crate::JsonStorageFormat;

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

#[test]
fn parses_json_fixture() {
    let raw = std::fs::read_to_string(fixture_path("default-config.example.json"))
        .expect("read json fixture");
    let parsed: serde_json::Value = JsonStorageFormat
        .parse_from_storage(&raw)
        .expect("parse json fixture");
    assert!(parsed.is_object(), "json fixture must decode to object");
}

#[test]
fn converts_and_parses_round_trip() {
    let dto = RoundTrip {
        name: "json".to_string(),
        enabled: true,
    };

    let pretty = JsonStorageFormat
        .convert_to_storage_pretty(&dto)
        .expect("serialize json pretty");
    let parsed: RoundTrip = JsonStorageFormat
        .parse_from_storage(&pretty)
        .expect("parse json pretty");

    assert_eq!(parsed, dto);
}
