use serde::{Deserialize, Serialize};

use crate::StorageFormatCodec;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeCodecError;

impl std::fmt::Display for FakeCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fake codec error")
    }
}

impl std::error::Error for FakeCodecError {}

#[derive(Default)]
struct FakeCodec;

impl StorageFormatCodec for FakeCodec {
    type Error = FakeCodecError;

    fn parse_from_storage<T: serde::de::DeserializeOwned>(
        &self,
        raw: &str,
    ) -> Result<T, Self::Error> {
        serde_json::from_str(raw).map_err(|_| FakeCodecError)
    }

    fn convert_to_storage<T: serde::Serialize>(&self, value: &T) -> Result<String, Self::Error> {
        serde_json::to_string(value).map_err(|_| FakeCodecError)
    }

    fn convert_to_storage_pretty<T: serde::Serialize>(
        &self,
        value: &T,
    ) -> Result<String, Self::Error> {
        serde_json::to_string_pretty(value).map_err(|_| FakeCodecError)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RoundTrip {
    name: String,
    enabled: bool,
}

#[test]
fn generic_codec_contract_supports_round_trip_helpers() {
    let codec = FakeCodec;
    let value = RoundTrip {
        name: "core".into(),
        enabled: true,
    };

    let pretty = codec
        .convert_to_storage_pretty(&value)
        .expect("serialize through generic codec contract");
    let parsed: RoundTrip = codec
        .parse_from_storage(&pretty)
        .expect("parse through generic codec contract");

    assert_eq!(parsed, value);
}
