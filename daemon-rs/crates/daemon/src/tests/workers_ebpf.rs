use crate::workers::ebpf_worker::{extract_pid_uid, find_numeric};
use serde_json::json;

#[test]
fn find_numeric_reads_nested_numeric_values() {
    let payload = json!({
        "value": {
            "meta": {"uid": 1000},
            "process": {"tgid": 4242}
        }
    });

    assert_eq!(find_numeric(&payload, &["uid"]), Some(1000));
    assert_eq!(find_numeric(&payload, &["tgid"]), Some(4242));
}

#[test]
fn extract_pid_uid_prefers_pid_and_uid_fields() {
    let payload = json!({
        "value": {
            "pid": 31337,
            "uid": 501
        }
    });

    assert_eq!(extract_pid_uid(&payload), Some((31337, 501)));
}

#[test]
fn extract_pid_uid_accepts_tgid_and_uid_gid_low_bits() {
    let payload = json!({
        "value": {
            "tgid": 9001,
            "uid_gid": 0x0000_03E8_0000_00FFu64
        }
    });

    // uid_gid lower 32 bits are interpreted as uid.
    assert_eq!(extract_pid_uid(&payload), Some((9001, 255)));
}

#[test]
fn extract_pid_uid_returns_none_when_pid_like_key_missing() {
    let payload = json!({
        "value": {
            "uid": 1000,
            "comm": "curl"
        }
    });

    assert_eq!(extract_pid_uid(&payload), None);
}
