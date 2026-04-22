use crate::utils::transient_files::is_transient_artifact_name;

#[test]
fn detects_known_transient_names() {
    assert!(is_transient_artifact_name("rule.json.tmp"));
    assert!(is_transient_artifact_name("config.json.tmp-123"));
    assert!(is_transient_artifact_name("domains.txt.download"));
    assert!(is_transient_artifact_name(".domains.txt.swp"));

    assert!(!is_transient_artifact_name("rule.json"));
    assert!(!is_transient_artifact_name("domains.txt"));
}
