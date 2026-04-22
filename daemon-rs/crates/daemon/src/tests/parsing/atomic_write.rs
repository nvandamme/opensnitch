use crate::utils::atomic_write::{sibling_temp_path_with_suffix, unique_sibling_temp_path};
use std::path::Path;

#[test]
fn sibling_temp_path_appends_suffix_to_file_name() {
    let path = Path::new("/tmp/example.json");
    assert_eq!(
        sibling_temp_path_with_suffix(path, ".tmp"),
        Path::new("/tmp/example.json.tmp")
    );
    assert_eq!(
        sibling_temp_path_with_suffix(path, ".download"),
        Path::new("/tmp/example.json.download")
    );
}

#[test]
fn unique_sibling_temp_path_keeps_parent_and_marks_tmp_prefix() {
    let path = Path::new("/tmp/example.json");
    let temp = unique_sibling_temp_path(path, "tmp");
    let temp_str = temp.to_string_lossy();
    assert!(temp_str.starts_with("/tmp/example.json.tmp-"));
}
