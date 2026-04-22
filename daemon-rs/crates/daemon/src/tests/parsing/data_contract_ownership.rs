use std::{
    fs,
    path::{Path, PathBuf},
};

fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn has_contract_marker(content: &str) -> bool {
    let derive_contract = content.lines().any(|line| {
        line.contains("#[derive(")
            && (line.contains("Serialize")
                || line.contains("Deserialize")
                || line.contains("prost::Message"))
    });

    derive_contract
        || content.contains("serde::Serialize")
        || content.contains("serde::Deserialize")
        || content.contains("#[derive(prost::Message)]")
}

#[test]
fn contract_types_stay_under_models() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_root = crate_root.join("src");

    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files);

    let mut violations = Vec::new();
    for file in files {
        let rel = match file.strip_prefix(crate_root) {
            Ok(path) => path,
            Err(_) => continue,
        };
        let rel_str = rel.to_string_lossy();

        if rel_str.starts_with("src/models/") || rel_str.starts_with("src/tests/") {
            continue;
        }

        // This helper uses local untagged serde parsing for input normalization,
        // but it does not define domain data-contract types.
        if rel_str == "src/utils/serde_helpers.rs" {
            continue;
        }

        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        if has_contract_marker(&content) {
            violations.push(rel_str.to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "data-contract ownership drift detected outside src/models: {}",
        violations.join(", ")
    );
}
