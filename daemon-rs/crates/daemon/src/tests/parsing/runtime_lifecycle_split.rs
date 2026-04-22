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

fn has_process_singleton_static(content: &str) -> bool {
    content.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("static ")
            && (trimmed.contains("OnceLock<") || trimmed.contains("LazyLock<"))
    })
}

fn collect_service_dirs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.push(path);
        }
    }
}

#[test]
fn service_process_singletons_live_in_runtime_lifecycle_modules() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let services_root = crate_root.join("src/services");

    let mut files = Vec::new();
    collect_rs_files(&services_root, &mut files);

    let mut violations = Vec::new();

    for file in files {
        let rel = match file.strip_prefix(crate_root) {
            Ok(path) => path,
            Err(_) => continue,
        };
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        if rel_str.ends_with("/runtime_lifecycle.rs") {
            continue;
        }

        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };

        if has_process_singleton_static(&content) {
            violations.push(rel_str);
        }
    }

    assert!(
        violations.is_empty(),
        "service singleton split violation: process-wide singletons must live in runtime_lifecycle.rs; found: {}",
        violations.join(", ")
    );
}

#[test]
fn every_service_directory_has_runtime_lifecycle_module() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let services_root = crate_root.join("src/services");

    let mut dirs = Vec::new();
    collect_service_dirs(&services_root, &mut dirs);

    let mut missing = Vec::new();

    for dir in dirs {
        let rel = match dir.strip_prefix(crate_root) {
            Ok(path) => path,
            Err(_) => continue,
        };
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        // Shared lifecycle utility module is not a concrete domain service.
        if rel_str == "src/services/lifecycle" {
            continue;
        }

        let lifecycle_file = dir.join("runtime_lifecycle.rs");
        if !lifecycle_file.exists() {
            missing.push(rel_str);
        }
    }

    assert!(
        missing.is_empty(),
        "runtime_lifecycle split violation: missing runtime_lifecycle.rs in service directories: {}",
        missing.join(", ")
    );
}
