use std::process::Command;

#[test]
fn tools_binary_enforces_release_mode_in_dev_test_runs() {
    let exe = env!("CARGO_BIN_EXE_tools");
    let output = Command::new(exe)
        .arg("__profile_check__")
        .output()
        .expect("run tools binary");

    assert!(
        !output.status.success(),
        "tools binary should fail for this smoke-check invocation",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    if cfg!(debug_assertions) {
        assert!(
            stderr.contains("tools benchmarks must run in release mode"),
            "expected release-mode guard message in debug profile, got: {stderr}"
        );
    } else {
        assert!(
            stderr.contains("unsupported tools command: __profile_check__"),
            "expected unsupported-command message in release profile, got: {stderr}"
        );
    }
}
