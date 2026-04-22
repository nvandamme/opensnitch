use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    DynError, env_flag, find_line, parity_stress_rounds, parse_metric, parse_named_u64,
    perf_go_log_level, perf_repeats, perf_rust_log_level, run_command,
};

static PREBUILD_DONE: AtomicBool = AtomicBool::new(false);
const PREBUILD_DONE_ENV: &str = "OPENSNITCH_PARITY_PREBUILD_DONE";

pub(crate) fn microbench_connect_dispatch() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;
    let manifest = daemon_rs_manifest_path()?;
    maybe_prebuild_daemon_rs_release_tests(repo_root, &manifest)?;
    let rounds = env::var("OPENSNITCH_MICROBENCH_ROUNDS").unwrap_or_else(|_| "4000".to_string());
    let repeats = perf_repeats();
    let rust_log = perf_rust_log_level();

    let mut runs = Vec::with_capacity(repeats);
    for run_idx in 0..repeats {
        let started = std::time::Instant::now();
        let output = run_command(
            repo_root,
            "cargo",
            [
                "test",
                "--release",
                "--manifest-path",
                manifest.to_string_lossy().as_ref(),
                "-p",
                "opensnitchd-rs",
                "stress_profile_reports_connect_latency_and_pipeline_drops",
                "--",
                "--ignored",
                "--nocapture",
            ],
            &[
                ("RUST_LOG", rust_log.as_str()),
                ("OPENSNITCH_STRESS_ROUNDS", rounds.as_str()),
            ],
        )?;
        let elapsed_s = started.elapsed().as_secs_f64();
        let line = find_line(&output, "stress-profile rounds=")?.to_string();
        let rounds_u64 = parse_named_u64(&line, "rounds")?;
        let p95 = parse_metric(&line, "p95_ms")?;
        let rounds_f64 = rounds_u64 as f64;
        let time_op_us = if rounds_u64 > 0 {
            (elapsed_s * 1_000_000.0) / rounds_f64
        } else {
            f64::NAN
        };
        let ops_s = if elapsed_s > 0.0 {
            rounds_f64 / elapsed_s
        } else {
            f64::NAN
        };
        println!(
            "microbench-connect-dispatch run={}/{} p95_ms={:.3} wall_s={elapsed_s:.3} time_op_us={time_op_us:.3} ops_s={ops_s:.1}",
            run_idx + 1,
            repeats,
            p95,
        );
        runs.push((p95, elapsed_s, time_op_us, ops_s, line));
    }

    runs.sort_by(|left, right| left.0.total_cmp(&right.0));
    let (_, elapsed_s, time_op_us, ops_s, line) = &runs[runs.len() / 2];
    println!(
        "microbench-connect-dispatch median run_count={} wall_s={elapsed_s:.3} time_op_us={time_op_us:.3} ops_s={ops_s:.1} {line}",
        repeats,
    );
    Ok(())
}

pub(crate) fn run_parity_gate_command() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;
    let manifest = daemon_rs_manifest_path()?;
    maybe_prebuild_daemon_rs_release_tests(repo_root, &manifest)?;

    run_parity_gate_internal(repo_root)
}

pub(crate) fn run_parity_hot_path_harness_once_command() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;
    let manifest = daemon_rs_manifest_path()?;
    maybe_prebuild_daemon_rs_release_tests(repo_root, &manifest)?;

    let output = run_hot_path_harness_once_internal(repo_root)?;
    print!("{output}");
    Ok(())
}

pub(crate) fn run_parity_cold_path_harness_command() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;
    let manifest = daemon_rs_manifest_path()?;
    maybe_prebuild_daemon_rs_release_tests(repo_root, &manifest)?;

    let output = run_cold_path_harness_internal(repo_root)?;
    print!("{output}");
    Ok(())
}

pub(crate) fn run_parity_hot_cold_delta_once_command() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;
    let manifest = daemon_rs_manifest_path()?;
    maybe_prebuild_daemon_rs_release_tests(repo_root, &manifest)?;

    run_parity_hot_cold_delta_once_internal(repo_root)
}

fn run_parity_hot_cold_delta_once_internal(repo_root: &Path) -> Result<(), DynError> {
    let rounds = parity_stress_rounds();

    println!(
        "Running hot/cold parity delta harness with STRESS_ROUNDS={} (tools-driven)",
        rounds
    );

    let hot_output = run_hot_path_harness_once_internal(repo_root)?;
    print!("{hot_output}");

    let cold_output = run_cold_path_harness_internal(repo_root)?;
    print!("{cold_output}");

    let go_mixed_line = find_line(&hot_output, "mixed-saturation backend=go")?;
    let rust_mixed_line = find_line(&hot_output, "mixed-saturation backend=rust")?;
    let go_hot_line = find_line(&hot_output, "stress-profile backend=go")?;
    let rust_hot_line = find_line(&hot_output, "stress-profile rounds=")?;

    let go_rule_line = find_line(&cold_output, "cold-profile backend=go component=rule")?;
    let go_ui_line = find_line(&cold_output, "cold-profile backend=go component=ui")?;
    let rust_rule_line = find_line(&cold_output, "cold-profile backend=rust component=rule")?;
    let rust_ui_line = find_line(&cold_output, "cold-profile backend=rust component=ui")?;

    let go_tasks_lines: Vec<&str> = cold_output
        .lines()
        .filter(|line| line.contains("cold-profile backend=go component=tasks"))
        .collect();
    let rust_tasks_lines: Vec<&str> = cold_output
        .lines()
        .filter(|line| line.contains("cold-profile backend=rust component=tasks"))
        .collect();

    if go_tasks_lines.len() < 2 || rust_tasks_lines.len() < 2 {
        return Err("failed to parse both go/rust task cold-profile lines".into());
    }

    let go_mixed_ms = parse_metric(go_mixed_line, "verdict_ms")?;
    let rust_mixed_ms = parse_metric(rust_mixed_line, "verdict_ms")?;

    let go_p50 = parse_metric(go_hot_line, "p50_ms")?;
    let go_p95 = parse_metric(go_hot_line, "p95_ms")?;
    let go_p99 = parse_metric(go_hot_line, "p99_ms")?;
    let go_max = parse_metric(go_hot_line, "max_ms")?;
    let go_drop = parse_metric(go_hot_line, "drop_total")?;
    let go_time_op_us = parse_metric(go_hot_line, "time_op_us")?;
    let go_ops_s = parse_metric(go_hot_line, "ops_s")?;

    let rust_p50 = parse_metric(rust_hot_line, "p50_ms")?;
    let rust_p95 = parse_metric(rust_hot_line, "p95_ms")?;
    let rust_p99 = parse_metric(rust_hot_line, "p99_ms")?;
    let rust_max = parse_metric(rust_hot_line, "max_ms")?;
    let rust_drop = parse_metric(rust_hot_line, "drop_total")?;
    let rust_time_op_us = parse_metric(rust_hot_line, "time_op_us")?;
    let rust_ops_s = parse_metric(rust_hot_line, "ops_s")?;
    let go_rounds = parse_named_u64(go_hot_line, "rounds")?;
    let rust_rounds = parse_named_u64(rust_hot_line, "rounds")?;
    let go_hot_wall_s = (go_rounds as f64) * go_time_op_us / 1_000_000.0;
    let rust_hot_wall_s = (rust_rounds as f64) * rust_time_op_us / 1_000_000.0;

    let go_rule_elapsed = parse_metric(go_rule_line, "elapsed_s")?;
    let go_ui_elapsed = parse_metric(go_ui_line, "elapsed_s")?;
    let rust_rule_elapsed = parse_metric(rust_rule_line, "elapsed_s")?;
    let rust_ui_elapsed = parse_metric(rust_ui_line, "elapsed_s")?;

    let go_tasks_elapsed: f64 = go_tasks_lines
        .iter()
        .map(|line| parse_metric(line, "elapsed_s"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum();
    let rust_tasks_elapsed: f64 = rust_tasks_lines
        .iter()
        .map(|line| parse_metric(line, "elapsed_s"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum();

    let delta = |a: f64, b: f64| -> f64 { a - b };

    let mixed_delta = delta(rust_mixed_ms, go_mixed_ms);
    let go_cold = go_rule_elapsed + go_ui_elapsed;
    let rust_cold = rust_rule_elapsed + rust_ui_elapsed;
    let go_cold_with_tasks = go_cold + go_tasks_elapsed;
    let rust_cold_with_tasks = rust_cold + rust_tasks_elapsed;
    let cold_rule_delta = delta(rust_rule_elapsed, go_rule_elapsed);
    let cold_ui_delta = delta(rust_ui_elapsed, go_ui_elapsed);
    let cold_tasks_delta = delta(rust_tasks_elapsed, go_tasks_elapsed);

    println!(
        "PARITY DELTA HOT MIXED: go_verdict_ms={:.3} rust_verdict_ms={:.3} delta_ms={:+.3}",
        go_mixed_ms, rust_mixed_ms, mixed_delta
    );
    println!(
        "PARITY DELTA COLD COMPONENTS: go_rule_s={:.3} go_ui_s={:.3} go_tasks_s={:.3} rust_rule_s={:.3} rust_ui_s={:.3} rust_tasks_s={:.3}",
        go_rule_elapsed,
        go_ui_elapsed,
        go_tasks_elapsed,
        rust_rule_elapsed,
        rust_ui_elapsed,
        rust_tasks_elapsed
    );
    println!(
        "PARITY DELTA COLD DETAIL: rust_rule-vs-go_rule_s={:+.3} rust_ui-vs-go_ui_s={:+.3} rust_tasks-vs-go_tasks_s={:+.3}",
        cold_rule_delta, cold_ui_delta, cold_tasks_delta
    );
    println!(
        "PARITY DELTA COLD COMPARABLE-TASKS: go_total_with_tasks_s={:.3} rust_total_with_tasks_s={:.3} delta_with_tasks_s={:+.3}",
        go_cold_with_tasks,
        rust_cold_with_tasks,
        delta(rust_cold_with_tasks, go_cold_with_tasks)
    );
    println!(
        "PARITY DELTA HOT COMPONENTS: go_hot_wall_s={:.3} rust_hot_wall_s={:.3}",
        go_hot_wall_s, rust_hot_wall_s
    );
    println!(
        "PARITY DELTA HOT THROUGHPUT: go_time_op_us={:.3} rust_time_op_us={:.3} go_ops_s={:.1} rust_ops_s={:.1}",
        go_time_op_us, rust_time_op_us, go_ops_s, rust_ops_s
    );
    println!(
        "PARITY DELTA HOT: vs_go p50={:+.3} p95={:+.3} p99={:+.3} max={:+.3} drop_total={:+.0}",
        delta(rust_p50, go_p50),
        delta(rust_p95, go_p95),
        delta(rust_p99, go_p99),
        delta(rust_max, go_max),
        delta(rust_drop, go_drop),
    );
    println!(
        "PARITY DELTA COLD: go_total_s={:.3} rust_total_s={:.3} delta_s={:+.3}",
        go_cold,
        rust_cold,
        delta(rust_cold, go_cold)
    );

    println!("PARITY DELTA STATUS: PASS");
    Ok(())
}

fn run_hot_path_harness_once_internal(repo_root: &Path) -> Result<String, DynError> {
    let rounds = parity_stress_rounds();
    let rust_log = perf_rust_log_level();
    let go_log = perf_go_log_level();
    let go_kernel_pressure_secs =
        env::var("GO_KERNEL_PRESSURE_SECS").unwrap_or_else(|_| "3".to_string());
    let go_kernel_pressure_sweep_secs =
        env::var("GO_KERNEL_PRESSURE_SWEEP_SECS").unwrap_or_else(|_| "2".to_string());
    let daemon_dir = repo_root.join("daemon");

    let mut out = String::new();
    out.push_str(&format!(
        "Running hot-path parity harness (Go + Rust) with STRESS_ROUNDS={rounds}\n"
    ));

    out.push_str(&run_command(
        &daemon_dir,
        "go",
        [
            "test",
            "./runtimeprofile",
            "-run",
            "TestConnectAttemptProgressesUnderMixedNonConnectSaturation",
            "-count=1",
            "-v",
        ],
        &[("OPENSNITCH_HARNESS_GO_LOG_LEVEL", go_log.as_str())],
    )?);
    out.push('\n');

    out.push_str(&run_command(
        &daemon_dir,
        "go",
        [
            "test",
            "./runtimeprofile",
            "-run",
            "TestStressProfileReportsConnectLatencyAndPipelineDrops",
            "-count=1",
            "-v",
        ],
        &[
            ("OPENSNITCH_HARNESS_GO_LOG_LEVEL", go_log.as_str()),
            ("OPENSNITCH_STRESS_PROFILE", "1"),
            ("OPENSNITCH_STRESS_ROUNDS", rounds.as_str()),
        ],
    )?);
    out.push('\n');

    out.push_str(&run_command(
        &daemon_dir,
        "go",
        [
            "test",
            "./runtimeprofile",
            "-run",
            "TestStressProfileReportsKernelPipelinePressure",
            "-count=1",
            "-v",
        ],
        &[
            ("OPENSNITCH_HARNESS_GO_LOG_LEVEL", go_log.as_str()),
            ("OPENSNITCH_STRESS_PROFILE", "1"),
            (
                "OPENSNITCH_KERNEL_PRESSURE_SECS",
                go_kernel_pressure_secs.as_str(),
            ),
        ],
    )?);
    out.push('\n');

    out.push_str(&run_command(
        &daemon_dir,
        "go",
        [
            "test",
            "./runtimeprofile",
            "-run",
            "TestStressProfileReportsKernelPipelineTimeoutSweep",
            "-count=1",
            "-v",
        ],
        &[
            ("OPENSNITCH_HARNESS_GO_LOG_LEVEL", go_log.as_str()),
            ("OPENSNITCH_STRESS_PROFILE", "1"),
            (
                "OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS",
                go_kernel_pressure_sweep_secs.as_str(),
            ),
        ],
    )?);
    out.push('\n');

    out.push_str(&run_prebuilt_daemon_rs_test(
        repo_root,
        "tests::daemon_runtime::connect_attempt_progresses_under_mixed_non_connect_saturation",
        &["--nocapture"],
        &[("RUST_LOG", rust_log.as_str())],
    )?);
    out.push('\n');

    out.push_str(&run_prebuilt_daemon_rs_test(
        repo_root,
        "tests::daemon_runtime::stress_profile_reports_connect_latency_and_pipeline_drops",
        &["--ignored", "--nocapture"],
        &[
            ("RUST_LOG", rust_log.as_str()),
            ("OPENSNITCH_STRESS_ROUNDS", rounds.as_str()),
        ],
    )?);
    out.push('\n');

    out.push_str(&run_prebuilt_daemon_rs_test(
        repo_root,
        "tests::daemon_runtime::stress_profile_reports_kernel_pipeline_pressure",
        &["--ignored", "--nocapture"],
        &[
            ("RUST_LOG", rust_log.as_str()),
            ("OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK", "1"),
        ],
    )?);
    out.push('\n');

    out.push_str(&run_prebuilt_daemon_rs_test(
        repo_root,
        "tests::daemon_runtime::stress_profile_reports_kernel_pipeline_timeout_sweep",
        &["--ignored", "--nocapture"],
        &[
            ("RUST_LOG", rust_log.as_str()),
            ("OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK", "1"),
        ],
    )?);

    out.push_str("\nPARITY HOT-PATH STATUS: PASS\n");
    Ok(out)
}

fn run_cold_path_harness_internal(repo_root: &Path) -> Result<String, DynError> {
    let rust_log = perf_rust_log_level();
    let go_log = perf_go_log_level();
    let daemon_dir = repo_root.join("daemon");

    let fixture_path = repo_root.join("daemon/ui/testdata/default-config.json");
    let backup_path =
        fixture_path.with_file_name(format!("default-config.json.backup.{}", std::process::id()));

    fs::copy(&fixture_path, &backup_path)?;

    let run_result: Result<String, DynError> = (|| {
        let mut out = String::new();
        out.push_str("Running cold-path parity harness (watch/reload paths, Go + Rust)\n");

        out.push_str(&run_command(
            &daemon_dir,
            "go",
            ["test", "./rule", "-run", "TestLiveReload", "-count=1", "-v"],
            &[("OPENSNITCH_HARNESS_GO_LOG_LEVEL", go_log.as_str())],
        )?);
        out.push('\n');

        out.push_str(&run_command(
            &daemon_dir,
            "go",
            [
                "test",
                "./ui",
                "-run",
                "TestClientReloadingConfig",
                "-count=1",
                "-v",
            ],
            &[("OPENSNITCH_HARNESS_GO_LOG_LEVEL", go_log.as_str())],
        )?);
        out.push('\n');

        out.push_str(&run_command(
            &daemon_dir,
            "go",
            [
                "test",
                "./ui",
                "-run",
                "TestRuntimeTaskCommandsIgnoreUnsupportedNamesWithoutImmediateReply",
                "-count=1",
                "-v",
            ],
            &[("OPENSNITCH_HARNESS_GO_LOG_LEVEL", go_log.as_str())],
        )?);
        out.push('\n');

        out.push_str(&run_command(
            &daemon_dir,
            "go",
            [
                "test",
                "./ui",
                "-run",
                "TestRuntimeTaskStartDuplicateReturnsErrorWithoutInitialStartedReply",
                "-count=1",
                "-v",
            ],
            &[("OPENSNITCH_HARNESS_GO_LOG_LEVEL", go_log.as_str())],
        )?);
        out.push('\n');

        out.push_str(&run_prebuilt_daemon_rs_test(
            repo_root,
            "tests::watch_service::rules_watch_task_matches_go_live_reload_add_then_delete_flow",
            &["--nocapture"],
            &[("RUST_LOG", rust_log.as_str())],
        )?);
        out.push('\n');

        out.push_str(&run_prebuilt_daemon_rs_test(
            repo_root,
            "tests::watch_service::config_watch_task_reloads_runtime_snapshot_after_file_change",
            &["--nocapture"],
            &[("RUST_LOG", rust_log.as_str())],
        )?);
        out.push('\n');

        out.push_str(&run_prebuilt_daemon_rs_test(
            repo_root,
            "tests::daemon_runtime::runtime_task_start_duplicate_returns_error_without_initial_started_reply",
            &["--nocapture"],
            &[("RUST_LOG", rust_log.as_str())],
        )?);
        out.push('\n');

        out.push_str(&run_prebuilt_daemon_rs_test(
            repo_root,
            "tests::daemon_runtime::runtime_task_commands_ignore_unsupported_names_without_immediate_reply",
            &["--nocapture"],
            &[("RUST_LOG", rust_log.as_str())],
        )?);

        out.push_str("\nPARITY COLD-PATH STATUS: PASS\n");
        Ok(out)
    })();

    let restore_result = fs::copy(&backup_path, &fixture_path).map(|_| ());
    let cleanup_result = fs::remove_file(&backup_path);

    match (run_result, restore_result, cleanup_result) {
        (Ok(output), Ok(()), Ok(())) => Ok(output),
        (Err(err), _, _) => Err(err),
        (Ok(_), Err(err), _) => Err(err.into()),
        (Ok(_), Ok(()), Err(err)) => Err(err.into()),
    }
}

fn prebuild_daemon_rs_release_tests(repo_root: &Path, manifest: &Path) -> Result<(), DynError> {
    let _ = run_command(
        repo_root,
        "cargo",
        [
            "test",
            "--manifest-path",
            manifest.to_string_lossy().as_ref(),
            "--release",
            "--workspace",
            "--all-targets",
            "--no-run",
        ],
        &[],
    )?;

    Ok(())
}

fn prebuild_flag_enabled() -> bool {
    match env::var("OPENSNITCH_PARITY_PREBUILD") {
        Ok(value) => matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"),
        Err(_) => true,
    }
}

fn prebuild_done_state() -> bool {
    PREBUILD_DONE.load(Ordering::Relaxed) || env_flag(PREBUILD_DONE_ENV)
}

fn mark_prebuild_done() {
    PREBUILD_DONE.store(true, Ordering::Relaxed);
}

fn maybe_prebuild_daemon_rs_release_tests(
    repo_root: &Path,
    manifest: &Path,
) -> Result<(), DynError> {
    if prebuild_flag_enabled() && !prebuild_done_state() {
        prebuild_daemon_rs_release_tests(repo_root, manifest)?;
        mark_prebuild_done();
    }
    Ok(())
}

fn daemon_rs_manifest_path() -> Result<PathBuf, DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    Ok(daemon_rs_dir.join("Cargo.toml"))
}

fn daemon_rs_release_test_binary_path(repo_root: &Path) -> Result<PathBuf, DynError> {
    let deps_dir = repo_root.join("daemon-rs/target/release/deps");
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;

    for entry in fs::read_dir(&deps_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name,
            None => continue,
        };

        if !name.starts_with("opensnitchd_rs-") || path.extension().is_some() {
            continue;
        }

        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            continue;
        }

        let modified = metadata
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        match &newest {
            Some((current, _)) if modified <= *current => {}
            _ => newest = Some((modified, path)),
        }
    }

    newest
        .map(|(_, path)| path)
        .ok_or_else(|| "no prebuilt opensnitchd-rs release test binary found".into())
}

fn run_prebuilt_daemon_rs_test(
    repo_root: &Path,
    test_filter: &str,
    test_args: &[&str],
    envs: &[(&str, &str)],
) -> Result<String, DynError> {
    let test_binary = daemon_rs_release_test_binary_path(repo_root)?;
    let mut command = Command::new(&test_binary);
    command
        .current_dir(repo_root)
        .arg(test_filter)
        .args(test_args);
    for (key, value) in envs {
        command.env(key, value);
    }

    let output = command.output()?;
    if output.status.success() {
        let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok(combined)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(format!(
            "prebuilt test binary failed: {} {} {}\nstdout:\n{}\nstderr:\n{}",
            test_binary.display(),
            test_filter,
            test_args.join(" "),
            stdout,
            stderr
        )
        .into())
    }
}

pub(crate) fn run_parity_gate_internal(repo_root: &Path) -> Result<(), DynError> {
    let rounds = parity_stress_rounds();
    let repeats = perf_repeats();
    let require_exceed = env_flag("OPENSNITCH_PARITY_REQUIRE_EXCEED_GO");
    let rust_log = perf_rust_log_level();
    let go_log = perf_go_log_level();
    let prebuild_done = if prebuild_done_state() { "1" } else { "0" };

    println!(
        "Running parity gate with STRESS_ROUNDS={} ({}x, median by hot p95 delta)...",
        rounds, repeats
    );
    let mut runs = Vec::with_capacity(repeats);
    for run_idx in 0..repeats {
        let output = run_command(
            repo_root,
            "make",
            [
                "parity-hot-cold-delta",
                &format!("STRESS_ROUNDS={rounds}"),
                "PERF_REPEATS=1",
            ],
            &[
                ("PERF_RUST_LOG_LEVEL", rust_log.as_str()),
                ("HARNESS_GO_LOG_LEVEL", go_log.as_str()),
                (PREBUILD_DONE_ENV, prebuild_done),
            ],
        )?;

        let status_line = find_line(&output, "PARITY DELTA STATUS:")?.to_string();
        let hot_line = find_line(&output, "PARITY DELTA HOT:")?.to_string();
        let hot_p95 = parse_metric(&hot_line, "p95")?;
        let hot_p99 = parse_metric(&hot_line, "p99")?;
        println!(
            "parity-gate run={}/{} hot_p95={:+.3} hot_p99={:+.3} status={}",
            run_idx + 1,
            repeats,
            hot_p95,
            hot_p99,
            status_line,
        );
        runs.push((hot_p95, hot_p99, status_line, hot_line));
    }

    runs.sort_by(|left, right| left.0.total_cmp(&right.0));
    let (hot_p95, hot_p99, status_line, _) = &runs[runs.len() / 2];
    if !status_line.contains("PASS") {
        return Err(format!("parity gate failed: {status_line}").into());
    }

    if require_exceed && (*hot_p95 > 0.0 || *hot_p99 > 0.0) {
        return Err(format!(
            "parity gate exceed-go check failed: p95={hot_p95:+.3} p99={hot_p99:+.3}"
        )
        .into());
    }

    println!(
        "parity-gate median run_count={} status={} hot_p95={:+.3} hot_p99={:+.3}",
        repeats, status_line, hot_p95, hot_p99
    );
    Ok(())
}
