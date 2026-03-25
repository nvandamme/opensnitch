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

/// Canonical content of the Go-side UI test fixture used by the cold-path
/// harness.  The harness writes this to `daemon/ui/testdata/default-config.json`
/// before tests run so the fixture always starts from a known-good state,
/// regardless of what a previous (possibly crashed) run may have left behind.
const COLD_PATH_CONFIG_FIXTURE: &str =
    include_str!("../fixtures/default-config.json");
/// Path within the repo root at which the Go tests and Rust watch tests both
/// expect the UI config fixture to live.
const COLD_PATH_CONFIG_FIXTURE_REL: &str = "daemon/ui/testdata/default-config.json";

pub(crate) fn microbench_connect_dispatch() -> Result<(), DynError> {
    crate::test_guard::with_guard("microbench-connect-dispatch", || {
    let repo_root = crate::test_guard::repo_root()?;
    let manifest = daemon_rs_manifest_path()?;
    maybe_prebuild_daemon_rs_release_tests(&repo_root, &manifest)?;
    let rounds = env::var("OPENSNITCH_MICROBENCH_ROUNDS").unwrap_or_else(|_| "4000".to_string());
    let repeats = perf_repeats();
    let rust_log = perf_rust_log_level();

    let mut runs = Vec::with_capacity(repeats);
    for run_idx in 0..repeats {
        let started = std::time::Instant::now();
        let output = run_command(
            &repo_root,
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
    }) // with_guard
}

pub(crate) fn run_parity_gate_command() -> Result<(), DynError> {
    crate::test_guard::with_guard("parity-gate", || {
    let repo_root = crate::test_guard::repo_root()?;
    let manifest = daemon_rs_manifest_path()?;
    maybe_prebuild_daemon_rs_release_tests(&repo_root, &manifest)?;
    run_parity_gate_internal(&repo_root)
    }) // with_guard
}

pub(crate) fn run_parity_hot_path_harness_once_command() -> Result<(), DynError> {
    crate::test_guard::with_guard("parity-hot-path-harness-once", || {
    let repo_root = crate::test_guard::repo_root()?;
    let manifest = daemon_rs_manifest_path()?;
    maybe_prebuild_daemon_rs_release_tests(&repo_root, &manifest)?;
    let output = run_hot_path_harness_once_internal(&repo_root)?;
    print!("{output}");
    Ok(())
    }) // with_guard
}

/// `parity-hot-path-harness`: run the hot-path parity harness `perf_repeats()`
/// times.  Pre-build happens on the first pass only (matching the former
/// Makefile loop that set `PERF_PREBUILD=1` for `i==1` only).
pub(crate) fn run_parity_hot_path_harness() -> Result<(), DynError> {
    crate::test_guard::with_guard("parity-hot-path-harness", || {
    let repo_root = crate::test_guard::repo_root()?;
    let manifest = daemon_rs_manifest_path()?;
    let repeats = perf_repeats();
    for i in 1..=repeats {
        eprintln!("[tools] parity-hot-path-harness run {i}/{repeats}");
        if i == 1 {
            maybe_prebuild_daemon_rs_release_tests(&repo_root, &manifest)?;
        }
        let output = run_hot_path_harness_once_internal(&repo_root)?;
        print!("{output}");
    }
    Ok(())
    }) // with_guard
}

pub(crate) fn run_parity_cold_path_harness_command() -> Result<(), DynError> {
    crate::test_guard::with_guard("parity-cold-path-harness", || {
    let repo_root = crate::test_guard::repo_root()?;
    let manifest = daemon_rs_manifest_path()?;
    maybe_prebuild_daemon_rs_release_tests(&repo_root, &manifest)?;
    let output = run_cold_path_harness_internal(&repo_root)?;
    print!("{output}");
    Ok(())
    }) // with_guard
}

pub(crate) fn run_parity_hot_cold_delta_once_command() -> Result<(), DynError> {
    crate::test_guard::with_guard("parity-hot-cold-delta-once", || {
    let repo_root = crate::test_guard::repo_root()?;
    let manifest = daemon_rs_manifest_path()?;
    maybe_prebuild_daemon_rs_release_tests(&repo_root, &manifest)?;
    run_parity_hot_cold_delta_once_internal(&repo_root)
        .map(|output| print!("{}", format_parity_delta_table(&output)))
    }) // with_guard
}

/// `parity-hot-cold-delta`: run the full hot+cold parity delta harness
/// `perf_repeats()` times (default 3, override with `OPENSNITCH_PERF_REPEATS`),
/// then print the median run by hot-path p95 delta.  Unlike `parity-gate` this
/// command does not perform a threshold check and does not write PERF.md.
pub(crate) fn run_parity_hot_cold_delta_command() -> Result<(), DynError> {
    crate::test_guard::with_guard("parity-hot-cold-delta", || {
    let repo_root = crate::test_guard::repo_root()?;
    let manifest = daemon_rs_manifest_path()?;
    let repeats = perf_repeats();
    let rounds = parity_stress_rounds();

    eprintln!(
        "[tools] parity-hot-cold-delta STRESS_ROUNDS={rounds} repeats={repeats}"
    );

    maybe_prebuild_daemon_rs_release_tests(&repo_root, &manifest)?;

    // (hot_p95, status_line, full output)
    let mut runs: Vec<(f64, String, String)> = Vec::with_capacity(repeats);
    for run_idx in 0..repeats {
        let output = run_parity_hot_cold_delta_once_internal(&repo_root)?;
        let status_line = find_line(&output, "PARITY DELTA STATUS:")?.to_string();
        let hot_line = find_line(&output, "PARITY DELTA HOT:")?.to_string();
        let hot_p95 = parse_metric(&hot_line, "p95")?;
        print!("{}", format_parity_delta_table(&output));
        println!(
            "parity-hot-cold-delta run={}/{} hot_p95={:+.3} status={}",
            run_idx + 1,
            repeats,
            hot_p95,
            status_line,
        );
        runs.push((hot_p95, status_line, output));
    }

    runs.sort_by(|l, r| l.0.total_cmp(&r.0));
    let (hot_p95, status_line, median_output) = &runs[runs.len() / 2];
    println!("\n--- parity-hot-cold-delta median ---");
    print!("{}", format_parity_delta_table(median_output));
    println!(
        "parity-hot-cold-delta median run_count={repeats} hot_p95={hot_p95:+.3} status={status_line}",
    );
    Ok(())
    }) // with_guard
}

/// Returns the full parity delta output as a String (for callers that need to
/// parse it, like the parity-gate repeat loop and update-run-perf).
pub(crate) fn run_parity_delta_to_string(repo_root: &Path) -> Result<String, DynError> {
    run_parity_hot_cold_delta_once_internal(repo_root)
}

fn run_parity_hot_cold_delta_once_internal(repo_root: &Path) -> Result<String, DynError> {
    let rounds = parity_stress_rounds();
    let mut out = String::new();

    out.push_str(&format!(
        "Running hot/cold parity delta harness with STRESS_ROUNDS={} (tools-driven)\n",
        rounds
    ));

    // Use the delta-only hot path: skips kernel-pressure tests whose output is
    // not needed for the delta computation, saving ~15s per pass.
    let hot_output = run_hot_path_delta_only_internal(repo_root)?;
    out.push_str(&hot_output);

    let cold_output = run_cold_path_harness_internal(repo_root)?;
    out.push_str(&cold_output);

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

    use std::fmt::Write as _;

    let delta = |a: f64, b: f64| -> f64 { a - b };

    let mixed_delta = delta(rust_mixed_ms, go_mixed_ms);
    let go_cold = go_rule_elapsed + go_ui_elapsed;
    let rust_cold = rust_rule_elapsed + rust_ui_elapsed;
    let go_cold_with_tasks = go_cold + go_tasks_elapsed;
    let rust_cold_with_tasks = rust_cold + rust_tasks_elapsed;
    let cold_rule_delta = delta(rust_rule_elapsed, go_rule_elapsed);
    let cold_ui_delta = delta(rust_ui_elapsed, go_ui_elapsed);
    let cold_tasks_delta = delta(rust_tasks_elapsed, go_tasks_elapsed);

    let _ = writeln!(out,
        "PARITY DELTA HOT MIXED: go_verdict_ms={:.3} rust_verdict_ms={:.3} delta_ms={:+.3}",
        go_mixed_ms, rust_mixed_ms, mixed_delta
    );
    let _ = writeln!(out,
        "PARITY DELTA COLD COMPONENTS: go_rule_s={:.3} go_ui_s={:.3} go_tasks_s={:.3} rust_rule_s={:.3} rust_ui_s={:.3} rust_tasks_s={:.3}",
        go_rule_elapsed, go_ui_elapsed, go_tasks_elapsed,
        rust_rule_elapsed, rust_ui_elapsed, rust_tasks_elapsed
    );
    let _ = writeln!(out,
        "PARITY DELTA COLD DETAIL: rust_rule-vs-go_rule_s={:+.3} rust_ui-vs-go_ui_s={:+.3} rust_tasks-vs-go_tasks_s={:+.3}",
        cold_rule_delta, cold_ui_delta, cold_tasks_delta
    );
    let _ = writeln!(out,
        "PARITY DELTA COLD COMPARABLE-TASKS: go_total_with_tasks_s={:.3} rust_total_with_tasks_s={:.3} delta_with_tasks_s={:+.3}",
        go_cold_with_tasks, rust_cold_with_tasks,
        delta(rust_cold_with_tasks, go_cold_with_tasks)
    );
    let _ = writeln!(out,
        "PARITY DELTA HOT COMPONENTS: go_hot_wall_s={:.3} rust_hot_wall_s={:.3}",
        go_hot_wall_s, rust_hot_wall_s
    );
    let _ = writeln!(out,
        "PARITY DELTA HOT THROUGHPUT: go_time_op_us={:.3} rust_time_op_us={:.3} go_ops_s={:.1} rust_ops_s={:.1}",
        go_time_op_us, rust_time_op_us, go_ops_s, rust_ops_s
    );
    let _ = writeln!(out,
        "PARITY DELTA HOT: vs_go p50={:+.3} p95={:+.3} p99={:+.3} max={:+.3} drop_total={:+.0}",
        delta(rust_p50, go_p50), delta(rust_p95, go_p95),
        delta(rust_p99, go_p99), delta(rust_max, go_max),
        delta(rust_drop, go_drop),
    );
    let _ = writeln!(out,
        "PARITY DELTA COLD: go_total_s={:.3} rust_total_s={:.3} delta_s={:+.3}",
        go_cold, rust_cold, delta(rust_cold, go_cold)
    );
    out.push_str("PARITY DELTA STATUS: PASS
");
    Ok(out)
}

/// Full hot-path harness — runs all 8 tests including the kernel-pressure suite.
/// Used by `parity-hot-path-harness-once` (the standalone command) so users see
/// everything.  Not used by the delta / parity-gate repeat loop.
fn run_hot_path_harness_once_internal(repo_root: &Path) -> Result<String, DynError> {
    let rounds = parity_stress_rounds();
    let rust_log = perf_rust_log_level();
    let go_log = perf_go_log_level();
    let rounds_u64 = rounds.parse::<u64>().unwrap_or(500);
    let default_kernel_pressure_secs = if rounds_u64 <= 500 { "1" } else { "3" };
    let default_kernel_pressure_sweep_secs = if rounds_u64 <= 500 { "1" } else { "2" };
    let go_kernel_pressure_secs = env::var("GO_KERNEL_PRESSURE_SECS")
        .unwrap_or_else(|_| default_kernel_pressure_secs.to_string());
    let go_kernel_pressure_sweep_secs = env::var("GO_KERNEL_PRESSURE_SWEEP_SECS")
        .unwrap_or_else(|_| default_kernel_pressure_sweep_secs.to_string());
    let daemon_dir = repo_root.join("daemon");

    let mut out = String::new();
    out.push_str(&format!(
        "Running hot-path parity harness (Go + Rust) with STRESS_ROUNDS={rounds}\n"
    ));

    out.push_str(&run_hot_path_core(repo_root, &daemon_dir, &rounds, &go_log, &rust_log)?);

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
        "tests::daemon_runtime::stress_profile_reports_kernel_pipeline_pressure",
        &["--ignored", "--nocapture"],
        &[
            ("RUST_LOG", rust_log.as_str()),
            ("OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK", "1"),
            (
                "OPENSNITCH_KERNEL_PRESSURE_SECS",
                go_kernel_pressure_secs.as_str(),
            ),
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
            (
                "OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS",
                go_kernel_pressure_sweep_secs.as_str(),
            ),
        ],
    )?);

    out.push_str("\nPARITY HOT-PATH STATUS: PASS\n");
    Ok(out)
}

/// Fast hot-path variant used by the delta / parity-gate repeat loop.
/// Runs only the 4 tests whose output is required for the delta computation
/// (mixed-saturation + stress-profile for Go and Rust), skipping the
/// kernel-pressure suite which is not read by the delta parser.
fn run_hot_path_delta_only_internal(repo_root: &Path) -> Result<String, DynError> {
    let rounds = parity_stress_rounds();
    let rust_log = perf_rust_log_level();
    let go_log = perf_go_log_level();
    let daemon_dir = repo_root.join("daemon");

    let mut out = String::new();
    out.push_str(&format!(
        "Running hot-path parity harness (Go + Rust, delta-subset) with STRESS_ROUNDS={rounds}\n"
    ));

    out.push_str(&run_hot_path_core(repo_root, &daemon_dir, &rounds, &go_log, &rust_log)?);
    out.push_str("\nPARITY HOT-PATH STATUS: PASS\n");
    Ok(out)
}

/// Shared core: mixed-saturation + stress-profile for both Go and Rust.
fn run_hot_path_core(
    repo_root: &Path,
    daemon_dir: &Path,
    rounds: &str,
    go_log: &str,
    rust_log: &str,
) -> Result<String, DynError> {
    let mut out = String::new();

    out.push_str(&run_command(
        daemon_dir,
        "go",
        [
            "test",
            "./runtimeprofile",
            "-run",
            "TestConnectAttemptProgressesUnderMixedNonConnectSaturation",
            "-count=1",
            "-v",
        ],
        &[("OPENSNITCH_HARNESS_GO_LOG_LEVEL", go_log)],
    )?);
    out.push('\n');

    out.push_str(&run_command(
        daemon_dir,
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
            ("OPENSNITCH_HARNESS_GO_LOG_LEVEL", go_log),
            ("OPENSNITCH_STRESS_PROFILE", "1"),
            ("OPENSNITCH_STRESS_ROUNDS", rounds),
        ],
    )?);
    out.push('\n');

    out.push_str(&run_prebuilt_daemon_rs_test(
        repo_root,
        "tests::daemon_runtime::connect_attempt_progresses_under_mixed_non_connect_saturation",
        &["--nocapture"],
        &[("RUST_LOG", rust_log)],
    )?);
    out.push('\n');

    out.push_str(&run_prebuilt_daemon_rs_test(
        repo_root,
        "tests::daemon_runtime::stress_profile_reports_connect_latency_and_pipeline_drops",
        &["--ignored", "--nocapture"],
        &[
            ("RUST_LOG", rust_log),
            ("OPENSNITCH_STRESS_ROUNDS", rounds),
        ],
    )?);
    out.push('\n');

    Ok(out)
}

fn run_cold_path_harness_internal(repo_root: &Path) -> Result<String, DynError> {
    let rust_log = perf_rust_log_level();
    let go_log = perf_go_log_level();
    let daemon_dir = repo_root.join("daemon");

    let fixture_path = repo_root.join(COLD_PATH_CONFIG_FIXTURE_REL);
    let backup_path =
        fixture_path.with_file_name(format!("default-config.json.backup.{}", std::process::id()));

    // Preserve the existing Go-side fixture; it is restored unconditionally on exit.
    fs::copy(&fixture_path, &backup_path)?;
    // Write our canonical copy so the harness always starts from a known-good
    // state — a crashed previous run cannot leave a partially-mutated file behind.
    fs::write(&fixture_path, COLD_PATH_CONFIG_FIXTURE)?;

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
            "tests::watch_workers::rules_watch_task_matches_go_live_reload_add_then_delete_flow",
            &["--nocapture"],
            &[("RUST_LOG", rust_log.as_str())],
        )?);
        out.push('\n');

        out.push_str(&run_prebuilt_daemon_rs_test(
            repo_root,
            "tests::watch_workers::config_watch_task_reloads_runtime_snapshot_after_file_change",
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
            "-p",
            "opensnitchd-rs",
            "--tests",
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
    // When the harness runs with CARGO_TARGET_DIR (e.g. daemon-rs/target-kernel), the
    // prebuild writes the test binary there — NOT in the default daemon-rs/target dir.
    // Use the env var so both paths stay in sync.
    let target_dir = if let Ok(dir) = env::var("CARGO_TARGET_DIR") {
        PathBuf::from(dir)
    } else {
        repo_root.join("daemon-rs/target")
    };
    let deps_dir = target_dir.join("release/deps");

    // Cargo hard-links the final daemon binary from deps/opensnitchd_rs-HASH to
    // target/release/opensnitchd-rs.  Picking that hard-linked file would run the
    // production daemon, not the test harness.  Exclude any deps/ candidate whose
    // inode matches the release binary so we always pick the real test binary.
    use std::os::unix::fs::MetadataExt as _;
    let release_ino: Option<u64> = fs::metadata(target_dir.join("release/opensnitchd-rs"))
        .ok()
        .map(|m| m.ino());

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

        // Skip the daemon binary (same inode as release/opensnitchd-rs).
        if release_ino.map_or(false, |ino| metadata.ino() == ino) {
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
        .args(test_args)
        // The parity harness always runs as root.  Set this so the test binary
        // knows it is executing in a privileged context (mirrors what the
        // Makefile does for every parity/harness target).
        .env("OPENSNITCH_RUN_PRIVILEGED_TESTS", "1");
    for (key, value) in envs {
        command.env(key, value);
    }
    let label = format!("prebuilt-test {test_filter}");
    crate::run_timed(command, &label)
}

pub(crate) fn run_parity_gate_internal(repo_root: &Path) -> Result<(), DynError> {
    let rounds = parity_stress_rounds();
    let repeats = perf_repeats();
    let require_exceed = env_flag("OPENSNITCH_PARITY_REQUIRE_EXCEED_GO");

    println!(
        "Running parity gate with STRESS_ROUNDS={} ({}x, median by hot p95 delta)...",
        rounds, repeats
    );
    let mut runs = Vec::with_capacity(repeats);
    for run_idx in 0..repeats {
        // Run in-process — avoids spawning a new subprocess + cargo warm start
        // each iteration which was adding overhead per repeat.
        let output = run_parity_delta_to_string(repo_root)?;

        let status_line = find_line(&output, "PARITY DELTA STATUS:")?.to_string();
        let hot_line = find_line(&output, "PARITY DELTA HOT:")?.to_string();
        let hot_p95 = parse_metric(&hot_line, "p95")?;
        let hot_p99 = parse_metric(&hot_line, "p99")?;
        print!("{}", format_parity_delta_table(&output));
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

/// Formats the machine-readable parity delta output as a human-readable table.
/// Falls back to the raw output string if any metric cannot be parsed.
pub(crate) fn format_parity_delta_table(output: &str) -> String {
    build_parity_delta_table(output).unwrap_or_else(|_| output.to_string())
}

fn build_parity_delta_table(output: &str) -> Result<String, DynError> {
    use std::fmt::Write as _;

    let hot_mixed_line = find_line(output, "PARITY DELTA HOT MIXED:")?;
    let hot_throughput_line = find_line(output, "PARITY DELTA HOT THROUGHPUT:")?;
    let hot_line = find_line(output, "PARITY DELTA HOT:")?;
    let hot_components_line = find_line(output, "PARITY DELTA HOT COMPONENTS:")?;
    let cold_components_line = find_line(output, "PARITY DELTA COLD COMPONENTS:")?;
    let cold_detail_line = find_line(output, "PARITY DELTA COLD DETAIL:")?;
    let cold_line = find_line(output, "PARITY DELTA COLD:")?;
    let status_line = find_line(output, "PARITY DELTA STATUS:")?;
    let status = status_line.split(':').nth(1).map(str::trim).unwrap_or("PASS");
    let cold_comparable_line = output.lines().find(|l| {
        l.contains("PARITY DELTA COLD COMPARABLE-TASKS:")
            || l.contains("PARITY DELTA COLD NON-COMPARABLE-TASKS:")
    });

    let go_mixed_ms = parse_metric(hot_mixed_line, "go_verdict_ms")?;
    let rust_mixed_ms = parse_metric(hot_mixed_line, "rust_verdict_ms")?;
    let mixed_delta_ms = parse_metric(hot_mixed_line, "delta_ms")?;
    let go_wall = parse_metric(hot_components_line, "go_hot_wall_s")?;
    let rust_wall = parse_metric(hot_components_line, "rust_hot_wall_s")?;
    let go_time_op = parse_metric(hot_throughput_line, "go_time_op_us")?;
    let rust_time_op = parse_metric(hot_throughput_line, "rust_time_op_us")?;
    let go_ops_s = parse_metric(hot_throughput_line, "go_ops_s")?;
    let rust_ops_s = parse_metric(hot_throughput_line, "rust_ops_s")?;
    let hot_p50 = parse_metric(hot_line, "p50")?;
    let hot_p95 = parse_metric(hot_line, "p95")?;
    let hot_p99 = parse_metric(hot_line, "p99")?;
    let hot_max = parse_metric(hot_line, "max")?;
    let hot_drop = parse_metric(hot_line, "drop_total")?;
    let go_rule = parse_metric(cold_components_line, "go_rule_s")?;
    let rust_rule = parse_metric(cold_components_line, "rust_rule_s")?;
    let delta_rule = parse_metric(cold_detail_line, "rust_rule-vs-go_rule_s")?;
    let go_ui = parse_metric(cold_components_line, "go_ui_s")?;
    let rust_ui = parse_metric(cold_components_line, "rust_ui_s")?;
    let delta_ui = parse_metric(cold_detail_line, "rust_ui-vs-go_ui_s")?;
    let go_tasks = parse_metric(cold_components_line, "go_tasks_s")?;
    let rust_tasks = parse_metric(cold_components_line, "rust_tasks_s")?;
    let delta_tasks = parse_metric(cold_detail_line, "rust_tasks-vs-go_tasks_s")?;
    let go_cold = parse_metric(cold_line, "go_total_s")?;
    let rust_cold = parse_metric(cold_line, "rust_total_s")?;
    let cold_delta = parse_metric(cold_line, "delta_s")?;
    let (go_cold_wt, rust_cold_wt, cold_wt_delta) = if let Some(line) = cold_comparable_line {
        (
            parse_metric(line, "go_total_with_tasks_s")?,
            parse_metric(line, "rust_total_with_tasks_s")?,
            parse_metric(line, "delta_with_tasks_s")?,
        )
    } else {
        (go_cold, rust_cold, cold_delta)
    };

    // Layout: metric=16, go=13, rust=13, delta=15 → total line width = 70 chars.
    // Verified: 1+1+16+1 + 1+1+13+1 + 1+1+13+1 + 1+1+15+1+1 = 70
    fn row(c0: &str, c1: &str, c2: &str, c3: &str) -> String {
        format!("│ {c0:<16} │ {c1:<13} │ {c2:<13} │ {c3:<15} │\n")
    }
    fn hr(cl: char, cm: char, cr: char) -> String {
        format!(
            "{cl}{}{cm}{}{cm}{}{cm}{}{cr}\n",
            "─".repeat(18),
            "─".repeat(15),
            "─".repeat(15),
            "─".repeat(17)
        )
    }
    // Section close: join column separators into bottom-T connectors.
    fn hr_close() -> String {
        format!(
            "├{}┴{}┴{}┴{}┤\n",
            "─".repeat(18),
            "─".repeat(15),
            "─".repeat(15),
            "─".repeat(17)
        )
    }
    // Full-width banner: │ + space + 66-char content + space + │ = 70 chars.
    fn banner(text: &str) -> String {
        format!("│ {:<66} │\n", text)
    }

    let mut t = String::new();
    let _ = write!(t, "{}", hr('┌', '┬', '┐'));
    let _ = write!(t, "{}", row("Metric", "Go", "Rust", "Delta (Rust-Go)"));
    let _ = write!(t, "{}", hr('├', '┼', '┤'));
    let _ = write!(
        t,
        "{}",
        row(
            "Hot: mixed",
            &format!("{:.3} ms", go_mixed_ms),
            &format!("{:.3} ms", rust_mixed_ms),
            &format!("{:+.3} ms", mixed_delta_ms),
        )
    );
    let _ = write!(
        t,
        "{}",
        row(
            "Hot: wall time",
            &format!("{:.3} s", go_wall),
            &format!("{:.3} s", rust_wall),
            "",
        )
    );
    let _ = write!(
        t,
        "{}",
        row(
            "Hot: time/op",
            &format!("{:.3} us", go_time_op),
            &format!("{:.3} us", rust_time_op),
            "",
        )
    );
    let _ = write!(
        t,
        "{}",
        row(
            "Hot: ops/sec",
            &format!("{:.1} /s", go_ops_s),
            &format!("{:.1} /s", rust_ops_s),
            "",
        )
    );
    let _ = write!(t, "{}", row("Hot delta p50", "", "", &format!("{:+.3} ms", hot_p50)));
    let _ = write!(t, "{}", row("Hot delta p95", "", "", &format!("{:+.3} ms", hot_p95)));
    let _ = write!(t, "{}", row("Hot delta p99", "", "", &format!("{:+.3} ms", hot_p99)));
    let _ = write!(t, "{}", row("Hot delta max", "", "", &format!("{:+.3} ms", hot_max)));
    let _ = write!(t, "{}", row("Hot delta drop", "", "", &format!("{:+.0}", hot_drop)));
    let _ = write!(t, "{}", hr('├', '┼', '┤'));
    let _ = write!(
        t,
        "{}",
        row(
            "Cold: rule",
            &format!("{:.3} s", go_rule),
            &format!("{:.3} s", rust_rule),
            &format!("{:+.3} s", delta_rule),
        )
    );
    let _ = write!(
        t,
        "{}",
        row(
            "Cold: ui",
            &format!("{:.3} s", go_ui),
            &format!("{:.3} s", rust_ui),
            &format!("{:+.3} s", delta_ui),
        )
    );
    let _ = write!(
        t,
        "{}",
        row(
            "Cold: tasks",
            &format!("{:.3} s", go_tasks),
            &format!("{:.3} s", rust_tasks),
            &format!("{:+.3} s", delta_tasks),
        )
    );
    let _ = write!(
        t,
        "{}",
        row(
            "Cold: total",
            &format!("{:.3} s", go_cold),
            &format!("{:.3} s", rust_cold),
            &format!("{:+.3} s", cold_delta),
        )
    );
    let _ = write!(
        t,
        "{}",
        row(
            "Cold: +tasks",
            &format!("{:.3} s", go_cold_wt),
            &format!("{:.3} s", rust_cold_wt),
            &format!("{:+.3} s", cold_wt_delta),
        )
    );
    let _ = write!(t, "{}", hr_close());
    let _ = write!(t, "{}", banner(&format!("STATUS: {status}")));
    let _ = write!(t, "└{}┘\n", "─".repeat(68));

    Ok(t)
}
