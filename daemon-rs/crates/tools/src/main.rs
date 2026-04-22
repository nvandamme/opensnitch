use std::{
    collections::hash_map::DefaultHasher,
    env, fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

type DynError = Box<dyn std::error::Error>;

const TABLE_HEADER: &str = "| Date | Backend | Profile | Rounds | Commit | p50 ms | p95 ms | p99 ms | max ms | drop_total | Baseline Check | Go Ref | vs Go p50 | vs Go p95 | vs Go p99 | vs Go max | vs Go drop | Prev Commit Ref | vs Prev p50 | vs Prev p95 | vs Prev p99 | vs Prev max | vs Prev drop | Notes |";
const DELTA_TABLE_HEADER: &str = "| Date | Delta Target | Rounds | Commit | Hot Δ p50 ms | Hot Δ p95 ms | Hot Δ p99 ms | Hot Δ max ms | Hot Δ drop_total | Cold Go total s | Cold Rust total s | Cold Δ s (Rust-Go) | Result | Notes |";
const EMPTY_COMPARISON_COLUMNS: &str = "- | - | - | - | - | - | - | - | - | - | - | -";

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), DynError> {
    ensure_release_tools_mode()?;

    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("update-run-perf") => update_perf_md(),
        Some("quick-pressure-sweep-tunables") => quick_pressure_sweep_tunables(),
        Some("auto-tune-kernel-pressure-tunables") => auto_tune_kernel_pressure_tunables(),
        Some("microbench-connect-dispatch") => microbench_connect_dispatch(),
        Some("parity-gate") => run_parity_gate_command(),
        Some("launch-daemon-live-logs") => launch_daemon_live_logs(),
        Some("stop-daemon-live-logs") => stop_daemon_live_logs(),
        Some(command) => Err(format!("unsupported tools command: {command}").into()),
        None => Err(
            "usage: cargo run -p tools -- <update-run-perf|quick-pressure-sweep-tunables|auto-tune-kernel-pressure-tunables|microbench-connect-dispatch|parity-gate|launch-daemon-live-logs|stop-daemon-live-logs>".into(),
        ),
    }
}

fn ensure_release_tools_mode() -> Result<(), DynError> {
    if cfg!(debug_assertions) {
        return Err(
            "tools benchmarks must run in release mode; use: cargo run --release -p tools -- <command>"
                .into(),
        );
    }
    Ok(())
}

fn perf_rust_log_level() -> String {
    let raw = env::var("OPENSNITCH_PERF_RUST_LOG_LEVEL").unwrap_or_else(|_| "error".to_string());
    let normalized = raw.to_ascii_lowercase();
    let has_warn_or_error = normalized.contains("warn") || normalized.contains("error");
    let has_debug_or_trace = normalized.contains("debug") || normalized.contains("trace");

    if !has_warn_or_error || has_debug_or_trace {
        eprintln!(
            "OPENSNITCH_PERF_RUST_LOG_LEVEL must be WARN/ERROR-only for harness/perf commands (current={:?})",
            raw
        );
        std::process::exit(2);
    }

    raw
}

fn perf_go_log_level() -> String {
    let raw = env::var("OPENSNITCH_PERF_GO_LOG_LEVEL").unwrap_or_else(|_| "error".to_string());
    let normalized = raw.to_ascii_lowercase();
    if normalized != "err" && normalized != "error" {
        eprintln!(
            "OPENSNITCH_PERF_GO_LOG_LEVEL must be err|error for harness/perf commands (current={:?})",
            raw
        );
        std::process::exit(2);
    }

    raw
}

fn parity_stress_rounds() -> String {
    env::var("OPENSNITCH_PARITY_STRESS_ROUNDS").unwrap_or_else(|_| "4000".to_string())
}

#[derive(Clone, Copy, Debug)]
struct SweepRow {
    timeout_us: u64,
    enqueued_pps: f64,
    enqueue_drop_ratio: f64,
    forced_kernel_abort: bool,
}

#[derive(Clone, Copy, Debug)]
struct PressureRun {
    enqueued_pps: f64,
    enqueue_drop_ratio: f64,
    forced_kernel_abort: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TunableSet {
    max_concurrent_connect_attempts: usize,
    connect_worker_queue_capacity: usize,
    connect_dispatch_batch_size: usize,
    kernel_dns_queue_capacity: usize,
    kernel_process_queue_capacity: usize,
    kernel_firewall_queue_capacity: usize,
}

impl TunableSet {
    fn conservative() -> Self {
        Self {
            max_concurrent_connect_attempts: 32,
            connect_worker_queue_capacity: 64,
            connect_dispatch_batch_size: 64,
            kernel_dns_queue_capacity: 512,
            kernel_process_queue_capacity: 512,
            kernel_firewall_queue_capacity: 128,
        }
    }

    fn max_bounds_for_cores(logical_cores: usize) -> Self {
        // Always leave one logical core for kernel/system work.
        let usable_cores = logical_cores.saturating_sub(1).max(1);
        let connect_workers = (usable_cores.saturating_mul(4)).clamp(32, 256);
        let connect_queue = (usable_cores.saturating_mul(256)).clamp(512, 8192);
        let kernel_queue = (usable_cores.saturating_mul(512)).clamp(512, 16384);

        Self {
            max_concurrent_connect_attempts: connect_workers,
            connect_worker_queue_capacity: connect_queue,
            connect_dispatch_batch_size: 256,
            kernel_dns_queue_capacity: kernel_queue,
            kernel_process_queue_capacity: kernel_queue,
            kernel_firewall_queue_capacity: kernel_queue,
        }
    }

    fn scaled(base: Self, factor: usize, max: Self) -> Self {
        fn mul_clamp(base: usize, factor: usize, max: usize) -> usize {
            base.saturating_mul(factor).clamp(base, max)
        }

        Self {
            max_concurrent_connect_attempts: mul_clamp(
                base.max_concurrent_connect_attempts,
                factor,
                max.max_concurrent_connect_attempts,
            ),
            connect_worker_queue_capacity: mul_clamp(
                base.connect_worker_queue_capacity,
                factor,
                max.connect_worker_queue_capacity,
            ),
            connect_dispatch_batch_size: mul_clamp(
                base.connect_dispatch_batch_size,
                factor,
                max.connect_dispatch_batch_size,
            ),
            kernel_dns_queue_capacity: mul_clamp(
                base.kernel_dns_queue_capacity,
                factor,
                max.kernel_dns_queue_capacity,
            ),
            kernel_process_queue_capacity: mul_clamp(
                base.kernel_process_queue_capacity,
                factor,
                max.kernel_process_queue_capacity,
            ),
            kernel_firewall_queue_capacity: mul_clamp(
                base.kernel_firewall_queue_capacity,
                factor,
                max.kernel_firewall_queue_capacity,
            ),
        }
    }

    fn scaled_ratio(base: Self, factor: f64, max: Self) -> Self {
        fn scale(base: usize, factor: f64) -> usize {
            ((base as f64) * factor).round() as usize
        }

        Self {
            max_concurrent_connect_attempts: scale(base.max_concurrent_connect_attempts, factor)
                .clamp(
                    base.max_concurrent_connect_attempts,
                    max.max_concurrent_connect_attempts,
                ),
            connect_worker_queue_capacity: scale(base.connect_worker_queue_capacity, factor).clamp(
                base.connect_worker_queue_capacity,
                max.connect_worker_queue_capacity,
            ),
            connect_dispatch_batch_size: scale(base.connect_dispatch_batch_size, factor).clamp(
                base.connect_dispatch_batch_size,
                max.connect_dispatch_batch_size,
            ),
            kernel_dns_queue_capacity: scale(base.kernel_dns_queue_capacity, factor).clamp(
                base.kernel_dns_queue_capacity,
                max.kernel_dns_queue_capacity,
            ),
            kernel_process_queue_capacity: scale(base.kernel_process_queue_capacity, factor).clamp(
                base.kernel_process_queue_capacity,
                max.kernel_process_queue_capacity,
            ),
            kernel_firewall_queue_capacity: scale(base.kernel_firewall_queue_capacity, factor)
                .clamp(
                    base.kernel_firewall_queue_capacity,
                    max.kernel_firewall_queue_capacity,
                ),
        }
    }

    fn apply_safety(self, factor: f64, floor: Self) -> Self {
        fn scale(value: usize, factor: f64) -> usize {
            ((value as f64) * factor).round() as usize
        }

        Self {
            max_concurrent_connect_attempts: scale(self.max_concurrent_connect_attempts, factor)
                .max(floor.max_concurrent_connect_attempts),
            connect_worker_queue_capacity: scale(self.connect_worker_queue_capacity, factor)
                .max(floor.connect_worker_queue_capacity),
            connect_dispatch_batch_size: scale(self.connect_dispatch_batch_size, factor)
                .max(floor.connect_dispatch_batch_size),
            kernel_dns_queue_capacity: scale(self.kernel_dns_queue_capacity, factor)
                .max(floor.kernel_dns_queue_capacity),
            kernel_process_queue_capacity: scale(self.kernel_process_queue_capacity, factor)
                .max(floor.kernel_process_queue_capacity),
            kernel_firewall_queue_capacity: scale(self.kernel_firewall_queue_capacity, factor)
                .max(floor.kernel_firewall_queue_capacity),
        }
    }
}

fn auto_tune_kernel_pressure_tunables() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;

    let runs_per_step = env::var("OPENSNITCH_AUTOTUNE_RUNS_PER_STEP")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(3)
        .clamp(2, 3);
    let hysteresis_gain = env::var("OPENSNITCH_AUTOTUNE_HYSTERESIS_GAIN")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.05)
        .clamp(0.0, 0.5);
    let max_drop_ratio = env::var("OPENSNITCH_AUTOTUNE_MAX_DROP_RATIO")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.10)
        .clamp(0.0, 1.0);
    let safety_factor = env::var("OPENSNITCH_AUTOTUNE_SAFETY_FACTOR")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.5)
        .clamp(0.1, 1.0);
    let max_steps = env::var("OPENSNITCH_AUTOTUNE_MAX_STEPS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(6)
        .clamp(1, 8);
    let regression_tolerance = env::var("OPENSNITCH_AUTOTUNE_REGRESSION_TOLERANCE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.03)
        .clamp(0.0, 0.5);
    let regression_drop_delta_max = env::var("OPENSNITCH_AUTOTUNE_REGRESSION_DROP_DELTA_MAX")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.02)
        .clamp(0.0, 1.0);
    let validation_runs = env::var("OPENSNITCH_AUTOTUNE_VALIDATION_RUNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(runs_per_step)
        .clamp(2, 3);
    let sweetspot_factors = parse_factor_list(
        &env::var("OPENSNITCH_AUTOTUNE_SWEETSPOT_FACTORS")
            .unwrap_or_else(|_| "1.10,1.25,1.50,1.75".to_string()),
    );
    let sweetspot_min_uplift = env::var("OPENSNITCH_AUTOTUNE_SWEETSPOT_MIN_UPLIFT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.005)
        .clamp(0.0, 0.5);
    let sweetspot_drop_delta_max = env::var("OPENSNITCH_AUTOTUNE_SWEETSPOT_DROP_DELTA_MAX")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.01)
        .clamp(0.0, 1.0);

    let pressure_secs =
        env::var("OPENSNITCH_AUTOTUNE_PRESSURE_SECS").unwrap_or_else(|_| "1".to_string());
    let pressure_tasks =
        env::var("OPENSNITCH_AUTOTUNE_PRESSURE_TASKS").unwrap_or_else(|_| "2".to_string());
    let enqueue_mode =
        env::var("OPENSNITCH_AUTOTUNE_ENQUEUE_MODE").unwrap_or_else(|_| "timeout".to_string());
    let enqueue_timeout_us =
        env::var("OPENSNITCH_AUTOTUNE_ENQUEUE_TIMEOUT_US").unwrap_or_else(|_| "200".to_string());

    let output_path = env::var("OPENSNITCH_TUNABLES_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| daemon_rs_dir.join("data/tunables.json"));
    let tmp_dir = env::var("OPENSNITCH_AUTOTUNE_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| env::temp_dir());
    let run_parity_gate_after = env_flag("OPENSNITCH_AUTOTUNE_RUN_PARITY_GATE");
    let logical_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let base = TunableSet::conservative();
    let max_bounds = TunableSet::max_bounds_for_cores(logical_cores);
    let mut last_candidate = None;
    let mut last_stable: Option<(TunableSet, f64, f64)> = None;
    let mut stop_reason = "max-steps".to_string();

    println!(
        "Auto-tune start: runs_per_step={} hysteresis_gain={:.3} max_drop_ratio={:.3} safety_factor={:.2} max_steps={} logical_cores={} worker_cap={} connect_queue_cap={} kernel_queue_cap={}",
        runs_per_step,
        hysteresis_gain,
        max_drop_ratio,
        safety_factor,
        max_steps,
        logical_cores,
        max_bounds.max_concurrent_connect_attempts,
        max_bounds.connect_worker_queue_capacity,
        max_bounds.kernel_dns_queue_capacity,
    );

    for step in 0..max_steps {
        let factor = 1usize << step;
        let candidate = TunableSet::scaled(base, factor, max_bounds);
        if last_candidate.is_some_and(|prev| prev == candidate) {
            stop_reason = "reached-bounds".to_string();
            break;
        }
        last_candidate = Some(candidate);

        let (median_enqueued_pps, median_drop_ratio, any_abort) = benchmark_tunable_set(
            repo_root,
            daemon_rs_dir,
            &tmp_dir,
            candidate,
            runs_per_step,
            pressure_secs.as_str(),
            pressure_tasks.as_str(),
            enqueue_mode.as_str(),
            enqueue_timeout_us.as_str(),
            format!("step-{step}"),
        )?;
        let is_stable = !any_abort && median_drop_ratio <= max_drop_ratio;

        let gain_vs_prev = if let Some((_, prev_pps, _)) = last_stable {
            if prev_pps > 0.0 {
                (median_enqueued_pps - prev_pps) / prev_pps
            } else {
                1.0
            }
        } else {
            1.0
        };

        println!(
            "autotune-step={} factor={} stable={} median_enqueued_pps={:.0} median_drop_ratio={:.4} any_abort={} gain_vs_prev={:.4}",
            step,
            factor,
            is_stable,
            median_enqueued_pps,
            median_drop_ratio,
            any_abort,
            gain_vs_prev,
        );

        if !is_stable {
            stop_reason = "instability-or-drops".to_string();
            break;
        }

        if last_stable.is_some() && gain_vs_prev < hysteresis_gain {
            stop_reason = "hysteresis-no-significant-gain".to_string();
            break;
        }

        last_stable = Some((candidate, median_enqueued_pps, median_drop_ratio));
    }

    let (max_stable, stable_pps, stable_drop_ratio) = last_stable.unwrap_or((base, 0.0, 1.0));
    let mut final_tunables = max_stable.apply_safety(safety_factor, base);

    let (baseline_pps, baseline_drop, baseline_abort) = benchmark_tunable_set(
        repo_root,
        daemon_rs_dir,
        &tmp_dir,
        base,
        validation_runs,
        pressure_secs.as_str(),
        pressure_tasks.as_str(),
        enqueue_mode.as_str(),
        enqueue_timeout_us.as_str(),
        "validation-baseline".to_string(),
    )?;
    let (selected_pps, selected_drop, selected_abort) = benchmark_tunable_set(
        repo_root,
        daemon_rs_dir,
        &tmp_dir,
        final_tunables,
        validation_runs,
        pressure_secs.as_str(),
        pressure_tasks.as_str(),
        enqueue_mode.as_str(),
        enqueue_timeout_us.as_str(),
        "validation-selected".to_string(),
    )?;

    let regression = selected_abort
        || (baseline_pps > 0.0 && selected_pps < baseline_pps * (1.0 - regression_tolerance))
        || (selected_drop > baseline_drop + regression_drop_delta_max);
    if regression {
        if let Some((sweet_tunables, sweet_pps, sweet_drop)) = find_sweetspot_candidate(
            repo_root,
            daemon_rs_dir,
            &tmp_dir,
            base,
            max_bounds,
            &sweetspot_factors,
            validation_runs,
            pressure_secs.as_str(),
            pressure_tasks.as_str(),
            enqueue_mode.as_str(),
            enqueue_timeout_us.as_str(),
            baseline_pps,
            baseline_drop,
            sweetspot_min_uplift,
            sweetspot_drop_delta_max,
        )? {
            final_tunables = sweet_tunables;
            stop_reason.push_str("+sweetspot-recover");
            println!(
                "autotune-sweetspot selected median_enqueued_pps={:.0} median_drop_ratio={:.4}",
                sweet_pps, sweet_drop
            );
        } else {
            final_tunables = base;
            stop_reason.push_str("+regression-fallback");
        }
    }

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let metadata = format!(
        "autotune stop_reason={} safety_factor={:.2} stable_enqueued_pps={:.0} stable_drop_ratio={:.4} validation_baseline_pps={:.0} validation_baseline_drop_ratio={:.4} validation_baseline_abort={} validation_selected_pps={:.0} validation_selected_drop_ratio={:.4} validation_selected_abort={} regression_tolerance={:.4} regression_drop_delta_max={:.4}",
        stop_reason,
        safety_factor,
        stable_pps,
        stable_drop_ratio,
        baseline_pps,
        baseline_drop,
        baseline_abort,
        selected_pps,
        selected_drop,
        selected_abort,
        regression_tolerance,
        regression_drop_delta_max,
    );
    fs::write(
        &output_path,
        tunables_profile_json("auto-tuned", final_tunables, &metadata),
    )?;

    println!(
        "Auto-tune wrote {} with stop_reason={} final(max_concurrent_connect_attempts={}, connect_worker_queue_capacity={}, connect_dispatch_batch_size={}, kernel_dns_queue_capacity={}, kernel_process_queue_capacity={}, kernel_firewall_queue_capacity={})",
        output_path.display(),
        stop_reason,
        final_tunables.max_concurrent_connect_attempts,
        final_tunables.connect_worker_queue_capacity,
        final_tunables.connect_dispatch_batch_size,
        final_tunables.kernel_dns_queue_capacity,
        final_tunables.kernel_process_queue_capacity,
        final_tunables.kernel_firewall_queue_capacity,
    );

    if run_parity_gate_after {
        run_parity_gate_internal(repo_root)?;
    }

    Ok(())
}

fn find_sweetspot_candidate(
    repo_root: &Path,
    daemon_rs_dir: &Path,
    tmp_dir: &Path,
    base: TunableSet,
    max_bounds: TunableSet,
    factors: &[f64],
    runs: usize,
    pressure_secs: &str,
    pressure_tasks: &str,
    enqueue_mode: &str,
    enqueue_timeout_us: &str,
    baseline_pps: f64,
    baseline_drop: f64,
    min_uplift: f64,
    drop_delta_max: f64,
) -> Result<Option<(TunableSet, f64, f64)>, DynError> {
    let mut best: Option<(TunableSet, f64, f64)> = None;

    for factor in factors {
        let candidate = TunableSet::scaled_ratio(base, *factor, max_bounds);
        let (median_pps, median_drop, any_abort) = benchmark_tunable_set(
            repo_root,
            daemon_rs_dir,
            tmp_dir,
            candidate,
            runs,
            pressure_secs,
            pressure_tasks,
            enqueue_mode,
            enqueue_timeout_us,
            format!("sweetspot-{:.2}", factor),
        )?;

        let uplift_ok = if baseline_pps > 0.0 {
            median_pps >= baseline_pps * (1.0 + min_uplift)
        } else {
            median_pps > 0.0
        };
        let drop_ok = median_drop <= baseline_drop + drop_delta_max;
        let stable = !any_abort;

        println!(
            "autotune-sweetspot factor={:.2} stable={} median_enqueued_pps={:.0} median_drop_ratio={:.4} uplift_ok={} drop_ok={}",
            factor, stable, median_pps, median_drop, uplift_ok, drop_ok,
        );

        if stable && uplift_ok && drop_ok {
            let replace = if let Some((_, best_pps, best_drop)) = best {
                median_pps > best_pps
                    || ((median_pps - best_pps).abs() < f64::EPSILON && median_drop < best_drop)
            } else {
                true
            };
            if replace {
                best = Some((candidate, median_pps, median_drop));
            }
        }
    }

    Ok(best)
}

fn parse_factor_list(raw: &str) -> Vec<f64> {
    let mut factors = raw
        .split(',')
        .filter_map(|token| token.trim().parse::<f64>().ok())
        .filter(|value| *value > 1.0)
        .collect::<Vec<_>>();
    factors.sort_by(|a, b| a.total_cmp(b));
    factors.dedup_by(|a, b| (*a - *b).abs() < f64::EPSILON);
    if factors.is_empty() {
        factors.extend([1.10, 1.25, 1.50, 1.75]);
    }
    factors
}

fn benchmark_tunable_set(
    repo_root: &Path,
    daemon_rs_dir: &Path,
    tmp_dir: &Path,
    tunables: TunableSet,
    runs: usize,
    pressure_secs: &str,
    pressure_tasks: &str,
    enqueue_mode: &str,
    enqueue_timeout_us: &str,
    run_tag: String,
) -> Result<(f64, f64, bool), DynError> {
    let mut run_results = Vec::with_capacity(runs);
    for run_idx in 0..runs {
        let tmp_tunables = tmp_dir.join(format!(
            "opensnitch-autotune-{}-{}-{}.json",
            std::process::id(),
            run_tag,
            run_idx
        ));
        fs::write(
            &tmp_tunables,
            tunables_profile_json("candidate", tunables, &run_tag),
        )?;

        let output = run_command(
            repo_root,
            "cargo",
            [
                "test",
                "--release",
                "--manifest-path",
                daemon_rs_dir.join("Cargo.toml").to_string_lossy().as_ref(),
                "-p",
                "opensnitchd-rs",
                "stress_profile_reports_kernel_pipeline_pressure",
                "--",
                "--ignored",
                "--nocapture",
            ],
            &[
                ("RUST_LOG", "error"),
                (
                    "OPENSNITCH_TUNABLES_FILE",
                    tmp_tunables.to_string_lossy().as_ref(),
                ),
                ("OPENSNITCH_KERNEL_PRESSURE_SECS", pressure_secs),
                ("OPENSNITCH_KERNEL_PRESSURE_TASKS", pressure_tasks),
                ("OPENSNITCH_KERNEL_PRESSURE_ENQUEUE_MODE", enqueue_mode),
                (
                    "OPENSNITCH_KERNEL_PRESSURE_ENQUEUE_TIMEOUT_US",
                    enqueue_timeout_us,
                ),
            ],
        );
        let _ = fs::remove_file(&tmp_tunables);

        let output = output?;
        let line = find_line(&output, "kernel-pressure mode=")?;
        run_results.push(parse_pressure_run(line)?);
    }

    let median_enqueued_pps = median_f64(
        run_results
            .iter()
            .map(|run| run.enqueued_pps)
            .collect::<Vec<_>>(),
    );
    let median_drop_ratio = median_f64(
        run_results
            .iter()
            .map(|run| run.enqueue_drop_ratio)
            .collect::<Vec<_>>(),
    );
    let any_abort = run_results.iter().any(|run| run.forced_kernel_abort);
    Ok((median_enqueued_pps, median_drop_ratio, any_abort))
}

fn parse_pressure_run(line: &str) -> Result<PressureRun, DynError> {
    Ok(PressureRun {
        enqueued_pps: parse_metric(line, "enqueued_pps")?,
        enqueue_drop_ratio: parse_metric(line, "enqueue_drop_ratio")?,
        forced_kernel_abort: parse_named_bool(line, "forced_kernel_abort")?,
    })
}

fn parse_named_bool(line: &str, key: &str) -> Result<bool, DynError> {
    let prefix = format!("{key}=");
    let value = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
        .ok_or_else(|| format!("missing key {key} in line: {line}"))?;
    Ok(value.parse::<bool>()?)
}

fn median_f64(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.total_cmp(b));
    let len = values.len();
    if len % 2 == 1 {
        values[len / 2]
    } else {
        (values[len / 2 - 1] + values[len / 2]) / 2.0
    }
}

fn tunables_profile_json(profile: &str, tunables: TunableSet, note: &str) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"profile\": \"{}\",\n",
            "  \"max_concurrent_connect_attempts\": {},\n",
            "  \"connect_worker_queue_capacity\": {},\n",
            "  \"connect_dispatch_batch_size\": {},\n",
            "  \"kernel_dns_queue_capacity\": {},\n",
            "  \"kernel_process_queue_capacity\": {},\n",
            "  \"kernel_firewall_queue_capacity\": {},\n",
            "  \"generated_by\": \"cargo run -p tools -- auto-tune-kernel-pressure-tunables\",\n",
            "  \"note\": \"{}\"\n",
            "}}\n"
        ),
        profile,
        tunables.max_concurrent_connect_attempts,
        tunables.connect_worker_queue_capacity,
        tunables.connect_dispatch_batch_size,
        tunables.kernel_dns_queue_capacity,
        tunables.kernel_process_queue_capacity,
        tunables.kernel_firewall_queue_capacity,
        note,
    )
}

fn quick_pressure_sweep_tunables() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;

    let sweep_secs = env::var("OPENSNITCH_TUNABLES_SWEEP_SECS").unwrap_or_else(|_| "1".to_string());
    let sweep_tasks =
        env::var("OPENSNITCH_TUNABLES_SWEEP_TASKS").unwrap_or_else(|_| "2".to_string());
    let sweep_us = env::var("OPENSNITCH_TUNABLES_SWEEP_US")
        .unwrap_or_else(|_| "50,100,200,500,1000".to_string());
    let drop_ratio_max = env::var("OPENSNITCH_TUNABLES_DROP_RATIO_MAX")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.10);
    let min_enqueued_pps = env::var("OPENSNITCH_TUNABLES_MIN_ENQUEUED_PPS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(10_000.0);

    let output_path = env::var("OPENSNITCH_TUNABLES_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| daemon_rs_dir.join("data/tunables.json"));

    println!(
        "Running quick kernel-pressure sweep (secs={}, tasks={}, us={})...",
        sweep_secs, sweep_tasks, sweep_us
    );
    let sweep_output = run_command(
        repo_root,
        "cargo",
        [
            "test",
            "--release",
            "--manifest-path",
            daemon_rs_dir.join("Cargo.toml").to_string_lossy().as_ref(),
            "-p",
            "opensnitchd-rs",
            "stress_profile_reports_kernel_pipeline_timeout_sweep",
            "--",
            "--ignored",
            "--nocapture",
        ],
        &[
            ("RUST_LOG", "error"),
            ("OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS", sweep_secs.as_str()),
            (
                "OPENSNITCH_KERNEL_PRESSURE_SWEEP_TASKS",
                sweep_tasks.as_str(),
            ),
            ("OPENSNITCH_KERNEL_PRESSURE_SWEEP_US", sweep_us.as_str()),
        ],
    )?;

    let rows = parse_sweep_rows(&sweep_output)?;
    let recommended_timeout = parse_recommended_timeout(&sweep_output).ok();
    let selected_row = if let Some(timeout_us) = recommended_timeout {
        rows.iter()
            .find(|row| row.timeout_us == timeout_us)
            .copied()
            .unwrap_or_else(|| choose_best_sweep_row(&rows))
    } else {
        choose_best_sweep_row(&rows)
    };

    let use_high_profile = !selected_row.forced_kernel_abort
        && selected_row.enqueue_drop_ratio <= drop_ratio_max
        && selected_row.enqueued_pps >= min_enqueued_pps;
    let selected_profile = if use_high_profile {
        "high-throughput"
    } else {
        "conservative"
    };

    let (
        max_concurrent_connect_attempts,
        connect_worker_queue_capacity,
        connect_dispatch_batch_size,
        kernel_dns_queue_capacity,
        kernel_process_queue_capacity,
        kernel_firewall_queue_capacity,
    ) = if use_high_profile {
        (64, 128, 16, 2048, 2048, 512)
    } else {
        (32, 64, 64, 512, 512, 128)
    };

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = format!(
        concat!(
            "{{\n",
            "  \"profile\": \"{}\",\n",
            "  \"max_concurrent_connect_attempts\": {},\n",
            "  \"connect_worker_queue_capacity\": {},\n",
            "  \"connect_dispatch_batch_size\": {},\n",
            "  \"kernel_dns_queue_capacity\": {},\n",
            "  \"kernel_process_queue_capacity\": {},\n",
            "  \"kernel_firewall_queue_capacity\": {},\n",
            "  \"generated_by\": \"cargo run -p tools -- quick-pressure-sweep-tunables\",\n",
            "  \"sweep\": {{\n",
            "    \"recommended_timeout_us\": {},\n",
            "    \"enqueued_pps\": {:.0},\n",
            "    \"enqueue_drop_ratio\": {:.4},\n",
            "    \"forced_kernel_abort\": {},\n",
            "    \"decision_thresholds\": {{\n",
            "      \"max_drop_ratio\": {:.4},\n",
            "      \"min_enqueued_pps\": {:.0}\n",
            "    }}\n",
            "  }}\n",
            "}}\n"
        ),
        selected_profile,
        max_concurrent_connect_attempts,
        connect_worker_queue_capacity,
        connect_dispatch_batch_size,
        kernel_dns_queue_capacity,
        kernel_process_queue_capacity,
        kernel_firewall_queue_capacity,
        selected_row.timeout_us,
        selected_row.enqueued_pps,
        selected_row.enqueue_drop_ratio,
        selected_row.forced_kernel_abort,
        drop_ratio_max,
        min_enqueued_pps,
    );
    fs::write(&output_path, json)?;

    println!(
        "Wrote tunables profile '{}' to {} (timeout_us={}, enqueued_pps={:.0}, drop_ratio={:.4}, forced_abort={})",
        selected_profile,
        output_path.display(),
        selected_row.timeout_us,
        selected_row.enqueued_pps,
        selected_row.enqueue_drop_ratio,
        selected_row.forced_kernel_abort,
    );
    Ok(())
}

fn parse_sweep_rows(output: &str) -> Result<Vec<SweepRow>, DynError> {
    let mut rows = Vec::new();
    for line in output.lines() {
        if !line.starts_with("kernel-pressure-sweep-csv,") {
            continue;
        }

        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() != 16 {
            return Err(format!("unexpected sweep csv format: {line}").into());
        }

        rows.push(SweepRow {
            timeout_us: cols[1].parse::<u64>()?,
            forced_kernel_abort: cols[8].parse::<bool>()?,
            enqueued_pps: cols[10].parse::<f64>()?,
            enqueue_drop_ratio: cols[11].parse::<f64>()?,
        });
    }

    if rows.is_empty() {
        return Err("no kernel-pressure-sweep-csv rows found in benchmark output".into());
    }

    Ok(rows)
}

fn parse_recommended_timeout(output: &str) -> Result<u64, DynError> {
    let line = find_line(output, "kernel-pressure-sweep-recommend")?;
    parse_named_u64(line, "timeout_us")
}

fn parse_named_u64(line: &str, key: &str) -> Result<u64, DynError> {
    let prefix = format!("{key}=");
    let value = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
        .ok_or_else(|| format!("missing key {key} in line: {line}"))?;
    Ok(value.parse::<u64>()?)
}

fn choose_best_sweep_row(rows: &[SweepRow]) -> SweepRow {
    let has_non_abort = rows.iter().any(|row| !row.forced_kernel_abort);
    let mut best = rows[0];
    let mut best_score = f64::NEG_INFINITY;

    for row in rows {
        if has_non_abort && row.forced_kernel_abort {
            continue;
        }
        let score = row.enqueued_pps * (1.0 - row.enqueue_drop_ratio);
        let replace = if score > best_score {
            true
        } else if (score - best_score).abs() < f64::EPSILON {
            row.enqueue_drop_ratio < best.enqueue_drop_ratio
                || ((row.enqueue_drop_ratio - best.enqueue_drop_ratio).abs() < f64::EPSILON
                    && row.timeout_us < best.timeout_us)
        } else {
            false
        };

        if replace {
            best = *row;
            best_score = score;
        }
    }

    best
}

fn microbench_connect_dispatch() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;
    let rounds = env::var("OPENSNITCH_MICROBENCH_ROUNDS").unwrap_or_else(|_| "4000".to_string());
    let rust_log = perf_rust_log_level();

    let output = run_command(
        repo_root,
        "cargo",
        [
            "test",
            "--release",
            "--manifest-path",
            daemon_rs_dir.join("Cargo.toml").to_string_lossy().as_ref(),
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
    let line = find_line(&output, "stress-profile rounds=")?;
    println!("microbench-connect-dispatch {line}");
    Ok(())
}

fn run_parity_gate_command() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;
    run_parity_gate_internal(repo_root)
}

fn run_parity_gate_internal(repo_root: &Path) -> Result<(), DynError> {
    let rounds = parity_stress_rounds();
    let require_exceed = env_flag("OPENSNITCH_PARITY_REQUIRE_EXCEED_GO");
    let rust_log = perf_rust_log_level();
    let go_log = perf_go_log_level();

    println!("Running parity gate with STRESS_ROUNDS={rounds}...");
    let output = run_command(
        repo_root,
        "make",
        ["parity-hot-cold-delta", &format!("STRESS_ROUNDS={rounds}")],
        &[
            ("PERF_RUST_LOG_LEVEL", rust_log.as_str()),
            ("HARNESS_GO_LOG_LEVEL", go_log.as_str()),
        ],
    )?;

    let status_line = find_line(&output, "PARITY DELTA STATUS:")?;
    let hot_line = find_line(&output, "PARITY DELTA HOT:")?;
    if !status_line.contains("PASS") {
        return Err(format!("parity gate failed: {status_line}").into());
    }

    let hot_p95 = parse_metric(hot_line, "p95")?;
    let hot_p99 = parse_metric(hot_line, "p99")?;
    if require_exceed && (hot_p95 > 0.0 || hot_p99 > 0.0) {
        return Err(format!(
            "parity gate exceed-go check failed: p95={hot_p95:+.3} p99={hot_p99:+.3}"
        )
        .into());
    }

    println!(
        "parity-gate status={} hot_p95={:+.3} hot_p99={:+.3}",
        status_line, hot_p95, hot_p99
    );
    Ok(())
}

fn launch_daemon_live_logs() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;

    let logs_dir = env::var("OPENSNITCH_DAEMON_RS_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join("logs"));
    fs::create_dir_all(&logs_dir)?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock error: {err}"))?
        .as_secs();
    let stem = format!("daemon-rs-live-{ts}");
    let stdout_path = logs_dir.join(format!("{stem}.stdout.log"));
    let stderr_path = logs_dir.join(format!("{stem}.stderr.log"));
    let latest_path = logs_dir.join("daemon-rs-live.latest");
    let rust_log = env::var("OPENSNITCH_DAEMON_RS_RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let run_release = !env_flag("OPENSNITCH_DAEMON_RS_LIVE_DEBUG");
    let manifest_path = daemon_rs_dir.join("Cargo.toml");

    run_command(repo_root, "sudo", ["-n", "true"], &[])?;

    let stdout_file = fs::File::create(&stdout_path)?;
    let stderr_file = fs::File::create(&stderr_path)?;

    let mut command = Command::new("sudo");
    command
        .arg("-n")
        .arg("env")
        .arg(format!("RUST_LOG={rust_log}"))
        .arg("cargo")
        .arg("run");

    if run_release {
        command.arg("--release");
    }

    command
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("-p")
        .arg("opensnitchd-rs")
        .current_dir(repo_root)
        .stdout(stdout_file)
        .stderr(stderr_file);

    let child = command.spawn()?;
    let pid = child.id();

    let mode = if run_release { "release" } else { "debug" };
    let latest_content = format!(
        "pid={pid}\nmode={mode}\nrust_log={rust_log}\nstdout={}\nstderr={}\n",
        stdout_path.display(),
        stderr_path.display(),
    );
    fs::write(&latest_path, latest_content)?;

    println!("daemon-rs live log session launched pid={pid} mode={mode}");
    println!("stdout={}", stdout_path.display());
    println!("stderr={}", stderr_path.display());
    println!("latest={}", latest_path.display());
    println!("tail: tail -f {}", stdout_path.display(),);
    println!("stop: sudo kill {pid}");

    Ok(())
}

fn stop_daemon_live_logs() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;

    let logs_dir = env::var("OPENSNITCH_DAEMON_RS_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join("logs"));
    let latest_path = logs_dir.join("daemon-rs-live.latest");

    if !latest_path.exists() {
        println!(
            "no live session metadata found at {}",
            latest_path.display()
        );
        return Ok(());
    }

    let latest_content = fs::read_to_string(&latest_path)?;
    let Some(pid_line) = latest_content
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
    else {
        fs::remove_file(&latest_path)?;
        println!(
            "stale metadata without pid removed at {}",
            latest_path.display()
        );
        return Ok(());
    };
    let pid_str = pid_line.trim().to_string();

    let _pid: u32 = pid_str.parse().map_err(|err| {
        format!(
            "invalid pid '{pid_str}' in {}: {err}",
            latest_path.display()
        )
    })?;

    run_command(repo_root, "sudo", ["-n", "true"], &[])?;

    match run_command(
        repo_root,
        "sudo",
        ["-n", "kill", "-0", pid_str.as_str()],
        &[],
    ) {
        Ok(_) => {
            run_command(repo_root, "sudo", ["-n", "kill", pid_str.as_str()], &[])?;
            println!("stopped daemon-rs live session pid={pid_str}");
        }
        Err(err) => {
            let text = err.to_string();
            if text.contains("No such process") {
                println!("daemon-rs live session pid={pid_str} was already stopped");
            } else {
                return Err(err);
            }
        }
    }

    fs::remove_file(&latest_path)?;
    println!("removed metadata file {}", latest_path.display());

    Ok(())
}

fn update_perf_md() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir
        .parent()
        .ok_or("daemon-rs dir missing parent")?;
    let perf_md = env::var("PERF_MD_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| daemon_rs_dir.join("PERF.md"));
    let stress_rounds = env::var("STRESS_ROUNDS").unwrap_or_else(|_| "4000".to_string());
    let parity_rounds = parity_stress_rounds();
    let rust_log = perf_rust_log_level();
    let go_log = perf_go_log_level();
    let run_date = run_git(daemon_rs_dir, ["log", "-1", "--date=short", "--pretty=%ad"]);
    let current_commit = run_git(daemon_rs_dir, ["rev-parse", "--short", "HEAD"]);
    let current_subject = run_git(daemon_rs_dir, ["log", "-1", "--pretty=%s"]);
    let prev_commit = run_git(daemon_rs_dir, ["rev-parse", "--short", "HEAD^"]);
    let prev_commit_full = run_git(daemon_rs_dir, ["rev-parse", "HEAD^"]);
    let prev_subject = run_git(daemon_rs_dir, ["log", "-1", "--pretty=%s", "HEAD^"]);
    let cache_root = cache_root(repo_root);
    let refresh_prev_base = env_flag("OPENSNITCH_PERF_REFRESH_BASE");
    let workspace_state = if run_git(repo_root, ["status", "--short"]).is_empty() {
        "clean"
    } else {
        "dirty"
    };

    println!("Running current Rust release stress profile...");
    let current_rust_output = run_command(
        repo_root,
        "cargo",
        [
            "test",
            "--manifest-path",
            daemon_rs_dir.join("Cargo.toml").to_string_lossy().as_ref(),
            "--release",
            "-p",
            "opensnitchd-rs",
            "stress_profile_reports_connect_latency_and_pipeline_drops",
            "--",
            "--ignored",
            "--nocapture",
        ],
        &[
            ("RUST_LOG", rust_log.as_str()),
            ("OPENSNITCH_STRESS_ROUNDS", stress_rounds.as_str()),
        ],
    )?;
    let current_rust_line = find_line(&current_rust_output, "stress-profile rounds=")?;

    println!("Running current Go stress profile...");
    let current_go_output = run_command(
        &repo_root.join("daemon"),
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
            ("OPENSNITCH_STRESS_ROUNDS", stress_rounds.as_str()),
        ],
    )?;
    let current_go_line = find_line(&current_go_output, "stress-profile backend=go")?;

    let prev_rust_line = cached_or_run_prev_rust_profile(
        repo_root,
        &cache_root,
        &prev_commit,
        &prev_commit_full,
        &stress_rounds,
        refresh_prev_base,
    )?;

    let current_rust = Metrics::parse(current_rust_line)?;
    let current_go = Metrics::parse(current_go_line)?;
    let prev_rust = Metrics::parse(&prev_rust_line)?;

    let row_rust = format!(
        "| {run_date} | Rust | release (ThinLTO) | {stress_rounds} | `{current_commit}` | {current_rust} | pass | Go default same run | {vs_go} | `{prev_commit}` | {vs_prev} | Auto-updated current reference Rust run ({current_subject}); workspace {workspace_state}. |",
        current_rust = current_rust.format_values(),
        vs_go = current_rust.delta_string(&current_go),
        vs_prev = current_rust.delta_string(&prev_rust),
    );
    let row_go = format!(
        "| {run_date} | Go | default | {stress_rounds} | `{current_commit}` | {current_go} | pass | {empty} | Auto-updated current Go comparison row paired with Rust actual. |",
        current_go = current_go.format_values(),
        empty = EMPTY_COMPARISON_COLUMNS,
    );
    let row_prev = format!(
        "| {run_date} | Rust | release (ThinLTO) | {stress_rounds} | `{prev_commit}` | {prev_rust} | pass | {empty} | Auto-updated previous commit benchmark ({prev_subject}) using cached previous-commit worktree/results when available. |",
        prev_rust = prev_rust.format_values(),
        empty = EMPTY_COMPARISON_COLUMNS,
    );

    prepend_rows(&perf_md, TABLE_HEADER, &[row_rust, row_go, row_prev])?;

    println!("Running parity hot/cold delta harness...");
    let parity_output =
        with_fixture_backup(repo_root, "daemon/ui/testdata/default-config.json", || {
            run_command(
                repo_root,
                "make",
                [
                    "parity-hot-cold-delta",
                    &format!("STRESS_ROUNDS={parity_rounds}"),
                ],
                &[
                    ("PERF_RUST_LOG_LEVEL", rust_log.as_str()),
                    ("HARNESS_GO_LOG_LEVEL", go_log.as_str()),
                ],
            )
        })?;

    let hot_line = find_line(&parity_output, "PARITY DELTA HOT:")?;
    let cold_line = find_line(&parity_output, "PARITY DELTA COLD:")?;
    let status_line = find_line(&parity_output, "PARITY DELTA STATUS:")?;

    let hot_p50 = parse_metric(hot_line, "p50")?;
    let hot_p95 = parse_metric(hot_line, "p95")?;
    let hot_p99 = parse_metric(hot_line, "p99")?;
    let hot_max = parse_metric(hot_line, "max")?;
    let hot_drop_total = parse_metric(hot_line, "drop_total")?;
    let cold_go = parse_metric(cold_line, "go_total_s")?;
    let cold_rust = parse_metric(cold_line, "rust_total_s")?;
    let cold_delta = parse_metric(cold_line, "delta_s")?;
    let status = status_line
        .split(':')
        .nth(1)
        .map(str::trim)
        .unwrap_or("PASS");

    let delta_row = format!(
        "| {run_date} | `make parity-hot-cold-delta` | {parity_rounds} | `{current_commit}` | {hot_p50:+.3} | {hot_p95:+.3} | {hot_p99:+.3} | {hot_max:+.3} | {hot_drop:+.0} | {cold_go:.3} | {cold_rust:.3} | {cold_delta:+.3} | {status} | Auto-updated parity hot/cold delta row from tools command. |",
        hot_drop = hot_drop_total,
    );

    prepend_rows(&perf_md, DELTA_TABLE_HEADER, &[delta_row])?;

    println!("Updated {}", perf_md.display());
    println!("Current Rust: {current_rust_line}");
    println!("Current Go:   {current_go_line}");
    println!("Prev Rust:    {prev_rust_line}");
    println!("Prev cache:   {}", cache_root.display());

    Ok(())
}

fn with_fixture_backup<T, F>(repo_root: &Path, relative_path: &str, work: F) -> Result<T, DynError>
where
    F: FnOnce() -> Result<T, DynError>,
{
    let fixture_path = repo_root.join(relative_path);
    let fixture_name = fixture_path
        .file_name()
        .ok_or("fixture path missing filename")?
        .to_string_lossy()
        .into_owned();
    let backup_path =
        fixture_path.with_file_name(format!("{fixture_name}.backup.{}", std::process::id()));

    fs::copy(&fixture_path, &backup_path)?;

    let result = work();
    let restore_result = fs::copy(&backup_path, &fixture_path).map(|_| ());
    let cleanup_result = fs::remove_file(&backup_path);

    match (result, restore_result, cleanup_result) {
        (Ok(value), Ok(()), Ok(())) => Ok(value),
        (Err(err), _, _) => Err(err),
        (Ok(_), Err(err), _) => Err(err.into()),
        (Ok(_), Ok(()), Err(err)) => Err(err.into()),
    }
}

fn cached_or_run_prev_rust_profile(
    repo_root: &Path,
    cache_root: &Path,
    prev_commit: &str,
    prev_commit_full: &str,
    stress_rounds: &str,
    refresh_prev_base: bool,
) -> Result<String, DynError> {
    let rust_log = perf_rust_log_level();
    fs::create_dir_all(cache_root)?;
    let cached_result_path = cache_root.join(format!(
        "prev-rust-release-{prev_commit}-rounds-{stress_rounds}.txt"
    ));

    if !refresh_prev_base && cached_result_path.is_file() {
        let cached_line = fs::read_to_string(&cached_result_path)?.trim().to_string();
        if cached_line.contains("stress-profile rounds=") {
            println!(
                "Reusing cached previous-commit Rust profile from {}",
                cached_result_path.display()
            );
            return Ok(cached_line);
        }
    }

    let worktree_path = cache_root.join("prev-worktree");
    ensure_cached_worktree(repo_root, &worktree_path, prev_commit_full)?;

    println!("Running previous-commit Rust release stress profile...");
    let prev_rust_output = run_command(
        repo_root,
        "cargo",
        [
            "test",
            "--manifest-path",
            worktree_path
                .join("daemon-rs/Cargo.toml")
                .to_string_lossy()
                .as_ref(),
            "--release",
            "-p",
            "opensnitchd-rs",
            "stress_profile_reports_connect_latency_and_pipeline_drops",
            "--",
            "--ignored",
            "--nocapture",
        ],
        &[
            ("RUST_LOG", rust_log.as_str()),
            ("OPENSNITCH_STRESS_ROUNDS", stress_rounds),
        ],
    )?;
    let prev_rust_line = find_line(&prev_rust_output, "stress-profile rounds=")?.to_string();
    fs::write(&cached_result_path, format!("{prev_rust_line}\n"))?;
    Ok(prev_rust_line)
}

fn ensure_cached_worktree(
    repo_root: &Path,
    worktree_path: &Path,
    expected_commit: &str,
) -> Result<(), DynError> {
    if worktree_path.exists() {
        let current_head = run_command(worktree_path, "git", ["rev-parse", "HEAD"], &[])
            .ok()
            .map(|value| value.trim().to_string());
        if current_head.as_deref() == Some(expected_commit) {
            return Ok(());
        }

        let _ = run_command(
            repo_root,
            "git",
            [
                "worktree",
                "remove",
                worktree_path.to_string_lossy().as_ref(),
                "--force",
            ],
            &[],
        );
        if worktree_path.exists() {
            fs::remove_dir_all(worktree_path)?;
        }
    }

    run_command(
        repo_root,
        "git",
        [
            "worktree",
            "add",
            "--detach",
            worktree_path.to_string_lossy().as_ref(),
            expected_commit,
        ],
        &[],
    )?;
    Ok(())
}

fn prepend_rows(perf_md: &Path, header: &str, rows: &[String]) -> Result<(), DynError> {
    let text = fs::read_to_string(perf_md)?;
    let header_idx = text
        .find(header)
        .ok_or_else(|| format!("table header not found in PERF.md: {header}"))?;
    let first_newline = text[header_idx..]
        .find('\n')
        .ok_or("run history header line not terminated")?
        + header_idx;
    let second_newline = text[first_newline + 1..]
        .find('\n')
        .ok_or("run history divider row not found")?
        + first_newline
        + 1;
    let insert_at = second_newline + 1;
    let mut updated = String::with_capacity(text.len() + rows.len() * 256);
    updated.push_str(&text[..insert_at]);
    for row in rows {
        updated.push_str(row);
        updated.push('\n');
    }
    updated.push_str(&text[insert_at..]);
    fs::write(perf_md, updated)?;
    Ok(())
}

fn run_git<const N: usize>(cwd: &Path, args: [&str; N]) -> String {
    run_command(cwd, "git", args, &[])
        .expect("git command failed")
        .trim()
        .to_string()
}

fn run_command<const N: usize>(
    cwd: &Path,
    program: &str,
    args: [&str; N],
    envs: &[(&str, &str)],
) -> Result<String, DynError> {
    let mut command = Command::new(program);
    command.current_dir(cwd).args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(format!(
            "command failed: {} {}\nstdout:\n{}\nstderr:\n{}",
            program,
            args.join(" "),
            stdout,
            stderr
        )
        .into())
    }
}

fn find_line<'a>(text: &'a str, needle: &str) -> Result<&'a str, DynError> {
    text.lines()
        .find(|line| line.contains(needle))
        .ok_or_else(|| format!("expected output line containing: {needle}").into())
}

fn cache_root(repo_root: &Path) -> PathBuf {
    if let Ok(value) = env::var("OPENSNITCH_PERF_CACHE_DIR") {
        return PathBuf::from(value);
    }

    let mut hasher = DefaultHasher::new();
    repo_root.to_string_lossy().hash(&mut hasher);
    let repo_hash = hasher.finish();
    env::temp_dir().join(format!("opensnitch-perf-cache-{repo_hash:016x}"))
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

#[derive(Clone, Copy)]
struct Metrics {
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
    drop_total: f64,
}

impl Metrics {
    fn parse(line: &str) -> Result<Self, DynError> {
        Ok(Self {
            p50: parse_metric(line, "p50_ms")?,
            p95: parse_metric(line, "p95_ms")?,
            p99: parse_metric(line, "p99_ms")?,
            max: parse_metric(line, "max_ms")?,
            drop_total: parse_metric(line, "drop_total")?,
        })
    }

    fn format_values(self) -> String {
        format!(
            "{:.3} | {:.3} | {:.3} | {:.3} | {:.0}",
            self.p50, self.p95, self.p99, self.max, self.drop_total
        )
    }

    fn delta_string(self, base: &Self) -> String {
        format!(
            "{:+.3} | {:+.3} | {:+.3} | {:+.3} | {:+.0}",
            self.p50 - base.p50,
            self.p95 - base.p95,
            self.p99 - base.p99,
            self.max - base.max,
            self.drop_total - base.drop_total,
        )
    }
}

fn parse_metric(line: &str, key: &str) -> Result<f64, DynError> {
    let prefix = format!("{key}=");
    let value = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
        .ok_or_else(|| format!("missing metric {key} in line: {line}"))?;
    Ok(value.parse::<f64>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn with_fixture_backup_restores_original_content_after_success() {
        let repo_root = make_temp_repo_root();
        let fixture = repo_root.join("daemon/ui/testdata/default-config.json");
        fs::create_dir_all(fixture.parent().expect("fixture parent")).expect("create fixture dir");
        fs::write(&fixture, "original\n").expect("write original fixture");

        let result =
            with_fixture_backup(&repo_root, "daemon/ui/testdata/default-config.json", || {
                fs::write(&fixture, "mutated\n").expect("write mutated fixture");
                Ok::<_, DynError>("ok")
            })
            .expect("backup helper should succeed");

        assert_eq!(result, "ok");
        assert_eq!(
            fs::read_to_string(&fixture).expect("read restored fixture"),
            "original\n"
        );
        assert!(!fixture.with_file_name(backup_file_name(&fixture)).exists());
    }

    #[test]
    fn with_fixture_backup_restores_original_content_after_error() {
        let repo_root = make_temp_repo_root();
        let fixture = repo_root.join("daemon/ui/testdata/default-config.json");
        fs::create_dir_all(fixture.parent().expect("fixture parent")).expect("create fixture dir");
        fs::write(&fixture, "original\n").expect("write original fixture");

        let result =
            with_fixture_backup(&repo_root, "daemon/ui/testdata/default-config.json", || {
                fs::write(&fixture, "mutated\n").expect("write mutated fixture");
                Err::<(), DynError>("expected failure".into())
            });

        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(&fixture).expect("read restored fixture"),
            "original\n"
        );
        assert!(!fixture.with_file_name(backup_file_name(&fixture)).exists());
    }

    fn make_temp_repo_root() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let dir = env::temp_dir().join(format!(
            "opensnitch-tools-tests-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp repo root");
        dir
    }

    fn backup_file_name(fixture: &Path) -> String {
        format!(
            "{}.backup.{}",
            fixture.file_name().expect("fixture name").to_string_lossy(),
            std::process::id()
        )
    }
}
