use std::{
    collections::hash_map::DefaultHasher,
    env, fs,
    hash::{Hash, Hasher},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use time::{OffsetDateTime, macros::format_description};

mod build_cmds;
mod cli;
mod harness_cmds;
mod live_logs;
mod test_guard;

pub(crate) type DynError = Box<dyn std::error::Error>;

const TABLE_HEADER: &str = "| Date | Backend | Profile | Rounds | Commit | p50 ms | p95 ms | p99 ms | max ms | drop_total | Baseline Check | Go Ref | vs Go p50 | vs Go p95 | vs Go p99 | vs Go max | vs Go drop | Prev Commit Ref | vs Prev p50 | vs Prev p95 | vs Prev p99 | vs Prev max | vs Prev drop | Notes |";
const DELTA_TABLE_HEADER: &str = "| Date | Delta Target | Rounds | Commit | Hot Mixed Go verdict ms | Hot Mixed Rust verdict ms | Hot Mixed Δ ms (Rust-Go) | Hot Throughput Go time/op us | Hot Throughput Rust time/op us | Hot Throughput Go op/s | Hot Throughput Rust op/s | Hot Δ p50 ms | Hot Δ p95 ms | Hot Δ p99 ms | Hot Δ max ms | Hot Δ drop_total | Cold Go rule s | Cold Rust rule s | Cold Δ rule s | Cold Go ui s | Cold Rust ui s | Cold Δ ui s | Cold Go tasks s | Cold Rust tasks s | Cold Δ tasks s | Cold Go total s (with tasks) | Cold Rust total s (with tasks) | Cold Δ total s (Rust-Go, with tasks) | Result | Notes |";
const DELTA_TABLE_HEADER_LEGACY: &str = "| Date | Delta Target | Rounds | Commit | Hot Mixed Go verdict ms | Hot Mixed Rust verdict ms | Hot Mixed Δ ms (Rust-Go) | Hot Throughput Go time/op us | Hot Throughput Rust time/op us | Hot Throughput Go op/s | Hot Throughput Rust op/s | Hot Δ p50 ms | Hot Δ p95 ms | Hot Δ p99 ms | Hot Δ max ms | Hot Δ drop_total | Cold Go rule s | Cold Rust rule s | Cold Δ rule s | Cold Go ui s | Cold Rust ui s | Cold Δ ui s | Cold Go tasks s | Cold Rust tasks s | Cold Δ tasks s | Cold Go total s | Cold Rust total s | Cold Δ total s (Rust-Go, with tasks) | Result | Notes |";
const DELTA_TABLE_HEADER_LEGACY_ALT: &str = "| Date | Delta Target | Rounds | Commit | Hot Mixed Go verdict ms | Hot Mixed Rust verdict ms | Hot Mixed Δ ms (Rust-Go) | Hot Throughput Go time/op us | Hot Throughput Rust time/op us | Hot Throughput Go op/s | Hot Throughput Rust op/s | Hot Δ p50 ms | Hot Δ p95 ms | Hot Δ p99 ms | Hot Δ max ms | Hot Δ drop_total | Cold Go rule s | Cold Rust rule s | Cold Δ rule s | Cold Go ui s | Cold Rust ui s | Cold Δ ui s | Cold Go tasks s | Cold Rust tasks s | Cold Δ tasks s | Cold Go total s | Cold Rust total s | Cold Δ total s (Rust-Go) | Result | Notes |";
const EMPTY_COMPARISON_COLUMNS: &str = "- | - | - | - | - | - | - | - | - | - | - | -";
const TS_COMPACT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year][month][day]-[hour][minute][second]");

pub(crate) fn compact_timestamp() -> Result<String, DynError> {
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    Ok(now.format(TS_COMPACT)?)
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), DynError> {
    let all_args: Vec<String> = env::args().skip(1).collect();

    // --help / -h works in both debug and release (before release-mode check).
    if all_args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", cli::help_text());
        return Ok(());
    }

    ensure_release_tools_mode()?;
    apply_tools_env_defaults()?;

    let command = cli::parse_and_apply(&all_args)?;

    match command.as_deref() {
        // ── build ─────────────────────────────────────────────────────────
        Some("build") => build_cmds::run_build(),
        Some("build-all") => build_cmds::run_build_all(),
        Some("build-ebpf") => build_cmds::run_build_ebpf(),
        // ── test ──────────────────────────────────────────────────────────
        Some("test") => build_cmds::run_parity_tests(),
        Some("test-kernel-it") => build_cmds::run_kernel_it(),
        Some("test-filter") => build_cmds::run_test_filter(),
        // ── aya eBPF smoke tests ──────────────────────────────────────────
        Some("aya-smoke-proc") => build_cmds::run_aya_proc_smoke(),
        Some("aya-smoke-dns") => build_cmds::run_aya_dns_smoke(),
        Some("aya-smoke-conn") => build_cmds::run_aya_conn_smoke(),
        Some("aya-smoke-tunnel") => build_cmds::run_aya_tunnel_smoke(),
        // ── kernel profile harness ────────────────────────────────────────
        Some("kernel-profile-harness") => build_cmds::run_kernel_profile_harness(),
        // ── harness / perf ────────────────────────────────────────────────
        Some("update-run-perf") => update_perf_md(),
        Some("quick-pressure-sweep-tunables") => quick_pressure_sweep_tunables(),
        Some("auto-tune-kernel-pressure-tunables") => auto_tune_kernel_pressure_tunables(),
        Some("microbench-connect-dispatch") => microbench_connect_dispatch(),
        Some("parity-gate") => run_parity_gate_command(),
        Some("parity-hot-path-harness") => harness_cmds::run_parity_hot_path_harness(),
        Some("parity-hot-path-harness-once") => run_parity_hot_path_harness_once_command(),
        Some("parity-cold-path-harness") => run_parity_cold_path_harness_command(),
        Some("parity-hot-cold-delta") => harness_cmds::run_parity_hot_cold_delta_command(),
        Some("parity-hot-cold-delta-once") => run_parity_hot_cold_delta_once_command(),
        // ── live daemon ───────────────────────────────────────────────────
        Some("launch-daemon-live-logs") => launch_daemon_live_logs(),
        Some("stop-daemon-live-logs") => stop_daemon_live_logs(),
        Some("run-daemon-mock-ui-live-session") => run_daemon_mock_ui_live_session(),
        Some(command) => Err(format!("unsupported tools command: {command}\n\n{}", cli::help_text()).into()),
        None => Err(cli::help_text().into()),
    }
}

fn apply_tools_env_defaults() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;

    // Keep cargo-run behavior aligned with Makefile defaults.
    let default_target = daemon_rs_dir.join("target-kernel");
    if env::var_os("CARGO_TARGET_DIR").is_none() {
        unsafe {
            env::set_var("CARGO_TARGET_DIR", &default_target);
        }
    }
    if env::var_os("OPENSNITCH_CARGO_TARGET_DIR").is_none() {
        let resolved = env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| default_target.into_os_string());
        unsafe {
            env::set_var("OPENSNITCH_CARGO_TARGET_DIR", resolved);
        }
    }

    Ok(())
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

pub(crate) fn perf_rust_log_level() -> String {
    let raw = env::var("OPENSNITCH_PERF_RUST_LOG_LEVEL").unwrap_or_else(|_| "warn".to_string());
    let normalized = raw.to_ascii_lowercase();
    let has_warn_or_error = normalized.contains("warn")
        || normalized.contains("warning")
        || normalized.contains("err")
        || normalized.contains("error");
    let has_debug_or_trace = normalized.contains("debug") || normalized.contains("trace");

    if !has_warn_or_error || has_debug_or_trace {
        eprintln!(
            "warning: OPENSNITCH_PERF_RUST_LOG_LEVEL should be warn|warning|err|error for harness/perf commands (current={:?}); continuing",
            raw
        );
    }

    raw
}

pub(crate) fn perf_go_log_level() -> String {
    let raw = env::var("OPENSNITCH_PERF_GO_LOG_LEVEL").unwrap_or_else(|_| "warn".to_string());
    let normalized = raw.to_ascii_lowercase();
    if normalized != "warn"
        && normalized != "warning"
        && normalized != "err"
        && normalized != "error"
    {
        eprintln!(
            "warning: OPENSNITCH_PERF_GO_LOG_LEVEL should be warn|warning|err|error for harness/perf commands (current={:?}); continuing",
            raw
        );
    }

    raw
}

pub(crate) fn parity_stress_rounds() -> String {
    env::var("OPENSNITCH_PARITY_STRESS_ROUNDS").unwrap_or_else(|_| "500".to_string())
}

pub(crate) fn perf_repeats() -> usize {
    env::var("OPENSNITCH_PERF_REPEATS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3)
        .clamp(1, 9)
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
    test_guard::with_guard("auto-tune-kernel-pressure-tunables", || {
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
        .unwrap_or(0.02)
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
    }) // with_guard auto_tune_kernel_pressure_tunables
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
    test_guard::with_guard("quick-pressure-sweep-tunables", || {
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
    }) // with_guard quick_pressure_sweep_tunables
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

pub(crate) fn parse_named_u64(line: &str, key: &str) -> Result<u64, DynError> {
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
    harness_cmds::microbench_connect_dispatch()
}

fn run_parity_gate_command() -> Result<(), DynError> {
    harness_cmds::run_parity_gate_command()
}

fn run_parity_hot_path_harness_once_command() -> Result<(), DynError> {
    harness_cmds::run_parity_hot_path_harness_once_command()
}

fn run_parity_cold_path_harness_command() -> Result<(), DynError> {
    harness_cmds::run_parity_cold_path_harness_command()
}

fn run_parity_hot_cold_delta_once_command() -> Result<(), DynError> {
    harness_cmds::run_parity_hot_cold_delta_once_command()
}

fn run_parity_gate_internal(repo_root: &Path) -> Result<(), DynError> {
    harness_cmds::run_parity_gate_internal(repo_root)
}

fn launch_daemon_live_logs() -> Result<(), DynError> {
    live_logs::launch_daemon_live_logs()
}

fn stop_daemon_live_logs() -> Result<(), DynError> {
    live_logs::stop_daemon_live_logs()
}

fn run_daemon_mock_ui_live_session() -> Result<(), DynError> {
    live_logs::run_daemon_mock_ui_live_session()
}

fn update_perf_md() -> Result<(), DynError> {
    test_guard::with_guard("update-run-perf", || {
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
    let stress_rounds = env::var("STRESS_ROUNDS").unwrap_or_else(|_| "500".to_string());
    let perf_repeats = perf_repeats();
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

    println!(
        "Running current Rust release stress profile ({}x, median by p95)...",
        perf_repeats
    );
    let mut current_rust_runs = Vec::with_capacity(perf_repeats);
    for run_idx in 0..perf_repeats {
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
        let current_rust_line = find_stress_profile_line(&current_rust_output)?.to_string();
        let current_rust_metrics = Metrics::parse(&current_rust_line)?;
        println!(
            "  rust-run {}/{} p95_ms={:.3}",
            run_idx + 1,
            perf_repeats,
            current_rust_metrics.p95,
        );
        current_rust_runs.push((current_rust_metrics, current_rust_line));
    }
    let (current_rust, current_rust_line) = select_median_metrics_run(current_rust_runs);

    println!(
        "Running current Go stress profile ({}x, median by p95)...",
        perf_repeats
    );
    let mut current_go_runs = Vec::with_capacity(perf_repeats);
    for run_idx in 0..perf_repeats {
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
        let current_go_line =
            find_line(&current_go_output, "stress-profile backend=go")?.to_string();
        let current_go_metrics = Metrics::parse(&current_go_line)?;
        println!(
            "  go-run   {}/{} p95_ms={:.3}",
            run_idx + 1,
            perf_repeats,
            current_go_metrics.p95,
        );
        current_go_runs.push((current_go_metrics, current_go_line));
    }
    let (current_go, current_go_line) = select_median_metrics_run(current_go_runs);

    let prev_rust_line = cached_or_run_prev_rust_profile(
        repo_root,
        &cache_root,
        &prev_commit,
        &prev_commit_full,
        &stress_rounds,
        perf_repeats,
        refresh_prev_base,
    )
    .ok();
    let prev_rust = prev_rust_line
        .as_ref()
        .and_then(|line| Metrics::parse(line).ok());

    let prev_commit_cell = if prev_rust.is_some() {
        format!("`{prev_commit}`")
    } else {
        "unavailable".to_string()
    };
    let vs_prev_cell = if let Some(prev) = prev_rust.as_ref() {
        current_rust.delta_string(prev)
    } else {
        "n/a".to_string()
    };

    let row_rust = format!(
        "| {run_date} | Rust | release (ThinLTO) | {stress_rounds} | `{current_commit}` | {current_rust} | pass | Go default same run | {vs_go} | {prev_commit_cell} | {vs_prev_cell} | Auto-updated current reference Rust run ({current_subject}); workspace {workspace_state}. |",
        current_rust = current_rust.format_values(),
        vs_go = current_rust.delta_string(&current_go),
    );
    let row_go = format!(
        "| {run_date} | Go | default | {stress_rounds} | `{current_commit}` | {current_go} | pass | {empty} | Auto-updated current Go comparison row paired with Rust actual. |",
        current_go = current_go.format_values(),
        empty = EMPTY_COMPARISON_COLUMNS,
    );
    let row_prev = if let Some(prev) = prev_rust.as_ref() {
        format!(
            "| {run_date} | Rust | release (ThinLTO) | {stress_rounds} | `{prev_commit}` | {prev_rust} | pass | {empty} | Auto-updated previous commit benchmark ({prev_subject}) using cached previous-commit worktree/results when available. |",
            prev_rust = prev.format_values(),
            empty = EMPTY_COMPARISON_COLUMNS,
        )
    } else {
        format!(
            "| {run_date} | Rust | release (ThinLTO) | {stress_rounds} | `{prev_commit}` | unavailable | fail | {empty} | Previous-commit benchmark unavailable (build/compat issue in previous commit). |",
            empty = EMPTY_COMPARISON_COLUMNS,
        )
    };

    prepend_rows(&perf_md, TABLE_HEADER, &[row_rust, row_go, row_prev])?;

    println!(
        "Running parity hot/cold delta harness ({}x, median by hot p95 delta)...",
        perf_repeats
    );
    let mut parity_runs = Vec::with_capacity(perf_repeats);
    for run_idx in 0..perf_repeats {
        // Call in-process instead of spawning `make parity-hot-cold-delta`, which
        // avoids a full subprocess launch + cargo warm start per repeat.
        let parity_output = harness_cmds::run_parity_delta_to_string(repo_root)?;
        print!("{}", harness_cmds::format_parity_delta_table(&parity_output));
        let parsed = parse_parity_delta_summary(&parity_output)?;
        println!(
            "  parity-run {}/{} hot_p95_delta_ms={:+.3} status={}",
            run_idx + 1,
            perf_repeats,
            parsed.hot_p95,
            parsed.status,
        );
        parity_runs.push(parsed);
    }
    let parity = select_median_parity_run(parity_runs);

    let hot_mixed_go_ms = parity.hot_mixed_go_ms;
    let hot_mixed_rust_ms = parity.hot_mixed_rust_ms;
    let hot_mixed_delta_ms = parity.hot_mixed_delta_ms;
    let hot_thr_go_time_op_us = parity.hot_thr_go_time_op_us;
    let hot_thr_rust_time_op_us = parity.hot_thr_rust_time_op_us;
    let hot_thr_go_ops_s = parity.hot_thr_go_ops_s;
    let hot_thr_rust_ops_s = parity.hot_thr_rust_ops_s;
    let hot_p50 = parity.hot_p50;
    let hot_p95 = parity.hot_p95;
    let hot_p99 = parity.hot_p99;
    let hot_max = parity.hot_max;
    let hot_drop_total = parity.hot_drop_total;
    let cold_go_rule = parity.cold_go_rule;
    let cold_rust_rule = parity.cold_rust_rule;
    let cold_rule_delta = parity.cold_rule_delta;
    let cold_go_ui = parity.cold_go_ui;
    let cold_rust_ui = parity.cold_rust_ui;
    let cold_ui_delta = parity.cold_ui_delta;
    let cold_go_tasks = parity.cold_go_tasks;
    let cold_rust_tasks = parity.cold_rust_tasks;
    let cold_tasks_delta = parity.cold_tasks_delta;
    let cold_go = parity.cold_go;
    let cold_rust = parity.cold_rust;
    let cold_delta = parity.cold_delta;
    let status = parity.status.as_str();

    let delta_row = format!(
        "| {run_date} | `make parity-hot-cold-delta` | {parity_rounds} | `{current_commit}` | {hot_mixed_go_ms:.3} | {hot_mixed_rust_ms:.3} | {hot_mixed_delta_ms:+.3} | {hot_thr_go_time_op_us:.3} | {hot_thr_rust_time_op_us:.3} | {hot_thr_go_ops_s:.1} | {hot_thr_rust_ops_s:.1} | {hot_p50:+.3} | {hot_p95:+.3} | {hot_p99:+.3} | {hot_max:+.3} | {hot_drop:+.0} | {cold_go_rule:.3} | {cold_rust_rule:.3} | {cold_rule_delta:+.3} | {cold_go_ui:.3} | {cold_rust_ui:.3} | {cold_ui_delta:+.3} | {cold_go_tasks:.3} | {cold_rust_tasks:.3} | {cold_tasks_delta:+.3} | {cold_go:.3} | {cold_rust:.3} | {cold_delta:+.3} | {status} | Auto-updated parity hot/cold delta row from tools command. |",
        hot_drop = hot_drop_total,
    );

    prepend_rows_any_header(
        &perf_md,
        &[
            DELTA_TABLE_HEADER,
            DELTA_TABLE_HEADER_LEGACY,
            DELTA_TABLE_HEADER_LEGACY_ALT,
        ],
        &[delta_row],
    )?;

    println!("Updated {}", perf_md.display());
    println!("Current Rust (median): {current_rust_line}");
    println!("Current Go (median):   {current_go_line}");
    if let Some(prev_rust_line) = prev_rust_line.as_ref() {
        println!("Prev Rust:    {prev_rust_line}");
    } else {
        println!("Prev Rust:    unavailable (previous commit benchmark failed)");
    }
    println!("Prev cache:   {}", cache_root.display());

    Ok(())
    }) // with_guard update_perf_md
}

#[allow(dead_code)]
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
    perf_repeats: usize,
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

    println!(
        "Running previous-commit Rust release stress profile ({}x, median by p95)...",
        perf_repeats
    );
    let manifest_path = worktree_path.join("daemon-rs/Cargo.toml");
    let run_prev_profile = |rust_log_value: &str| {
        run_command(
            repo_root,
            "cargo",
            [
                "test",
                "--manifest-path",
                manifest_path.to_string_lossy().as_ref(),
                "--release",
                "-p",
                "opensnitchd-rs",
                "stress_profile_reports_connect_latency_and_pipeline_drops",
                "--",
                "--ignored",
                "--nocapture",
            ],
            &[
                ("RUST_LOG", rust_log_value),
                ("OPENSNITCH_STRESS_ROUNDS", stress_rounds),
            ],
        )
    };

    let mut prev_runs = Vec::with_capacity(perf_repeats);
    for run_idx in 0..perf_repeats {
        let prev_rust_output = run_prev_profile(rust_log.as_str())?;
        let prev_rust_line = match find_stress_profile_line(&prev_rust_output) {
            Ok(line) => line.to_string(),
            Err(_) => {
                // Older commits may only emit stress metrics at info-level.
                eprintln!(
                    "previous commit stress-profile line not found with RUST_LOG={}; retrying with RUST_LOG=info",
                    rust_log
                );
                let fallback_output = run_prev_profile("info")?;
                find_stress_profile_line(&fallback_output)?.to_string()
            }
        };
        let metrics = Metrics::parse(&prev_rust_line)?;
        println!(
            "  prev-rust-run {}/{} p95_ms={:.3}",
            run_idx + 1,
            perf_repeats,
            metrics.p95,
        );
        prev_runs.push((metrics, prev_rust_line));
    }
    let (_, prev_rust_line) = select_median_metrics_run(prev_runs);
    fs::write(&cached_result_path, format!("{prev_rust_line}\n"))?;
    Ok(prev_rust_line)
}

fn select_median_metrics_run(mut runs: Vec<(Metrics, String)>) -> (Metrics, String) {
    runs.sort_by(|left, right| left.0.p95.total_cmp(&right.0.p95));
    runs[runs.len() / 2].clone()
}

#[derive(Clone)]
struct ParityDeltaSummary {
    hot_mixed_go_ms: f64,
    hot_mixed_rust_ms: f64,
    hot_mixed_delta_ms: f64,
    hot_thr_go_time_op_us: f64,
    hot_thr_rust_time_op_us: f64,
    hot_thr_go_ops_s: f64,
    hot_thr_rust_ops_s: f64,
    hot_p50: f64,
    hot_p95: f64,
    hot_p99: f64,
    hot_max: f64,
    hot_drop_total: f64,
    cold_go_rule: f64,
    cold_rust_rule: f64,
    cold_rule_delta: f64,
    cold_go_ui: f64,
    cold_rust_ui: f64,
    cold_ui_delta: f64,
    cold_go_tasks: f64,
    cold_rust_tasks: f64,
    cold_tasks_delta: f64,
    cold_go: f64,
    cold_rust: f64,
    cold_delta: f64,
    status: String,
}

fn parse_parity_delta_summary(output: &str) -> Result<ParityDeltaSummary, DynError> {
    let hot_mixed_line = find_line(output, "PARITY DELTA HOT MIXED:")?;
    let hot_throughput_line = find_line(output, "PARITY DELTA HOT THROUGHPUT:")?;
    let hot_line = find_line(output, "PARITY DELTA HOT:")?;
    let cold_components_line = find_line(output, "PARITY DELTA COLD COMPONENTS:")?;
    let cold_detail_line = find_line(output, "PARITY DELTA COLD DETAIL:")?;
    let cold_line = find_line(output, "PARITY DELTA COLD:")?;
    let status_line = find_line(output, "PARITY DELTA STATUS:")?;

    let comparable_cold_line = output
        .lines()
        .find(|line| line.contains("PARITY DELTA COLD COMPARABLE-TASKS:"))
        .or_else(|| {
            output
                .lines()
                .find(|line| line.contains("PARITY DELTA COLD NON-COMPARABLE-TASKS:"))
        });

    let (cold_go, cold_rust, cold_delta) = if let Some(line) = comparable_cold_line {
        (
            parse_metric(line, "go_total_with_tasks_s")?,
            parse_metric(line, "rust_total_with_tasks_s")?,
            parse_metric(line, "delta_with_tasks_s")?,
        )
    } else {
        (
            parse_metric(cold_line, "go_total_s")?,
            parse_metric(cold_line, "rust_total_s")?,
            parse_metric(cold_line, "delta_s")?,
        )
    };

    Ok(ParityDeltaSummary {
        hot_mixed_go_ms: parse_metric(hot_mixed_line, "go_verdict_ms")?,
        hot_mixed_rust_ms: parse_metric(hot_mixed_line, "rust_verdict_ms")?,
        hot_mixed_delta_ms: parse_metric(hot_mixed_line, "delta_ms")?,
        hot_thr_go_time_op_us: parse_metric(hot_throughput_line, "go_time_op_us")?,
        hot_thr_rust_time_op_us: parse_metric(hot_throughput_line, "rust_time_op_us")?,
        hot_thr_go_ops_s: parse_metric(hot_throughput_line, "go_ops_s")?,
        hot_thr_rust_ops_s: parse_metric(hot_throughput_line, "rust_ops_s")?,
        hot_p50: parse_metric(hot_line, "p50")?,
        hot_p95: parse_metric(hot_line, "p95")?,
        hot_p99: parse_metric(hot_line, "p99")?,
        hot_max: parse_metric(hot_line, "max")?,
        hot_drop_total: parse_metric(hot_line, "drop_total")?,
        cold_go_rule: parse_metric(cold_components_line, "go_rule_s")?,
        cold_rust_rule: parse_metric(cold_components_line, "rust_rule_s")?,
        cold_rule_delta: parse_metric(cold_detail_line, "rust_rule-vs-go_rule_s")?,
        cold_go_ui: parse_metric(cold_components_line, "go_ui_s")?,
        cold_rust_ui: parse_metric(cold_components_line, "rust_ui_s")?,
        cold_ui_delta: parse_metric(cold_detail_line, "rust_ui-vs-go_ui_s")?,
        cold_go_tasks: parse_metric(cold_components_line, "go_tasks_s")?,
        cold_rust_tasks: parse_metric(cold_components_line, "rust_tasks_s")?,
        cold_tasks_delta: parse_metric(cold_detail_line, "rust_tasks-vs-go_tasks_s")?,
        cold_go,
        cold_rust,
        cold_delta,
        status: status_line
            .split(':')
            .nth(1)
            .map(str::trim)
            .unwrap_or("PASS")
            .to_string(),
    })
}

fn select_median_parity_run(mut runs: Vec<ParityDeltaSummary>) -> ParityDeltaSummary {
    runs.sort_by(|left, right| left.hot_p95.total_cmp(&right.hot_p95));
    runs[runs.len() / 2].clone()
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

    // Clean up stale registered worktrees (missing on disk but still listed by git).
    let _ = run_command(repo_root, "git", ["worktree", "prune"], &[]);

    run_command(
        repo_root,
        "git",
        [
            "worktree",
            "add",
            "-f",
            "--detach",
            worktree_path.to_string_lossy().as_ref(),
            expected_commit,
        ],
        &[],
    )?;
    Ok(())
}

fn prepend_rows(perf_md: &Path, header: &str, rows: &[String]) -> Result<(), DynError> {
    prepend_rows_any_header(perf_md, &[header], rows)
}

fn prepend_rows_any_header(perf_md: &Path, headers: &[&str], rows: &[String]) -> Result<(), DynError> {
    let text = fs::read_to_string(perf_md)?;
    let header_idx = headers
        .iter()
        .find_map(|candidate| text.find(candidate))
        .ok_or_else(|| format!("table header not found in PERF.md: {}", headers.join(" || ")))?;
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

fn harness_cmd_timeout() -> Duration {
    let secs = env::var("OPENSNITCH_HARNESS_CMD_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300);
    Duration::from_secs(secs)
}

/// Run `cmd` with a per-command timeout, draining stdout/stderr concurrently to
/// prevent pipe-buffer deadlocks.  Prints `[harness] START/DONE/TIMEOUT` lines
/// to stderr regardless of the caller's log level.
pub(crate) fn run_timed(mut cmd: Command, label: &str) -> Result<String, DynError> {
    let timeout = harness_cmd_timeout();
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let started = Instant::now();
    eprintln!("[harness] START {label}");
    let mut child = cmd.spawn()?;

    // Drain stdout/stderr in background threads so full pipe buffers never
    // block the child process.
    let mut stdout_pipe = child.stdout.take().expect("stdout pipe");
    let mut stderr_pipe = child.stderr.take().expect("stderr pipe");

    let stdout_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let stderr_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

    let stdout_clone = stdout_buf.clone();
    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        *stdout_clone.lock().unwrap() = buf;
    });

    let stderr_clone = stderr_buf.clone();
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        *stderr_clone.lock().unwrap() = buf;
    });

    loop {
        match child.try_wait()? {
            Some(status) => {
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                let elapsed = started.elapsed().as_secs_f64();
                let out = stdout_buf.lock().unwrap().to_vec();
                let err = stderr_buf.lock().unwrap().to_vec();
                if status.success() {
                    eprintln!("[harness] DONE {label} elapsed={elapsed:.1}s");
                    let mut combined = String::from_utf8_lossy(&out).into_owned();
                    combined.push_str(&String::from_utf8_lossy(&err));
                    return Ok(combined);
                } else {
                    let stdout = String::from_utf8_lossy(&out);
                    let stderr = String::from_utf8_lossy(&err);
                    return Err(format!(
                        "command failed: {label}\nstdout:\n{stdout}\nstderr:\n{stderr}"
                    )
                    .into());
                }
            }
            None => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    let elapsed = started.elapsed().as_secs_f64();
                    eprintln!(
                        "[harness] TIMEOUT {label} after {elapsed:.0}s (limit={}s)",
                        timeout.as_secs()
                    );
                    return Err(format!(
                        "[harness] TIMEOUT {label} after {elapsed:.0}s (limit={}s)",
                        timeout.as_secs()
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

pub(crate) fn run_command<const N: usize>(
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
    let label = format!("{program} {}", args.join(" "));
    run_timed(command, &label)
}

pub(crate) fn find_line<'a>(text: &'a str, needle: &str) -> Result<&'a str, DynError> {
    text.lines()
        .find(|line| line.contains(needle))
        .ok_or_else(|| format!("expected output line containing: {needle}").into())
}

fn find_stress_profile_line<'a>(text: &'a str) -> Result<&'a str, DynError> {
    text.lines()
        .find(|line| {
            line.contains("stress-profile")
                && line.contains("p50_ms=")
                && line.contains("p95_ms=")
                && line.contains("p99_ms=")
                && line.contains("max_ms=")
        })
        .ok_or_else(|| "expected stress-profile metrics output line".into())
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

pub(crate) fn env_flag(name: &str) -> bool {
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

pub(crate) fn parse_metric(line: &str, key: &str) -> Result<f64, DynError> {
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
