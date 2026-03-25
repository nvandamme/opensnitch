//! CLI argument parsing for the tools binary.
//!
//! Flags override environment variables by calling `env::set_var` at startup.
//! All existing env-var-based config accessors (`perf_rust_log_level()`, etc.)
//! continue to work unchanged, so Makefile / shell invocations are fully compatible.
//!
//! Usage:
//!   cargo ost <command> [flags...]
//!   cargo ost --help

use std::env;

use crate::DynError;

// ── public API ───────────────────────────────────────────────────────────────

/// Parse `args` (everything after `argv[0]`), apply recognized `--flags` as
/// env-var overrides, and return the command name (first non-flag argument).
///
/// `--help` / `-h` → prints help and exits 0 (handled before release-mode check
/// in the caller, so it works in debug builds too).
///
/// Returns `Ok(None)` when no command is found (caller should show help/error).
pub(crate) fn parse_and_apply(args: &[String]) -> Result<Option<String>, DynError> {
    let mut command: Option<String> = None;

    for arg in args {
        if arg == "--help" || arg == "-h" {
            println!("{}", help_text());
            std::process::exit(0);
        }
        if let Some(rest) = arg.strip_prefix("--") {
            if let Some(eq) = rest.find('=') {
                let key = &rest[..eq];
                let val = &rest[eq + 1..];
                apply_value_flag(key, val)?;
            } else {
                apply_bool_flag(rest)?;
            }
        } else if command.is_none() {
            command = Some(arg.clone());
        } else {
            return Err(format!("unexpected extra argument: {arg:?}; did you mean --{arg}=<value>?").into());
        }
    }

    Ok(command)
}

pub(crate) fn help_text() -> &'static str {
    concat!(
        "Usage:\n",
        "  cargo ost <command> [flags...]\n",
        "  cargo run --release --manifest-path daemon-rs/Cargo.toml -p tools -- <command> [flags...]\n",
        "\n",
        "Build commands:\n",
        "  build                                Build daemon crate (release)\n",
        "  build-all                            Build full daemon-rs workspace (release)\n",
        "  build-ebpf                           Build eBPF crate (root required; privilege via TEST_GUARD)\n",
        "\n",
        "Test commands:\n",
        "  test                                 Run parity test suites (config, firewall, client)\n",
        "  test-kernel-it                       Run kernel integration tests (privileged + strict)\n",
        "  test-filter                          Run tests matching --filter=PATTERN\n",
        "\n",
        "Harness / perf commands:\n",
        "  parity-hot-cold-delta                Hot+cold parity delta Nx repeats (median by hot p95)\n",
        "  parity-hot-cold-delta-once           One hot+cold parity delta pass (Go vs Rust)\n",
        "  parity-hot-path-harness-once         One hot-path parity pass\n",
        "  parity-cold-path-harness             Cold-path parity pass\n",
        "  parity-hot-path-harness              Hot-path harness N×repeats (pre-build on pass 1)\n",
        "  parity-gate                          Full parity gate (multi-repeat, gate check)\n",
        "  update-run-perf                      Full perf update cycle; writes PERF.md\n",
        "  quick-pressure-sweep-tunables        Quick kernel-pressure sweep to calibrate tunables\n",
        "  auto-tune-kernel-pressure-tunables   Auto-tune kernel pressure tunables\n",
        "  microbench-connect-dispatch          Microbenchmark connect dispatch\n",
        "\n",
        "eBPF smoke test commands:\n",
        "  aya-smoke-proc                       Run aya process eBPF smoke test\n",
        "  aya-smoke-dns                        Run aya DNS eBPF smoke test\n",
        "  aya-smoke-conn                       Run aya connection eBPF smoke test\n",
        "  aya-smoke-tunnel                     Run aya tunnel eBPF smoke test\n",
        "  kernel-profile-harness               Rust kernel-pressure + sweep harness (N repeats)\n",
        "\n",
        "Live daemon commands:\n",
        "  launch-daemon-live-logs              Start daemon with live log streaming\n",
        "  stop-daemon-live-logs                Stop live daemon session\n",
        "  run-daemon-mock-ui-live-session      Run daemon with mock Python UI\n",
        "\n",
        "Build flags:\n",
        "  --crate=NAME          Crate to build/test                 [OPENSNITCH_BUILD_CRATE] (default: opensnitchd-rs)\n",
        "  --all-features        Pass --all-features to cargo build  [OPENSNITCH_BUILD_ALL_FEATURES=1]\n",
        "\n",
        "Test flags:\n",
        "  --test-log=LEVEL      RUST_LOG for test runs              [OPENSNITCH_TEST_LOG_LEVEL] (default: info,opensnitchd_rs=debug)\n",
        "  --filter=PATTERN      Test name filter (test-filter cmd)  [OPENSNITCH_TEST_FILTER]\n",
        "  --privileged          Set OPENSNITCH_RUN_PRIVILEGED_TESTS [OPENSNITCH_RUN_PRIVILEGED_TESTS=1]\n",
        "  --kernel-it-strict    Set OPENSNITCH_KERNEL_IT_STRICT     [OPENSNITCH_KERNEL_IT_STRICT=1]\n",
        "  --release             Run cargo test --release            [OPENSNITCH_TEST_RELEASE=1]\n",
        "  --ignored             Pass --ignored to cargo test        [OPENSNITCH_TEST_IGNORED=1]\n",
        "\n",
        "Global flags:\n",
        "  --rounds=N            Stress/parity rounds                [OPENSNITCH_PARITY_STRESS_ROUNDS, STRESS_ROUNDS] (default: 500)\n",
        "  --repeats=N           Perf repeat count, median taken     [OPENSNITCH_PERF_REPEATS] (default: 3, max: 9)\n",
        "  --rust-log=LEVEL      Rust log level for harness          [OPENSNITCH_PERF_RUST_LOG_LEVEL] (default: warn)\n",
        "  --go-log=LEVEL        Go log level for harness            [OPENSNITCH_PERF_GO_LOG_LEVEL] (default: warn)\n",
        "  --prebuild            Pre-build Rust test binary once     [OPENSNITCH_PARITY_PREBUILD=1]\n",
        "  --no-prebuild         Skip pre-build step                 [OPENSNITCH_PARITY_PREBUILD=skip]\n",
        "  --refresh-base        Force-refresh cached prev-commit baseline [OPENSNITCH_PERF_REFRESH_BASE=1]\n",
        "  --require-exceed-go   Gate fails if Rust does not exceed Go    [OPENSNITCH_PARITY_REQUIRE_EXCEED_GO=1]\n",
        "  --skip-regression     Skip stress regression guard check  [OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1]\n",
        "\n",
        "Pressure/sweep flags (quick-pressure-sweep-tunables, auto-tune-kernel-pressure-tunables):\n",
        "  --secs=N              Pressure run duration (seconds)     [OPENSNITCH_TUNABLES_SWEEP_SECS, OPENSNITCH_AUTOTUNE_PRESSURE_SECS] (default: 1)\n",
        "  --tasks=N             Flood thread count                  [OPENSNITCH_TUNABLES_SWEEP_TASKS, OPENSNITCH_AUTOTUNE_PRESSURE_TASKS] (default: 2)\n",
        "  --sweep-us=LIST       Timeout sweep values, comma-sep     [OPENSNITCH_TUNABLES_SWEEP_US] (default: 50,100,200,500,1000)\n",
        "  --timeout-us=N        Enqueue timeout (microseconds)      [OPENSNITCH_KERNEL_PRESSURE_ENQUEUE_TIMEOUT_US] (default: 200)\n",
        "  --mode=try|timeout    Enqueue mode                        [OPENSNITCH_AUTOTUNE_ENQUEUE_MODE] (default: timeout)\n",
        "  --run-parity-gate     Run parity gate after auto-tune     [OPENSNITCH_AUTOTUNE_RUN_PARITY_GATE=1]\n",
        "\n",
        "Output flags:\n",
        "  --perf-md=PATH        Path to PERF.md                     [PERF_MD_PATH]\n",
        "  --output=PATH         Tunables output path                [OPENSNITCH_TUNABLES_OUTPUT]\n",
        "  --baseline=PATH       Stress baseline file path           [OPENSNITCH_STRESS_BASELINE_PATH]\n",
        "\n",
        "eBPF smoke flags:\n",
        "  --smoke-timeout=N     aya smoke test timeout (secs)       [DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS] (default: 90)\n",
        "  --smoke-kill-after=N  aya smoke SIGKILL grace (secs)      [DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS] (default: 3)\n",
        "\n",
        "Other:\n",
        "  --microbench-rounds=N  Rounds for microbench-connect-dispatch  [OPENSNITCH_MICROBENCH_ROUNDS] (default: 4000)\n",
        "  --help, -h             Show this help\n",
        "\n",
        "All flags can also be set via environment variable (shown in brackets).\n",
        "See daemon-rs/DOCS.md for extended documentation.\n",
    )
}

// ── internal ─────────────────────────────────────────────────────────────────

fn apply_value_flag(key: &str, val: &str) -> Result<(), DynError> {
    match key {
        // Rounds: sets both PARITY and STRESS variants so all commands agree.
        "rounds" => {
            set("OPENSNITCH_PARITY_STRESS_ROUNDS", val);
            set("STRESS_ROUNDS", val);
        }
        // Separate alias when caller wants parity-only override.
        "parity-rounds" => set("OPENSNITCH_PARITY_STRESS_ROUNDS", val),

        "repeats" => set("OPENSNITCH_PERF_REPEATS", val),

        "rust-log" => set("OPENSNITCH_PERF_RUST_LOG_LEVEL", val),
        // go-log feeds both the tools-side and the Go harness env.
        "go-log" => {
            set("OPENSNITCH_PERF_GO_LOG_LEVEL", val);
            set("OPENSNITCH_HARNESS_GO_LOG_LEVEL", val);
        }

        // Pressure / sweep
        "secs" => {
            set("OPENSNITCH_TUNABLES_SWEEP_SECS", val);
            set("OPENSNITCH_AUTOTUNE_PRESSURE_SECS", val);
        }
        "tasks" => {
            set("OPENSNITCH_TUNABLES_SWEEP_TASKS", val);
            set("OPENSNITCH_AUTOTUNE_PRESSURE_TASKS", val);
        }
        "sweep-us" => {
            set("OPENSNITCH_TUNABLES_SWEEP_US", val);
            set("OPENSNITCH_KERNEL_PRESSURE_SWEEP_US", val);
        }
        "timeout-us" => {
            set("OPENSNITCH_KERNEL_PRESSURE_ENQUEUE_TIMEOUT_US", val);
            set("OPENSNITCH_AUTOTUNE_ENQUEUE_TIMEOUT_US", val);
        }
        "mode" => {
            set("OPENSNITCH_AUTOTUNE_ENQUEUE_MODE", val);
            set("OPENSNITCH_KERNEL_PRESSURE_ENQUEUE_MODE", val);
        }

        // Output / path flags
        "perf-md" => set("PERF_MD_PATH", val),
        "output" => set("OPENSNITCH_TUNABLES_OUTPUT", val),
        "baseline" => set("OPENSNITCH_STRESS_BASELINE_PATH", val),

        // microbench
        "microbench-rounds" => set("OPENSNITCH_MICROBENCH_ROUNDS", val),

        // aya smoke
        "smoke-timeout" => set("DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS", val),
        "smoke-kill-after" => set("DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS", val),

        // build / test
        "crate" => set("OPENSNITCH_BUILD_CRATE", val),
        "test-log" => {
            set("OPENSNITCH_TEST_LOG_LEVEL", val);
            set("RUST_TEST_LOG_LEVEL", val);
        }
        "filter" => set("OPENSNITCH_TEST_FILTER", val),

        other => return Err(format!("unknown flag: --{other}; run with --help for usage").into()),
    }
    Ok(())
}

fn apply_bool_flag(key: &str) -> Result<(), DynError> {
    match key {
        "prebuild" => set("OPENSNITCH_PARITY_PREBUILD", "1"),
        "no-prebuild" => set("OPENSNITCH_PARITY_PREBUILD", "skip"),
        "refresh-base" => set("OPENSNITCH_PERF_REFRESH_BASE", "1"),
        "require-exceed-go" => set("OPENSNITCH_PARITY_REQUIRE_EXCEED_GO", "1"),
        "skip-regression" => set("OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK", "1"),
        "run-parity-gate" => set("OPENSNITCH_AUTOTUNE_RUN_PARITY_GATE", "1"),

        // build / test booleans
        "all-features" => set("OPENSNITCH_BUILD_ALL_FEATURES", "1"),
        "privileged" => set("OPENSNITCH_RUN_PRIVILEGED_TESTS", "1"),
        "kernel-it-strict" => set("OPENSNITCH_KERNEL_IT_STRICT", "1"),
        "release" => set("OPENSNITCH_TEST_RELEASE", "1"),
        "ignored" => set("OPENSNITCH_TEST_IGNORED", "1"),

        other => return Err(format!("unknown flag: --{other}; run with --help for usage").into()),
    }
    Ok(())
}

// Safety: called at program startup before any worker threads are spawned.
#[allow(unsafe_code)]
fn set(name: &str, val: &str) {
    unsafe { env::set_var(name, val) }
}
