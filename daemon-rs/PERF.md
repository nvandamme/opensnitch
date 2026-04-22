# Perf Tracker

Track stress-profile harness runs for Rust and Go backends.

## Harness Commands

- Rust (release):
  - `cd daemon-rs && OPENSNITCH_STRESS_ROUNDS=4000 cargo test --release -p opensnitchd-rs stress_profile_reports_connect_latency_and_pipeline_drops -- --ignored --nocapture`
  - `cd daemon-rs && RUST_LOG=error OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1 cargo test --release -p opensnitchd-rs stress_profile_reports_kernel_pipeline_pressure -- --ignored --nocapture`
  - `cd daemon-rs && RUST_LOG=error OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1 cargo test --release -p opensnitchd-rs stress_profile_reports_kernel_pipeline_timeout_sweep -- --ignored --nocapture`
- Go:
  - `cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=error OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=4000 go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v`
- Combined:
  - `make profile-backends STRESS_ROUNDS=4000`
  - `make daemon-rs-kernel-profile-harness`
- Hot-path parity matrix slice (Go + Rust):
  - `make parity-hot-path-harness STRESS_ROUNDS=4000`
- Cold-path parity matrix slice (watch/reload behavior, Go + Rust):
  - `make parity-cold-path-harness`
- Full parity matrix gate:
  - `make parity-hot-cold-matrix STRESS_ROUNDS=4000`
- Full parity matrix gate with computed deltas:
  - `make parity-hot-cold-delta STRESS_ROUNDS=4000`
- Update tracker automatically:
  - `make update-run-perf STRESS_ROUNDS=4000`
  - `STRESS_ROUNDS=4000 cargo run --release --manifest-path daemon-rs/Cargo.toml -p tools -- update-run-perf`
  - `OPENSNITCH_PARITY_STRESS_ROUNDS` defaults to `4000` for tools parity harness runs (`update-run-perf` and `parity-gate`).
  - `update-run-perf` always updates `Hot/Cold Delta History` via `make parity-hot-cold-delta`.
  - `OPENSNITCH_PERF_REFRESH_BASE=1` forces a fresh previous-commit Rust benchmark instead of using the cache.
  - `OPENSNITCH_PERF_CACHE_DIR=/custom/path` overrides the default `/tmp` cache location used by the tools crate.

Rust perf/stress profiling must always use `--release`.
All Rust harness/perf test commands must run with WARN/ERROR-only logging (`RUST_LOG=warn` or `RUST_LOG=error`); debug/trace log levels are disallowed for performance runs.
`stress_profile_reports_connect_latency_and_pipeline_drops` and `stress_profile_reports_kernel*` enforce this policy at test runtime.
All Go harness/perf test commands must run with `OPENSNITCH_HARNESS_GO_LOG_LEVEL=error` (or `err`) for apples-to-apples low-noise comparisons.
Timed Rust measurements inside `make parity-hot-cold-delta` should use low-noise logging (`PERF_RUST_LOG_LEVEL=error` by default) to keep Go-vs-Rust cold-path wall-clock comparisons stable.
Rust cold-path commands in parity harness targets should use current `tests::...` namespaces (`tests::watch_service::`, `tests::config_service::`, `tests::notification_flow::`, `tests::process_service::`, `tests::task_runtime::`) to avoid false zero-test timings.
Tools-based perf commands (`update-run-perf`, `parity-gate`, `microbench-connect-dispatch`) enforce low-noise Rust logs via `OPENSNITCH_PERF_RUST_LOG_LEVEL` (default `error`) and fail fast on noisy values.
Tools-based perf/parity commands also enforce low-noise Go harness logging via `OPENSNITCH_PERF_GO_LOG_LEVEL` (default `error`) and fail fast on non-ERR/ERROR values.
Compare only like-for-like profiles for retained history entries.

ThinLTO for release is enforced in `daemon-rs/Cargo.toml` under `[profile.release]`.

## Regression Policy

- Baselines are sourced from `daemon-rs/TODO.md` keys under `Perf Regression Baselines (Machine-Readable)`.
- Harness checks treat a metric as a clear regression when:
  - `observed_ms > baseline_ms * PERF_CLEAR_REGRESSION_FACTOR`
  - and `observed_ms - baseline_ms > PERF_CLEAR_REGRESSION_MIN_DELTA_MS`
- `drop_total` is a hard check and must not exceed baseline.

## Run History

Keep one row per benchmark run. For rows that matter operationally, record the two comparison families inline: Rust actual vs current Go backend, and Rust actual vs previous Rust commit. Leave comparison cells as `-` when not applicable.

The `update-run-perf` tools command runs the current Rust release harness and current Go harness every time. For the previous Rust commit, it reuses a persistent `/tmp` cache keyed by repo path, commit, and rounds; when needed it refreshes a cached worktree and rewrites the cached previous-commit result before prepending the three rows to this table.

| Date | Backend | Profile | Rounds | Commit | p50 ms | p95 ms | p99 ms | max ms | drop_total | Baseline Check | Go Ref | vs Go p50 | vs Go p95 | vs Go p99 | vs Go max | vs Go drop | Prev Commit Ref | vs Prev p50 | vs Prev p95 | vs Prev p99 | vs Prev max | vs Prev drop | Notes |
|---|---|---|---:|---|---:|---:|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---|
| 2026-03-17 | Rust | release (ThinLTO) | 4000 | `04965b92` | 0.001 | 0.005 | 0.006 | 0.069 | 0 | pass | Go default same run | +0.000 | +0.003 | +0.003 | -0.040 | +0 | `ad55f96c` | +0.000 | +0.002 | +0.002 | +0.014 | +0 | Auto-updated current reference Rust run (perf: tighten verdict fast-path and prune perf history); workspace dirty. |
| 2026-03-17 | Go | default | 4000 | `04965b92` | 0.001 | 0.002 | 0.003 | 0.109 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-17 | Rust | release (ThinLTO) | 4000 | `ad55f96c` | 0.001 | 0.003 | 0.004 | 0.055 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (harness: enforce low-noise Go logging for parity runs) using cached previous-commit worktree/results when available. |
| 2026-03-17 | Rust | release (ThinLTO) | 2000 | `04965b92` | 0.001 | 0.003 | 0.004 | 0.069 | 0 | pass | Go default same run | +0.000 | +0.001 | +0.001 | +0.041 | +0 | `ad55f96c` | +0.000 | +0.001 | +0.000 | +0.019 | +0 | Auto-updated current reference Rust run (perf: tighten verdict fast-path and prune perf history); workspace dirty. |
| 2026-03-17 | Go | default | 2000 | `04965b92` | 0.001 | 0.002 | 0.003 | 0.028 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-17 | Rust | release (ThinLTO) | 2000 | `ad55f96c` | 0.001 | 0.002 | 0.004 | 0.050 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (harness: enforce low-noise Go logging for parity runs) using cached previous-commit worktree/results when available. |
| 2026-03-17 | Rust | release (ThinLTO) | 2000 | `7c8761f7` | 0.001 | 0.005 | 0.006 | 0.061 | 0 | pass | Go default same run | +0.000 | +0.004 | +0.004 | -0.006 | +0 | `f8b69bac` | +0.000 | +0.003 | +0.003 | +0.021 | +0 | Auto-updated current reference Rust run (perf: adapt kernel fanout batch for fairer scheduling); workspace dirty. |
| 2026-03-17 | Go | default | 2000 | `7c8761f7` | 0.001 | 0.001 | 0.002 | 0.067 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-17 | Rust | release (ThinLTO) | 2000 | `f8b69bac` | 0.001 | 0.002 | 0.003 | 0.040 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (perf: batch kernel ingress fanout and refresh perf baseline) using cached previous-commit worktree/results when available. |
| 2026-03-17 | Rust | release (ThinLTO) | 2000 | `f8b69bac` | 0.001 | 0.002 | 0.003 | 0.065 | 0 | pass | Go default same run | +0.000 | +0.001 | +0.001 | -0.092 | +0 | `352b1f14` | +0.000 | -0.002 | -0.003 | +0.028 | +0 | Auto-updated current reference Rust run (perf: batch kernel ingress fanout and refresh perf baseline); workspace dirty. |
| 2026-03-17 | Go | default | 2000 | `f8b69bac` | 0.001 | 0.001 | 0.002 | 0.157 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-17 | Rust | release (ThinLTO) | 2000 | `352b1f14` | 0.001 | 0.004 | 0.006 | 0.037 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (perf: enforce release parity policy and streamline kernel ingress dispatch) using cached previous-commit worktree/results when available. |
| 2026-03-15 | Rust | release | 2000 | - | 0.009 | 0.013 | 0.019 | 0.127 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Initial historical baseline anchor. |
| 2026-03-15 | Go | default | 2000 | - | 0.004 | 0.009 | 0.015 | 0.209 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Initial historical baseline anchor. |

## Hot/Cold Parity Matrix History

Track cross-backend harness results that validate both hot-path and cold-path behavior equivalence gates.

| Date | Matrix Target | Rounds | Commit | Hot-Path Go | Hot-Path Rust | Cold-Path Go | Cold-Path Rust | Result | Notes |
|---|---|---:|---|---|---|---|---|---|---|
| 2026-03-16 | `make parity-hot-cold-matrix` | 500 | `7b0f3508` | pass (`p50=0.001`, `p95=0.003`, `p99=0.010`, `max=0.127`, `drop_total=0`) | pass (`p50=0.001`, `p95=0.005`, `p99=0.009`, `max=0.035`, `drop_total=0`) | pass (`rule.TestLiveReload`, `ui.TestClientReloadingConfig`, `tasks.TestTaskManager`) | pass (`services::watch_service::tests::`, `services::config_service::tests::`, `commands::task_runtime::tests::`) | PASS | First unified hot+cold parity matrix run after adding dedicated harness targets. |

## Hot/Cold Delta History

Track explicit Rust-vs-Go deltas emitted by `parity-hot-cold-delta`.

| Date | Delta Target | Rounds | Commit | Hot Δ p50 ms | Hot Δ p95 ms | Hot Δ p99 ms | Hot Δ max ms | Hot Δ drop_total | Cold Go total s | Cold Rust total s | Cold Δ s (Rust-Go) | Result | Notes |
|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 2026-03-17 | `make parity-hot-cold-delta` | 4000 | `04965b92` | +0.001 | +0.001 | +0.001 | -0.030 | +0 | 13.995 | 13.980 | -0.015 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-17 | `make parity-hot-cold-delta` | 2000 | `04965b92` | +0.000 | +0.002 | +0.002 | -0.046 | +0 | 13.989 | 14.002 | +0.013 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-17 | `make parity-hot-cold-delta` | 2000 | `7c8761f7` | +0.000 | +0.002 | +0.001 | -0.092 | +0 | 13.984 | 13.982 | -0.002 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-17 | `make parity-hot-cold-delta` | 2000 | `f8b69bac` | +0.000 | +0.000 | +0.000 | -0.025 | +0 | 14.011 | 13.981 | -0.030 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-17 | `make parity-hot-cold-delta` | 2000 | `352b1f14` | +0.000 | +0.000 | -0.001 | +0.041 | +0 | 13.986 | 13.989 | +0.003 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-16 | `make parity-hot-cold-delta` | 2000 | working-tree | +0.000 | -0.001 | -0.002 | -0.133 | +0 | 13.990 | 13.971 | -0.019 | PASS | Prior 2000-round reference before current optimization cycle. |
