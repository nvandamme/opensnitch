# Perf Tracker

Track stress-profile harness runs for Rust and Go backends.

## Harness Commands

- Rust (release):
  - `cd daemon-rs && OPENSNITCH_STRESS_ROUNDS=1000 cargo test --release -p opensnitchd-rs stress_profile_reports_connect_latency_and_pipeline_drops -- --ignored --nocapture`
  - `cd daemon-rs && RUST_LOG=error OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1 cargo test --release -p opensnitchd-rs stress_profile_reports_kernel_pipeline_pressure -- --ignored --nocapture`
  - `cd daemon-rs && RUST_LOG=error OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1 cargo test --release -p opensnitchd-rs stress_profile_reports_kernel_pipeline_timeout_sweep -- --ignored --nocapture`
- Go:
  - `cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=error OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=1000 go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v`
- Combined:
  - `make profile-backends STRESS_ROUNDS=1000`
  - `make daemon-rs-kernel-profile-harness`
- Hot-path parity matrix slice (Go + Rust):
  - `make parity-hot-path-harness STRESS_ROUNDS=1000`
- Cold-path parity matrix slice (watch/reload behavior, Go + Rust):
  - `make parity-cold-path-harness`
- Full parity matrix gate:
  - `make parity-hot-cold-matrix STRESS_ROUNDS=1000`
- Full parity matrix gate with computed deltas:
  - `make parity-hot-cold-delta STRESS_ROUNDS=1000`
- Update tracker automatically:
  - `make update-run-perf STRESS_ROUNDS=1000`
  - `STRESS_ROUNDS=1000 cargo run --release --manifest-path daemon-rs/Cargo.toml -p tools -- update-run-perf`
  - `OPENSNITCH_PARITY_STRESS_ROUNDS` defaults to `1000` for tools parity harness runs (`update-run-perf` and `parity-gate`).
  - `update-run-perf` always updates `Hot/Cold Delta History` via `make parity-hot-cold-delta`.
  - `OPENSNITCH_PERF_REFRESH_BASE=1` forces a fresh previous-commit Rust benchmark instead of using the cache.
  - `OPENSNITCH_PERF_CACHE_DIR=/custom/path` overrides the default `/tmp` cache location used by the tools crate.

Rust perf/stress profiling must always use `--release`.
All Rust harness/perf test commands must run with WARN/ERROR-only logging (`RUST_LOG=warn` or `RUST_LOG=error`); debug/trace log levels are disallowed for performance runs.
`stress_profile_reports_connect_latency_and_pipeline_drops` and `stress_profile_reports_kernel*` enforce this policy at test runtime.
All Go harness/perf test commands must run with `OPENSNITCH_HARNESS_GO_LOG_LEVEL=error` (or `err`) for apples-to-apples low-noise comparisons.
`make parity-hot-cold-delta` now parses `cold-profile ... elapsed_s=` lines emitted by each Go/Rust cold-path subtest (`rule`, `ui`, `tasks`) instead of shell timing wrappers.
Rust cold-path commands in parity harness targets should use current concrete test paths (`tests::watch_service::...`, `daemon::tests::...`) to avoid false zero-test timings.
Tools-based perf commands (`update-run-perf`, `parity-gate`, `microbench-connect-dispatch`) enforce low-noise Rust logs via `OPENSNITCH_PERF_RUST_LOG_LEVEL` (default `error`) and fail fast on noisy values.
Tools-based perf/parity commands also enforce low-noise Go harness logging via `OPENSNITCH_PERF_GO_LOG_LEVEL` (default `error`) and fail fast on non-ERR/ERROR values.
Compare only like-for-like profiles for retained history entries.

ThinLTO for release is enforced in `daemon-rs/Cargo.toml` under `[profile.release]`.

## Hot-Path Engineering Policy (Crate-Wide)

This policy applies to `daemon-rs/crates/daemon/src/**` and should be treated as a default for all runtime-path code.

1. Avoid costly async calls in critical hot paths.
- Prefer `try_send` fast paths for mpsc channels.
- Await only on explicit backpressure (`Full`) fallback.
- Do not introduce async wrappers that only call another async function without adding logic.
- In decision loops, keep awaits limited to operations that are truly async-bound (network, disk, channel backpressure, blocking interop).

2. Use direct Arc snapshot reads for runtime state.
- Runtime/config snapshots should be read as `Arc<...>` whenever possible.
- Avoid value-clone snapshot helpers in hot paths.
- Build-once/publish-once snapshot updates are preferred for reloadable state.

3. Allowed exceptions.
- Use awaited send as the primary path only when ordering/backpressure semantics require it.
- Value snapshots are acceptable in tests and one-shot cold control paths where clarity is more important than micro-optimization.
- If an API must remain value-returning for compatibility, document the reason in code review notes.

4. Review checklist for hot-path touching PRs.
- Confirm no new unnecessary `.send(...).await` was added in hot loops.
- Confirm new snapshot reads are Arc-based where practical.
- Confirm no extra parse/clone work was added in per-packet/per-event paths.
- Run targeted crate tests plus at least one parity/perf harness when behavior allows.

Policy audit command:
- `make daemon-rs-async-send-audit`
- `make daemon-rs-snapshot-clone-audit`

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
| 2026-03-19 | Rust | release (ThinLTO) | 10000 | `5dacbb86` | 0.001 | 0.004 | 0.006 | 0.103 | 0 | pass | Go default same run | +0.000 | +0.002 | +0.002 | -0.089 | +0 | `60b478c8` | +0.000 | +0.002 | +0.002 | +0.040 | +0 | Auto-updated current reference Rust run (parity: align go runtimeprofile loop semantics and rust ui-miss verdict flow); workspace dirty. |
| 2026-03-19 | Go | default | 10000 | `5dacbb86` | 0.001 | 0.002 | 0.004 | 0.192 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-19 | Rust | release (ThinLTO) | 10000 | `60b478c8` | 0.001 | 0.002 | 0.004 | 0.063 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: speed up hot-path parity harness and refresh perf baselines) using cached previous-commit worktree/results when available. |
| 2026-03-19 | Rust | release (ThinLTO) | 10000 | `d9340a45` | 0.001 | 0.003 | 0.003 | 0.072 | 0 | pass | Go default same run | +0.000 | +0.001 | -0.001 | -0.177 | +0 | `04bc9f84` | +0.000 | +0.000 | -0.002 | +0.029 | +0 | Auto-updated current reference Rust run (daemon-rs: align notification/task runtime flow with Go parity); workspace dirty. |
| 2026-03-19 | Go | default | 10000 | `d9340a45` | 0.001 | 0.002 | 0.004 | 0.249 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-19 | Rust | release (ThinLTO) | 10000 | `04bc9f84` | 0.001 | 0.003 | 0.005 | 0.043 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: numeric IP hot path + scoped list matching prep) using cached previous-commit worktree/results when available. |
| 2026-03-19 | Rust | release (ThinLTO) | 4000 | `2523b4c9` | 0.001 | 0.004 | 0.005 | 0.075 | 0 | pass | Go default same run | +0.000 | +0.002 | +0.001 | +0.023 | +0 | unavailable | n/a | Auto-updated current reference Rust run (refactor daemon-rs runtime, workers, services, and tests); workspace dirty. |
| 2026-03-19 | Go | default | 4000 | `2523b4c9` | 0.001 | 0.002 | 0.004 | 0.052 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-19 | Rust | release (ThinLTO) | 4000 | `3ad71062` | unavailable | fail | - | - | - | - | - | - | - | - | - | - | - | - | Previous-commit benchmark unavailable (build/compat issue in previous commit). |
| 2026-03-19 | Rust | release (ThinLTO) | 4000 | `2523b4c9` | 0.001 | 0.002 | 0.003 | 0.073 | 0 | pass | Go default same run | +0.000 | +0.001 | +0.000 | -0.007 | +0 | unavailable | n/a | Auto-updated current reference Rust run (refactor daemon-rs runtime, workers, services, and tests); workspace dirty. |
| 2026-03-19 | Go | default | 4000 | `2523b4c9` | 0.001 | 0.001 | 0.003 | 0.080 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-19 | Rust | release (ThinLTO) | 4000 | `3ad71062` | unavailable | fail | - | - | - | - | - | - | - | - | - | - | - | - | Previous-commit benchmark unavailable (build/compat issue in previous commit). |
| 2026-03-19 | Rust | release (ThinLTO) | 4000 | `2523b4c9` | 0.002 | 0.002 | 0.003 | 0.085 | 0 | pass | Go default same run | +0.001 | +0.000 | +0.000 | +0.019 | +0 | unavailable | n/a | Auto-updated current reference Rust run (refactor daemon-rs runtime, workers, services, and tests); workspace dirty. |
| 2026-03-19 | Go | default | 4000 | `2523b4c9` | 0.001 | 0.002 | 0.003 | 0.066 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-19 | Rust | release (ThinLTO) | 4000 | `3ad71062` | unavailable | fail | - | - | - | - | - | - | - | - | - | - | - | - | Previous-commit benchmark unavailable (build/compat issue in previous commit). |
| 2026-03-19 | Rust | release (ThinLTO) | 4000 | `2523b4c9` | 0.001 | 0.005 | 0.006 | 0.094 | 0 | pass | Go default same run | +0.000 | +0.002 | +0.002 | -0.023 | +0 | unavailable | n/a | Auto-updated current reference Rust run (refactor daemon-rs runtime, workers, services, and tests); workspace dirty. |
| 2026-03-19 | Go | default | 4000 | `2523b4c9` | 0.001 | 0.003 | 0.004 | 0.117 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-19 | Rust | release (ThinLTO) | 4000 | `3ad71062` | unavailable | fail | - | - | - | - | - | - | - | - | - | - | - | - | Previous-commit benchmark unavailable (build/compat issue in previous commit). |
| 2026-03-19 | Rust | release (ThinLTO) | 4000 | `2523b4c9` | 0.001 | 0.004 | 0.005 | 0.093 | 0 | pass | Go default same run | +0.000 | +0.002 | +0.002 | -0.207 | +0 | unavailable | n/a | Auto-updated current reference Rust run (refactor daemon-rs runtime, workers, services, and tests); workspace dirty. |
| 2026-03-19 | Go | default | 4000 | `2523b4c9` | 0.001 | 0.002 | 0.003 | 0.300 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-19 | Rust | release (ThinLTO) | 4000 | `3ad71062` | unavailable | fail | - | - | - | - | - | - | - | - | - | - | - | - | Previous-commit benchmark unavailable (build/compat issue in previous commit). |
| 2026-03-18 | Rust | release (ThinLTO) | 4000 | `3246981b` | 0.001 | 0.002 | 0.003 | 0.079 | 0 | pass | Go default same run | +0.000 | +0.000 | +0.000 | +0.006 | +0 | `4695ea75` | -0.001 | -0.001 | +0.000 | +0.019 | +0 | Auto-updated current reference Rust run (release: prepare v0.1.0); workspace dirty. |
| 2026-03-18 | Go | default | 4000 | `3246981b` | 0.001 | 0.002 | 0.003 | 0.073 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-18 | Rust | release (ThinLTO) | 4000 | `4695ea75` | 0.002 | 0.003 | 0.003 | 0.060 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (Align daemon-rs runtime behavior with Go parity) using cached previous-commit worktree/results when available. |
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

| Date | Delta Target | Rounds | Commit | Hot Mixed Go verdict ms | Hot Mixed Rust verdict ms | Hot Mixed Δ ms (Rust-Go) | Hot Throughput Go time/op us | Hot Throughput Rust time/op us | Hot Throughput Go op/s | Hot Throughput Rust op/s | Hot Δ p50 ms | Hot Δ p95 ms | Hot Δ p99 ms | Hot Δ max ms | Hot Δ drop_total | Cold Go rule s | Cold Rust rule s | Cold Δ rule s | Cold Go ui s | Cold Rust ui s | Cold Δ ui s | Cold Go tasks s | Cold Rust tasks s | Cold Δ tasks s | Cold Go total s | Cold Rust total s | Cold Δ total s (Rust-Go) | Result | Notes |
|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 2026-03-19 | `make parity-hot-cold-delta` | 10000 | `5dacbb86` | 0.074 | 0.017 | -0.057 | 1.321 | 1.805 | 756757.3 | 553978.9 | +0.000 | +0.002 | +0.001 | -0.252 | +0 | 0.100 | 0.401 | +0.301 | 4.001 | 4.001 | +0.000 | 0.000 | 0.244 | +0.244 | 4.101 | 4.402 | +0.301 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-19 | `make parity-hot-cold-delta` | 10000 | `d9340a45` | 0.012 | 0.010 | -0.002 | 1.484 | 1.954 | 673628.9 | 511714.6 | +0.000 | +0.003 | +0.002 | -0.376 | +0 | 0.101 | 0.401 | +0.300 | 4.001 | 4.205 | +0.204 | 0.000 | 0.244 | +0.244 | 4.102 | 4.606 | +0.504 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-19 | `make parity-hot-cold-delta` | 4000 | `2523b4c9` | 0.081 | 0.280 | +0.199 | 1.461 | 1.978 | 684235.9 | 505687.5 | +0.001 | -0.001 | +0.000 | -0.016 | +0 | 3.001 | 2.802 | -0.199 | 4.000 | 4.005 | +0.005 | 0.000 | 0.244 | +0.244 | 7.001 | 6.807 | -0.194 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-19 | `make parity-hot-cold-delta` | 4000 | `2523b4c9` | 0.014 | 0.236 | +0.222 | 1.431 | 2.570 | 698997.8 | 389136.7 | +0.000 | +0.003 | +0.002 | -0.075 | +0 | 3.001 | 2.801 | -0.200 | 4.001 | 4.205 | +0.204 | 0.000 | 0.244 | +0.244 | 7.002 | 7.006 | +0.004 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-19 | `make parity-hot-cold-delta` | 4000 | `2523b4c9` | 0.005 | 0.255 | +0.250 | 1.415 | 2.160 | 706809.1 | 462993.1 | +0.000 | +0.001 | +0.000 | -0.014 | +0 | 3.002 | 2.805 | -0.197 | 10.006 | 12.208 | +2.202 | 0.000 | 0.244 | +0.244 | 13.008 | 15.257 | +2.249 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-19 | `make parity-hot-cold-delta` | 4000 | `2523b4c9` | 0.029 | 0.350 | +0.321 | 1.298 | 2.133 | 770346.6 | 468815.4 | +0.000 | +0.001 | +0.000 | -0.017 | +0 | 3.001 | 2.806 | -0.195 | 10.006 | 12.208 | +2.202 | 0.000 | 0.245 | +0.245 | 13.007 | 15.259 | +2.252 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-19 | `make parity-hot-cold-delta` | 4000 | `2523b4c9` | 0.044 | 0.216 | +0.172 | 1.429 | 1.920 | 699898.1 | 520888.6 | +0.000 | +0.000 | -0.001 | -0.151 | +0 | 3.000 | 2.606 | -0.394 | 10.006 | 12.210 | +2.204 | 0.000 | 0.245 | +0.245 | 13.006 | 15.061 | +2.055 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-18 | `make parity-hot-cold-delta` | 4000 | `3246981b` | 0.006 | 0.217 | +0.211 | 1.072 | 1.905 | 933231.1 | 524804.2 | +0.000 | +0.000 | +0.000 | -0.045 | +0 | 3.001 | 2.805 | -0.196 | 10.006 | 12.209 | +2.203 | 0.000 | 0.244 | +0.244 | 13.007 | 15.258 | +2.251 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-17 | `make parity-hot-cold-delta` | 4000 | `04965b92` | +0.001 | +0.001 | +0.001 | -0.030 | +0 | 13.995 | 13.980 | -0.015 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-17 | `make parity-hot-cold-delta` | 2000 | `04965b92` | +0.000 | +0.002 | +0.002 | -0.046 | +0 | 13.989 | 14.002 | +0.013 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-17 | `make parity-hot-cold-delta` | 2000 | `7c8761f7` | +0.000 | +0.002 | +0.001 | -0.092 | +0 | 13.984 | 13.982 | -0.002 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-17 | `make parity-hot-cold-delta` | 2000 | `f8b69bac` | +0.000 | +0.000 | +0.000 | -0.025 | +0 | 14.011 | 13.981 | -0.030 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-17 | `make parity-hot-cold-delta` | 2000 | `352b1f14` | +0.000 | +0.000 | -0.001 | +0.041 | +0 | 13.986 | 13.989 | +0.003 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-16 | `make parity-hot-cold-delta` | 2000 | working-tree | +0.000 | -0.001 | -0.002 | -0.133 | +0 | 13.990 | 13.971 | -0.019 | PASS | Prior 2000-round reference before current optimization cycle. |
