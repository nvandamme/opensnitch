# Perf Tracker

Track stress-profile harness runs for Rust and Go backends.

## Harness Commands

- Rust (release):
  - `cd daemon-rs && OPENSNITCH_STRESS_ROUNDS=2000 cargo test --release -p opensnitchd-rs stress_profile_reports_connect_latency_and_pipeline_drops -- --ignored --nocapture`
- Go:
  - `cd daemon && OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=2000 go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v`
- Combined:
  - `make profile-backends STRESS_ROUNDS=2000`
- Update tracker automatically:
  - `make update-run-perf STRESS_ROUNDS=2000`
  - `STRESS_ROUNDS=2000 cargo run --manifest-path daemon-rs/Cargo.toml -p tools -- update-run-perf`
  - `OPENSNITCH_PERF_REFRESH_BASE=1` forces a fresh previous-commit Rust benchmark instead of using the cache.
  - `OPENSNITCH_PERF_CACHE_DIR=/custom/path` overrides the default `/tmp` cache location used by the tools crate.

Rust perf/stress profiling must always use `--release`.
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
| 2026-03-16 | Rust | release (ThinLTO) | 2000 | `a7b1f7d5` | 0.001 | 0.005 | 0.006 | 0.036 | 0 | pass | Go default same run | +0.000 | +0.003 | +0.002 | -0.026 | +0 | `82c2f859` | -0.002 | +0.001 | +0.000 | -0.016 | +0 | Auto-updated current reference Rust run (daemon-rs: add daemon-owned fast-allow telemetry counter); workspace dirty. |
| 2026-03-16 | Go | default | 2000 | `a7b1f7d5` | 0.001 | 0.002 | 0.004 | 0.062 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-16 | Rust | release (ThinLTO) | 2000 | `82c2f859` | 0.003 | 0.004 | 0.006 | 0.052 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: unify worker control runtime and perf regression guards) measured in isolated worktree. |
| 2026-03-15 | Rust | release | 2000 | - | 0.009 | 0.013 | 0.019 | 0.127 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Initial release baseline row. |
| 2026-03-15 | Go | default | 2000 | - | 0.004 | 0.009 | 0.015 | 0.209 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Initial Go baseline row. |
| 2026-03-16 | Go | default (avg x3) | 2000 | - | 0.003 | 0.007 | 0.011 | 0.416 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Averaged Go baseline row. |
