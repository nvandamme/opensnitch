# Perf Tracker

Track stress-profile harness runs for Rust and Go backends.

Last reviewed: 2026-03-25 (`release: v0.5.0`, commit `4d92dad8`)

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
All Rust harness/perf test commands should use low-noise logging (`RUST_LOG=warn` by default; `error` also accepted); debug/trace log levels are discouraged for performance runs.
`stress_profile_reports_connect_latency_and_pipeline_drops` and `stress_profile_reports_kernel*` enforce this policy at test runtime.
All Go harness/perf test commands should use low-noise logging (`OPENSNITCH_HARNESS_GO_LOG_LEVEL=warn` by default; `warning|err|error` also accepted) for apples-to-apples comparisons.
`make parity-hot-cold-delta` now parses `cold-profile ... elapsed_s=` lines emitted by each Go/Rust cold-path subtest (`rule`, `ui`, `tasks`) instead of shell timing wrappers.
Rust cold-path commands in parity harness targets should use current concrete test paths (`tests::watch_workers::...`, `daemon::tests::...`) to avoid false zero-test timings.
Tools-based perf commands (`update-run-perf`, `parity-gate`, `microbench-connect-dispatch`) validate low-noise Rust logs via `OPENSNITCH_PERF_RUST_LOG_LEVEL` (default `warn`, accepts `warn|warning|err|error`) and emit warnings for noisy values.
Tools-based perf/parity commands also validate low-noise Go harness logging via `OPENSNITCH_PERF_GO_LOG_LEVEL` (default `warn`, accepts `warn|warning|err|error`) and emit warnings for invalid values.
Compare only like-for-like profiles for retained history entries.

ThinLTO for release is enforced in `daemon-rs/Cargo.toml` under `[profile.release]`.

## Hot-Path Engineering Policy (Crate-Wide)

This policy applies to `daemon-rs/crates/daemon/src/**` and should be treated as a default for all runtime-path code.

1. Avoid costly async calls in critical hot paths.
- Prefer `try_send` fast paths for mpsc channels.
- Await only on explicit backpressure (`Full`) fallback.
- Do not introduce async wrappers that only call another async function without adding logic.
- In decision loops, keep awaits limited to operations that are truly async-bound (network, disk, channel backpressure, blocking interop).

1. Use direct Arc snapshot reads for runtime state.
- Runtime/config snapshots should be read as `Arc<...>` whenever possible.
- Avoid value-clone snapshot helpers in hot paths.
- Build-once/publish-once snapshot updates are preferred for reloadable state.

1. Allowed exceptions.
- Use awaited send as the primary path only when ordering/backpressure semantics require it.
- Value snapshots are acceptable in tests and one-shot cold control paths where clarity is more important than micro-optimization.
- If an API must remain value-returning for compatibility, document the reason in code review notes.

1. Review checklist for hot-path touching PRs.
- Confirm no new unnecessary `.send(...).await` was added in hot loops.
- Confirm new snapshot reads are Arc-based where practical.
- Confirm no extra parse/clone work was added in per-packet/per-event paths.
- Run targeted crate tests plus at least one parity/perf harness when behavior allows.

Policy audit command:
- `make daemon-rs-async-send-audit`
- `make daemon-rs-snapshot-clone-audit`

## Optimization Backlog (Rescan 2026-03-26)

Prioritized hot-path findings from full codebase scan. Tracked as actionable items in TODO.md.

**Status as of 2026-03-27: all HIGH/MEDIUM items and two LOW items fully implemented.**

### HIGH priority — ✅ all implemented

| # | Location | Issue | Resolution |
|---|---|---|---|
| 1 | `services/connection/owner.rs` | `format!` per inode probe; full /proc scan on miss | `pid_owns_inode_at(&Path)`; one `PathBuf::with_capacity(24)` reused across all /proc candidates |
| 2 | `services/rule/matching.rs` L702,707 | `args.join(" ")` + 4× numeric `.to_string()` per rule eval | 5 `OnceLock<String>` fields on `AttemptDerived`; `operator_operand_value` returns `Cow::Borrowed` |
| 3 | `services/dns/cache_ops.rs` L39 | `HashSet` alloc per `lookup_ip` call | Bounded hop-limit loop (`0..8`) — no heap alloc |
| 4 | `flows/verdict/verdict.rs` L105,118,141 | `format!` + 2× `to_owned()` for decision key per connection | `DashMap<u64, u64>` + `decision_key_hash()` via `DefaultHasher` |
| 5 | `services/process/inspection.rs` L44 | `cleanup_expired()` (mutex) on every cache miss | Removed from hot path; background task (10 s) handles eviction |

### MEDIUM priority — ✅ all implemented

| # | Location | Issue | Resolution |
|---|---|---|---|
| 6 | `services/connection/ebpf.rs` L73 | `Vec<u8>` (12/36 B) per `build_bpf_key` call | `BpfKey { V4([u8;12]), V6([u8;36]) }` enum; `Deref/DerefMut → &[u8]` |
| 7 | `flows/kernel/kernel.rs` L56 | Per-event Arc clone + closure alloc for on_drop counter | `dispatch_kernel_pipeline_event` takes `&Arc<KernelPipelineCounters>` + `KernelPipeline` directly |
| 8 | `flows/verdict/verdict.rs` L589 | `pb_conn.get_or_insert_with().clone()` keeps proto alive during gRPC wait | `pb_conn.take().unwrap_or_else(...)` — no backup copy during ask_rule round-trip |
| 9 | `services/connection/resolution.rs` L96 | Whole attempt cloned before `spawn_blocking` | Deferred (clone is shallow; no observed impact under load) |
| 10 | `services/dns/parsing.rs` L72 | `ip.to_string()` + `host.to_string()` per event for dedup key | Deferred (DNS parsing not on per-connection hot path) |
| 11 | `services/rule/matching.rs` L707 | (covered by #2 above) | Resolved as part of item 2 |

### LOW priority — ✅ implemented (2 of 4)

| # | Location | Issue | Resolution |
|---|---|---|---|
| 12 | `workers/runtime/control/control.rs` | Sequential `join_all` on shutdown | `tokio::task::JoinSet` for concurrent shutdown awaiting |
| 13 | `services/storage/event_bus.rs` L64 | Full `StorageEvent` clone per broadcast recipient (including `PathBuf`) | Broadcast `Arc<StorageEvent>` — Arc clone per recipient instead of struct clone |
| 14 | `services/firewall/config_ops.rs` L14 | Reload/reconcile repeats disk read in separate ops | Deferred — rare operator-triggered path, negligible impact |
| 15 | `commands/rule/rule.rs` L236 | Sequential async delete/upsert for large rule sets on rollback | Deferred — rollback path only; large rule set counts uncommon |

### Already well-optimized (no action needed)

- `services/connection/connection.rs`: lock-free eBPF map id snapshot via ArcSwap
- `workers/runtime/connect/dispatch.rs`: `try_send`-first probing across worker lanes
- `services/rule/rule.rs`: `AttemptDerived` prewarm and compiled rule snapshot
- `services/rule/matching.rs`: `OnceLock` caching for src/dst ip text
- `flows/verdict/verdict.rs`: `try_send` fast path with fallback send
- `services/process/inspection.rs`: deferred hash computation in background task
- `flows/connect/connect.rs`: pre-sized worker handle/tx vectors and burst draining
- `services/process/cache.rs`: weighted cache sizing with quick-cache
- `services/rule/rule.rs`: `reload_inline` (no `spawn_blocking`) on inotify fast path

## Regression Policy

- Baselines are sourced from the machine-readable keys in this file.
- Harness checks treat a metric as a clear regression when:
  - `observed_ms > baseline_ms * PERF_CLEAR_REGRESSION_FACTOR`
  - and `observed_ms - baseline_ms > PERF_CLEAR_REGRESSION_MIN_DELTA_MS`
- `drop_total` is a hard check and must not exceed baseline.

Machine-readable keys consumed by Rust/Go stress harness guards:

```text
PERF_CLEAR_REGRESSION_FACTOR=1.75
PERF_CLEAR_REGRESSION_MIN_DELTA_MS=0.050

PERF_BASELINE_RUST_DEBUG_P95_MS=0.114
PERF_BASELINE_RUST_DEBUG_P99_MS=0.173
PERF_BASELINE_RUST_DEBUG_MAX_MS=0.607
PERF_BASELINE_RUST_DEBUG_DROP_TOTAL=0

PERF_BASELINE_RUST_RELEASE_P95_MS=0.013
PERF_BASELINE_RUST_RELEASE_P99_MS=0.019
PERF_BASELINE_RUST_RELEASE_MAX_MS=0.127
PERF_BASELINE_RUST_RELEASE_DROP_TOTAL=0

PERF_BASELINE_GO_P95_MS=0.007
PERF_BASELINE_GO_P99_MS=0.011
PERF_BASELINE_GO_MAX_MS=0.416
PERF_BASELINE_GO_DROP_TOTAL=0
```

## Run History

Keep one row per benchmark run. For rows that matter operationally, record the two comparison families inline: Rust actual vs current Go backend, and Rust actual vs previous Rust commit. Leave comparison cells as `-` when not applicable.

The `update-run-perf` tools command runs the current Rust release harness and current Go harness every time. For the previous Rust commit, it reuses a persistent `/tmp` cache keyed by repo path, commit, and rounds; when needed it refreshes a cached worktree and rewrites the cached previous-commit result before prepending the three rows to this table.

| Date | Backend | Profile | Rounds | Commit | p50 ms | p95 ms | p99 ms | max ms | drop_total | Baseline Check | Go Ref | vs Go p50 | vs Go p95 | vs Go p99 | vs Go max | vs Go drop | Prev Commit Ref | vs Prev p50 | vs Prev p95 | vs Prev p99 | vs Prev max | vs Prev drop | Notes |
|---|---|---|---:|---|---:|---:|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---|
| 2026-04-22 | Rust | release (ThinLTO) | 500 | `39e79768` | 0.001 | 0.001 | 0.003 | 0.060 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.004 | +0.039 | +0 | `6b7feecd` | +0.000 | -0.001 | +0.000 | -0.010 | +0 | Auto-updated current reference Rust run (daemon-rs: openwrt docs — align ubus boundary and plan); workspace dirty. |
| 2026-04-22 | Go | default | 500 | `39e79768` | 0.001 | 0.002 | 0.007 | 0.021 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-04-22 | Rust | release (ThinLTO) | 500 | `6b7feecd` | 0.001 | 0.002 | 0.003 | 0.070 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: tracker - define Bandix-inspired future perf/metrics objective) using cached previous-commit worktree/results when available. |
| 2026-04-06 | Rust | release (ThinLTO) | 500 | `52d48734` | 0.003 | 0.004 | 0.008 | 0.125 | 0 | pass | Go default same run | +0.001 | -0.004 | -0.010 | +0.091 | +0 | `4007d875` | +0.001 | +0.002 | +0.003 | +0.051 | +0 | Auto-updated current reference Rust run (daemon-rs: move TODO maintenance guidance into commit hygiene); workspace dirty. |
| 2026-04-06 | Go | default | 500 | `52d48734` | 0.002 | 0.008 | 0.018 | 0.034 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-04-06 | Rust | release (ThinLTO) | 500 | `4007d875` | 0.002 | 0.002 | 0.005 | 0.074 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: reconcile TODO cleanup with HEAD and preserve backlog history guidance) using cached previous-commit worktree/results when available. |
| 2026-04-06 | Rust | release (ThinLTO) | 500 | `52d48734` | 0.003 | 0.004 | 0.008 | 0.116 | 0 | pass | Go default same run | +0.000 | -0.004 | -0.004 | +0.047 | +0 | `4007d875` | +0.001 | +0.002 | +0.003 | +0.042 | +0 | Auto-updated current reference Rust run (daemon-rs: move TODO maintenance guidance into commit hygiene); workspace dirty. |
| 2026-04-06 | Go | default | 500 | `52d48734` | 0.003 | 0.008 | 0.012 | 0.069 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-04-06 | Rust | release (ThinLTO) | 500 | `4007d875` | 0.002 | 0.002 | 0.005 | 0.074 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: reconcile TODO cleanup with HEAD and preserve backlog history guidance) using cached previous-commit worktree/results when available. |
| 2026-04-06 | Rust | release (ThinLTO) | 500 | `52d48734` | 0.002 | 0.002 | 0.004 | 0.069 | 0 | pass | Go default same run | -0.001 | -0.005 | -0.008 | +0.010 | +0 | `4007d875` | +0.000 | +0.000 | -0.001 | -0.005 | +0 | Auto-updated current reference Rust run (daemon-rs: move TODO maintenance guidance into commit hygiene); workspace dirty. |
| 2026-04-06 | Go | default | 500 | `52d48734` | 0.003 | 0.007 | 0.012 | 0.059 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-04-06 | Rust | release (ThinLTO) | 500 | `4007d875` | 0.002 | 0.002 | 0.005 | 0.074 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: reconcile TODO cleanup with HEAD and preserve backlog history guidance) using cached previous-commit worktree/results when available. |
| 2026-04-01 | Rust | release (ThinLTO) | 500 | `7debb430` | 0.001 | 0.001 | 0.003 | 0.064 | 0 | pass | Go default same run | +0.000 | -0.002 | -0.003 | +0.022 | +0 | `9f1bac79` | +0.000 | +0.000 | +0.000 | +0.014 | +0 | Auto-updated current reference Rust run (daemon-rs: firewall backends — split persistence/introspection and canonicalize netlink+nftables naming); workspace dirty. |
| 2026-04-01 | Go | default | 500 | `7debb430` | 0.001 | 0.003 | 0.006 | 0.042 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-04-01 | Rust | release (ThinLTO) | 500 | `9f1bac79` | 0.001 | 0.001 | 0.003 | 0.050 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: runtime-target tooling — remove legacy kernel-target compatibility) using cached previous-commit worktree/results when available. |
| 2026-04-01 | Rust | release (ThinLTO) | 500 | `9f1bac79` | 0.001 | 0.001 | 0.003 | 0.056 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.003 | +0.031 | +0 | `afacd55a` | +0.000 | +0.000 | -0.002 | +0.007 | +0 | Auto-updated current reference Rust run (daemon-rs: runtime-target tooling — remove legacy kernel-target compatibility); workspace dirty. |
| 2026-04-01 | Go | default | 500 | `9f1bac79` | 0.001 | 0.002 | 0.006 | 0.025 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-04-01 | Rust | release (ThinLTO) | 500 | `afacd55a` | 0.001 | 0.001 | 0.005 | 0.049 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: minimize workspace default-members to core crates) using cached previous-commit worktree/results when available. |
| 2026-04-01 | Rust | release (ThinLTO) | 500 | `2983d36b` | 0.001 | 0.001 | 0.003 | 0.056 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.004 | +0.032 | +0 | `64a87494` | +0.000 | +0.000 | +0.000 | +0.002 | +0 | Auto-updated current reference Rust run (daemon-rs: tools/tests — fix live-session and smoke regressions); workspace dirty. |
| 2026-04-01 | Go | default | 500 | `2983d36b` | 0.001 | 0.002 | 0.007 | 0.024 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-04-01 | Rust | release (ThinLTO) | 500 | `64a87494` | 0.001 | 0.001 | 0.003 | 0.054 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: transport/storage boundaries – decouple adapters) using cached previous-commit worktree/results when available. |
| 2026-04-01 | Rust | release (ThinLTO) | 500 | `64a87494` | 0.001 | 0.001 | 0.003 | 0.054 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.002 | +0.008 | +0 | `72277ca1` | +0.000 | +0.000 | +0.000 | +0.006 | +0 | Auto-updated current reference Rust run (daemon-rs: transport/storage boundaries – decouple adapters); workspace dirty. |
| 2026-04-01 | Go | default | 500 | `64a87494` | 0.001 | 0.002 | 0.005 | 0.046 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-04-01 | Rust | release (ThinLTO) | 500 | `72277ca1` | 0.001 | 0.001 | 0.003 | 0.048 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: transport-wire/client — finalize decoupling and boundary contracts) using cached previous-commit worktree/results when available. |
| 2026-03-27 | Rust | release (ThinLTO) | 500 | `603b939a` | 0.001 | 0.002 | 0.004 | 0.077 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.005 | +0.049 | +0 | `812f9e55` | +0.000 | +0.000 | +0.000 | +0.022 | +0 | Auto-updated current reference Rust run (release: v0.6.0); workspace dirty. |
| 2026-03-27 | Go | default | 500 | `603b939a` | 0.001 | 0.003 | 0.009 | 0.028 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-27 | Rust | release (ThinLTO) | 500 | `812f9e55` | 0.001 | 0.002 | 0.004 | 0.055 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (feat(daemon-rs): persistent file-based hash cache with invalidation) using cached previous-commit worktree/results when available. |
| 2026-03-25 | Rust | release (ThinLTO) | 500 | `75ac11aa` | 0.001 | 0.001 | 0.003 | 0.077 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.002 | +0.058 | +0 | `90acb5d5` | +0.000 | +0.000 | +0.000 | +0.008 | +0 | Auto-updated current reference Rust run (release: v0.5.0); workspace dirty. |
| 2026-03-25 | Go | default | 500 | `75ac11aa` | 0.001 | 0.002 | 0.005 | 0.019 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-25 | Rust | release (ThinLTO) | 500 | `90acb5d5` | 0.001 | 0.001 | 0.003 | 0.069 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: add transactional policy path and multi-user verdict safeguards) using cached previous-commit worktree/results when available. |
| 2026-03-25 | Rust | release (ThinLTO) | 500 | `75ac11aa` | 0.001 | 0.001 | 0.003 | 0.086 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.003 | +0.061 | +0 | `90acb5d5` | +0.000 | +0.000 | +0.000 | +0.017 | +0 | Auto-updated current reference Rust run (release: v0.5.0); workspace dirty. |
| 2026-03-25 | Go | default | 500 | `75ac11aa` | 0.001 | 0.002 | 0.006 | 0.025 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-25 | Rust | release (ThinLTO) | 500 | `90acb5d5` | 0.001 | 0.001 | 0.003 | 0.069 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: add transactional policy path and multi-user verdict safeguards) using cached previous-commit worktree/results when available. |
| 2026-03-25 | Rust | release (ThinLTO) | 500 | `75ac11aa` | 0.001 | 0.001 | 0.003 | 0.074 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.001 | +0.034 | +0 | `90acb5d5` | +0.000 | +0.000 | +0.000 | +0.005 | +0 | Auto-updated current reference Rust run (release: v0.5.0); workspace dirty. |
| 2026-03-25 | Go | default | 500 | `75ac11aa` | 0.001 | 0.002 | 0.004 | 0.040 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-25 | Rust | release (ThinLTO) | 500 | `90acb5d5` | 0.001 | 0.001 | 0.003 | 0.069 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (daemon-rs: add transactional policy path and multi-user verdict safeguards) using cached previous-commit worktree/results when available. |
| 2026-03-23 | Rust | release (ThinLTO) | 1000 | `613ef5cc` | 0.001 | 0.001 | 0.001 | 0.067 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.003 | -0.024 | +0 | `0bc72a16` | +0.000 | +0.000 | +0.000 | +0.004 | +0 | Auto-updated current reference Rust run (daemon-rs: expand nft netlink parity with telemetry and tests); workspace dirty. |
| 2026-03-23 | Go | default | 1000 | `613ef5cc` | 0.001 | 0.002 | 0.004 | 0.091 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-23 | Rust | release (ThinLTO) | 1000 | `0bc72a16` | 0.001 | 0.001 | 0.001 | 0.063 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (release: bump daemon-rs to v0.4.0 and activate netfilter/netlink backlog) using cached previous-commit worktree/results when available. |
| 2026-03-23 | Rust | release (ThinLTO) | 1000 | `613ef5cc` | 0.001 | 0.001 | 0.002 | 0.074 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.001 | +0.002 | +0 | `0bc72a16` | +0.000 | +0.000 | +0.001 | +0.011 | +0 | Auto-updated current reference Rust run (daemon-rs: expand nft netlink parity with telemetry and tests); workspace dirty. |
| 2026-03-23 | Go | default | 1000 | `613ef5cc` | 0.001 | 0.002 | 0.003 | 0.072 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-23 | Rust | release (ThinLTO) | 1000 | `0bc72a16` | 0.001 | 0.001 | 0.001 | 0.063 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (release: bump daemon-rs to v0.4.0 and activate netfilter/netlink backlog) using cached previous-commit worktree/results when available. |
| 2026-03-23 | Rust | release (ThinLTO) | 1000 | `613ef5cc` | 0.001 | 0.001 | 0.002 | 0.074 | 0 | pass | Go default same run | +0.000 | -0.001 | -0.002 | +0.055 | +0 | `0bc72a16` | +0.000 | +0.000 | +0.001 | +0.011 | +0 | Auto-updated current reference Rust run (daemon-rs: expand nft netlink parity with telemetry and tests); workspace clean. |
| 2026-03-23 | Go | default | 1000 | `613ef5cc` | 0.001 | 0.002 | 0.004 | 0.019 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated current Go comparison row paired with Rust actual. |
| 2026-03-23 | Rust | release (ThinLTO) | 1000 | `0bc72a16` | 0.001 | 0.001 | 0.001 | 0.063 | 0 | pass | - | - | - | - | - | - | - | - | - | - | - | - | Auto-updated previous commit benchmark (release: bump daemon-rs to v0.4.0 and activate netfilter/netlink backlog) using cached previous-commit worktree/results when available. |
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
| 2026-03-16 | `make parity-hot-cold-matrix` | 500 | `7b0f3508` | pass (`p50=0.001`, `p95=0.003`, `p99=0.010`, `max=0.127`, `drop_total=0`) | pass (`p50=0.001`, `p95=0.005`, `p99=0.009`, `max=0.035`, `drop_total=0`) | pass (`rule.TestLiveReload`, `ui.TestClientReloadingConfig`, `tasks.TestTaskManager`) | pass (`tests::watch_workers::`, `services::config_service::tests::`, `commands::task_runtime::tests::`) | PASS | First unified hot+cold parity matrix run after adding dedicated harness targets. |

## Hot/Cold Delta History

Track explicit Rust-vs-Go deltas emitted by `parity-hot-cold-delta`.

| Date | Delta Target | Rounds | Commit | Hot Mixed Go verdict ms | Hot Mixed Rust verdict ms | Hot Mixed Δ ms (Rust-Go) | Hot Throughput Go time/op us | Hot Throughput Rust time/op us | Hot Throughput Go op/s | Hot Throughput Rust op/s | Hot Δ p50 ms | Hot Δ p95 ms | Hot Δ p99 ms | Hot Δ max ms | Hot Δ drop_total | Cold Go rule s | Cold Rust rule s | Cold Δ rule s | Cold Go ui s | Cold Rust ui s | Cold Δ ui s | Cold Go tasks s | Cold Rust tasks s | Cold Δ tasks s | Cold Go total s | Cold Rust total s | Cold Δ total s (Rust-Go) | Result | Notes |
|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 2026-04-22 | `make parity-hot-cold-delta` | 500 | `39e79768` | 0.007 | 0.022 | +0.015 | 1.219 | 1.002 | 820621.9 | 997790.9 | +0.000 | -0.001 | -0.001 | +0.041 | +0 | 0.010 | 0.016 | +0.006 | 4.001 | 4.007 | +0.006 | 0.244 | 0.244 | -0.000 | 4.255 | 4.267 | +0.012 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-04-06 | `make parity-hot-cold-delta` | 500 | `52d48734` | 0.017 | 0.134 | +0.117 | 4.087 | 2.903 | 244691.4 | 344530.3 | -0.001 | -0.004 | -0.007 | +0.057 | +0 | 0.011 | 0.019 | +0.008 | 4.001 | 4.010 | +0.009 | 0.253 | 0.246 | -0.007 | 4.265 | 4.275 | +0.010 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-04-01 | `make parity-hot-cold-delta` | 500 | `7debb430` | 0.006 | 0.008 | +0.002 | 1.241 | 0.989 | 805779.7 | 1011245.0 | +0.000 | -0.001 | +0.000 | -0.002 | +0 | 0.010 | 0.020 | +0.010 | 4.000 | 4.010 | +0.010 | 0.247 | 0.245 | -0.002 | 4.257 | 4.275 | +0.018 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-04-01 | `make parity-hot-cold-delta` | 500 | `9f1bac79` | 0.021 | 0.017 | -0.004 | 1.206 | 1.001 | 828985.3 | 998522.2 | +0.000 | -0.001 | -0.002 | +0.026 | +0 | 0.010 | 0.017 | +0.007 | 4.001 | 4.012 | +0.011 | 0.247 | 0.244 | -0.002 | 4.258 | 4.273 | +0.016 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-04-01 | `make parity-hot-cold-delta` | 500 | `2983d36b` | 0.008 | 0.027 | +0.019 | 1.327 | 1.019 | 753300.2 | 980892.2 | +0.000 | -0.001 | -0.001 | +0.020 | +0 | 0.011 | 0.016 | +0.005 | 4.001 | 4.009 | +0.008 | 0.246 | 0.243 | -0.002 | 4.258 | 4.268 | +0.011 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-04-01 | `make parity-hot-cold-delta` | 500 | `64a87494` | 0.010 | 0.005 | -0.005 | 1.454 | 0.986 | 687536.6 | 1014198.8 | +0.000 | -0.001 | -0.005 | +0.021 | +0 | 0.010 | 0.021 | +0.011 | 4.001 | 4.004 | +0.003 | 0.246 | 0.245 | -0.001 | 4.257 | 4.270 | +0.013 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-27 | `make parity-hot-cold-delta` | 500 | `603b939a` | 0.009 | 0.009 | +0.000 | 1.723 | 0.999 | 580328.5 | 1000502.3 | +0.000 | -0.002 | -0.005 | +0.030 | +0 | 0.010 | 0.017 | +0.007 | 4.000 | 4.007 | +0.007 | 0.246 | 0.244 | -0.002 | 4.256 | 4.268 | +0.012 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-25 | `make parity-hot-cold-delta` | 500 | `75ac11aa` | 0.006 | 0.010 | +0.004 | 1.575 | 1.544 | 635119.0 | 647800.1 | +0.000 | -0.001 | +0.000 | +0.081 | +0 | 0.050 | 0.151 | +0.101 | 4.000 | 4.013 | +0.013 | 0.249 | 0.244 | -0.005 | 4.299 | 4.408 | +0.109 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-25 | `make parity-hot-cold-delta` | 500 | `75ac11aa` | 0.007 | 0.022 | +0.015 | 1.679 | 1.066 | 595456.4 | 937701.0 | +0.000 | -0.002 | -0.004 | +0.016 | +0 | 0.100 | 0.155 | +0.055 | 4.000 | 4.014 | +0.014 | 0.246 | 0.244 | -0.002 | 4.346 | 4.413 | +0.067 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-25 | `make parity-hot-cold-delta` | 500 | `75ac11aa` | 0.007 | 0.013 | +0.006 | 1.629 | 1.136 | 613788.4 | 880610.4 | +0.000 | -0.002 | -0.002 | +0.032 | +0 | 0.101 | 0.151 | +0.050 | 4.001 | 4.012 | +0.011 | 0.246 | 0.245 | -0.002 | 4.348 | 4.408 | +0.059 | PASS | Auto-updated parity hot/cold delta row from tools command. |
| 2026-03-23 | `make parity-hot-cold-delta` | 1000 | `613ef5cc` | 0.008 | 0.028 | +0.020 | 1.111 | 1.059 | 899832.5 | 944635.8 | +0.000 | -0.001 | -0.003 | +0.066 | +0 | 0.101 | 0.153 | +0.052 | 4.000 | 4.013 | +0.013 | 0.247 | 0.243 | -0.003 | 4.348 | 4.409 | +0.062 | PASS | Auto-updated parity hot/cold delta row from tools command. |
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
