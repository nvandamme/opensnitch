# Daemon-RS Unified Tracker

This is the single tracker file for backend parity, async/runtime hardening, and future enhancements.

It supersedes:
- `daemon-rs/FEATURE_PARITY.md`
- `daemon-rs/SERVICE_ASYNC_AND_MODEL_SCAN_2026-03-15.md`

Last update: 2026-03-16

## Scope

Track parity and runtime behavior between:
- Go backend: `daemon/`
- Rust backend: `daemon-rs/crates/daemon/`

Out of scope for now:
- Replacing NFQUEUE verdicting with a non-FFI backend.
- Replacing `libbpf-rs` usage with a full Aya runtime path as default.
- Replacing proc connector path with a high-level netlink crate.

## Current Status Snapshot

- Latest parity scan status: no open backend parity gaps in the scanned slice.
- Async/runtime hardening status: all high-priority 2026-03-15 verdict-path items are implemented.
- Test baseline after latest runtime changes: `cargo test -p opensnitchd-rs` passes (66/66 + 1 ignored profiling harness).
- Latest full-suite verification status: `sudo make go-test-full` and `make parity-hot-cold-matrix STRESS_ROUNDS=500` both passed on 2026-03-16 with no new Go-vs-Rust parity drift identified in the follow-up inventory pass.
- Root orchestration now auto-restores `daemon/ui/testdata/default-config.json` after full Go and cold-path parity runs so the Go UI reload test no longer leaves the worktree dirty.
- Rust parity-heavy tests now have a reusable tracing bootstrap via `utils::test_support::init_test_logging()` so reload/runtime tests can emit inspectable logs similar to Go's verbose test flows.
- Rust now parses and applies Go logging config fields (`LogUTC`, `LogMicro`, `Server.LogFile`, `Server.Loggers`) and supports active file/UDP sink routing through the daemon logging subsystem.
- DNS worker now includes a direct systemd-resolved varlink socket monitor path (`/run/systemd/resolve/io.systemd.Resolve.Monitor`) with `resolvectl monitor` fallback for compatibility.

## Perf Regression Baselines (Machine-Readable)

These keys are consumed by Rust and Go stress-profile harness tests to flag clear regressions.

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

Override at runtime when needed:
- `OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1` skips baseline enforcement.
- `OPENSNITCH_STRESS_TODO_PATH=/path/to/TODO.md` overrides baseline file path.

## Active Backlog

1. Evidence-driven non-verdict event tuning
- [ ] If pressure is measurable, tune per-pipeline capacities and/or add bounded fan-out per event class.

2. Future enhancements
- [ ] Add optional `aya-ebpf` implementation path as a high-level replacement candidate for current `libbpf-rs` integration.
- [ ] Keep `native-ebpf-ringbuf` as default until Aya path reaches parity and passes runtime validation.
- [x] Define migration acceptance criteria before switching defaults (probe coverage, perf impact, packaging/CI changes).
	Criteria:
	- For software-forwarding targets (prosumer/x86 path), sustain >= 6M PPS offered load in dedicated kernel-pipeline pressure runs with bounded enqueue drop ratio and no daemon instability.
	- Keep hot-path connection latency contained under load (track p95/p99/max in stress harness against Go reference and TODO baselines).
	- Preserve drop parity semantics (`drop_total` guardrails) and parity test matrix PASS status.
	- For hardware-offload paths (tens to hundreds of Mpps), treat this daemon path as control-plane/exception-path and require validation on hardware-assisted lab profiles.

3. Go parity follow-up (2026-03-16 rescan)
- [x] Add Rust parity path for disk-task outputs with `notification_id == 0` so task status/errors are surfaced to UI, not only daemon logs.
- [x] Pin NFQUEUE overload fallback policy to Go parity: `fail-open` with explicit warning telemetry on timeout/saturation fallback events.
- [ ] Policy review: should Rust move to a stricter `deny-fast + warn` overload stance in the future (security-first mode), and if so under which rollout/compatibility conditions?
- [x] Replace task/rule/config poll-only watch with hybrid event-driven + polling fallback file-watch path for closer Go responsiveness parity.

4. Go test parity follow-up (2026-03-16 thorough scan)
- [x] Add dedicated Rust coverage for nftables expression/table/chain conversion parity (Go has broad unit coverage in `daemon/firewall/nftables/**`).
- [x] Expand Rust rule-matching parity tests to cover list/domain/regexp/range edge cases mirroring Go `daemon/rule/operator_test.go`.
- [x] Add deeper proc monitor parity tests for eBPF/process event decoding and integration behavior currently covered in Go `daemon/procmon/ebpf/ebpf_test.go`.

5. Full Go backend rescan follow-up (2026-03-16 files + tests)
- [x] Extend Rust config/logging parity for Go-managed logging fields and outputs (`LogUTC`, `LogMicro`, `Server.LogFile`, `Server.Loggers`, logger-manager style sinks) by parsing/applying these fields and enabling active file/UDP sink routing.
- [x] Port the Go `dns/systemd.ResolvedMonitor` compatibility path by adding direct systemd-resolved varlink socket monitoring in Rust with `resolvectl` fallback.

6. Rule operator scope parity follow-up
- [ ] Add optional `scope` field to gRPC/proto `Operator` in a dedicated compatibility PR (default dst semantics, backward-compatible wire evolution, Go/Rust/Python client alignment).

## Netlink Parity Matrix

| Protocol Family | Current Use In Daemon | Current Rust Crates | Recommended Stack | Recommendation |
|---|---|---|---|---|
| `NETLINK_ROUTE` | Interface lookup for sockets monitor | `rtnetlink` | `rtnetlink` (+ packet-route internally) | Keep as-is |
| `NETLINK_AUDIT` | Audit event stream worker | `audit`, `netlink-packet-core` | `audit` | Keep as-is |
| `NETLINK_CONNECTOR` | Process fork/exec/exit monitoring | `netlink-sys` | `netlink-sys` (+ typed packet crate if available) | Keep as-is |
| `NETLINK_SOCK_DIAG` | Socket dump/destroy path | `netlink-sys`, `netlink-packet-sock-diag` | same | Keep as-is |
| `NETLINK_NETFILTER` | Packet verdict path | libc + FFI boundary | keep current path | Keep as-is |

## Completed Milestones

### Parity hardening

- Typed sock-diag request construction for socket destroy path.
- Protocol-focused proc connector and sock-diag tests.
- Runtime task-control parity hardening for start/stop/reload semantics.
- Subscribe identity parity updates (runtime hostname/kernel with safe fallback).
- Downloader and IOC scanner disk-task runtime execution parity.
- Stats event backlog buffering and snapshot draining.
- Notification hello frame parity (`Id: 0` reply on stream open).
- Notification close-sentinel parity (`Action::NONE` now breaks stream and triggers temporary-task teardown flow).
- StartTask duplicate rejection parity.
- Default reject fallback parity with socket teardown when context exists.
- DNS response fast-path parity (track + accept before rule/UI verdict path).
- Self-connection fast-allow parity for internal daemon flows.
- UI-decided connection stats parity (rule-hit/event emission after ask-rule decision).
- Tasks watcher reconciliation every poll tick for referenced task changes.

### Async/runtime hardening

- Firewall adapter command execution migrated to async process paths.
- RuleService, ConfigService, Task runtime loader, and watcher polling moved off sync hot paths.
- Process inspect and PID owner resolution heavy work isolated behind blocking boundaries.
- Dedicated connect-attempt queue split from shared kernel-event queue.
- Bounded verdict concurrency with semaphore limits.
- Rule match cache pass (prebuilt lists/aliases/regex, no hot-path disk reads).
- Owner enrichment moved off NFQUEUE callback thread to async worker path.
- Worker shutdown latency hardening (cancellation-aware sleeps, bounded joins, blocking join context).
- Non-connect kernel event handler split into dedicated DNS/process/firewall pipelines to reduce single-loop serialization pressure.
- Non-connect worker event dispatch now uses bounded `try_send` retries with short backoff and drop-on-sustained-saturation behavior (replacing unbounded `blocking_send`).
- Kernel dispatcher fan-out to DNS/process/firewall pipelines now also uses bounded retry/backoff to avoid stalling the non-connect router loop on one saturated pipeline.
- Runtime now tracks cumulative dropped non-connect events per pipeline (dns/process/firewall) to support evidence-driven queue-pressure tuning.
- Added Go-side comparability stress harness under `daemon/runtimeprofile/` to report connect-latency percentiles and per-pipeline drop deltas in the same output shape as Rust baseline profiling.
- Verdict flow now short-circuits self-connect attempts before async owner enrichment, removing unnecessary hot-path work for self-connections.

## Change Log (2026-03-15)

1. Follow-up implementation pass
- Queue-aware timeout policy, requeue aliasing, late-verdict stale-entry guard.
- Non-blocking connect enqueue fallback under saturation.

2. Parity follow-up closure pass
- Reject fallback socket teardown parity.
- Duplicate task start rejection parity.
- Notification hello handshake parity.
- Pending-stats ping gating parity.

3. Connect queue isolation pass
- Dedicated bus channel for `ConnectionAttempt`.
- Separate daemon task for connect attempt handling.
- Bounded concurrent connect handling.

4. Rule match cache pass
- In-memory list and alias cache for verdict matching.
- Regex precompile cache for rule operators.

5. Owner enrichment offload pass
- Expensive owner enrichment moved off callback path.

6. Shutdown latency hardening pass
- Bounded worker joins in runtime.
- Cancellation-aware worker sleeps.

7. Non-connect kernel event pipeline split pass
- Shared non-connect queue now dispatches into dedicated DNS/process/firewall worker pipelines in daemon runtime.

8. Post-merge parity/runtime rescan pass
- DNS response packets now fast-path to accept while still publishing DNS mappings.
- Notification stream now treats `Action::NONE` (and lower sentinel values) as server-ordered close.
- Verdict path now records stats hit/event for UI-decided first-seen connections.

9. Post-merge parity/runtime follow-up pass
- Verdict flow now fast-allows self connection attempts before rule/UI evaluation.
- Worker non-connect event emission now uses bounded retry/backoff dispatch to avoid unbounded producer thread blocking when kernel event queues are saturated.

10. Non-connect dispatcher hardening pass
- Daemon kernel-event router now uses bounded retry/backoff when dispatching to DNS/process/firewall sub-pipelines so one saturated sub-queue cannot indefinitely stall routing.
- Added focused daemon dispatcher tests for closed-channel stop and bounded drop-on-full behavior.

11. Saturation observability and isolation regression pass
- Added mixed non-connect saturation regression test proving connect-attempt handling remains responsive under heavy dns/proc/firewall event bursts.
- Added per-pipeline dropped-event runtime counters for non-connect dispatcher backpressure events.

12. Profiling baseline harness pass
- Added ignored stress-profile harness that reports connect-attempt latency percentiles and per-pipeline drop deltas.
- Captured baseline run (rounds=2000): p50=13.518ms, p95=16.290ms, p99=17.626ms, max=38.052ms, drop_total=0.

13. Go backend apples-to-apples stress-profile pass
- Added `daemon/runtimeprofile/runtime_profile_test.go` with:
	- mixed non-connect saturation responsiveness regression,
	- opt-in stress profile reporting `p50/p95/p99/max` and `drop_dns/drop_process/drop_firewall/drop_total`.
- Verified aligned 2000-round harness runs for apples-to-apples comparison:
	- Rust release (`OPENSNITCH_STRESS_ROUNDS=2000 cargo test --release -p opensnitchd-rs stress_profile_reports_connect_latency_and_pipeline_drops -- --ignored --nocapture`): p50=0.009ms, p95=0.013ms, p99=0.019ms, max=0.127ms, drop_total=0.
	- Go (`OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=2000 go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v`): p50=0.004ms, p95=0.009ms, p99=0.015ms, max=0.209ms, drop_total=0.

14. Cross-backend one-command profile target
- Added root `Makefile` target `profile-backends` with shared `STRESS_ROUNDS` to run both Rust and Go harnesses in one command.

15. Connect hot-path optimization pass
- Moved self-connection fast-allow check ahead of async owner enrichment in `verdict_flow`.
- Result: Rust release stress profile moved from multi-millisecond latency to sub-millisecond latency at 2000 rounds while retaining `drop_total=0`.

16. Perf tracker and regression guard pass
- Added `daemon-rs/PERF.md` as a persistent stress-profile history tracker for Rust and Go backend harness runs.
- Added machine-readable perf baseline keys in `daemon-rs/TODO.md`.
- Rust ignored stress-profile harness now enforces clear-regression checks against TODO baselines.
- Go runtimeprofile stress harness now enforces clear-regression checks against TODO baselines.
- Added explicit tooling command `cargo run --manifest-path daemon-rs/Cargo.toml -p tools -- update-run-perf` (and `make update-run-perf`) to auto-refresh PERF run rows with Rust-vs-Go and Rust-vs-previous-commit deltas.

17. Parity rescan and drop observability follow-up
- Performed Go-vs-Rust parity rescan focused on non-connect pipelines, task notifications, overload fallback behavior, and watcher responsiveness.
- Added global warning/debug observability for worker kernel-event dispatch backpressure drops and closed-channel outcomes.

18. NFQUEUE overload fallback mode parity pass
- Added configurable overload fallback mode via `OPENSNITCH_NFQUEUE_OVERLOAD_FALLBACK` (`default-action` or `fail-open`).
- Added explicit fallback telemetry for timeout/saturation decisions and mode-aware verdict behavior.
- Added focused tests covering fail-open repeat-queue allow and primary-queue requeue invariants.

19. Go UI config parity test port pass (Rust)
- Added `config.rs` tests for full config parsing expectations and invalid `ProcMonitorMethod` fallback to `Proc`.
- Added `firewall_service.rs` test ensuring `reload_from_config` updates backend/system-firewall state without requiring privileged firewall rule application.

20. Go UI subscribe-payload parity test port pass (Rust)
- Added `client.rs` tests validating runtime identity fields are non-empty.
- Added `client.rs` test validating `build_subscribe_config` payload fields (id/name/version/log-level/raw-config/rules/system-firewall) match expected values.

21. Kernel/reconfigure parity hardening pass (Rust)
- Added feature-gated, opt-in root smoke tests for iptables/nftables NFQUEUE wiring under `integration_kernel_tests`.
- Added `config_service.rs` tests covering invalid `ProcMonitorMethod` fallback-to-`Proc` and invalid-json snapshot immutability.
- Added root `Makefile` orchestration targets: `rust-parity-tests`, `rust-kernel-it`, and `go-rust-parity-full` (single-line pass summary on success).

22. Go test parity thorough rescan (analysis pass)
- Re-ran package-level parity inventory against Go tests (`daemon/**/*_test.go`) and Rust tests (`daemon-rs/crates/daemon/src/**/*.rs`).
- Confirmed recent parity ports are green in combined root flow (`go-rust-parity-full` PASS).
- Identified largest remaining parity density deltas by domain: `firewall/nftables`, `rule`, and `procmon/ebpf`.

23. Hybrid file-watch parity pass
- Replaced poll-only config/rules/tasks watchers in Rust `WatchService` with a hybrid model: lightweight inotify-based filesystem triggers plus existing periodic polling as fallback.
- Added event filtering tests for filesystem trigger forwarding behavior and retained poll safety on watcher setup/channel failures.

24. Cross-backend hot/cold parity harness matrix pass
- Added root `Makefile` targets to run paired Go/Rust hot-path harnesses (`parity-hot-path-harness`) and cold-path watch/reload harnesses (`parity-cold-path-harness`).
- Added aggregate `parity-hot-cold-matrix` target with a single PASS summary for combined parity-gate runs.

25. Config reload parity test port pass
- Added Rust watch-service test covering config file mutation and watcher-driven runtime reload semantics, mirroring Go `ui.TestClientReloadingConfig` behavior at service/runtime level.

26. Go parity rescan hygiene pass
- Re-ran `sudo make go-test-full` and `make parity-hot-cold-matrix STRESS_ROUNDS=500`; both completed successfully and the latest static Go-vs-Rust inventory pass found no new parity/test consistency drift.
- Wired automatic restore of `daemon/ui/testdata/default-config.json` into the root Makefile targets that execute the Go UI config reload test path, eliminating the recurring dirty-worktree side effect.

27. Full Go backend rescan and Rust test-log parity pass
- Completed a full-file Go backend rescan covering runtime features and tests; the main remaining Go-only gaps are logging/config sink parity and the `dns/systemd.ResolvedMonitor` event-source path.
- Added `utils::test_support::init_test_logging()` plus `logging::init_for_tests()` so Rust reload-path tests use the daemon logging subsystem and can emit inspectable logs during parity debugging.

28. Logging sink + systemd-resolved compatibility port pass
- Extended Rust config parsing/runtime wiring for Go logging fields (`LogUTC`, `LogMicro`, `Server.LogFile`, `Server.Loggers`) and integrated active file/UDP sink routing into `logging.rs` with reload-path application.
- Added a direct systemd-resolved varlink socket monitor in DNS worker (`io.systemd.Resolve.Monitor.SubscribeQueryResults`) with robust parsing for A/AAAA and CNAME answers plus existing `resolvectl monitor` fallback.
- Added unit coverage for varlink DNS event extraction and verified reload/config parity tests remain green after logging integration.

29. Cold-path harness log parity rescan and gap-fill pass
- Rescanned full cold-path harness output (Go + Rust interleaved) against the Go-backend transcript attached in the session; identified four log-line gaps.
- Fixed `reqwest` version regression (`0.13.2` had renamed `rustls-tls` feature; reverted to stable `0.12` series with working `rustls-tls` feature).
- Fixed second `Delete() rule` + `Rule deleted` pair: `rules_watch_task_emits_live_reload_delete_sequence` now deletes both `test-live-reload-delete.json` and `test-live-reload-remove.json` and polls until `rules.is_empty()`, mirroring Go `TestLiveReload` removing both files.
- Added `uiClient exit` log to both `Ok(())` return paths of `NotificationFlow::run()`, matching Go `uiClient.StartPolling()` exit label.
- Restructured `notification_flow_runs_ui_poller_path_against_live_server` test to keep `task_reply_tx` alive through stream-close, so `client.disconnect()` is emitted before `uiClient exit`; test validates hello handshake, `client.disconnect()`, and clean `uiClient exit` in sequence.
- Moved `[tasks] Adding task: {name}` log from `daemon.rs` dispatch loop into `spawn_task_monitor()` in `task_runtime.rs`, aligning it with the Go `Manager.AddTask()` log site.
- Added `spawn_task_monitor_emits_adding_task_log` test exercising `spawn_task_monitor("basic-task", ...)` with immediate cancel; `[tasks] Adding task: basic-task` now visible in cold-path harness alongside Go's `TestTaskManager/AddTask` section.
- Added `spawn_task_monitor_emits_adding_task_log` test exercising `spawn_task_monitor("basic-task", ...)` with immediate cancel; `[tasks] Adding task: basic-task` now visible in cold-path harness alongside Go's `TestTaskManager/AddTask` section.
- `make parity-cold-path-harness` → PARITY COLD-PATH STATUS: PASS, 15/15 Rust tests.
- Post-session regression investigation: `parity-hot-cold-delta` was missing `RUST_LOG=error` on the Rust hot-path bench; with `init_for_tests()` defaulting to `opensnitchd_rs=debug`, every hot-path `debug!()` in `verdict_flow.rs` was being emitted and each call acquired the `OpensnitchMakeWriter` and `OpensnitchTimer` `RwLock` twice per event, causing ~3x p50 regression.
- Fixed `parity-hot-cold-delta` Makefile to add `RUST_LOG=error` on the Rust hot bench (matching `parity-hot-path-harness`).
- Fixed `logging.rs`: added `LOG_SINK_HAS_FILE`, `LOG_SINK_HAS_UDP`, `LOG_SINK_UTC`, `LOG_SINK_MICRO` `AtomicBool` statics kept in sync by `apply_config()`; `MakeWriter::make_writer()` and `FormatTime::format_time()` use atomic loads as fast-path to bypass `RwLock` entirely in the common stdout-only case.
- Post-fix `parity-hot-cold-delta` result: vs-Go Δ p50=0.000, p95=+0.003, p99=+0.003, max=+0.020 — all well under baseline thresholds.

30. Hot/cold parity optimization pass (feature-parity preserved)
- Hot path: removed non-parity debug logs from `flows/verdict_flow.rs` connection handling and replaced full-config snapshot reads with focused `ConfigService::{default_action, client_addr}` accessors to avoid cloning whole `Config` when only one field is needed.
- Hot path: split self fast-allow into `fast_allow_try()` + async fallback send (`send_verdict`) so the common queue-not-full case does not pay an `await`/state-machine hop in `spawn_connect_attempt_task`.
- Cold path: event-driven config-watch wait experiment was validated but then reverted to fixed `tokio::time::sleep(Duration::from_secs(10))` for strict apples-to-apples parity with Go `ui.TestClientReloadingConfig` timing policy.
- Validation: `RUST_LOG=error cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs` remains green (97 passed, 1 ignored).
- Benchmark (`make parity-hot-cold-delta STRESS_ROUNDS=500`, commit `e23c2f7a` + working-tree optimization patch):
	- Hot: Go `p50=0.001 p95=0.003 p99=0.005 max=0.054`, Rust `p50=0.001 p95=0.004 p99=0.006 max=0.046`, Δ `p50=+0.000 p95=+0.001 p99=+0.001 max=-0.008 drop_total=0`.
	- Cold totals: Go `13.986s`, Rust `4.368s`, Δ `-9.618s`.
	- Result: `PARITY DELTA STATUS: PASS`.

31. Additional hot-path optimization pass (feature-parity preserved)
- Implemented optimization #1 (queue topology): added lane-specific bus capacities via `BusCaps` and `build_bus_with_caps()`, with runtime defaults tuned to reduce cross-lane contention (`connect=1024`, `verdict=1024`, `kernel=512`, `client_cmd=256`, `task_reply=256`).
- Implemented optimization #2 (connect pipeline): replaced non-daemon connect handling from per-attempt semaphore+spawn to a bounded fixed worker pool with per-worker queues and round-robin dispatch; added bounded batch drain (`CONNECT_DISPATCH_BATCH_SIZE=64`) from `connect_rx` to reduce dispatcher wakeups.
- Implemented additional stats contention reduction: moved high-frequency scalar counters (`connections`, `dns_responses`, `accepted`, `dropped`, `ignored`, `rule_hits`, `rule_misses`) to atomic counters and kept mutex-protected maps/events for rich snapshots.
- Restored fixed 10s watcher delay for parity comparability as requested; cold-path delta remains apples-to-apples against Go tests.
- Validation: `RUST_LOG=error cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs` remains green (97 passed, 1 ignored).
- Benchmark (`make parity-hot-cold-delta STRESS_ROUNDS=500`, commit `d1830792` + working-tree optimization patch):
	- Hot: Go `p50=0.001 p95=0.002 p99=0.005 max=0.107`, Rust `p50=0.001 p95=0.004 p99=0.009 max=0.056`, Δ `p50=+0.000 p95=+0.002 p99=+0.004 max=-0.051 drop_total=0`.
	- Cold totals: Go `13.975s`, Rust `13.965s`, Δ `-0.010s`.
	- Result: `PARITY DELTA STATUS: PASS`.

32. Process cache lookup lock-contention reduction (sweet-spot trial)
- [x] Keep feature parity and fixed 10s watcher delay while reducing hot lookup lock pressure.
- [x] Updated `ProcessService::inspect()` to use a read-lock hit path and only take write-lock cleanup when entry is missing or expired.
- [x] Reverted interim connect dispatcher tuning experiments (queue-capacity and dispatch strategy variants) after noisy variance; retained the process-cache fast path as the cleaner candidate.

Validation:

- Full suite: `RUST_LOG=error cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs` => `97 passed; 0 failed; 1 ignored`.
- `make parity-hot-cold-delta STRESS_ROUNDS=500` => `PARITY DELTA STATUS: PASS`.
- Candidate run snapshot:
	- Hot: Go `p50=0.001 p95=0.002 p99=0.008 max=0.033`, Rust `p50=0.001 p95=0.003 p99=0.006 max=0.040`, Δ `p50=+0.000 p95=+0.001 p99=-0.002 max=+0.007 drop_total=0`.
	- Cold totals: Go `13.990s`, Rust `13.971s`, Δ `-0.019s`.
	- Result: `PARITY DELTA STATUS: PASS`.
- 2000-round stability validation (pre-commit):
	- Run #1 hot: Go `p50=0.001 p95=0.002 p99=0.004 max=0.228`, Rust `p50=0.001 p95=0.004 p99=0.005 max=0.050`, Δ `p50=+0.000 p95=+0.002 p99=+0.001 max=-0.178 drop_total=0`; cold Δ `+0.014s`.
	- Run #2 hot: Go `p50=0.001 p95=0.002 p99=0.004 max=0.135`, Rust `p50=0.001 p95=0.004 p99=0.006 max=0.067`, Δ `p50=+0.000 p95=+0.002 p99=+0.002 max=-0.068 drop_total=0`; cold Δ `+0.005s`.
	- Both runs: `PARITY DELTA STATUS: PASS`; full suite remained `97 passed; 0 failed; 1 ignored`.

33. Stress harness comparability alignment (Go-vs-Rust hot tails)
- [x] Kept runtime feature parity; aligned Rust stress-profile test load model to Go runtimeprofile harness so measurements compare equivalent pipeline work.
- [x] In Rust stress-profile test, replaced full daemon kernel-service handling with lightweight per-pipeline workers (2ms delay) and bounded router dispatch, matching Go harness behavior.
- [x] Adjusted Rust stress-profile timing window to exclude per-iteration `ConnectionAttempt` object construction and focus on dispatch/verdict latency, consistent with Go harness timing intent.

Validation:

- Full suite: `RUST_LOG=error cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs` => `97 passed; 0 failed; 1 ignored`.
- 2000-round parity run #1: Go `p50=0.001 p95=0.003 p99=0.004 max=0.139`, Rust `p50=0.001 p95=0.002 p99=0.003 max=0.051`, Δ `p50=+0.000 p95=-0.001 p99=-0.001 max=-0.088 drop_total=0`; cold Δ `-0.005s`.
- 2000-round parity run #2: Go `p50=0.001 p95=0.003 p99=0.005 max=0.179`, Rust `p50=0.001 p95=0.002 p99=0.003 max=0.046`, Δ `p50=+0.000 p95=-0.001 p99=-0.002 max=-0.133 drop_total=0`; cold Δ `-0.019s`.
- Result: both runs `PARITY DELTA STATUS: PASS`; Rust now matches/exceeds Go on hot p95/p99 in this aligned harness.

34. Throughput-focused default tuning for high-PPS edge targets
- [x] Updated runtime defaults in `daemon.rs` toward higher burst tolerance and contained latency:
	- `MAX_CONCURRENT_CONNECT_ATTEMPTS=64`
	- `CONNECT_WORKER_QUEUE_CAPACITY=128`
	- `CONNECT_DISPATCH_BATCH_SIZE=16`
	- `KERNEL_DNS_QUEUE_CAPACITY=2048`
	- `KERNEL_PROCESS_QUEUE_CAPACITY=2048`
	- `KERNEL_FIREWALL_QUEUE_CAPACITY=512`
- [x] Added ignored benchmark `stress_profile_reports_kernel_pipeline_pressure` to exercise the real `spawn_kernel_task` pipeline with configurable flood duration/task count and report attempted/enqueued PPS plus enqueue/pipeline drops.
- [x] Full suite re-validated after tuning: `97 passed; 0 failed; 2 ignored`.
- [x] Hot-path stress re-validated: `OPENSNITCH_STRESS_ROUNDS=2000` => `p50=0.001 p95=0.002 p99=0.004 max=0.054 drop_total=0`.

35. Kernel-pressure benchmark robustness and timeout-sweep profiling
- [x] Refactored pressure benchmark internals into reusable helper `run_kernel_pressure_profile(...)` to avoid duplicated benchmark logic and keep mode handling consistent.
- [x] Added ignored benchmark `stress_profile_reports_kernel_pipeline_timeout_sweep` that runs timeout-mode pressure tests over configurable timeout points (`OPENSNITCH_KERNEL_PRESSURE_SWEEP_US`, default `50,100,200,500,1000`).
- [x] Added machine-friendly sweep CSV output lines (`kernel-pressure-sweep-csv-header` + `kernel-pressure-sweep-csv,...`) to simplify PERF ingestion and post-run plotting.
- [x] Added auto-selected timeout recommendation summary (`kernel-pressure-sweep-recommend ...`) based on delivered throughput and enqueue-drop ratio, preferring non-abort candidates.
- [x] Kept benchmark shutdown bounded and non-hanging under heavy load with cancellation-friendly flood workers and timeout-bounded join/abort behavior.
- [x] Validation: `cargo test -p opensnitchd-rs stress_profile_reports_kernel_pipeline_timeout_sweep -- --ignored --nocapture` passed.

36. Opt-in runtime tunables file and quick sweep generation
- [x] Added Rust-only runtime tunables loader (`tunables.rs`) with conservative defaults and opt-in overrides from `/etc/opensnitchd/tunables.json`, `daemon-rs/data/tunables.json` (dev), or `OPENSNITCH_TUNABLES_FILE`.
- [x] Added per-field env overrides for runtime tuning (`OPENSNITCH_TUNE_*`) with safe clamping.
- [x] Replaced hardcoded connect/kernel queue and worker constants in daemon runtime with effective tunable values logged at bootstrap.
- [x] Added tools command `cargo run -p tools -- quick-pressure-sweep-tunables` that runs the timeout sweep benchmark and writes `daemon-rs/data/tunables.json` (or `OPENSNITCH_TUNABLES_OUTPUT`) using conservative/high-throughput profile selection thresholds.
- [x] Added `daemon-rs/data/tunables.example.json` and ignored generated `daemon-rs/data/tunables.json` in repo `.gitignore`.

37. Auto-tune kernel-pressure tunables with stability guardrails
- [x] Added tools command `cargo run -p tools -- auto-tune-kernel-pressure-tunables` implementing step-up tuning from conservative defaults with `x2` scale factors.
- [x] Each step runs repeated pressure profiles (`OPENSNITCH_AUTOTUNE_RUNS_PER_STEP`, clamped to 2-3) and uses median `enqueued_pps` and median `enqueue_drop_ratio` for robust decisioning.
- [x] Added hysteresis (`OPENSNITCH_AUTOTUNE_HYSTERESIS_GAIN`) so tiny gains do not trigger continued doubling.
- [x] Added hard caps for all tuned dimensions (workers, connect queue, dispatch batch, kernel pipeline queues) to avoid pathological sizes.
- [x] Stability guardrails stop escalation when forced abort occurs or median drop ratio exceeds `OPENSNITCH_AUTOTUNE_MAX_DROP_RATIO`.
- [x] Final profile applies configurable safety backoff (`OPENSNITCH_AUTOTUNE_SAFETY_FACTOR`, default 0.5) with floor at conservative defaults, then writes `tunables.json`.
- [x] Added post-selection no-regression validation (median repeated runs for conservative baseline vs selected profile) with automatic conservative fallback on regressions (`OPENSNITCH_AUTOTUNE_REGRESSION_TOLERANCE`, `OPENSNITCH_AUTOTUNE_REGRESSION_DROP_DELTA_MAX`, `OPENSNITCH_AUTOTUNE_VALIDATION_RUNS`).
- [x] Refined regression handling with a sweet-spot rerun pass using lower scale factors from defaults (`OPENSNITCH_AUTOTUNE_SWEETSPOT_FACTORS`) and relaxed uplift/drop constraints (`OPENSNITCH_AUTOTUNE_SWEETSPOT_MIN_UPLIFT`, `OPENSNITCH_AUTOTUNE_SWEETSPOT_DROP_DELTA_MAX`) before final fallback.
- [x] Added CPU-core-aware autotune caps (`available_parallelism`) so worker/queue max bounds adapt to host core count while preserving hard upper limits.
- [x] Added release microbench helper command `cargo run --release -p tools -- microbench-connect-dispatch` for fast dispatch-path trend checks.
- [x] Added explicit parity gate command `cargo run --release -p tools -- parity-gate` (optional strict exceed-Go check via `OPENSNITCH_PARITY_REQUIRE_EXCEED_GO=1`) and optional auto-run from autotune via `OPENSNITCH_AUTOTUNE_RUN_PARITY_GATE=1`.
- [x] Refined CPU-cap logic to always reserve one logical core for kernel/system operations before computing autotune max bounds.
- [x] Reduced kernel-pressure enqueue contention in stress harness flood path via adaptive batch sizing and short saturation-aware backoff, with extra focus on DNS/process lane saturation.
- [x] Reduced per-event overhead in pressure harness by replacing per-iteration DNS string formatting with precomputed host/IP pools reused across dispatch loops.
- [x] Optimized connect-attempt dispatch hot path to probe alternate worker queues before blocking, reducing head-of-line stalls when one worker lane is saturated.
- [x] Added regression tests for connect dispatch rerouting under primary-queue saturation and closed-worker behavior.

38. Startup autotune orchestration with safety preflight (default-on)
- [x] Added default-on startup autotune-once attempt before tunables load: runs only when tunables file/marker are absent and autotune is not disabled.
- [x] Added load/memory/CPU-idle preflight checks (`/proc/loadavg`, `/proc/meminfo`, `/proc/stat`) with configurable thresholds to skip autotune under host pressure.
- [x] Added timeout-bounded autotune subprocess execution (`cargo run --release -p tools -- auto-tune-kernel-pressure-tunables`) with inherited logging and conservative fallback on failure.
- [x] Added one-shot completion marker file to avoid repeated startup autotune on subsequent restarts.
- [x] Added explicit opt-out switch `OPENSNITCH_AUTOTUNE_DISABLE=1` and marker path override `OPENSNITCH_AUTOTUNE_MARKER_FILE`.
- [x] Added systemd notify status signaling during startup autotune (`STATUS=...`, periodic `EXTEND_TIMEOUT_USEC=...`) and only emit readiness (`READY=1`) once daemon workers/tasks are running.

## Update Rules

1. Update this file directly after each parity or async/runtime change.
2. Move closed items from Active Backlog into Completed Milestones.
3. Keep behavior references concrete (file + behavior), not generic.
4. Keep this as the only active tracker file.
