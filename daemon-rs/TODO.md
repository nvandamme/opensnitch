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
- [ ] Define migration acceptance criteria before switching defaults (probe coverage, perf impact, packaging/CI changes).

3. Go parity follow-up (2026-03-16 rescan)
- [x] Add Rust parity path for disk-task outputs with `notification_id == 0` so task status/errors are surfaced to UI, not only daemon logs.
- [x] Add configurable overload fallback mode for NFQUEUE timeout/saturation (`fail-open` parity mode vs `fail-closed` hard mode), with explicit telemetry on fallback use.
- [ ] Evaluate replacing task/rule/config poll-only watch with event-driven or hybrid file-watch path for closer Go responsiveness parity.

4. Go test parity follow-up (2026-03-16 thorough scan)
- [x] Add dedicated Rust coverage for nftables expression/table/chain conversion parity (Go has broad unit coverage in `daemon/firewall/nftables/**`).
- [x] Expand Rust rule-matching parity tests to cover list/domain/regexp/range edge cases mirroring Go `daemon/rule/operator_test.go`.
- [x] Add deeper proc monitor parity tests for eBPF/process event decoding and integration behavior currently covered in Go `daemon/procmon/ebpf/ebpf_test.go`.

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
- Self-connection fast-allow parity for daemon-owned flows.
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
- Verdict flow now short-circuits daemon-owned connect attempts before async owner enrichment, removing unnecessary hot-path work for self-connections.

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
- Verdict flow now fast-allows daemon-owned connection attempts before rule/UI evaluation.
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
- Moved daemon-owned connection fast-allow check ahead of async owner enrichment in `verdict_flow`.
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

## Update Rules

1. Update this file directly after each parity or async/runtime change.
2. Move closed items from Active Backlog into Completed Milestones.
3. Keep behavior references concrete (file + behavior), not generic.
4. Keep this as the only active tracker file.
