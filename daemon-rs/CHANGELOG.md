# Daemon-RS Changelog

This changelog records release-level changes for the daemon-rs branch line.

Versioning baseline:
- `v0.1.0`
- `v0.1.1`
- `v0.2.0`
- `v0.3.0`
- `v0.4.0`
- `v0.5.0`

## [v0.5.0] - 2026-03-26

### Added
- `parity-hot-cold-delta` tools command: runs the full hot+cold parity delta harness
  `OPENSNITCH_PERF_REPEATS` times (default 3), then prints the median run by hot-path
  p95 delta.  Unlike `parity-gate` it does not apply a threshold check and does not
  write PERF.md; unlike the former single-shot alias it gives a noise-reduced view of
  parity.  Makefile target updated to delegate to this command.
- `daemon-rs/crates/tools/fixtures/default-config.json`: canonical copy of the Go-side
  UI test fixture (`daemon/ui/testdata/default-config.json`) owned by the tools crate.
  The cold-path harness now writes this copy to the fixture path before every run so
  tests always start from a known-good state regardless of what a prior crashed run may
  have left behind.
- `daemon-rs/crates/daemon/src/tests/testdata/hagezi-pro-hosts-sample.txt`: bundled
  5,000-line sample of the Hagezi Pro hosts list (every 80th data line from the ~400k-line
  source).  `blocklist_large_segments_load_and_latency_smoke` now falls back to this
  sample when the full local list is absent, making the test runnable without a local
  subscription checkout.  Set `OPENSNITCH_LARGE_SEGMENT_FIXTURE` to override the path
  used for both the full file and the fallback decision.
- Transactional policy mutation coordinator (`services/policy_tx`) with:
  - idempotency dedup (`DuplicateInFlight` / `DuplicateCommitted`),
  - serialized apply path,
  - rollback callback support,
  - persisted changesets and audit log records.
- Verdict-flow multi-user race arbitration via per-connection decision key/epoch gate.
- Async verdict rule persistence worker that keeps immediate verdict emission on the hot path while delegating durable rule writes to background transactional execution.
- Runtime config field `AskTimeoutPolicy` (`allow|drop|default`, with default behavior when missing/null) parsed from config JSON and wired into daemon-side UI-miss fallback handling.
- Lightweight non-GUI mock Python UI service (`daemon-rs/scripts/mock_ui_client.py`) plus tools orchestration command (`run-daemon-mock-ui-live-session`) for daemon-to-UI handshake validation.
- Explicit notification/session client identity logging fields: `client_id` and `client_origin` (`ClientPrincipal`-derived).
- Interception-health diagnostic reporting for firewall drift checks with backend detail payloads (including nftables tagged-rule count mismatch context).

### Changed
- Rule/control command mutation paths now execute through shared transactional coordinator ownership-tagged by active client principal (`primary_owner()`).
- `SetInterception`, `SetFirewall`, and `ReloadFirewall` now share transactional semantics with rollback-on-failure behavior.
- Compatibility reference expanded for transactional mutation model, multi-user precedence/owner attribution, and `AskTimeoutPolicy` safeguard semantics.
- Make-level live daemon commands now align with test-guard behavior and tools privilege routing for launch/stop/mock-ui session orchestration.
- Tools live log launch/stop path now tracks stopped services in session metadata and restores them on stop, mirroring guarded test workflow semantics.
- Notification reconnect warning logs are throttled to reduce repeated warning flood while preserving warn-level signaling for timeout/error/non-stateful disconnect paths.
- Firewall monitor polling now honors configured runtime interval (instead of fixed 1s cadence).
- eBPF build policy now enforces root execution and a single kernel artifact target tree (`daemon-rs/target-kernel`) for both build/runtime paths to avoid root/user ownership conflicts in live runs.
- Design-rule conformance tightened via module refactor: `services/policy_tx/mod.rs` and `services/lifecycle/mod.rs` are now linker-only with implementation moved to sibling files; policy transaction tests moved to `src/tests/services/policy_tx.rs`.
- `cargo ost` replaces `cargo unit` as the tools runner alias (`.cargo/config.toml`).
- Privileged-command test guard extracted from `live_logs.rs` into a shared `test_guard.rs` module and wired into all guarded tools commands (`build-ebpf`, eBPF smoke tests, `test-kernel-it`, harness/live commands); privilege routing (`direct`/`pkexec`/`sudo`) and service stop/restart semantics are now consistent across all privileged paths.
- `gotools` Go CLI ported to the same test-guard pattern using an inline `withGuard` function; the `$(TEST_GUARD)` shell wrapper variable is removed from the top-level Makefile (guard lives entirely in the tools binaries).
- `gotools` help text and DOCS.md updated to reflect the full command/flag surface; `build`, `test`, eBPF smoke, and `kernel-profile-harness` command groups are now documented.
- Release process convention (backfilled for `v0.5.0`, required for future releases): each `release: vx.y.z` commit message should embed the full changelog entry for that version so release metadata remains self-contained in git history.
- Release workflow automation added: `daemon-rs/scripts/release_commit_from_changelog.sh vX.Y.Z --dry-run|--push` now standardizes changelog extraction, release commit amend, tag move, and optional remote sync.

### Fixed
- Harness hang in `parity-hot-cold-delta-once` / `parity-hot-path-*` commands when
  invoked via `cargo ost` (without the Makefile).  Cargo hard-links the final daemon
  binary into `target/release/deps/` under an `opensnitchd_rs-<HASH>` name;
  `daemon_rs_release_test_binary_path` was picking that hard-link (the newest file in
  deps/) and running the production daemon instead of the test binary.  The function now
  excludes any candidate whose inode matches `target/release/opensnitchd-rs`.
- `run_prebuilt_daemon_rs_test` now unconditionally sets
  `OPENSNITCH_RUN_PRIVILEGED_TESTS=1` for the test binary subprocess, matching what the
  Makefile does for every parity/harness target.  Previously this env var was absent when
  the harness was launched directly with `cargo ost`, causing the test binary to skip
  privileged-context setup.
- `blocklist_large_segments_load_and_latency_smoke`: removed hardcoded absolute path
  `/home/nvand/.config/opensnitch/...`; the test now resolves the fixture via `$HOME`
  and falls back to the bundled sample when the full list is absent.
- Firewall drift-heal loop behavior after backend-toggle churn: recovery now validates post-reload convergence and applies bounded retry backoff when interception rules remain invalid.
- Warning profile cleanup for touched slices: removed dead helper code where not needed and kept explicit `#[allow(dead_code)]` only for intentional compatibility/API placeholders.

### Notes
- `AskTimeoutPolicy` is intentionally a daemon safeguard for ambiguous/no-decision paths (UI connect failure, AskRule RPC failure, stale/discarded decision). When UI returns a concrete rule, that rule remains authoritative.

## [v0.4.0] - 2026-03-23

### Added
- Netfilter/netlink milestone activation for the `v0.4.0` release slice.
- Expanded nftables netlink parity coverage with telemetry and focused tests.
- Shared per-domain netlink recovery gate with netlink-first fallback behavior.
- Split netlink recovery timing tunables:
  - `netlink_fallback_retry_delay_ms`
  - `netlink_recovery_poll_interval_ms`

### Changed
- Netlink protocol handling migrated from mixed per-protocol crates (`netlink-sys`, `rtnetlink`, `audit`, `netlink-packet-*`) to a unified stack based on `netlink-bindings` + `netlink-socket2`.
- Stress baseline source ownership moved from `TODO.md` to `PERF.md`.
- Stress harness override policy updated to prefer `OPENSNITCH_STRESS_BASELINE_PATH` while keeping backward-compatible fallback.
- Documentation/tracker policy aligned so perf run history and machine-readable baselines live in `PERF.md`.

### Fixed
- Dead-code noise reduced in feature-disabled/test compile surfaces while preserving subscription/API compatibility helpers.

## [v0.3.0] - 2026-03-23

### Added
- Aya-based probe migration coverage extended across remaining probe surfaces.
- Aya connection tunnel parity path with dedicated smoke test coverage.

### Changed
- Smoke target hygiene improved and warning noise reduced in daemon-rs test/build paths.

### Notes
- Added compatibility note for the eBPF `.text.unlikely` relocation quirk to keep kernel/runtime diagnostics explicit.

## [v0.2.0] - 2026-03-23

### Added
- Immutable-state policy rollout beyond snapshot-only guidance.
- Utility-backed dual-layer LRU abstractions for read-heavy runtime caches.
- Async touch reconciliation for dual-layer reads to preserve effective recency.
- Incremental immutable cache rollout across netlink address state, DNS lookups, and process cache surfaces.

### Changed
- Runtime/cache access strategy aligned with lock-free immutable read philosophy in hot paths.
- Policy audits and parity selectors tightened to keep refactor slices measurable and enforceable.

### Fixed
- Non-future design-rule backlog items closed with policy-gate verification and targeted parity harness fixes.

## [v0.1.1] - 2026-03-19

### Added
- Stronger hot/cold parity harness workflow (multi-run median strategy and higher default stress rounds).
- Numeric-IP hot-path and scoped list-matching preparation in daemon runtime path.

### Changed
- Parity harness latency tuning and prebuild strategy for faster repeated verification.
- Notification/task runtime flow aligned with Go parity expectations.
- Ongoing runtime/services/workers/tests refactor slices consolidated for parity-first behavior.

## [v0.1.0] - 2026-03-18

### Added
- Initial unified daemon-rs tracker baseline for parity and async/runtime hardening.
- Hybrid event-driven plus polling file-watch parity path for config/rules/tasks.
- Rust logging config parity with Go fields (`LogUTC`, `LogMicro`, `Server.LogFile`, `Server.Loggers`) and active sink routing.
- DNS monitor compatibility path via systemd-resolved varlink with `resolvectl monitor` fallback.

### Changed
- Baseline parity validation workflow established with Go full tests plus hot/cold matrix checks.
- Root orchestration updated to auto-restore Go UI test config artifact after parity runs to avoid worktree pollution.

### Notes
- `v0.1.0` is the first tagged baseline for this daemon-rs release line.

## Source Notes

Primary evidence sources used to compile this file:
- Git tags and release commits in this repository.
- Commit ranges between tagged versions on daemon-rs paths.
- Historical `daemon-rs/TODO.md` snapshots prior to tracker hard-pruning.
