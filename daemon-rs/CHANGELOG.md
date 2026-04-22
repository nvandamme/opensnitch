# Daemon-RS Changelog

This changelog records release-level changes for the daemon-rs branch line.

Versioning baseline:
- `v0.1.0`
- `v0.1.1`
- `v0.2.0`
- `v0.3.0`
- `v0.4.0`

## [Unreleased]

### Added
- Transactional policy mutation coordinator (`services/policy_tx`) with:
  - idempotency dedup (`DuplicateInFlight` / `DuplicateCommitted`),
  - serialized apply path,
  - rollback callback support,
  - persisted changesets and audit log records.
- Verdict-flow multi-user race arbitration via per-connection decision key/epoch gate.
- Async verdict rule persistence worker that keeps immediate verdict emission on the hot path while delegating durable rule writes to background transactional execution.
- Runtime config field `AskTimeoutPolicy` (`allow|drop|default`, with default behavior when missing/null) parsed from config JSON and wired into daemon-side UI-miss fallback handling.

### Changed
- Rule/control command mutation paths now execute through shared transactional coordinator ownership-tagged by active client principal (`primary_owner()`).
- `SetInterception`, `SetFirewall`, and `ReloadFirewall` now share transactional semantics with rollback-on-failure behavior.
- Compatibility reference expanded for transactional mutation model, multi-user precedence/owner attribution, and `AskTimeoutPolicy` safeguard semantics.

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
