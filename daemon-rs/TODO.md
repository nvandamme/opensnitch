# Daemon-RS Unified Tracker

This is the single tracker file for backend parity, async/runtime hardening, and future enhancements.

It supersedes:

- `daemon-rs/FEATURE_PARITY.md`
- `daemon-rs/SERVICE_ASYNC_AND_MODEL_SCAN_2026-03-15.md`

Last update: 2026-03-26

## Scope

Track parity and runtime behavior between:

- Go backend: `daemon/`
- Rust backend: `daemon-rs/crates/daemon/`

Out of scope for now:

- Replacing NFQUEUE verdicting with a non-FFI backend.
- Replacing `libbpf-rs` usage with a full Aya runtime path as default.
- Replacing proc connector path with a high-level netlink crate.

## Current Status Snapshot

- Post-release baseline: `v0.5.0`.
- Netfilter/netlink migration scope for this branch is complete.
- Netlink protocol handling is unified on `netlink-bindings` + `netlink-socket2` (replacing older mixed per-protocol netlink crates).
- Detailed perf history and machine-readable stress baselines are maintained in `daemon-rs/PERF.md`.
- This tracker is now active-only and intentionally compact.

## Version Changelog

- Archived per-version release notes are maintained in `daemon-rs/CHANGELOG.md`.
- `TODO.md` tracks only the current active version context and open backlog items.
- Release process rule (backfilled for `v0.5.0`, mandatory for future releases): every `release: vx.y.z` commit message must embed the full changelog content for that version (not only a condensed summary) to keep release metadata self-contained in git history.
- Release automation (preferred path): run `daemon-rs/scripts/release_commit_from_changelog.sh vX.Y.Z --dry-run` to preview, then `daemon-rs/scripts/release_commit_from_changelog.sh vX.Y.Z --push` to amend the release commit message, retag, and sync branch/tag in one step.

## Validation Workflow (v0.5.0)

- Root-required live daemon session:
  - `make daemon-rs-live-logs`
  - `make daemon-rs-live-stop`
  - Make-level launch/stop targets are guarded through `TEST_GUARD` and tools-side privilege routing (`direct`/`pkexec`/`sudo`) to match privileged test orchestration behavior.
- Root-required eBPF build policy:
  - `make daemon-rs-ebpf-build`
  - `make daemon-rs-ebpf-build-runtime`
  - eBPF artifacts are built under `daemon-rs/target-kernel` and enforced to run as root to prevent root/user ownership drift in mixed live workflows.
- Root-required daemon + mock Python UI orchestration (non-GUI compatibility flow):
  - `make daemon-rs-mock-ui-session`
  - This launches a lightweight Python gRPC mock UI endpoint, starts daemon-rs live logs, waits for `Subscribe`/`Ping`/`Notifications` handshake markers, then stops the live daemon session.
  - The same behavior is available directly via tools command `run-daemon-mock-ui-live-session` for non-Make invocation paths.
- Harness and regression/perf matrix:
  - `make parity-hot-cold-matrix STRESS_ROUNDS=1000`
  - `make parity-hot-cold-delta STRESS_ROUNDS=1000`

## Active Backlog (Post-v0.5.0)

### Active tasks

- [ ] Add concrete stats-snapshot exporter implementations for `StatsExporterPort`.
  - Current state: extension point exists in `platform/ports/stats_exporter_port.rs`, and `StatsFlow` hook is wired (`with_stats_exporter()`).
  - Gating policy: only `/metrics`-style export remains feature-gated (`metrics-export`) to preserve baseline Go parity by default.
  - Implement first-party adapters:
    - Prometheus `/metrics` scrape endpoint (preferred first target for Grafana dashboards).
    - Optional push-style adapter (Mimir/InfluxDB/push-gateway) for non-scrape environments.
  - Keep stats flow non-blocking: exporter implementations must run via internal async channel/background task and fail-open (no ping-loop stalls).
- [ ] Implement Privileged Control Boundary Rule (local + remote).
  - Classify incoming UI commands into unprivileged vs privileged.
  - Canonicalize privileged mapping names to `UPDATE_*` semantics in proto/client/daemon command mapping surfaces.
  - Gate rule persistence/deletion, config apply, firewall enable/disable/reload, and shutdown behind explicit daemon-side authorization.
  - Guard privileged behavior behind explicit feature/config tunables with secure defaults (deny-by-default when privileged authorization mode is not enabled).
  - Apply local-only owner-scope policy to local daemon/UI paths; require principal/capability-based authorization for remote daemon management.
  - Keep transport auth (`simple` / `tls-simple` / `tls-mutual`) separate from authorization; channel trust alone is not sufficient for host-wide mutation.
  - Future refinement: owner-scoped rule/firewall edits may be delegable only after the daemon can authenticate caller UID/GID and prove the requested mutation cannot escape that owner scope.
  - Requires protocol/Python UI evolution before privileged paths can be safely exposed without broad implicit trust.

### Future enhancements

- [ ] Add optional `scope` field to gRPC/proto `Operator` in a dedicated compatibility PR (default dst semantics, backward-compatible wire evolution, Go/Rust/Python client alignment).
  - Note: deferred for now to stay aligned with base opensnitch implementation; revisit in a future dedicated compatibility PR.
- [ ] Support AdBlock/AdGuard list format in rule list operators and subscriptions.
  - AdBlock/AdGuard `||domain^` syntax is common in community blocklists.
  - Requires parser normalization and compatibility-safe operator wiring.
  - Note: deferred for now to stay aligned with base opensnitch implementation; revisit in a future dedicated compatibility PR.
- [ ] Python UI client explicit disconnect on quit/CTRL-C (graceful stream shutdown before process exit).
  - Goal: avoid daemon-side noisy transport warnings during intentional UI termination.
  - Note: future work only; separate PR branch once related Python-client PR is accepted upstream.

## Completed In v0.5.0 (Condensed)

- CLI flag parity with Go daemon: `--rules-path`, `--config-file`, `--ui-socket`
  parsed in `main.rs` via `parse_cli_overrides()`; `CliOverrides` struct threaded through
  `Daemon::start` → `bootstrap`; `Config` extended with
  `load_from_default_locations_with_override` and `with_rules_path_override`.
- Live session rules isolation via `--rules-path <tmpdir>` (replaces previous
  `OPENSNITCH_CONFIG_FILE` temp-config workaround in `live_logs.rs`).
- Mock UI AskRule end-to-end round-trip: real nfqueue interception of TCP SYNs to
  RFC 5737 TEST-NET addresses → `AskRule` → `CHANGE_RULE_FROM_ASK` ack; 17/17 PASS.
  Background (non-TEST-NET) traffic silently allowed via `_ASK_RULE_EXPECTED_DSTS` filter.

- Transactional policy mutation envelope is implemented as a core release milestone (`services/policy_tx`): command paths now execute policy/rule mutations through transaction boundaries with dedup, rollback handling, and persisted changeset/audit records.
- Root-guarded live orchestration parity is implemented for both Make and tools command paths (`daemon-rs-live-logs`, `daemon-rs-live-stop`, `daemon-rs-mock-ui-session`, and tools equivalents).
- eBPF build policy is aligned to `target-kernel` with root enforcement for live/runtime builds, avoiding root/user ownership drift.
- Firewall drift-heal hardening landed: detailed health diagnostics, post-recovery convergence verification, and bounded retry backoff.
- Module-structure design-rule conformance is tightened: linker-only `mod.rs` for lifecycle/policy_tx slices with implementation in sibling files and policy_tx tests extracted under `src/tests/services`.

## Completed In v0.4.0 (Condensed)

- Netfilter/netlink migration milestones (nftables + NFQUEUE netlink-first with graceful fallback/recovery) are complete for this branch scope.
- Netlink stack migration completed from `netlink-sys`/`rtnetlink`/`audit`/`netlink-packet-*` to `netlink-bindings` + `netlink-socket2`.
- Split netlink recovery timing tunables are implemented and wired:
  - `netlink_fallback_retry_delay_ms`
  - `netlink_recovery_poll_interval_ms`
- Stress baseline source ownership moved from `TODO.md` to `PERF.md`:
  - preferred override: `OPENSNITCH_STRESS_BASELINE_PATH`
  - legacy fallback retained: `OPENSNITCH_STRESS_TODO_PATH`

## Documentation References

- Detailed compatibility matrices and rationale are maintained in `daemon-rs/COMPATIBILITY.md`.
- Tracker/design maintenance rules are maintained in `daemon-rs/DESIGN_RULES.md`.
- User installation/runtime operations guide is maintained in `daemon-rs/DOCS.md`.
- Version-by-version historical notes are maintained in `daemon-rs/CHANGELOG.md`.

## Recent History (Condensed)

- 2026-03-26: Added `--rules-path`, `--config-file`, `--ui-socket` flags to `cargo ost` CLI; `launch_daemon_live_logs` forwards them as daemon flags; `--ui-socket` also sets `OPENSNITCH_MOCK_UI_SOCKET`.
- 2026-03-26: Added `--profile=PROFILE` and `--target=TRIPLE` to `cargo ost build` / `build-all`; `daemon-rs-build` Makefile target forwards `CARGO_PROFILE` / `CARGO_TARGET_TRIPLE`; `install-rs` resolves binary via `DAEMON_RS_CARGO_TARGET_DIR/[triple/]CARGO_PROFILE/` to always match what `daemon-rs-build` produced.
- 2026-03-26: Makefile `export` block added — bridges `PERF_REPEATS`, `HARNESS_GO_LOG_LEVEL`, `PERF_RUST_LOG_LEVEL`, `PERF_PREBUILD`, `PARITY_STRESS_ROUNDS`, `STRESS_ROUNDS`, `GO_KERNEL_PRESSURE_*`, `DAEMON_RS_LIVE_RUST_LOG` and `DAEMON_RS_EBPF_*` to their `OPENSNITCH_*` equivalents; all parity/harness/go-test recipe lines simplified to bare tool invocations.
- 2026-03-26: Short lowercase Make aliases added for all tunable variables (`profile=`, `target=`, `rounds=`, `repeats=`, `rust_log=`, `go_log=`, `live_log=`, `pressure_secs=`, `sweep_secs=`, `smoke_timeout=`, `toolchain=`, `ebpf_target=`, `priv_cmd=`, `prefix=`, `sysconfdir=`, `bindir=`).
- 2026-03-26: `#[allow(dead_code)]` added to three future-API methods: `Config::load_from_default_locations`, `RuleService::collect_rule_list_dirs`, `RuleService::read_rules_dir_file_state_async`; workspace now builds with zero warnings.

- 2026-03-26: Added CLI flag parity with Go daemon (`--rules-path`, `--config-file`, `--ui-socket`) in daemon-rs `main.rs` via `parse_cli_overrides()`; `CliOverrides` threaded through `Daemon::start` → `bootstrap`; `Config` extended with `load_from_default_locations_with_override` and `with_rules_path_override`. Live-test rules isolation ported from `OPENSNITCH_CONFIG_FILE` temp-config to `-- --rules-path <tmpdir>` in `live_logs.rs`. Mock UI AskRule end-to-end round-trip fully exercised: real TCP SYNs to RFC 5737 TEST-NET addresses intercepted by nfqueue → `AskRule` → alternating allow/deny verdicts with `dest.ip` operator → `CHANGE_RULE_FROM_ASK` notification ack; 17/17 PASS. Background (non-TEST-NET) AskRule calls silently allowed via `_ASK_RULE_EXPECTED_DSTS` filter.

- 2026-03-26: Extended mock UI session to simulate real Python client behavior beyond endpoint reachability: Ping handler now logs stats fields (daemon_version, uptime, connections, rules) from PingRequest and emits `MOCK_UI PingStats` marker; Notifications handler now sends LOG_LEVEL command notification and correlates daemon NotificationReply by id, emitting `MOCK_UI NotificationCommandReply cmd=LOG_LEVEL` marker on reply — mirroring nodes.py/_notifications_sent callback dispatch; orchestration now asserts both new markers in addition to Subscribe/Ping/Notifications.

- 2026-03-26: Renamed `cargo unit` → `cargo ost` alias in `.cargo/config.toml`; extracted shared `test_guard.rs` privileged-command guard module and wired it into all guarded tools commands; ported test-guard semantics to `gotools` Go CLI and stripped `$(TEST_GUARD)` shell wrapper from the top-level Makefile (guard now lives entirely in the tools binaries). `DOCS.md` updated with full tools CLI reference (build/test/eBPF smoke/gotools sections).
- 2026-03-25: Completed full daemon-rs design-rule rescan against `DESIGN_RULES.md` constraints; fixed structural violations by making `services/policy_tx/mod.rs` and `services/lifecycle/mod.rs` linker-only, moving implementation into sibling files, and extracting policy transaction tests into `src/tests/services/policy_tx.rs`.
- 2026-03-25: Hardened firewall drift recovery in daemon runtime with detailed interception-health diagnostics, post-recovery convergence verification, and bounded retry backoff to avoid repeated immediate disable/ensure loops after failed convergence.
- 2026-03-25: Updated eBPF build policy so live/runtime eBPF compilation always runs as root under `target-kernel`; `build_ebpf.sh` now enforces root execution and Make targets route both build paths through the same root-owned kernel target tree.
- 2026-03-25: Completed dead-code warning review for touched surfaces: removed truly unused lifecycle/process helpers, retained compatibility placeholders with explicit `#[allow(dead_code)]` annotations where API intent is deliberate.
- 2026-03-25: Added guarded live-session orchestration parity between Make and tools paths: `daemon-rs-live-logs`, `daemon-rs-live-stop`, `daemon-rs-mock-ui-session`, and matching tools live commands now preserve test-guard privilege semantics and service preflight/restart behavior.
- 2026-03-25: Added lightweight non-GUI Python mock UI service (`daemon-rs/scripts/mock_ui_client.py`) and tools orchestration command `run-daemon-mock-ui-live-session` for deterministic daemon-to-UI handshake validation.
- 2026-03-25: Notification/session and client-command logs now include explicit client identity fields (`client_id`, `client_origin`) derived from `ClientPrincipal`; reconnect warning noise is throttled while preserving warn-level signaling for timeout/error/non-stateful disconnect paths.
- 2026-03-25: Added transactional policy mutation envelope (`services/policy_tx`) and integrated it into rule/control command paths (`commands/rule`, `commands/control`) including dedup (`DuplicateInFlight` / `DuplicateCommitted`), rollback handling, and persisted changeset/audit records.
- 2026-03-25: Added multi-user verdict arbitration and durability split in `flows/verdict`: per-connection decision key/epoch gate prevents stale concurrent AskRule writes; immediate verdict stays hot-path while rule persistence is delegated to background transactional worker.
- 2026-03-25: Added daemon config/runtime `AskTimeoutPolicy` (`allow|drop|default`, with default behavior when missing/null) and wired it only to daemon-side UI-miss fallback paths; concrete UI-returned rules remain authoritative.
- 2026-03-24: Added strict miss/default stats accounting mode for `nfqueue_overload_policy=drop-fast`: miss path now records `rule_misses` and verdict-based accepted/dropped without Go-style pessimistic drop bias; `fail-open` keeps Go parity accounting.
- 2026-03-24: Closed remaining SIEM/event-export parity gap: local `syslog` mode now uses system syslog writer semantics; event-export path parity with Go `log/loggers` + `statistics.OnConnectionEvent` is complete.
- 2026-03-24: Added runtime event-export logger hot-reload parity: `ConnectionEventLoggerAdapter` now refreshes sink workers from current config logger set during verdict-path emission without daemon restart.
- 2026-03-24: Added miss/default-action event export parity in `VerdictFlow`: miss paths now emit `ConnectionEventExporterPort` and stats backlog events with `rule=None` before applying default action.
- 2026-03-24: Implemented SIEM event-export baseline path in default runtime: concrete `ConnectionEventLoggerAdapter` wired into `VerdictFlow`, reconnect/backoff + `max_connect_attempts` behavior implemented, local sink fallback for empty `Server`, and formatter/sink tests added for JSON/CSV/RFC5424/RFC3164 over TCP/UDP.
- 2026-03-24: Added `daemon-rs/DOCS.md` and linked it in TODO `Documentation References`; aligned tracker rules so new canonical docs must be linked there.
- 2026-03-24: Privileged control boundary design finalized in `daemon-rs/DESIGN_RULES.md` (local owner-scoped path, remote capability-based authorization, `auth.*` rollout guard, and `UPDATE_*` naming).
- 2026-03-24: Backlog updated to keep Privileged Control Boundary Rule implementation as active future work.
- 2026-03-24: Older detailed documentation/design migration notes were swept from this tracker to keep TODO active-focused; refer to `git log -- daemon-rs/TODO.md` and canonical docs for historical detail.
