# Daemon-RS Unified Tracker

This is the single tracker file for backend parity, async/runtime hardening, and future enhancements.

It supersedes:

- `daemon-rs/FEATURE_PARITY.md`
- `daemon-rs/SERVICE_ASYNC_AND_MODEL_SCAN_2026-03-15.md`

Last update: 2026-03-24

## Scope

Track parity and runtime behavior between:

- Go backend: `daemon/`
- Rust backend: `daemon-rs/crates/daemon/`

Out of scope for now:

- Replacing NFQUEUE verdicting with a non-FFI backend.
- Replacing `libbpf-rs` usage with a full Aya runtime path as default.
- Replacing proc connector path with a high-level netlink crate.

## Current Status Snapshot

- Post-release baseline: `v0.4.0`.
- Netfilter/netlink migration scope for this branch is complete.
- Netlink protocol handling is unified on `netlink-bindings` + `netlink-socket2` (replacing older mixed per-protocol netlink crates).
- Detailed perf history and machine-readable stress baselines are maintained in `daemon-rs/PERF.md`.
- This tracker is now active-only and intentionally compact.

## Version Changelog

- Archived per-version release notes are maintained in `daemon-rs/CHANGELOG.md`.
- `TODO.md` tracks only the current active version context and open backlog items.

## Active Backlog (Post-v0.4.0)

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

- 2026-03-24: Added strict miss/default stats accounting mode for `nfqueue_overload_policy=drop-fast`: miss path now records `rule_misses` and verdict-based accepted/dropped without Go-style pessimistic drop bias; `fail-open` keeps Go parity accounting.
- 2026-03-24: Closed remaining SIEM/event-export parity gap: local `syslog` mode now uses system syslog writer semantics; event-export path parity with Go `log/loggers` + `statistics.OnConnectionEvent` is complete.
- 2026-03-24: Added runtime event-export logger hot-reload parity: `ConnectionEventLoggerAdapter` now refreshes sink workers from current config logger set during verdict-path emission without daemon restart.
- 2026-03-24: Added miss/default-action event export parity in `VerdictFlow`: miss paths now emit `ConnectionEventExporterPort` and stats backlog events with `rule=None` before applying default action.
- 2026-03-24: Implemented SIEM event-export baseline path in default runtime: concrete `ConnectionEventLoggerAdapter` wired into `VerdictFlow`, reconnect/backoff + `max_connect_attempts` behavior implemented, local sink fallback for empty `Server`, and formatter/sink tests added for JSON/CSV/RFC5424/RFC3164 over TCP/UDP.
- 2026-03-24: Added `daemon-rs/DOCS.md` and linked it in TODO `Documentation References`; aligned tracker rules so new canonical docs must be linked there.
- 2026-03-24: Privileged control boundary design finalized in `daemon-rs/DESIGN_RULES.md` (local owner-scoped path, remote capability-based authorization, `auth.*` rollout guard, and `UPDATE_*` naming).
- 2026-03-24: Backlog updated to keep Privileged Control Boundary Rule implementation as active future work.
- 2026-03-24: Older detailed documentation/design migration notes were swept from this tracker to keep TODO active-focused; refer to `git log -- daemon-rs/TODO.md` and canonical docs for historical detail.
