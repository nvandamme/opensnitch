# Daemon-RS Unified Tracker

This is the single tracker file for backend parity, async/runtime hardening, and future enhancements.

It supersedes:

- `daemon-rs/FEATURE_PARITY.md`
- `daemon-rs/SERVICE_ASYNC_AND_MODEL_SCAN_2026-03-15.md`

Last update: 2026-04-24 (full daemon-rs optimization scan + implementation plan)

## Scope

Track parity and runtime behavior between:

- Go backend: `daemon/`
- Rust backend: `daemon-rs/crates/daemon/`

Out of scope for now:

- Replacing NFQUEUE verdicting with a non-FFI backend.
- Replacing proc connector path with a high-level netlink crate.

eBPF library policy:

- **Aya is the preferred eBPF userspace library** for all new code and migration paths.
- `bpftool` subprocess usage must be eliminated from production paths (cannot guarantee system install).
- `libbpf-rs` is retained as an optional fallback feature (`libbpf-ebpf`) but is no longer required when `aya-ebpf` is enabled.
- Migration goal: make `aya-ebpf` sufficient as the sole eBPF runtime; `libbpf-ebpf` becomes a compat-only gate.

## Current Status Snapshot

- Active development: `v0.7.0` — subscription metrics + rule→subscription N:N mapping complete.
- Post-release baseline: `v0.6.0`.
- Subscription proto fully decoupled from `ui.proto`; `subscriptions.proto` carries its own
  service, enums, statistics shape, and `RuleSubscriptionEntry` N:N type.
- Metrics export covers both `pb.Statistics` (daemon) and `pb.SubscriptionStatistics`
  (subscription subsystem) across all formats (Prometheus text/OpenMetrics/proto, push-gateway, InfluxDB).
- Built-in one-shot cert generation supports local self-signed server/client PEM output
  (`--gen-self-signed-*-cert` + `--gen-self-signed-*-key`) for explicit TLS trust-anchor setup.
- `rule_subscriptions` field in `SubscriptionStatistics` provides live N:N rule→subscription
  mapping refreshed on every scheduler tick.
- Netfilter/netlink migration scope for this branch is complete.
- Netlink protocol handling is unified on `netlink-bindings` + `netlink-socket2`.
- Detailed perf history and machine-readable stress baselines are maintained in `daemon-rs/PERF.md`.
- This tracker is now active-only and intentionally compact.

## Version Changelog

- Archived per-version release notes are maintained in `daemon-rs/CHANGELOG.md`.
- `TODO.md` tracks only the current active version context and open backlog items.
- Release process rule (backfilled for `v0.5.0`, mandatory for future releases): every `release: vx.y.z` commit message must embed the full changelog content for that version (not only a condensed summary) to keep release metadata self-contained in git history.
- Release automation (preferred path): run `daemon-rs/scripts/release_commit_from_changelog.sh vX.Y.Z --dry-run` to preview, then `daemon-rs/scripts/release_commit_from_changelog.sh vX.Y.Z --push` to amend the release commit message, retag, and sync branch/tag in one step.

## Documentation References

- `daemon-rs/OPENWRT.md`: OpenWrt platform guidance for build-system/SDK assumptions, package/runtime model, ubus/uhttpd/rpcd integration, and adapter-boundary expectations.

## Validation Workflow

- Root-required live daemon session:
  - `make daemon-rs-live-logs`
  - `make daemon-rs-live-stop`
  - Make-level launch/stop targets are guarded through `TEST_GUARD` and tools-side privilege routing (`direct`/`pkexec`/`sudo`) to match privileged test orchestration behavior.
- User-scoped eBPF build policy:
  - `make daemon-rs-ebpf-build`
  - `make daemon-rs-ebpf-build-runtime`
  - `daemon-rs-ebpf-build` builds as regular user under `daemon-rs/target`.
  - `daemon-rs-ebpf-build-runtime` builds as regular user under `daemon-rs/target-runtime` for privileged runtime/test flows.
  - Privilege elevation is reserved for run/test orchestration paths, not the build step.
- Root-required daemon + mock Python UI orchestration (non-GUI compatibility flow):
  - `make daemon-rs-mock-ui-session`
  - This launches a lightweight Python gRPC mock UI endpoint, starts daemon-rs live logs, waits for `Subscribe`/`Ping`/`Notifications` handshake markers, then stops the live daemon session.
  - The same behavior is available directly via tools command `run-daemon-mock-ui-live-session` for non-Make invocation paths.
- Harness and regression/perf matrix:
  - `make parity-hot-cold-matrix STRESS_ROUNDS=1000`
  - `make parity-hot-cold-delta STRESS_ROUNDS=1000`
- Commit hygiene (mirrors `DESIGN_RULES.md` pre-commit checklist):
  - **Working-directory requirements (strict)**:
    - **Repo root required** (`opensnitch/`):
      - `cargo ost <command>`
      - `make <target>` wrappers (for example `make daemon-rs-mock-ui-session`, `make update-run-perf`)
      - Running `cargo ost` from `opensnitch/daemon-rs/` is invalid and will fail because it expects `daemon-rs/Cargo.toml` relative to repo root.
    - **Daemon workspace root required** (`opensnitch/daemon-rs/`):
      - Direct Cargo crate invocations such as `cargo build -p opensnitchd-rs`, `cargo check -p opensnitchd-rs`, `cargo test -p opensnitchd-rs ...`, `cargo test -p tools --test orchestration_smoke -- --nocapture`, and direct `cargo run -p tools -- ...` fallback commands.
      - Running these direct Cargo commands from repo root is invalid (`Cargo.toml` not found) unless an explicit `--manifest-path daemon-rs/Cargo.toml` is provided.
  - `cargo build` must be warning-free in touched scope.
  - If you bypass `cargo ost` and run privileged ignored smoke tests directly with elevated
    `cargo test`, use `-- --ignored --nocapture --test-threads=1` so Aya smoke tests run
    serially and do not conflict with the daemon single-instance guard.
  - Run tools orchestration CLI harness regression on every commit:
    `cargo test -p tools --test orchestration_smoke -- --nocapture`.
  - For most tools test/harness flows, prefer repo-level entrypoints when available:
    `cargo ost <command>` from repo root or root Makefile wrappers (`make <target>`).
    Keep the direct `cargo test -p tools --test orchestration_smoke -- --nocapture`
    invocation for this specific smoke test.
  - Run tools launcher regression commands on every commit:
    - `cargo ost run-daemon-mock-ui-live-session` or `make daemon-rs-mock-ui-session`
    - `cargo ost update-run-perf` or `make update-run-perf`
    - `run-daemon-mock-ui-live-session` timing semantics: daemon compile/startup time is gated by
      `OPENSNITCH_MOCK_UI_DAEMON_START_TIMEOUT_SECS` (default `180`) and is **not** counted against
      handshake/session marker windows.
    - Direct crate-level fallback remains valid:
      - `cargo run --release -p tools -- run-daemon-mock-ui-live-session`
      - `cargo run --release -p tools -- update-run-perf`
  - For warnings in touched code, either fix/remove the root cause or add a targeted
    `#[allow(...)]` with a short rationale when the API/path is intentionally retained.
  - When `mod.rs` `pub use` re-exports warn as unused, prefer consuming canonical re-export
    paths at call sites (for example `crate::config::*`) before considering `allow(unused_imports)`.
  - If an amended commit has already been pushed, push rewritten history with
    `git push --force-with-lease`.
  - Tracker hygiene for commits touching `TODO.md`:
    - Keep `TODO.md` active-only; when a change closes or supersedes a long backlog narrative,
      move durable detail to the owning docs (`CHANGELOG.md`, `COMPATIBILITY.md`, `PERF.md`,
      `DESIGN_RULES.md`) and leave only a short completion or status summary in `TODO.md`.
    - If a commit removes resolved backlog detail from `TODO.md`, the commit message should carry
      enough context to reconstruct what was archived or collapsed.
    - Older tracker states should be recovered from git history (`git log -- daemon-rs/TODO.md`,
      `git show <commit>:daemon-rs/TODO.md`) rather than preserved inline as pseudo-active backlog.
    - `Active tasks` should contain only unfinished current-slice work; new open items should use a
      normalized shape with goal, blockers if any, validation/proof, and an explicit closure condition.

## Active Backlog (Post-v0.7.0)

### Active tasks

- Current slice-local optimization follow-up is tracked below; broader open work remains under future enhancements and design-rule follow-ups.
- [ ] **PERF/FULL-SCAN-2026-04-24** Full daemon-rs optimization follow-up plan.
  - **Goal**: implement the next optimization pass found by the 2026-04-24 full workspace scan without weakening hot-path wait-free/read discipline or moving behavior across domain boundaries.
  - **Scan scope/proof**: reviewed `daemon-rs/crates/{daemon,tools,transport-wire-*,storage-format-*,kernel-caps}` with targeted `rg` scans for clone/allocation-heavy conversions, formatting, JSON encode/decode, lock waits, filesystem/proc reads, snapshot accessors, exporter copies, and >400/>500 line density; cross-checked findings against `DESIGN_RULES.md` hot-path and tracker rules.
  - **Priority A — shared immutable wire payload snapshots for verdict/event paths** (`crates/daemon/src/flows/verdict/{verdict.rs,helpers.rs}`, `crates/daemon/src/services/stats/*`, `crates/daemon/src/platform/ports/connection_event_exporter_port.rs`):
    - **Status 2026-04-24**: first implementation slice landed locally. Verdict flow now builds one per-attempt `Arc<WireConnection>` daemon-internal snapshot, stats event history stores shared connection/rule payloads until snapshot drain, warning alerts borrow the shared payload, and `ask_rule` remains the documented owned transport boundary.
    - treat `WireConnection` as an immutable wire payload DTO, not a transport/session handle; any sharing must preserve the transport/wire split so gRPC, Unix socket, ubus, and future transports remain adapter-owned,
    - wrap the per-attempt `WireConnection` once as an internal shared snapshot (`Arc<WireConnection>` or a daemon-local newtype) so stats event history, alert/exporter paths, and fallback branches reuse the same payload without deep-cloning `String`/`Vec`/`HashMap` fields,
    - keep transport-wire-core DTOs plain unless a broader adapter contract change is justified; prefer daemon-internal event records that hold shared wire payload snapshots and materialize owned transport payloads only at final adapter/wire boundaries,
    - replace `summary_rule_to_wire` static `String` clones with cheaper `&'static str`/owned-at-boundary construction or a shared immutable summary rule snapshot when stats/exporters need the same rule payload,
    - avoid rebuilding idempotency strings with intermediate `decision_key.to_string()` when a stack-backed formatter or single `write!` into the final buffer is enough.
    - **Validation/proof**: add/extend verdict flow regression tests for runtime-rule, unknown-default, client-connect-failure, ask-rule-failure, stale-decision, and client-rule persistence; compare `make parity-hot-cold-delta STRESS_ROUNDS=1000` before/after and require no p95/p99 regression. Local proof for the first slice: `cargo fmt --check`; `cargo check -p opensnitchd-rs`; `cargo test -p opensnitchd-rs stats_service -- --nocapture`; `cargo test -p opensnitchd-rs stats_flow -- --nocapture`; elevated `cargo test -p opensnitchd-rs verdict_flow -- --nocapture`.
    - **Closure condition**: verdict behavior and transport/wire decoupling are unchanged, connection event storage no longer requires repeated deep `WireConnection` clones, and any remaining owned clone happens only at a documented final wire/export boundary.
  - **Priority A — metrics snapshot/exporter copy reduction** (`crates/daemon/src/services/stats/snapshot_ops.rs`, `crates/daemon/src/platform/adapters/stats_exporters/{http_serve.rs,http_push.rs,http_push_influxdb.rs,syslog_push.rs,encoder_*}.rs`):
    - **Status 2026-04-24**: implementation slice landed locally. `MetricsSnapshot` now owns a cached shared `Arc<MetricsExportSnapshot>` export view; HTTP serve, HTTP push, InfluxDB push, and syslog exporters reuse that compact pre-sorted view instead of each adapter independently cloning/sorting the same breakdown maps. Syslog now queues the compact shared view rather than a cloned full `MetricsSnapshot`.
    - split UI ping stats from exporter stats so `StatsFlow` does not deep-clone large breakdown maps unless an exporter is enabled or pending,
    - store/export compact metrics snapshots behind `Arc` where multiple exporters consume the same tick, instead of independently cloning `subscription_stats`, `by_rule`, and sorted label pairs,
    - precompute sorted/breakdown vectors once per tick and share them across text/OpenMetrics/protobuf/push/syslog encoders.
    - **Validation/proof**: run metrics exporter tests (`stats_exporter_prometheus`, `stats_exporter_push`, `stats_exporter_syslog`, `stats_service`) and a metrics-enabled `cargo build`; compare one 60s metrics run with large synthetic breakdown maps. Local proof for this slice: `cargo fmt --check`; `cargo check -p opensnitchd-rs`; all-metrics `cargo check -p opensnitchd-rs --features metrics-http-serve-text,metrics-http-serve-openmetrics,metrics-http-serve-protobuf,metrics-http-push-text,metrics-http-push-openmetrics,metrics-http-push-protobuf,metrics-http-push-influxdb,metrics-syslog`; all-feature `prometheus_exporter_tests`, `push_exporter_tests`, and `syslog_exporter_tests`; `cargo test -p opensnitchd-rs stats_service -- --nocapture`.
    - **Closure condition**: exporter output remains byte-for-byte compatible where tests assert exact text, and per-tick clone/sort work is centralized.
  - **Priority B — process and DNS event allocation cleanup** (`crates/daemon/src/services/process/details.rs`, `crates/daemon/src/services/dns/parsing.rs`):
    - **Status 2026-04-24**: implementation slice landed locally. Process inspection/hash paths now reuse `/proc/<pid>` `PathBuf` joins instead of repeated `format!("/proc/{pid}/...")` construction, and IMA digest hex encoding uses the shared preallocated hex helper. Native eBPF DNS dedupe now uses typed keys (`DnsDedupKey::{Answer,Alias}`) backed by `IpAddr` + `Arc<str>` payloads instead of per-event concatenated `String` keys (`ip|host`).
    - avoid formatting `/proc/{pid}/...` paths repeatedly by reusing `PathBuf`/small buffers in process inspection and hash lookup,
    - build `env_preview` and `env_map` without duplicating every environment entry string when only key/value lookup and preview are needed,
    - change eBPF DNS dedupe key from one concatenated `String` (`ip|host`) to a typed key (`IpAddr` or enum + host `Arc<str>`/boxed string) to avoid per-event `ip.to_string()` plus concatenation.
    - **Validation/proof**: run `process_service`, `process_hash`, DNS worker/dedup tests, and the rule/process-env matching tests; add a focused DNS dedupe benchmark or timing smoke if no benchmark exists.
    - **Closure condition**: no regression in hash/env/rule matching semantics, and DNS dedupe no longer allocates an IP text key on every event.
  - **Priority B — owner-scope and firewall expression matching** (`crates/daemon/src/flows/notification/owner_scope.rs`, firewall adapter expression helpers):
    - **Status 2026-04-24**: implementation slice landed locally. Firewall owner-scope expression matching now avoids per-call `Vec<String>` GID text materialization and reuses shared parsed `meta` statement helpers for both positive owner-scope checks and conflict detection (`skuid`/`skgid`), keeping behavior aligned while reducing allocation churn on repeated authorization checks.
    - replace `owner_group_gids.iter().map(ToString::to_string).collect::<Vec<_>>()` with parse-on-demand numeric matching or a temporary `HashSet<u32>` only when group count crosses a small threshold,
    - reuse parsed owner match fragments for repeated firewall-rule authorization checks during notification command batches.
    - **Validation/proof**: run notification-flow owner-scope tests under the elevated suite and targeted local tests for UID/GID-scoped firewall/rule mutations.
    - **Closure condition**: local/remote privilege behavior is unchanged and group matching avoids per-rule string vector allocation.
  - **Priority B — storage/rule watch metadata churn** (`crates/daemon/src/services/storage/storage.rs`, `crates/daemon/src/services/rule/storage.rs`, `crates/daemon/src/workers/runtime/watch/*`):
    - **Status 2026-04-24**: implementation slice landed locally. Poll-triggered rule-watch scans now keep a single metadata pass (`read_rules_dir_scan_with_hint`) and hand the discovered main rule file paths directly into `RuleService::reload_from_rule_paths`, avoiding an immediate second rule-directory listing in the same reload cycle while preserving the existing inotify fast path.
    - keep one directory scan result usable for state comparison and reload target selection instead of re-listing/listing-with-metadata in adjacent watch paths,
    - preserve the current inotify fast path while adding a cold-path batched metadata snapshot for nested list directories,
    - keep all storage-format parsing behind adapter boundaries.
    - **Validation/proof**: run `watch_reload::watch_workers`, `rule_service`, and storage-format adapter tests; compare cold reload timing from existing watch reload smoke tests.
    - **Closure condition**: add/delete/list-content reload behavior stays Go-compatible and redundant directory metadata scans are removed from the same reload cycle.
  - **Priority C — adapter/tool cold-path allocation cleanup**:
    - **Status 2026-04-24**: implementation slices landed locally. `storage-format-uci` now uses keyed accumulation for repeated section list options instead of O(n²) `lists.iter_mut().find(...)`; `transport-wire-grpc-client` TLS identity extraction now uses a preallocated lower-hex encoder for SHA-256 fingerprints (`hex_lower`) instead of per-byte `format!`; tools live-session marker waits now use incremental offset-based log polling (instead of repeated full-file `read_to_string` loops), and process-tree cleanup reads `/proc/<pid>/status` via buffered line scanning up to `PPid:` instead of slurping full status files.
    - `crates/storage-format-uci/src/serde_bridge.rs`: replace per-section list accumulation with keyed accumulation to avoid O(n²) `lists.iter_mut().find(...)` for sections with many repeated list options,
    - `crates/transport-wire-grpc-client/src/tls.rs`: reuse the daemon hex encoder pattern for SHA-256 certificate fingerprints instead of per-byte `format!`,
    - `crates/tools/src/{main.rs,harness_cmds.rs,live_logs.rs,build_cmds.rs}`: split large command files while reducing repeated `/proc` scans/log-file reads in live-session cleanup and perf harness paths.
    - **Validation/proof**: run storage-format UCI tests, transport-wire gRPC client tests, and `cargo test -p tools --test orchestration_smoke -- --nocapture`.
    - **Closure condition**: cold-path behavior and fixture output stay unchanged; obvious repeated allocations are removed where the code is touched.
  - **Blockers/constraints**: full hot-path proof needs elevated/root runner parity because daemon-rs production paths require netlink socket and eBPF map access; do not add new global mutable singletons, protobuf leaks, or async lock waits in verdict/connect/kernel/eBPF paths.
  - **Overall validation**: `cargo fmt`; `cargo build -p opensnitchd-rs`; targeted tests listed above; `cargo test -p tools --test orchestration_smoke -- --nocapture`; elevated full daemon-rs suite; `make parity-hot-cold-delta STRESS_ROUNDS=1000` for any Priority A/B hot-path implementation.
  - **Closure condition**: this task closes when Priority A/B items are either implemented with validation and `PERF.md` updated, or explicitly marked no-op with benchmark/profiling evidence; Priority C may move to a separate cold-path cleanup task if it would otherwise delay hot-path closure.
- [x] **Completed 2026-04-24 daemon-rs optimization scan** — rule service snapshots now share immutable rule records through `Arc<Vec<RuleRecord>>` so rollback/listing capture avoids full rule-set clones, and process hash digest formatting now uses a preallocated hex encoder instead of per-byte `format!` allocation. Validation: `cargo check -p opensnitchd-rs`; `cargo test -p opensnitchd-rs rule_service -- --nocapture`; `cargo test -p opensnitchd-rs rule_command -- --nocapture`; `cargo test -p opensnitchd-rs process_hash -- --nocapture`.
- [x] **Completed v0.7.0 summary** — subscription proto decoupling, subscription/daemon metrics export, rule↔subscription N:N mapping, per-rule hit metrics, command-layer restructuring, and expanded metrics test coverage landed. Historical detail lives in `CHANGELOG.md` and the relevant release / implementation commit messages.
- [x] **Completed v0.5.1 runtime/perf summary** — aya-first eBPF userspace migration, hash-safety hardening and persistent cache, `DashMap` / `ArcSwap` / `quick-cache` migrations, and hot-path allocation / contention reductions landed. Historical detail lives in `PERF.md` and the relevant implementation commit messages.

### Future enhancements

- [ ] **PERF/FUTURE-HYBRID-BANDIX** Future performance goal: add Bandix-inspired observability + explore a fat Aya bootstrap branch for faster verdict flow experiments.
  - **Goal**: define a future-focused performance track (not a Phase 0 release gate) that improves hybrid eBPF verdict observability now and enables an optional fast-branch bootstrap path for later experiments.
  - **Reference baseline (full Bandix repository)**:
    - [https://github.com/timsaya/bandix](https://github.com/timsaya/bandix)
    - Scope to review explicitly: root architecture + `bandix/` userspace runtime + `bandix-ebpf/` Aya eBPF modules + `bandix-common/` shared wire/model structs.
  - **Why Bandix behavior is relevant**:
    - Bandix demonstrates that a lightweight eBPF-first classification stage can expose stable, low-overhead runtime signals (map occupancy/pressure, drop actions, ringbuf backpressure) that are useful even when policy authority remains in userspace.
    - For daemon-rs, the useful takeaway is not Bandix policy semantics, but Bandix-style observability semantics: count fast-path decisions and overflow conditions close to the kernel boundary, then reconcile with canonical userspace verdict accounting.
    - This directly reduces blind spots in hybrid mode where NFQUEUE fallback correctness depends on understanding hit/miss ratios, stale-entry churn, and cache-pressure behavior over time.
  - **Fat Aya bootstrap branch exploration (future experimental branch, optional)**:
    - Explore a single shared Aya program bootstrap pattern (Bandix-style shared ingress/egress module orchestration) for faster bring-up of a dedicated verdict-fast experiment branch.
    - Keep daemon-rs policy authority unchanged: kernel fast path may short-circuit known decisions, but canonical rule semantics and misses remain userspace/NFQUEUE-controlled.
    - Add explicit bootstrap counters so branch viability is measurable from first run:
      - `diag.hybrid.bootstrap.program_attach_success_total`
      - `diag.hybrid.bootstrap.program_attach_error_total`
      - `diag.hybrid.bootstrap.map_open_success_total`
      - `diag.hybrid.bootstrap.map_open_error_total`
      - `diag.hybrid.bootstrap.runtime_fallback_total`
  - **How to implement explicit metrics/counters (Bandix-inspired, daemon-rs semantics)**:
    - Add hybrid verdict counters at decision boundaries:
      - `diag.hybrid.fastpath_allow_total`
      - `diag.hybrid.fastpath_drop_total`
      - `diag.hybrid.fallback_nfqueue_total`
      - `diag.hybrid.cache_miss_total`
      - `diag.hybrid.cache_stale_total`
    - Add cache lifecycle counters from daemon-triggered writes/invalidations:
      - `diag.hybrid.cache_insert_total`
      - `diag.hybrid.cache_update_total`
      - `diag.hybrid.cache_delete_total`
      - `diag.hybrid.cache_invalidate_rule_reload_total`
      - `diag.hybrid.cache_invalidate_config_reload_total`
      - `diag.hybrid.cache_invalidate_owner_change_total`
    - Add pressure/backpressure counters modeled after Bandix map/ring stress observability:
      - `diag.hybrid.map_pressure_events_total`
      - `diag.hybrid.map_prune_total`
      - `diag.hybrid.ringbuf_poll_errors_total`
      - `diag.hybrid.ringbuf_samples_dropped_total`
    - Wire points (initial slice):
      - increment fast-path/fallback counters in the connection/verdict boundary where eBPF cache decision is arbitrated against NFQUEUE fallback,
      - increment cache mutation/invalidation counters in rule/config reload paths and post-verdict cache write path,
      - increment pressure/backpressure counters in eBPF supervisor/ringbuf worker paths where map pressure and poll failures are already detected.
    - Export/visibility requirements:
      - all new counters must flow through existing daemon statistics export surfaces (Prometheus/OpenMetrics/proto) with stable names,
      - add a periodic consistency check metric `diag.hybrid.accounting_skew_total` to record mismatches between fast-path counters and userspace verdict totals during validation runs.
  - **Blockers**: unresolved hook trade-off (`cgroup/connect4+connect6` vs `tc`) and unresolved key trade-off (`socket cookie` vs normalized 5-tuple + uid/process identity), plus unresolved scope boundary for how far a fat Aya module can go without duplicating RuleService policy semantics.
  - **Validation/proof**: commit a short future-goal memo + decision table and add focused test/perf plan bullets covering miss fallback correctness, stale-cache prevention, and p50/p95/p99 latency impact; include one mock/harness run report proving that each listed counter can be incremented at least once in a controlled scenario.
  - **Closure condition**: this task closes when the future-goal metrics contract is accepted (including bootstrap counters), Bandix reference scope is documented with the full repository URL above, and a concrete fast-branch exploration plan exists without reclassifying the work as mandatory Phase 0 delivery.

- [ ] **ARCH/OPENWRT** Deliver OpenWrt-native storage and ubus transport adapters without policy-layer coupling.
  - **Objective**: keep OpenWrt file formats, runtime command plans, and transport wiring adapter-owned while daemon services/flows stay canonical-model-first.
  - **Remote progress already landed**: firewall zones are part of the canonical firewall model, backend-to-DTO extraction exists for nftables and iptables, OpenWrt firewall authority is explicit (`OpenWrtUci`), UCI CLI plan scaffolding exists behind the `openwrt` feature, and OpenWrt mode now hard-requires UCI storage-format support.
  - **Policy to preserve**: generic Linux persistence is manager/nftables/iptables-owned as appropriate; OpenWrt persistence remains UCI/firewall4-owned, while runtime introspection and health stay netlink-first.
  - **Next work**: finish adapter-crate boundaries for ubus event/RPC transport and LuCI polling compatibility over the same `/ubus` JSON-RPC surface, without leaking OpenWrt wire/storage structs into daemon policy layers.
  - **Validation**: OpenWrt additions must stay adapter-local, daemon policy signatures must remain model-first, and transport/storage adapter tests must live with the owning adapter crates.
  - **Closure condition**:
    - ubus method/event schema v1 is defined and used as the single LuCI polling surface,
    - package skeleton and procd/UCI runtime assets exist in the OpenWrt package repo,
    - backend<->LuCI compatibility matrix and package release update automation are documented and exercised once.
  - **Reference**: OpenWrt UCI storage and ubus transport design is documented in `OPENWRT.md` with detailed rationale and implementation notes for deamon-rs and LuCI App.

- [ ] **ARCH/FIREWALL-PERSISTENCE** Implement true file-backed persistence surfaces per backend authority.
  - **Objective**: make firewall mutations survive reboot/reload through backend-owned persistent surfaces rather than runtime-only netlink/CLI mutation.
  - **nftables path**: detect the real loader contract from `/etc/nftables.conf`, persist only through an existing include-backed or explicitly provisioned managed path, and fail loudly on ambiguous/unsupported layouts instead of silently inventing one.
  - **iptables path**: target distro-native persistent restore authorities/services rather than treating runtime CLI mutation as durable state.
  - **OpenWrt path**: keep persistence on UCI CLI/ubus command plans; remote branch progress already includes stale managed-section removal and sidecar mapping for daemon rule identity during LuCI/UCI renames.
  - **Validation**: persistence must be idempotent, authority-owned, reload-safe, and verified with backend-specific restart/reload tests.

- [ ] **PERF/ARCH** Prototype hybrid eBPF fast-path ahead of NFQUEUE.
  - **Goal**: keep the current NFQUEUE/userspace rule engine as the canonical verdict source, while allowing eBPF to short-circuit already-known allow/deny decisions for repeat flows before they reach the queue.
  - **Non-goal**: do not attempt a 1:1 "port NFQUEUE to eBPF" replacement. eBPF may enforce cached decisions, but it cannot synchronously block on UI/userspace verdicts.
  - **Phase 0 design spike**: choose the hook point (`cgroup/connect4` + `connect6` preferred for local outbound flows; validate `tc` / other hook trade-offs), define the cache key (`socket cookie` vs normalized 5-tuple + uid/process identity), TTL/invalidation rules, and miss-path telemetry.
  - **Phase 1 prototype**: eBPF map hit => immediate allow/drop fast-path; eBPF map miss => fall back to the current NFQUEUE path unchanged.
  - **Phase 2 daemon integration**: after the canonical userspace verdict, write short-lived allow/deny cache entries into the eBPF map for subsequent connects; invalidate affected entries on rule reload/delete, config reload, and owner/process metadata changes where required.
  - **Guardrails**: no policy drift from `RuleService` semantics, no UI-interaction logic inside eBPF, preserve `fail-open` / `drop-fast` behavior, preserve auditable rule-hit/miss accounting, and keep the feature explicitly optional until parity is proven.
  - **Validation**: add A/B perf harness coverage against the current NFQUEUE-only path and always compare Rust daemon-rs vs Go backend when comparable harnesses exist; track p50/p95/p99 first-packet latency, miss rate, cache churn, stale-decision risk, and fallback frequency.

- [x] **Completed enhancement summary** — kernel capability diagnostics, API-surface file splits, stats exporter implementations, Prometheus/OpenMetrics support, metrics hot-reload, and metrics config migration are complete. Detailed rationale and implementation history live in `CHANGELOG.md` and the related commit messages.

- [ ] Implement Privileged Control Boundary Rule (local + remote).
  - **Current branch progress (2026-03-28)**:
    - **Done**: explicit `auth.mode` plumbing added to config/runtime parsing with
      `legacy | local-only | local+remote` parsing and `legacy` default.
    - **Done**: local auth config model supports `AllowedPrincipals` (`UID`+`GID`),
      `AllowedUsers` (resolved through libc account lookup), and `AllowedGroups`
      (resolved through libc group lookup) with dedup/sort and warning-on-invalid-entry behavior.
    - **Done**: runtime config carries both `local_control_allowed_principals` and
      `local_control_allowed_group_gids` for local authorization data.
    - **Done**: notification flow enforces local peer identity before connect handshake:
      UNIX sockets use SO_PEERCRED (`uid/gid/pid`) plus supplementary groups from
      `/proc/<pid>/status`; loopback TCP can enforce owner UID from `/proc/net/tcp*`
      and group checks via inode->pid resolution.
    - **Done**: notification ingress now classifies privileged actions and applies
      `auth.mode` policy before queueing `ClientCommand`s; hardened modes deny remote
      privileged mutations and require verified local identity for local privileged commands.
    - **Done**: parser and flow tests added for missing/null allowlist compatibility,
      principal parsing, username resolution, UNIX allow/deny, and loopback TCP allow/deny checks.
    - **Done**: hardened local modes default to root-only local privileged access when no
      explicit principal/group policy data is configured.
  - **Rollout policy direction**:
    - Use explicit runtime policy mode, not implicit field absence, to choose between
      compatibility and hardening.
    - `auth.mode = legacy | local-only | local+remote`
    - `legacy`: preserve current OpenSnitch trust model for migration compatibility,
      with loud warnings/audit records on privileged mutations.
    - `local-only`: enforce every locally verifiable authorization signal available now
      (SO_PEERCRED, loopback owner lookup, supplementary groups, owner-scope validators).
    - `local+remote`: remote privileged mutations require explicit
      principal/capability authorization; when no remote binding/capability match exists,
      privileged mutations remain deny-by-default.
    - `AllowedPrincipals` / `AllowedUsers` / `AllowedGroups` are policy data, not the rollout switch.
  - **Phase 1 (completed 2026-03-29)**:
    - Preserve baseline compatibility while introducing explicit policy surfaces.
    - Keep `legacy` as a first-class mode selectable by config (`Server.Authentication.Mode`) and by daemon startup switch (`--auth-mode legacy`).
    - Ensure daemon startup switch can override config for emergency rollback to legacy behavior during phased rollout.
    - Maintain deny-by-default for remote privileged commands outside `legacy` while local-only owner-scope checks continue to mature.
    - Runtime auth audit surfacing is active: denied privileged commands emit warn logs, legacy-mode privileged command allows emit explicit warning-level audit logs, and auth decision logs carry verdict fallback context (`nfqueue_overload_policy`, `AskTimeoutPolicy`).
  - **Phase 2 (in progress)**:
    - Introduced explicit ingress authorization classification buckets (`always_allowed`, `user_scoped_allowed`, `elevated_required`, `always_denied`) in notification flow.
    - Added tests to pin classification behavior and preserve local-root elevated allowance in hardened modes.
    - Added daemon-side owner-scope normalization/injection for compatible local non-elevated rule updates (`CHANGE_RULE`/`ENABLE_RULE`/`DISABLE_RULE`) with fail-closed conflict rejection when payload owner constraints disagree with authenticated caller scope.
    - Auth hardening must stay aligned with verdict fallback strategy: `fail-open` must keep privileged-command denials scoped to control mutations only, while `drop-fast` must preserve non-blocking/fail-closed packet-path behavior and strict miss accounting.
    - Auth normalization/authorization logs now include fallback-policy context so operators can distinguish `auth denied` from verdict/UI-miss behavior under `fail-open` vs `drop-fast`.
    - Added conservative firewall reload compatibility normalization for local non-root payloads: daemon injects `-m owner --uid-owner <uid>` for simple iptables-style rules and appends `meta skuid == <uid>` for compatible nft-style statement payloads when owner scope is absent; conflicting owner tokens/statements still fail closed.
    - Rule-mutation compatibility is daemon-driven, not UI-driven: for current Python UI behavior, missing owner scope on compatible incoming local rule mutations is transparently normalized to the authenticated caller UID by the daemon.
    - Added action-scoped hard rule schema constraint in hardened modes: `CHANGE_RULE` now requires non-empty operand semantics, while legacy minimal stubs for `ENABLE_RULE` / `DISABLE_RULE` / `DELETE_RULE` remain compatibility-accepted and continue through owner-scope/elevated authorization arbitration.
    - Clarified local principal semantics: UID remains the authenticated owner-scope anchor, while `AllowedPrincipals.GID` and `AllowedGroups` act as broad primary/supplementary group selectors rather than standalone authorization proof.
    - Formalized config-scope policy boundary: daemon config remains supplementary gating over OS-derived identity (peer credentials + syscall-backed account/group resolution), not an independent identity authority.
    - Clarified service/elevation boundary: daemon-rs remains a background service, not the desktop authority for deciding who may elevate; local interactive elevation should ultimately be UI-mediated through host backends such as polkit/pkexec, with the daemon consuming only the resulting grant/decision.
    - Added explicit ownerless-rule migration/arbitration mode for hardened deployments:
      one-shot CLI entrypoint (`--migrate-ownerless-rules --migrate-owner-uid <uid>`), dry-run by default, `--migrate-write` for persistence, and fail-closed write behavior when ambiguous/conflicting legacy rules remain.
    - Hardened authorization now resolves legacy `ENABLE_RULE` / `DISABLE_RULE` / `DELETE_RULE` minimal stubs against stored rules by name so principal-owned rule operations remain non-elevated when stored owner scope matches caller UID.
    - Extended owner-scope no-elevation logic to group selectors: `user.gid` rule operands and firewall owner matches (`--gid-owner` / `meta skgid`) are accepted when caller UID membership includes the referenced GID, with membership derived from syscall-backed account/group lookup (`getpwuid` + `getgrouplist`).
    - Decided nested `FwChain.rules` payloads remain elevated-required in hardened modes: owner-scope compatibility normalization applies only to flat owner-matchable firewall rule payloads, not chain-bearing payloads that can shape global chain metadata.
    - Added daemon-side remote-principal binding foundations for `local+remote`: `Server.Authentication.RemotePrincipalBindings` now maps certificate fingerprint / subject / SAN selectors to a resolved local principal plus normalized capability names, and config reload auth fingerprints treat those bindings as auth-relevant state.
    - Next slice: begin real server-mode identity subtasks (socket principal attachment / TCP listener principal attachment) so `local+remote` can extend the same authorization semantics to daemon-accepting server paths.
    - Implemented remote capability-based authorization for `local+remote` mode:
      `notification_command_allowed` now routes all `RemoteCert` sessions through
      `check_remote_capability_authorization` instead of the local peer-principal gate.
    - Added canonical capability constants model (`auth_capability.rs`): 10 capability strings
      (`rules.owner.write`, `rules.global.write`, `firewall.owner.write`, `firewall.global.write`,
      `config.write`, `daemon.control.stop`, `task.control`, `log.level`, `firewall.toggle`,
      `interception.toggle`) with `required_capability(action, class) -> Option<&str>` mapping.
    - Extended `ClientPrincipal` with `RemoteCert { binding_name, mapped_uid }` variant and
      `ClientSession` with `capabilities: Vec<String>` field, `for_remote_principal()` constructor,
      and `has_capability()` method.
    - Added `resolve_remote_principal_binding(config, fingerprint, subject, san)` that matches
      cert identity against configured `RemotePrincipalBindings` (priority: fingerprint > subject > SAN)
      and returns a capability-bearing `ClientSession`.
    - Wired config-based remote principal resolution into `session_binding_from_client_addr`:
      for TLS-configured remote endpoints, server cert PEM is loaded and identity extracted
      (`extract_identity_from_pem`) then resolved against bindings before falling through to
      generic network/IP sessions.
    - Added TLS cert identity infrastructure (`CapturedServerCertIdentity`, `CertCapturingVerifier`,
      `extract_identity_from_pem`) in transport layer using `x509-cert` + `sha2` for fingerprint/
      subject/SAN extraction from DER/PEM certificates.
    - Owner-scope normalization (`normalize_owner_scoped_rule_mutation_rules`,
      `normalize_owner_scoped_firewall_reload`) and `classify_privileged_notification_action`
      now extract owner UID from `RemoteCert { mapped_uid, .. }` alongside `LocalUid`.
    - Added 3 new audit event variants: `AllowedRemoteCapability`, `DeniedRemoteCapability`,
      `RemotePrincipalResolved` with Display formatting and audit emit sites in notification flow
      (denied/allowed authorization policy emits now differentiate local vs remote-capability
      sessions; `RemotePrincipalResolved` emitted on session binding resolution).
    - 24 new tests: remote principal binding resolution (fingerprint/subject/SAN/no-match/not-configured),
      required capability mapping (owner/global/elevated commands/always-allowed/always-denied),
      remote capability authorization via `notification_command_allowed` (allow with cap, deny without cap,
      deny empty caps, root mapped uid, owner-scoped rule, global rule with owner-only cap, legacy bypass,
      non-privileged action bypass), session construction (`for_remote_principal`, `has_capability`,
      local empty caps), remote principal classification (mapped uid owner scope check),
      owner-scope normalization with RemoteCert, PolicyOwner conversion, audit Display formatting.
    - Full test suite: 515 passed, 0 failed, 7 ignored (baseline was 491).
    - Next slice: begin server-mode identity subtasks (socket principal attachment for
      daemon gRPC server path when daemon acts as server accepting connections).
  - **Server-mode identity subtasks** (real daemon gRPC server path):
    1. Unix domain socket acceptor: read per-connection SO_PEERCRED (uid/gid/pid) and attach
       the resolved principal to request/session context before command dispatch.
    2. TCP listener identity: enforce explicit client identity via mTLS principal mapping
       (transport auth separate from authorization), then apply capability/policy checks per command.
    3. Loopback hardening path: for local TCP control endpoints, cross-check active listener ownership
       from `/proc/net/tcp*` (uid + inode -> pid where available) and apply local principal/group policy.
  - Add startup warnings/audit surfacing for non-remote-safe modes (`legacy`, transitional `local-only`).
  - In `legacy`, keep compatibility behavior explicit; do not infer it from missing principal config.
  - Extend `local-only` from current local identity/elevation enforcement to full owner-scope validation
    for all rule/firewall mutation shapes (remaining decision point: nested `FwChain.rules` normalization path).
  - In `local+remote`, remote capability-based authorization is now functional for configured
    `RemotePrincipalBindings` and live TLS handshake cert identity capture; remaining:
    server-mode daemon identity subtasks.
  - Remote manager identity model for `local+remote`:
    - derive remote UI identity from strong channel auth (mTLS fingerprint / SAN / subject or equivalent), never from payload-supplied username/uid/gid fields,
    - map that remote identity server-side to an existing daemon-host principal or dedicated service account,
    - resolve mapped principal UID/GID/groups from the node OS before any owner-scope authorization decision,
    - fail closed when no remote-identity mapping exists.
  - Keep remote owner-scoped management and remote elevated/global management as distinct authorization lanes:
    - owner-scoped remote mutations validate against the mapped principal's local UID/GID/group set,
    - global/shared mutations require explicit elevated capability or short-lived session-bound elevation grant,
    - valid remote manager identity alone must not imply global write authority.
  - Classify incoming UI commands into unprivileged (verdict, stats, notifications) vs privileged
    (rule persistence/deletion, config apply, firewall enable/disable/reload, subscription management, shutdown).
  - Canonicalize privileged mapping names to `UPDATE_*` semantics in proto/client/daemon command mapping surfaces.
  - Gate all privileged paths behind explicit daemon-side authorization with secure defaults
    driven by `auth.mode`.
  - Apply local-only owner-scope policy to local daemon/UI paths; require principal/capability-based
    authorization for remote daemon management (separate concerns from transport auth).
  - Keep transport auth (`simple` / `tls-simple` / `tls-mutual`) separate from authorization;
    channel trust alone is not sufficient for host-wide mutation.
  - **Elevation-aligned follow-on tasks**:
    - Deny any rule/firewall mutation that cannot prove caller owner scope or carry an explicit
      elevation grant; treat precedence rules, raw parameter escapes, chain/table/policy edits,
      shared config writes, and daemon-control commands as `elevated_required` by default.
    - Add an explicit remote elevation/auth RPC surface (likely a dedicated `auth.proto`, not the
      existing Notifications bidi stream) for future `local+remote` mode.
    - **Done**: added a daemon-side remote-principal binding table/config model (`Server.Authentication.RemotePrincipalBindings`) so remote UIs can be mapped from strong channel identity (cert fingerprint / subject / SAN) to a local principal plus capability set without impersonating arbitrary payload-supplied users.
    - Add a short `auth.proto` design sketch before implementation so PAM/capability work is
      anchored to explicit RPC boundaries (`BeginElevation`, PAM completion, grant state/revoke)
      instead of being buried in notification payload conventions.
    - PAM design spike: validate whether daemon-side PAM can safely back remote elevation on the
      target node, including session-bound grants, short TTL, replay protection, audit logging,
      and strong channel binding; do not accept reusable passwords on the notification stream.
    - Model remote elevation as a node-local proof that mints a daemon-validated grant for a
      specific client session and command class (`rules.global.write`, `firewall.global.write`,
      `config.write`, `daemon.control.stop`), not as a blanket authenticated session switch.
    - Preserve compatibility with current UI rule create/update flows by auto-injecting caller
      owner scope for non-elevated rule mutations at daemon ingress when the client omits it.
    - Owner-scope injection plan: add daemon-side normalization that augments compatible UI rule
      payloads with caller `uid`/`gid` constraints before validation/persistence, while rejecting
      payloads that already conflict with the authenticated caller scope.
    - PID scoping requires a separate semantics pass: do not persist stale `pid`-bound rules as
      durable policy by default; if supported, restrict automatic `pid` injection to ephemeral or
      session-bound rules where Linux process-lifetime semantics remain valid.
    - Evaluate whether owner-scoped firewall reload compatibility needs a similar normalization path
      (`iptables -m owner --uid-owner/--gid-owner`, `nft meta skuid/skgid`) for non-elevated local
      clients, while keeping global chain/policy edits elevation-only.
  - **SecOps analysis required** before implementation:
    - Enumerate full attack surface: all incoming gRPC method handlers, subscription command types,
      config-apply paths, firewall mutation entry points.
    - Threat model: privilege escalation via malformed commands, replay attacks on bidi streams,
      UID spoofing on local socket, TOCTOU on config file writes.
    - Document OWASP-aligned mitigations for each threat class in `DESIGN_RULES.md` §(new secops section).
  - **Hardening order milestone**:
    - Treat seccomp/sandbox enforcement as a post-auth freeze step: complete command/elevation model,
      scope validators, compatibility owner-scope injection semantics, and remote grant lifecycle first;
      then generate seccomp profiles from stabilized runtime traces and move from observe-only to enforce.
  - **Sandboxing evaluation** (apply where feasible under hardened auth modes):
    - Sequencing note: this block is Phase 3/4 hardening, not a prerequisite for current auth-model exploration.
    - `seccomp-bpf` filter (`seccompiler` crate) for daemon worker threads handling privileged commands —
      restrict syscalls to the minimum needed post-bind (no `execve`, constrained `open` paths, etc.).
    - Linux capability dropping: after startup (bind, raw sockets, eBPF) drop to minimal cap set via
      `capset()`; use `AmbientCapabilities` for worker threads that need specific caps only.
    - Dedicated service-user orchestration profile (future enhancement):
      run the steady-state daemon under a dedicated account (for example `opensnitchd-rs`) with
      bounded capability sets, while preserving root-required operations through an explicit,
      auditable privileged broker path.
      - Keep root-required surfaces explicit and minimal: netfilter/nftables mutation,
        NFQUEUE control, selected netlink families, eBPF load/pin/map operations,
        and `/proc` inspection paths that still require elevated privileges on target kernels.
      - Define a two-lane execution model:
        non-privileged runtime lane (service user + hard sandbox) and privileged lane
        (small helper/broker with narrow RPC surface, command allowlist, strict payload schema,
        and per-action audit records).
      - Delivery targets: systemd/OpenRC/procd templates should support an opt-in
        `User=/Group=` style deployment profile, plus a documented fallback profile for
        legacy/root-only environments where kernel capability granularity is insufficient.
      - Authorization guardrail: privileged broker actions must remain behind daemon-side
        command classification and principal/capability checks (`auth.mode`), never transport trust.
      - Validation gate: add a capability matrix CI check (kernel version x operation)
        proving which paths work unprivileged with caps vs require broker/root fallback.
    - Evaluate process namespace isolation (user namespaces) for subscription fetch workers that
      perform external HTTP — isolate from host network where feasible.
  - Future refinement: owner-scoped rule/firewall edits delegable only after the daemon can authenticate
    caller UID/GID and prove the requested mutation cannot escape that owner scope.
  - Requires protocol/Python UI evolution before privileged paths can be safely exposed without broad
    implicit trust.

- [ ] Add optional `scope` field to gRPC/proto `Operator` in a dedicated compatibility PR (default dst semantics, backward-compatible wire evolution, Go/Rust/Python client alignment).
  - Note: deferred for now to stay aligned with base opensnitch implementation; revisit in a future dedicated compatibility PR.

- [x] Support AdBlock/AdGuard list format in rule list operators and subscriptions. Historical parser/matcher detail lives in `CHANGELOG.md` and the related implementation commit messages.

- [ ] Python UI client explicit disconnect on quit/CTRL-C (graceful stream shutdown before process exit).
  - Goal: avoid daemon-side noisy transport warnings during intentional UI termination.
  - Note: future work only; separate PR branch once related Python-client PR is accepted upstream.

- [x] **`[ARCH]`** Isolate current gRPC UI transport behind a dedicated adapter feature.
  - **Current branch progress (2026-03-30)**:
    - **Done**: added explicit default-on Cargo feature gate for the gRPC wire adapter in `crates/daemon/Cargo.toml` (`transport-wire-grpc-client`).
    - **Done**: `ClientService` transport methods now have `transport-wire-grpc-client`/no-adapter behavior split; no-adapter builds return explicit transport-unavailable errors instead of panicking (`subscribe`, `ping`, `ask_rule`, `post_alert`, subscription RPCs, notification stream open).
    - **Done**: `connect*` helpers now degrade to `ClientService::default()` when `transport-wire-grpc-client` is disabled so policy/runtime paths can continue to apply fallback behavior instead of hard startup failure.
    - **Done**: tonic/rustls dependency wiring moved behind optional `transport-wire-grpc-client` feature deps (`hyper-rustls`, `rustls`, `rustls-pki-types`, `x509-cert`) and transport TLS helpers are now `#[cfg(feature = "transport-wire-grpc-client")]`-scoped.
    - **Done (2026-04-06)**: local validation now confirms `cargo check -p opensnitchd-rs --no-default-features --features storage-format-json` passes with gRPC adapter off; promote this into CI as a dedicated lane when CI matrix policy is updated.
    - **Done (2026-04-22)**: daemon feature graph now keeps gRPC/TLS stacks adapter-owned: `client-transport` is transport-generic, `transport-wire-grpc-client` owns grpc/tls dependency wiring, and default features enable the adapter feature directly.
    - **Done (2026-04-22)**: daemon runtime no longer has direct `tonic`/`opensnitch-proto` dependencies; gRPC test scaffolding dependencies moved to daemon `dev-dependencies`.
  - **Feature gate**: `transport-wire-grpc-client` default-on Cargo feature for the current tonic-based UI transport/client path.
  - **Intent**: treat gRPC as one transport adapter, not as the permanent shape of the daemon client.
  - **Scope**:
    - keep shared proto/domain contracts and session/auth policy available without tying them to tonic client types,
    - extract a transport-agnostic UI session/control port from `services/client`,
    - keep tonic/h2/rustls connector code behind the adapter feature,
    - ensure future adapters (HTTP+WebSocket, OpenWrt `ubus`/Luci, TUI/CLI bridge) target the same session/control boundary instead of re-implementing authorization or verdict routing.
  - **Sequencing**:
    - first split transport adapter code from session/control policy in the current inverted client model,
    - then reuse that seam during the daemon-as-server migration so inbound gRPC is also just an adapter,
    - keep default behavior unchanged until at least one alternate adapter path exists.
  - **Guardrails**:
    - do not hide remote-principal mapping or command authorization behind transport-specific code paths,
    - do not make wire adapters responsible for core command classification, owner-scope validation, or elevation policy,
    - do not gate proto definitions or shared UI message models that other adapters must reuse.
  - **Closure note (2026-04-22)**: complete. gRPC UI transport is adapter-scoped behind `transport-wire-grpc-client`, daemon runtime no longer directly depends on `tonic`/`opensnitch-proto`, and non-gRPC compile paths pass (`cargo check -p opensnitchd-rs --no-default-features --features storage-format-json` and `... --features storage-format-json,subscriptions`). Transport policy/session logic remains transport-agnostic in daemon core.

- [x] **`[ARCH]`** Extract transport/session client port and make transport libraries truly pluggable.
  - **Why**: current mapper-boundary progress is strong, but daemon runtime is still coupled to tonic client surfaces (`UiClient<Channel>`, `tonic::Streaming`, `NotificationStream` wire stream shape) and tonic remains a baseline dependency.
  - **Current branch progress (2026-03-31)**:
    - **Done**: introduced `platform/ports/client_transport_port.rs::NotificationInboundPort` as a transport-agnostic inbound notification stream contract.
    - **Done**: `services/client/notifications.rs::NotificationStream` now exposes `Box<dyn NotificationInboundPort>` instead of `tonic::Streaming<pb::Notification>`; gRPC stream adaptation is contained at the client adapter boundary.
    - **Done**: `flows/notification/notification.rs` now consumes inbound notifications via the port API (`recv`) and no longer calls tonic stream methods directly.
    - **Done**: subscription command bidi stream ingress now has a transport-agnostic open/receive seam — `ClientService::subscription_commands_open()` returns `Box<dyn SubscriptionCommandInboundPort>` plus ack sender; gRPC `ReceiverStream`/`tonic::Streaming` shaping moved to client adapter code.
    - **Done**: `flows/subscription/command_flow.rs` now consumes command ingress through `SubscriptionCommandInboundPort::recv_command()` and no longer calls tonic stream methods directly.
    - **Done**: introduced `ClientTransportPort` and adopted it in active flows (`notification`, `stats`, `verdict`, `subscription`) for `subscribe`/`post_alert`/`ping`/`ask_rule`/`subscription_execute` call sites, reducing direct flow coupling to concrete client transport APIs.
    - **Done**: introduced `ClientTransportConnectorPort` plus concrete `ClientTransportConnector` (cache-backed) so `stats`, `subscription`, `subscription-command`, and `verdict` flows now acquire clients via connector-port `connect_or_reuse()` / `invalidate()` instead of calling `ClientService::connect_or_reuse` directly.
    - **Done**: extracted transport contracts and shared notification wire helpers into unified workspace lib `crates/transport-wire-core` (`opensnitch-transport-wire-core`) with internal `ports`/`wire_helpers` module separation; rewired daemon flow/service imports and notification reply utilities to consume the external crate.
    - **Done**: introduced naming-aligned transport adapter crate `crates/transport-wire-grpc-client` (`opensnitch-transport-wire-grpc-client`) and set daemon default features to enable `transport-wire-grpc-client`.
    - **Done**: fully merged feature gating into `transport-wire-grpc-client`; daemon source no longer uses `#[cfg(feature = "grpc-ui")]` and `grpc-ui` is removed as a standalone daemon feature.
    - **Done**: `services/client/wire.rs` now owns grpc client/channel/stream runtime mechanics (`UiClient`, `SubscriptionsClient`, notification stream, subscription command stream); `services/client/client.rs` delegates through a wire adapter orchestrator (`ClientWire`) for subscribe/ping/ask-rule/alert/stream open operations.
    - **Done**: `services/client/notifications.rs` now opens inbound/outbound notification channels exclusively through `ClientService` wire-orchestrator APIs and no longer contains grpc stream shaping logic.
    - **Done**: added a second runtime-selectable transport wire stub (`stub://` client_addr) in `services/client/wire.rs`; `connect_with_config*` and `connect_or_reuse` now select between grpc wire and stub wire without changing flow/policy call sites.
    - **Done**: centralized wire selection in `services/client/wire.rs::select_wire_kind` (`ClientWireKind`) so adapter routing is strategy-driven rather than hard-coded prefix checks in client call sites.
    - **Done**: added adapter-local `subscriptions` feature gate in `crates/transport-wire-grpc-client` and propagated daemon `subscriptions` feature into it.
    - **Done**: moved subscription command-stream opening and subscription RPC wire calls (`list/apply/delete/refresh/deploy`) into `transport-wire-grpc-client` helper APIs; daemon wire layer now delegates those calls through adapter exports.
    - **Done**: moved remaining UI gRPC wire calls (`subscribe/ping/ask-rule/post-alert/notifications-open`) into `transport-wire-grpc-client` helper APIs; daemon `services/client/wire.rs` now holds orchestration + inbound adapter wrapping only.
    - **Done**: added dedicated transport adapter tests under `crates/transport-wire-grpc-client/src/tests/` and guarded daemon flow-consistency test modules (`notification_flow`, `stats_flow`, `verdict_flow`) behind `transport-wire-grpc-client`.
    - **Done**: centralized transport/storage adapter dependency versions in workspace-level `[workspace.dependencies]` and switched adapter/storage crates to `workspace = true` dependencies to reduce avoidable version drift for future libs.
    - **Done (2026-04-22)**: `subscriptions` feature no longer implicitly enables gRPC adapter wiring; non-gRPC compile path now works with `--no-default-features --features storage-format-json,subscriptions`.
    - **Done (2026-04-22)**: runtime dependency check confirms non-gRPC build graph excludes `tonic` (`cargo tree -p opensnitchd-rs --no-default-features --features storage-format-json --edges normal`).
  - **Target**:
    - introduce a transport-agnostic client/session port in `platform/ports` (connect, subscribe, ping, ask-rule, alert post, notification stream open/send/recv, subscription RPCs),
    - keep flow/service policy paths dependent on domain contracts and transport ports only,
    - move tonic-specific stream/client/channel types behind adapter implementations,
    - make tonic dependency optional under an adapter-specific feature so non-gRPC adapter builds can omit tonic/h2 stacks.
  - **Guardrails**:
    - no flow/service policy file should require tonic types in signatures,
    - wire-only enums/messages stay at adapter boundaries via explicit mappers,
    - no transport adapter may own authorization or owner-scope policy logic.
  - **Validation gate**:
    - `rg -n "tonic::|UiClient<|SubscriptionsClient<|tonic::Streaming" crates/daemon/src/flows crates/daemon/src/services crates/daemon/src/commands` should return only adapter/bridge surfaces,
    - a no-gRPC transport build path must compile once alternate adapter stubs exist,
    - tests cover parity of notification command/reply flow across at least one non-gRPC adapter stub.
  - **Closure note (2026-04-22)**: complete for current daemon-as-client architecture slice. Validation gate is green: transport type scan over core flows/services/commands returns no direct tonic client surfaces, no-gRPC builds compile, and runtime graph with non-gRPC feature set excludes `tonic` and `h2` (`cargo tree -p opensnitchd-rs --no-default-features --features storage-format-json --edges normal`). Remaining `hyper-rustls` in that graph is from daemon HTTPS client usage (`reqwest`) and is not UI transport coupling.

- [x] **`[ARCH]`** Extract loadable-state backend/codec ports and make file formats truly pluggable.
  - **Why**: pluggability must be symmetric with transport. Runtime currently assumes JSON/file-centric load paths for config/rules/network aliases/firewall state in multiple domains. We need explicit multi-format compatibility so OpenWrt-style configuration and control surfaces can plug in cleanly (for example UCI-like config files and ubus JSON-compatible payload contracts) without policy-layer rewrites.
  - **Current branch progress (2026-03-30)**:
    - **Done**: introduced external workspace storage-format crate `crates/storage-format-json` (`opensnitch-storage-format-json`) as a first format library boundary for loadable-state JSON parse/convert operations.
    - **Done**: rewired primary JSON loadable paths to codec-lib APIs without behavior changes: shared storage JSON reads (`services/storage/storage.rs`), rule sync file parsing (`services/rule/storage.rs`), firewall load/save (`services/firewall/storage.rs`), subscription store load/save (`services/subscription/storage.rs`), and config raw decode path (`config/config.rs`).
    - **Done**: added explicit CLI main-format override `--main-storage-format <json|yaml|toml>` and wired it into bootstrap/migration global storage policy (`services/storage/storage.rs`, `daemon/bootstrap.rs`, `daemon/migration.rs`).
    - **Done**: default compatibility now falls back to JSON when extension-based detection is missing/unsupported, while explicit CLI main-format overrides can force parse/convert behavior and rule file extension selection.
    - **Done (2026-04-06)**: introduced explicit loadable-state ports in `platform/ports/loadable_state_store_port.rs` (`ConfigStorePort`, `RuleStorePort`, `AliasStorePort`, `FirewallStorePort`) plus file-backed adapter implementation in `platform/adapters/loadable_state_file_store.rs`.
    - **Done (2026-04-06)**: rewired active load paths to consume the new ports/adapters (`services/config/storage.rs` reload, `services/rule/storage.rs` rule+alias loads, `services/firewall/storage.rs` load/save).
    - **Done (2026-04-06)**: moved remaining slice-targeted loadable-state helpers behind storage-format-aware boundaries: process hash-cache load/flush now uses `StorageService` parse/convert APIs, config raw parse helper now uses storage-format-aware parse for key-presence checks, and task storage file decode now routes through storage-format-aware parse.
    - **Done (2026-04-06)**: removed legacy JSON backward-compat from hash-cache (no migration path; `HashCacheFile`/`HashCacheRecord` model types deleted; `read_legacy_cache_file` + `From<HashCacheFile>` removed; hash cache is now purely internal binary-only).
    - **Done (2026-04-06)**: `policy_tx/persist_change_set` routed through `StorageService::convert_and_write_with_storage_format_to_path_and_notify` (atomic write + event notification); `persist_audit_record` documented as approved JSONL append; `ensure_base_dirs` simplified to audit-dir-only.
    - **Done (2026-04-06)**: task runtime payload shaping converted to typed Go-parity model structs: `SocketMonitorPayload`/`SocketMonitorRow`/`SocketEntry`/`SocketId`/`SocketMonitorProcessEntry` (`models/socket_monitor_payload.rs`), `PidMonitorResult`/`NodeMonitorResult`/`DownloaderResult` (`models/task_wire.rs`); `socket_monitor.rs` helpers now return typed structs; `runtime_handlers.rs` builds typed models and serialises at `emit_task_ok` boundary (APPROVED `serde_json::to_string` at wire edge).
    - **Done (2026-04-06)**: introduced `services/task/runtime_payload.rs::TaskRuntimePayload` so downloader/IOC task config decoding (`serde_json::from_value`) happens once at task payload construction (`task.rs` runtime start + `storage.rs` disk-task load) rather than inside `runtime_handlers.rs`; `ioc_schedule_matches_now()` now uses the same payload helper; runtime-task tests updated to construct payloads via the shared helper.
    - **Done (2026-04-06)**: removed internal rule-layer JSON parsing for legacy list operators by moving legacy `operator.data` string normalization into `models/rule_storage.rs` (`RuleFile::normalize_legacy_operator_lists`) and invoking it from rule loadable-state boundaries (`platform/adapters/loadable_state_file_store.rs`, sync load path in `services/rule/storage.rs`); `services/rule/conversions.rs` and `services/rule/utilities.rs` no longer parse JSON strings.
    - **Done (2026-04-06)**: `ioc_schedule_matches_now` signature changed from `&Value` to `&TaskRuntimePayload`; `serde_json::Value` import removed from `runtime_handlers.rs`; tests updated to construct `TaskRuntimePayload::from_task_data` directly.
    - **Done (2026-04-06)**: full `serde_json` audit across all daemon crates; only remaining approved JSON boundaries are: payload construction (`services/task/runtime_payload.rs`), legacy downloader TaskResults wire helper (`services/task/reply.rs`), rule legacy operator string normalization (`models/rule_storage.rs`), connection event logger JSON export adapter (`platform/adapters/connection_event_logger.rs`), config file/key-normalization load paths (`config/config.rs`, `services/config/parsing.rs`), eBPF/varlink kernel-wire bridges (explicitly excluded), and test code. `TaskNotification.data` field changed from `serde_json::Value` to `String` (opaque raw JSON bag-of-bytes); `from_task_data_raw(&str)` added to `TaskRuntimePayload` as the single raw-string decode entry point; `parse_task_notification_data` and smoke tests updated.
    - **Done (2026-04-06)**: removed direct storage-format bypasses in remaining loadable-state paths: `models/metrics_config.rs::load_sibling` and `tunables/autotune.rs::load_raw_tunables` now decode via `StorageService::parse_with_storage_format_for_path`; config/action probes now use `RawConfig::parse_normalized_for_path` from `config_storage`.
    - **Done (2026-04-06)**: moved notification JSON wire decode/encode to transport helpers (`transport-wire-core`): command notification parsing now uses `decode_json_notification_payload`, and config command success replies use `status_with_log_level_payload`.
    - **Done (2026-04-06)**: hardened internal task-event boundary by changing legacy downloader typed-result helper to return `String` (wire payload) instead of internal `serde_json::Value`; runtime/task tests updated to parse/assert at test boundary.
    - **Done (2026-04-06)**: completed non-test + test serialization-boundary sweep: direct JSON encode/decode in daemon/runtime tests now routes through `transport-wire-core` (`encode_json_notification_payload` / `decode_json_notification_payload`) or storage-format codec APIs (`StorageService::parse_with_storage_format_for_path`, `storage-format-json::JsonStorageFormat::convert_to_storage*`) instead of ad-hoc `serde_json::*` calls.
    - **Done (2026-04-06)**: OpenWrt rule-map sidecar file I/O in `openwrt_uci_firewall.rs` now uses storage-format boundaries (`StorageService` parse + `storage-format-json` pretty convert). UCI CLI command execution paths remain intentionally unchanged (CLI transport, not file codec).
    - **Done (2026-04-06)**: removed dead JSON probe paths tied to retired eBPF bpftool-era plumbing (`services/connection/parsing.rs`, `workers/runtime/ebpf/control/lifecycle.rs`, and related tests) and dropped now-unused numeric JSON helpers in `utils/json_value.rs`.
    - **Validation (2026-04-06)**: `cargo check -p opensnitchd-rs --tests` passes clean; `cargo check -p opensnitchd-rs --features openwrt` passes clean; targeted regressions pass (`task_runtime`, `rule_command`, `rule_service`, `firewall_netlink`, `daemon_runtime`).
    - **Closure note (2026-04-07)**: this slice is complete. The lasting governance rule now lives in `DESIGN_RULES.md`: parsing/encoding belongs in `storage-format-*` or `transport-wire-*` adapter libs, with only explicit boundary-owned exceptions. Approved exceptions are varlink kernel-wire JSON handling and adapter-owned imperative transport/runtime internals (for example UCI CLI, ubus, and future CLI/IPC method surfaces that are transport-shaped even when they mirror file or JSON semantics). For OpenWrt specifically, UCI **file** syntax remains `storage-format-uci` owned; UCI CLI / ubus command execution remains transport/runtime-adapter owned. A stricter CI denylist check can land later without reopening this architecture item.
  - **Target**:
    - introduce formal ports for loadable state (`ConfigStorePort`, `RuleStorePort`, `AliasStorePort`, `FirewallStorePort`) with explicit `load/save/watch` contracts,
    - separate storage backend from wire codec: backend (file/db/remote) and codec (json/yaml/toml/uci/etc.) are independent pluggable adapters,
    - keep flow/service policy paths dependent on canonical domain models only (`models/*`),
    - centralize wire<->domain mapping in adapter codecs (including compat JSON shape handling) and remove format assumptions from service logic,
    - align with `StorageBackend` evolution (`db-storage`) so file/db backends can share the same domain-facing contracts.
  - **Guardrails**:
    - no domain service/flow may parse or serialize raw loadable formats directly,
    - format-specific structs (`Raw*`/`Persisted*`/`Incoming*`) remain adapter-boundary only,
    - network-alias/rule/firewall/config reload logic must remain backend/codec agnostic.
  - **Validation gate**:
    - adding a new codec/backend should require adapter wiring only (no flow/service policy edits),
    - `rg -n "serde_json::|from_str\(|to_string\(" crates/daemon/src/services crates/daemon/src/flows` should return only approved adapter/storage modules,
    - integration tests prove parity for at least two codec/backend combinations (e.g., JSON+file and JSON+db/file-backend abstraction; future UCI codec for OpenWrt).

- [x] **`[ARCH]`** Enforce canonical-model-first wire mapping across UI/control transports.
  - **Policy**: every external serialization format (protobuf, JSON, future UCI/ubus) is a wire contract; only domain models in `models/` are canonical. See `DESIGN_RULES.md §3 Canonical Domain Model And Wire Contract Rule` for the full naming convention and adapter-boundary rules.
  - **Migration targets**:
    - inventory and reduce direct `pb::*` usage inside service/flow internals,
    - keep `pb::*` usage constrained to adapter and mapping layers,
    - keep JSON `Raw*`/`Persisted*`/`Incoming*` wire types constrained to storage adapters and command mapper modules,
    - add/standardize `wire <-> model` mappers for privileged command paths first (rules, firewall, auth/elevation),
    - ensure HTTP/WS, OpenWrt ubus/UCI, and any future adapters reuse the same canonical models and policy checks without re-implementing authorization or business rules.
  - **Validation gate**:
    - no new core policy path should accept or emit generated protobuf types directly,
    - `Serialize`/`Deserialize` on a domain type (outside `*_storage.rs`, `*_config.rs`, `Incoming*`/`Raw*`/`Persisted*`) is a code-review flag,
    - code review checklist must include a mapper-boundary check for every new transport endpoint.
  - **Completed slices**:
    - **Slice A (notification action)**: `CommandAction` domain discriminant enum added to `models/command_action.rs`
      (renamed from `NotificationAction` / `models/notification_action.rs` — transport-neutral name);
      `pb::Action` eliminated from all notification flow policy functions (`is_privileged_notification_action`,
      `classify_privileged_notification_action`, `notification_command_allowed`, `normalize_owner_scoped_rule_mutation_rules`,
      `normalize_owner_scoped_firewall_reload`, `log_privileged_authorization_allow`, etc.); wire→domain
      conversion `command_action_from_pb()` isolated at ingress boundary.
    - **Slice B (rule policy helpers)**: `pb::Rule` / `pb::Operator` eliminated from all rule classification,
      authorization, and injection helpers (`operator_matches_owner_scope`, `rule_matches_owner_scope`,
      `operator_has_any_operand`, `rule_has_operand_semantics`, `operator_owner_scope_conflicts`,
      `inject_owner_uid_scope`, `authorization_rule_candidates`); these now accept `RuleRecord` / `RuleOperator`
      from `models/rule_record.rs`; `Vec<pb::Rule>` removed from `command_from_action_or_reply` adapter;
      `Default` impls added to `RuleAction`, `RuleDuration`, `RuleRecord` to enable test stub construction.
    - **Slice D (test + design policy)**: fixed `local_unix_principal_check_enforced_when_allowlist_configured`
      test to use a provably-absent GID (enumerates process group membership via `nix::unistd::getgroups()`
      to avoid coincidental supplementary-group match); extended `DESIGN_RULES.md §3` to cover JSON and
      future UCI/ubus wire formats with the same adapter-boundary rules as protobuf.
    - **Slice C (firewall domain type)**: `pb::SysFirewall` fully eliminated from all domain code.
      `FirewallConfig` / `FirewallRule` / `FirewallChain` / `FirewallExpression` / `FirewallStatement` /
      `FirewallStatementValue` hierarchy introduced in `models/firewall_config.rs` (replacing the interim
      `models/sys_firewall.rs` file, which has been deleted). The deprecated `pb::FwChains` compat wrapper
      is flattened at ingress into two flat fields: `FirewallConfig.rules: Vec<FirewallRule>` (iptables-style
      rules) and `FirewallConfig.chains: Vec<FirewallChain>` (nftables chain definitions); `FirewallGroup`
      was removed entirely — it was a domain mirror of the deprecated wire wrapper. Reconstruction of
      `pb::FwChains` / `PersistedFirewallGroup` for wire/file backward compat is an egress-only adapter
      detail in `services/firewall/conversions.rs` and `services/firewall/storage.rs`. All firewall service
      functions, notification helpers, port traits, and all test files use domain types.
      `pb::SysFirewall` retained only at gRPC adapter boundaries (`services/client`,
      `platform/ports/firewall_port.rs`). `DESIGN_RULES.md §3` extended with `Firewall Domain Model Rule`
      (flattening rationale and future `FirewallZone` design anchor for firewalld/OpenWrt/VyOS zone support).
    - **Slice C follow-up (compat + alias inputs)**: legacy `daemon/data/system-fw.json` compatibility now
      inherits missing nested-rule `Table` / `Chain` fields from the parent chain during ingress conversion,
      matching the Go daemon's legacy file behavior. `Rules.NetworkAliasesFile` is now a first-class config
      field feeding `Config.network_aliases_path` and `RuleService`. Alias inputs are merged during
      `RuleService` cache rebuilds, and those rebuilds are now triggered by explicit firewall reload commands,
      nftables `NFNLGRP_NFTABLES` netlink events, and drift-heal recovery.
    - **Slice E (subscription command mapping, 2026-03-30)**: removed direct `pb::SubscriptionRequest` construction from flow/service internals on the list/refresh control path. `flows/subscription/subscription.rs` now emits domain `SubscriptionCommand` (`SubscriptionOperation::List`) and calls `ClientService::subscription_execute`; gRPC request shaping moved to client adapter boundary via `subscription_request_from_command`. `services/subscription/refresh_scheduler.rs` now calls `handle_command(SubscriptionCommand { Refresh, ... })` directly instead of self-issuing a protobuf request.
    - **Slice F (notification adapter mapping, 2026-03-30)**: moved notification wire-shaping helpers to the client adapter boundary (`services/client/alerts.rs::build_wire_alert`, `services/client/notifications.rs::notification_hello_reply_wire`) and removed duplicated flow-local wire builders. Notification command mapping now consumes canonical `CommandAction` end-to-end (`commands/client/client.rs::command_from_action_or_reply`), with wire `i32` action converted at ingress in `flows/notification/notification.rs`.
    - **Slice G (notification reply wire mapping, 2026-03-30)**: moved notification error-reply wire shaping to the client adapter boundary via `services/client/notifications.rs::notification_error_reply_wire`. `flows/notification/notification.rs` no longer builds `pb::NotificationReply` error payloads directly and now routes all hello/error reply construction through client adapter helpers.
    - **Slice H (notification wire-action mapper boundary, 2026-03-30)**: moved notification action wire→domain conversion and stream-close wire predicate from flow internals to the client adapter boundary (`services/client/notifications.rs::{command_action_from_notification_wire,is_stream_close_notification_wire}`). `flows/notification/notification.rs` now consumes adapter helpers for those decisions.
  - **Closure note (2026-03-30)**: canonical-model-first mapper boundary objective for current UI/control transport is complete on this branch. This closure does **not** imply full transport-library agnosticism; transport pluggability remains tracked in the dedicated `transport/session client port` backlog item above. Remaining protobuf-heavy work belongs to future daemon-as-server and alternate-transport backlog items below (`server-mode`, `http-client`, `openwrt`) and should reuse the same mapper-boundary contract.

- [ ] **`[ARCH]`** Migrate daemon to full gRPC server; Python UI and future clients become gRPC clients.
  - **Current architecture** (inverted): daemon is a gRPC *client* calling a Python UI acting as
    gRPC *server* (`UIService`); daemon connects outward to the UI socket on startup.
  - **Target architecture**: daemon becomes the gRPC *server* for all services — `UIService` (verdict
    dialogs, stats, notifications), `Subscriptions`, `Commands`; all clients (Python UI, TUI, CLI,
    web) connect inward to a daemon-owned address.
  - **Why this is the prerequisite for everything else**:
    - Removes startup-ordering dependency: daemon operates independently when no UI is connected.
    - Enables multiple simultaneous clients (Python UI + `ratatui` TUI + `clap` CLI + web).
    - HTTP+WebSocket client and OpenWrt `ubus`/Luci integration both require daemon-as-server.
    - `subscriptions.proto` already follows this model (`Subscriptions` + `Commands` are daemon-served
      RPCs); this task aligns `ui.proto` `UIService` with that pattern.
  - **Migration scope**:
    - `ui.proto`: invert `UIService` — `AskRule`, `Stats`, `Notifications` become server-streaming or
      bidi RPCs served by the daemon rather than stubs the daemon calls as a client.
    - `daemon-rs`: remove outward `tonic::Client` for `UIService`; implement `UIServiceImpl` server-side
      alongside `SubscriptionServiceImpl`; wire in `serve.rs`.
    - Python UI: migrate from `serve(UIServiceServicer(...))` listener to `stub = UIServiceStub(channel)`
      subscriber pattern; UI connects to daemon, reads `AskRule` stream, pushes verdict replies.
    - `clients/` service in `daemon-rs`: remodel as a session registry for inbound clients rather than
      an outbound connection pool.
    - reuse the transport-agnostic session/control port introduced by the transport-wire seam so server-mode
      gRPC stays an adapter, not a policy owner.
  - **Compatibility**: keep Go daemon unaffected (Go continues using current inverted model);
    `daemon-rs` flag-gates the server model behind a `server-mode` Cargo feature initially.
  - Blocks: `privilege-control` feature (cannot authorize clients without server-side session tracking),
    HTTP+WebSocket client, multi-client attach, TUI work.

- [ ] **`[ARCH]`** HTTP+WebSocket client for constrained devices (OpenWrt, embedded, no gRPC stack).
  - **Feature gate**: `http-client` non-default Cargo feature; no increase to default binary size.
  - **Target**: replace or complement gRPC transport for environments where `tonic`/`h2` is unavailable
    or undesirable (BusyBox-based OS, MIPS/ARM32 devices, web browser clients).
  - **Wire protocol**: JSON-over-WebSocket with a typed envelope
    `{ "type": "AskRule" | "Stats" | "Notification" | "Command" | ..., "id": u64, "payload": ... }`;
    payload schema mirrors the proto message fields (no protobuf encoding dependency on client side).
  - **Transport layer**: `axum` with `axum::extract::ws` (already a `tokio` ecosystem crate; no
    additional async runtime); single `/ws` endpoint handles multiplexed message types.
    REST fallback: `GET /api/v1/stats`, `POST /api/v1/rule`, etc. for clients that cannot do WebSocket.
  - **Auth**: bearer token (same mechanism as metrics push); TLS handled by reverse proxy or
    `axum-server`/`rustls` behind the feature flag.
  - **Session semantics**: verdict `AskRule` delivered via WS push; client sends verdict reply
    via WS frame within configurable timeout; daemon falls back to default action on timeout.
  - Prerequisite: daemon-as-gRPC-server arch task (daemon must own session registry before HTTP
    sessions can share the same connection pool).

- [ ] **`[ARCH]`** OpenWrt-specific integration (`openwrt` non-default Cargo feature).
  - **uci config syntax**: `UciConfig` reader/writer as an alternative backend to JSON in
    `models/config.rs`; OpenWrt UCI package `opensnitchd` with sections mapped to `DaemonConfig`
    fields (`config general`, `config firewall`, `config metrics`, …).
    - Spec: `uci set opensnitchd.general.log_level=info` round-trips through the same `DaemonConfig`
      model used by JSON path; hot-reload via SIGHUP unchanged.
    - `uci-rs` crate (parse UCI flat syntax) or hand-rolled parser gated behind `openwrt` feature to
      avoid mandatory dependency in non-OpenWrt builds.
  - **ubus integration**: register an `opensnitchd` ubus object (`libubus` FFI via `ubus-rs` or
    thin `platform/ffi/ubus.rs` wrapper) exposing:
    - `opensnitchd.verdict` — verdict reply method (native ubus path for LuCI verdict flow);
    - `opensnitchd.stats` — current stats snapshot as ubus response JSON;
    - `opensnitchd.rule_list` / `opensnitchd.rule_apply` — rule CRUD methods;
    - `opensnitchd.subscription_list` — current subscription states.
    - ubus object registration runs as a standalone task when the `openwrt` feature is enabled.
  - **LuCI integration** (companion `luci-app-opensnitchd`):
    - Consumes `opensnitchd.*` ubus methods via `uhttpd-mod-ubus` `/ubus` JSON-RPC 2.0 for verdicts, stats, and rule management.
    - UCI config editor page backed by `opensnitchd.rule_apply` ubus call.
    - Packaged as an opkg `.ipk` targeting OpenWrt 23.05+ (LuCI framework 2.0).
    - Separate repository / submodule; tracked here for scope awareness.
  - Prerequisite: ubus adapter (`transport-wire-openwrt-ubus`) is the transport boundary; LuCI consumes the same ubus object surface via polling.

- [ ] **`[ARCH]`** Evaluate embedded DB (`redb`) for ACID persistence of cold snapshotables (`db-storage` non-default feature).
  - **Exploration slice (2026-03-30)**:
    - **Done**: code-readiness scan confirms storage is still file-operation-centric (`StorageService`) with no `StorageBackend` port yet; multiple domains (`rule`, `subscription`, `task`, `config`, `hash_cache`) still call file APIs directly or through domain-local storage wrappers.
    - **Done**: created implementation-spike brief `daemon-rs/DB_STORAGE_SPIKE.md` with phased plan (port extraction, redb backend skeleton, dual-write import/export, crash-recovery acceptance checks) and risk checklist.
    - **Next**: land a no-behavior-change preparatory PR that introduces `StorageBackend` trait + `FileBackend` adapter only (no redb dependency yet), then wire one low-risk domain (`subscription`) through the trait as proof slice.
  - **Problem statement**: current persistence for rules, subscriptions, tasks, hash cache, and config
    relies on per-file atomic renames and JSON flushes.  Cross-snapshotable mutations (e.g. rule
    add + subscription state update + task record) are not atomic — a crash between writes leaves
    partially-applied state.  There is no built-in crash recovery beyond "re-scan filesystem on
    startup".
  - **Critical constraint — hot path is untouchable**: the verdict path
    (nfqueue → owner lookup → rule match → NF_ACCEPT/DROP) is sub-millisecond, purely in-memory.
    `ArcSwap<CompiledRuleSet>` + `quick-cache` + `DashMap` stay as-is.  No DB call ever enters
    the hot path.  The DB is a persistence backend, not a runtime data structure.
  - **Two-layer model**:
    - **Hot layer** (unchanged): `ArcSwap<CompiledRuleSet>` is the source of truth for verdicts;
      populated on startup and swapped atomically on any cold-layer mutation.
    - **Cold/persistence layer** (`db-storage` feature): `redb` tables replace file-based JSON
      mutation for rules, subscriptions, tasks, hash cache, and config snapshots.
      A single `redb` write transaction updates all affected tables atomically; on commit, the
      hot-layer `ArcSwap` is swapped to reflect the new compiled set.
  - **Candidate analysis**:
    - `redb` (**leading candidate**): pure Rust, zero C deps, MVCC, ACID, memory-mapped reads
      (near-zero read latency), actively maintained, typed-table API — no SQL overhead, no schema
      DSL, compile-time checked table types.
    - `fjall`: pure Rust LSM-tree, ACID, active; younger than redb but worth monitoring.
    - `heed` (LMDB wrapper): memory-mapped, very fast, C dep (LMDB) — ruled out for zero-dep goal.
    - SQLite (`rusqlite`): pragmatic, best ecosystem tooling (DB Browser), but C dep and SQL is
      overkill for what is effectively a typed KV/document store.
    - DuckDB: OLAP engine — wrong fit; columnar/analytical, not OLTP; massive binary overhead.
    - `sled`: pure Rust, ACID, but effectively abandoned since 2021 (v0.34).
  - **What `redb` tables would look like**:
    - `rules`: `TableDefinition<&str, &[u8]>` — key = rule name, value = JSON/proto bytes.
    - `subscriptions`: `TableDefinition<&str, &[u8]>` — key = subscription id/name, value = state.
    - `task_records`: `TableDefinition<u64, &[u8]>` — key = task epoch, value = serialized record.
    - `hash_cache`: `TableDefinition<&[u8], &[u8]>` — key = `(exe_path, inode, mtime, size)` hash,
      value = JSON checksums (replaces `DashMap` + periodic flush pattern).
    - `config_snapshots`: `TableDefinition<&str, &[u8]>` — key = config name, value = bytes.
  - **`StorageService` abstraction**:
    - Define a `StorageBackend` port trait with `read`, `write_batch`, `watch` methods.
    - `FileBackend`: current JSON file implementation (default, always available).
    - `RedbBackend`: `db-storage` feature-gated; wraps `redb::Database`; `write_batch` maps to a
      single `redb` write transaction with multi-table scope.
    - `StorageService` holds `Arc<dyn StorageBackend>`; swapped at startup based on feature + config.
  - **Crash recovery improvement**: on startup, `RedbBackend::scan_all()` reads committed tables
    in one read transaction instead of filesystem glob + partial-parse; half-written rules
    (from a pre-DB crash) are no longer possible.
  - **Not in scope for initial `db-storage`**: query/index (rules by action, subscriptions by
    group) — these are still done in application code using the in-memory compiled sets.  The DB
    is a durable store, not a query engine.
  - **Migration path**: if `db-storage` feature enabled and no `redb` file exists, import all
    existing JSON rule/subscription files into redb in one bootstrap transaction, then switch to
    redb-only writes.  Downgrade path: export all tables to JSON files on `--export-to-files` CLI flag.

### Design Rule Violations (rescan 2026-03-27)

- [x] Resolved design-rule cleanup summary — lifecycle module layout, proto snapshot Arc-read cleanup, and CLI > env var > JSON precedence alignment are complete. Detailed change history lives in the relevant implementation commit messages.

- [x] **`[LOW]`** §2 trait-first integration boundary violations — rescan (2026-03-30) remediation completed.
  - **Done**: introduced/used explicit port facades (`proto_mapper_port`, `nfqueue_runtime_port`, `net_iface_port`, `audit_netlink_port`, `nft_monitor_port`) so domain/runtime paths consume `platform/ports` instead of direct `platform/adapters` or `platform/ffi` imports.
  - Updated files: `flows/verdict/{helpers,submit,verdict}.rs`, `services/rule/matching_operators.rs`, `services/task/socket_monitor.rs`, `workers/{firewall/watch_worker,process/audit_worker,runtime/nfqueue/worker}.rs`.
  - Verification: `rg -n "platform::(adapters|ffi)" src/services src/flows src/workers` returns no matches.

- [ ] **`[LOW]`** §2 file-size enforcement — rescan (2026-03-30) shows remaining >500-line files after initial split pass.
  - Split progress confirmed: monolith paths `platform/adapters/firewall_netlink.rs`, `workers/runtime/ebpf/control.rs`, `platform/ffi/nfqueue.rs`, and `config.rs` were replaced by directory modules.
  - **Done (2026-03-30)**: `workers/runtime/watch/control.rs` split by extracting inotify trigger machinery to `workers/runtime/watch/control_trigger.rs`; `control.rs` reduced to 295 lines.
  - Still >500 lines: `platform/adapters/stats_exporter_prometheus.rs` (1086), `platform/adapters/stats_exporter_push.rs` (951), `services/task/runtime_handlers.rs` (915), `flows/notification/notification.rs` (891), `services/storage/storage.rs` (986), `platform/adapters/firewall_nftables.rs` (895), `platform/adapters/firewall_netlink/adapter.rs` (870), `services/client/client.rs` (761), `platform/adapters/nfqueue_netlink.rs` (713), `models/audit/kind.rs` (674), `daemon/tasks.rs` (642), `services/rule/matching.rs` (621), `workers/dns/dns_worker.rs` (581), `platform/adapters/connection_event_logger.rs` (556), `platform/adapters/firewall_iptables.rs` (539), `platform/adapters/firewall_netlink/apply.rs` (539), `workers/runtime/ebpf/control/aya_runtime.rs` (537), `platform/adapters/firewall_netlink/parse.rs` (528).
  - Concrete next-touch split plan for `platform/adapters/nfqueue_netlink.rs`: extract wire/message builders (`nlmsg` + config/verdict encoders) to `platform/adapters/nfqueue_netlink/wire.rs`, packet parsing to `.../parse.rs`, and socket/runtime loop control to `.../runtime.rs`, leaving `mod.rs`/facade-only startup helpers in the main adapter file.
  - Concrete next-touch split plan for `platform/adapters/firewall_nftables.rs`: extract extraction/parser logic to `platform/adapters/firewall_nftables/extract.rs`, expression normalization helpers to `.../normalize.rs`, and keep CLI apply/ensure orchestration in `.../mod.rs` facade.
  - Concrete next-touch split plan for `platform/adapters/firewall_netlink/adapter.rs`: move plan compilation (`plan_*` functions) to `platform/adapters/firewall_netlink/plan.rs`, dump translation/composition to `.../dump.rs`, and keep execution/preflight entrypoints in `adapter.rs`.
  - Concrete next-touch split plan for `platform/adapters/firewall_iptables.rs`: move save-dump extraction/parser helpers to `platform/adapters/firewall_iptables/extract.rs`, keep command execution/apply-clear paths in `firewall_iptables.rs`.
  - Concrete next-touch split plan for `platform/adapters/openwrt_uci_firewall.rs`: extract UCI show parsing + section assembly to `platform/adapters/openwrt_uci_firewall/show_parse.rs`, canonical firewall render/parse mapping to `.../mapping.rs`, and keep CLI command execution/persistence entrypoints in the main adapter facade.
  - Concrete next-touch split plan for `services/firewall/persistence_authority.rs` (868 lines): extract firewalld-specific methods (`persist_system_firewall_via_firewalld`, `ensure_firewalld_zones_exist`, `clear_firewalld_managed_rules`, `firewalld_rich_state_path`, `load/save_firewalld_managed_rich_rules`, `build_firewalld_{rich_rule,rule_tokens,family_for_rule}`) to `services/firewall/persistence_firewalld.rs` (~405 lines); extract UFW methods (`persist_system_firewall_via_ufw`, `clear_ufw_managed_rules`, `build_ufw_rule_tokens`) to `services/firewall/persistence_ufw.rs` (~140 lines); extract `ParsedRuleParameters`, `parse_rule_parameters`, `collect_enabled_firewall_rules{,_with_zone}`, and `build_direct_match_tokens` to `services/firewall/persistence_rule_parser.rs` (~210 lines); keep authority enum, constants, `command_{status_success,stdout}`, resolution, and dispatch in `persistence_authority.rs` (~130 lines). Make cross-module helper methods `pub(super)`.
  - Follow-up policy: split on next feature touch; prioritize runtime/flow/service files before adapter-only files when selecting incremental refactor slices.

### Resolved Optimization Sweeps (2026-03-26 / 2026-03-27)

- [x] The 2026-03-26 and 2026-03-27 hot-path, cold-path, and full-codebase optimization audits are complete. Their detailed findings and per-file outcomes have been archived to `PERF.md` and the related implementation commit messages; `TODO.md` now keeps only unresolved follow-up items.

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
- eBPF build policy keeps user-level compilation while reserving `target-runtime` as the runtime/test artifact split for elevated flows.
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

- 2026-03-30: Commit-hygiene follow-up for non-default packaging profile (`--no-default-features --features storage-format-yaml`): resolved pre-existing eBPF/runtime-mode compile errors and warning set by tightening feature-gated imports/locals, adding explicit feature-scoped dead-code justifications for dormant surfaces, and fixing a default-profile unreachable-code warning in `services/connection/ebpf.rs`. Validation now clean across all three gates: `cargo check`, `cargo test --no-run`, and non-default storage-format packaging profile.
- 2026-03-30: Loadable-state storage-format pluggability slice expanded and validated end-to-end: added CLI main format override `--main-storage-format <json|yaml|toml>` through daemon bootstrap and migration paths; `StorageService` now carries process-global main-storage policy, resolves format as `CLI override -> path extension -> compiled default`, and keeps JSON fallback compatibility for unknown extensions. Rule scanning/writes now honor the selected main format extension (`path_matches_main_storage_format` / `main_storage_extension`) and migration reads/writes now route through storage-format conversion helpers rather than hard-coded JSON parse/emit paths.
- 2026-03-30: Storage codec dependencies are now packaging-feature-gated in `crates/daemon/Cargo.toml` (`storage-format-json`, `storage-format-yaml`, `storage-format-toml`) with optional deps and compile-time invalid-build guard (at least one storage codec required). `DESIGN_RULES.md` updated with explicit Packaging Feature-Gating Rule and Compiler Warning Resolution Rule (promote/remove/justify arbitration, suppression hygiene, and commit warning gates).
- 2026-03-30: DNS varlink parsing now batches multiple A/AAAA addresses per host into `DnsPayload::answers` while preserving response order relative to alias records via ordered parsed-event staging. Added regression coverage in `tests/workers/workers_dns.rs` for multi-address host batching. `DnsPayload::answers`/`DnsAnswerRecord::new` are now active runtime paths (no dead-code suppression needed).
- 2026-03-30: Dead-code/unused-warning cleanup pass aligned with design rules: removed stale suppressions for production-used APIs, deleted genuinely unused helpers, and added explicit one-line justifications for remaining intentional test/feature-gated suppressions. `contract_types_stay_under_models` test now detects actual contract declarations (derive/impl) instead of import-only false positives. `Config::load_from_default_locations()` restored as a canonical no-override system-path loader and made reachable from bootstrap/migration when no CLI overrides are provided.
- 2026-03-30: UI TLS transport parity hardening: `tls-simple`/`tls-mutual` now fail closed when `SkipVerify=false` and no explicit trust material is configured (`TLSOptions.CACert` or `TLSOptions.ServerCert`), aligning Rust with Go's explicit `RootCAs` model. Maintainer/user-provided OpenSSL self-signed certs are supported as first-class trust anchors via those config fields. Added regression test in `tests/services/client.rs`.
- 2026-03-26: Full codebase rescan: Go/Rust parity audit (COMPATIBILITY.md updated with kernel self-check gap and firewall reload trigger model delta), DESIGN_RULES.md violation scan (3 items: lifecycle/runtime_lifecycle.rs missing, verdict Arc value-clone, API-surface density), hot/cold path optimization analysis (5 HIGH, 6 MEDIUM, 4 LOW items prioritized in PERF.md optimization backlog).  All findings tracked as actionable backlog items.
- 2026-03-26: Complete bpftool subprocess removal (db8970e follow-up): all bpftool-only code (`bpftool_list_maps`, `bpftool_lookup_owner`, `bpftool_lookup_owner`, `try_load_object_with_bpftool`, `is_already_pinned_error`, bpftool supervisor block, 9 `#[cfg(not(aya-ebpf))]`-gated helpers) deleted outright rather than left behind cfg gates.  `BpfProgram` struct removed from `models/ebpf_state.rs`.  `conn_pin_root`/`proc_pin_root`/`dns_pin_root` removed from `services/ebpf/ebpf.rs` (sole caller was bpftool loader).  `bpftool` removed from firewall preflight and smoke test fallback blocks.  623 lines deleted, 0 warnings, 425 passed.
- (post-v0.5.1): `async-trait` removed as a production dependency — all `#[async_trait::async_trait]` attributes stripped from service runtime traits (`ServiceLifecycle`, `ServiceFactory`, `ServiceRuntimeControl`) and their per-service impls; native AFIT used throughout. `async-trait` retained as a `[dev-dependencies]` entry only (required for the three tonic Ui test-server impls, because `tonic-prost-build 0.14` still desugars server traits via `#[async_trait]`). Rustc 1.93.1 / edition 2024. 34 annotations removed.
- (post-v0.5.1): Event-driven firewall drift detection: inotify on firewall config file + NFNLGRP_NFTABLES netlink subscription (`platform/adapters/nft_monitor.rs`). 20 s timer loop retained as safety-net fallback. 0 warnings, 425 passed.
- 2026-03-26: `quick_cache::Weighter` tuning applied to process cache: `ConcurrentLruCache<K,V>` made generic over `W: Weighter<K,V>` (default `UnitWeighter`); `with_weighter(weight_capacity, estimated_items, weighter)` constructor added.  `ProcessInfoWeighter` (O(1) env_map/args/chain len heuristics, ≈ 4 096 B/entry estimate) applied to `ProcessCache`; process cache now budgets by bytes not item count, preventing memory blow-up from processes with oversized env maps.  DNS/connection/inode caches retain `UnitWeighter` (uniform value sizes).  Two new tests added: `with_weighter_respects_byte_budget` and `with_weighter_stores_and_retrieves_entries`.  425 passed, 0 failed.
- 2026-03-26: Replaced `lru` crate with `quick_cache = "0.6"`; rewritten `utils/lru_cache.rs` as `ConcurrentLruCache` wrapping `quick_cache::sync::Cache`; eliminated dual-layer async/snapshot machinery; 8 policy_tx/rule_command test isolation failures fixed via `PolicyTxCoordinator::new(PathBuf)` + `RuleCommandService` restructure.  Enforced DESIGN_RULES §3 test-placement rule: removed inline `mod tests` from `lru_cache.rs`; fixed eviction algorithm description; added `Weighter`/`Lifecycle` extension-point docs.  All Cargo.toml version strings normalized to proper semver ranges; lockfile updated to latest compatible patches (aho-corasick 1.1.4, globset 0.4.18, hyper-util 0.1.20, regex 1.12.3, rustix 1.1.4, tower 0.5.3, zerocopy 0.8.47, etc.).
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
- 2026-04-01: Refined eBPF build policy so compilation is user-scoped (`build_ebpf.sh` enforces non-root), while elevated execution remains run/test-only. Make targets now split user build output (`daemon-rs/target`) from runtime/test build output (`daemon-rs/target-runtime`).
- 2026-03-25: Completed dead-code warning review for touched surfaces: removed truly unused lifecycle/process helpers, retained compatibility placeholders with explicit `#[allow(dead_code)]` annotations where API intent is deliberate.
- 2026-03-25: Added guarded live-session orchestration parity between Make and tools paths: `daemon-rs-live-logs`, `daemon-rs-live-stop`, `daemon-rs-mock-ui-session`, and matching tools live commands now preserve test-guard privilege semantics and service preflight/restart behavior.
- 2026-03-25: Added lightweight non-GUI Python mock UI service (`daemon-rs/scripts/mock_ui_client.py`) and tools orchestration command `run-daemon-mock-ui-live-session` for deterministic daemon-to-UI handshake validation.
- 2026-03-25: Notification/session and client-command logs now include explicit client identity fields (`client_id`, `client_origin`) derived from `ClientPrincipal`; reconnect warning noise is throttled while preserving warn-level signaling for timeout/error/non-stateful disconnect paths.
- 2026-03-25: Added transactional policy mutation envelope (`services/policy_tx`) and integrated it into rule/control command paths (`commands/rule`, `commands/control`) including dedup (`DuplicateInFlight` / `DuplicateCommitted`), rollback handling, and persisted changeset/audit records.
- 2026-03-25: Added multi-user verdict arbitration and durability split in `flows/verdict`: per-connection decision key/epoch gate prevents stale concurrent AskRule writes; immediate verdict stays hot-path while rule persistence is delegated to background transactional worker.
- 2026-03-25: Added daemon config/runtime `AskTimeoutPolicy` (`allow|drop|default`, with default behavior when missing/null) and wired it only to daemon-side UI-miss fallback paths; concrete UI-returned rules remain authoritative.
- 2026-03-30: Restructured `DESIGN_RULES.md` into 4 parts (§1–§11) with per-domain organization; added `Hot-Path State Access Rule` to §1 (wait-free read discipline, primitive table, six violation signals); ran full DESIGN_RULES violation scan — fixed four §4 wire-type naming violations: `models/policy_tx.rs` → `policy_tx_storage.rs`, `models/hash_cache.rs` → `hash_cache_storage.rs`, `models/task_payload.rs` → `task_wire.rs` (removed stray `Deserialize`), `BpfMap` → `RawBpfMap` in `models/ebpf_state.rs`; all other scan categories (hot-path Mutex, `{:?}` debug format, `DashMap` iteration, async snapshot accessors, `mod.rs` leaks) confirmed clean. Implemented full per-domain `models/audit/` module tree (17 files: `*Lifecycle`+`*Action` per domain, `AuditEventKind` sum type, `AuditSeverity` with `from_kind` auto-derivation, `AuditEventFamily`); implemented `AuditService` with fail-open ingress queue + dispatcher + broadcast + ring; implemented `AuditSinks` with three independent additive sinks (log-lines/NDJSON-file/syslog); wired `AuditSinkConfig` through config parsing + CLI flags (`--audit-sink-file/syslog/log`) + env vars; injected `AuditService` into `DaemonRuntime` and wired lifecycle/flow emit sites across notification, verdict, command, stats, kernel, and subscription flows; refactored `StorageEventBus` to async ingress queue with dropped-event counter; added `diag.stats.dropped_events_contention` and `diag.storage.event_bus.dropped_ingress` diagnostic counters to stat snapshots. 491 tests passing.
- 2026-03-30: Phase 2 TLS/client hardening slice completed: `CertCapturingVerifier` is now wired into live verified and skip-verify TLS handshakes, and remote principal binding resolution consumes the presented server certificate identity from the live handshake instead of falling back to configured PEM metadata when a live identity is available.
- 2026-03-28: Added explicit client authorization mode plumbing (`legacy | local-only | local+remote`) across config parsing/runtime state, startup warnings now surface unsafe/transition modes, and local-only modes default to root-only when no explicit principal/group policy is configured.
- 2026-03-28: Notification ingress now enforces hardened authorization before command queueing: remote privileged commands are denied outside `legacy`, loopback TCP listeners can bind to `LocalUid`, non-root local rule/firewall mutations require provable owner scope, and global firewall/control mutations remain elevated-only.
- 2026-03-28: `DOCS.md`, `TODO.md`, and `DESIGN_RULES.md` updated to document `auth.mode`, owner-scope enforcement, remote PAM/capability design direction, dedicated `auth.proto` planning, and compatibility owner-scope injection work items.
- 2026-03-24: Added strict miss/default stats accounting mode for `nfqueue_overload_policy=drop-fast`: miss path now records `rule_misses` and verdict-based accepted/dropped without Go-style pessimistic drop bias; `fail-open` keeps Go parity accounting.
- 2026-03-24: Closed remaining SIEM/event-export parity gap: local `syslog` mode now uses system syslog writer semantics; event-export path parity with Go `log/loggers` + `statistics.OnConnectionEvent` is complete.
- 2026-03-24: Added runtime event-export logger hot-reload parity: `ConnectionEventLoggerAdapter` now refreshes sink workers from current config logger set during verdict-path emission without daemon restart.
- 2026-03-24: Added miss/default-action event export parity in `VerdictFlow`: miss paths now emit `ConnectionEventExporterPort` and stats backlog events with `rule=None` before applying default action.
- 2026-03-24: Implemented SIEM event-export baseline path in default runtime: concrete `ConnectionEventLoggerAdapter` wired into `VerdictFlow`, reconnect/backoff + `max_connect_attempts` behavior implemented, local sink fallback for empty `Server`, and formatter/sink tests added for JSON/CSV/RFC5424/RFC3164 over TCP/UDP.
- 2026-03-24: Added `daemon-rs/DOCS.md` and linked it in TODO `Documentation References`; aligned tracker rules so new canonical docs must be linked there.
- 2026-03-24: Privileged control boundary design finalized in `daemon-rs/DESIGN_RULES.md` (local owner-scoped path, remote capability-based authorization, `auth.*` rollout guard, and `UPDATE_*` naming).
- 2026-03-24: Backlog updated to keep Privileged Control Boundary Rule implementation as active future work.
- 2026-03-24: Older detailed documentation/design migration notes were swept from this tracker to keep TODO active-focused; refer to `git log -- daemon-rs/TODO.md` and canonical docs for historical detail.
- 2026-03-30: §2 file-size enforcement pass: split `services/task/runtime_handlers.rs` (1181→913 lines) → `socket_monitor.rs` (pure socket-table helpers); split `tunables.rs` (755 lines) → `tunables/mod.rs` + `tunables/autotune.rs` (autotune preflight + runtime-tuning machinery); split `commands/control/control.rs` (812→383 lines) → `firewall_cmd.rs` (set/reload firewall) + `config_cmd.rs` (apply_config, set_log_level); split `flows/notification/notification.rs` (1965→1309 lines) → `authorization.rs` (peer credential + principal checks) + `owner_scope.rs` (operator/rule/firewall owner scope) + `classification.rs` (privileged action classifiers). Deferred split plans recorded in TODO for the 14 remaining over-threshold files. 491 tests passing.
