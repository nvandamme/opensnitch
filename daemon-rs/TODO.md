# Daemon-RS Unified Tracker

This is the single tracker file for backend parity, async/runtime hardening, and future enhancements.

It supersedes:

- `daemon-rs/FEATURE_PARITY.md`
- `daemon-rs/SERVICE_ASYNC_AND_MODEL_SCAN_2026-03-15.md`

Last update: 2026-03-30 (storage-format pluggability slice + warning arbitration/design-rule enforcement updates)

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
- Built-in one-shot cert generation path now supports local self-signed server/client
  PEM output (`--gen-self-signed-*-cert` + `--gen-self-signed-*-key`) to simplify
  explicit trust-anchor setup for TLS modes.
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
- Commit hygiene (mirrors `DESIGN_RULES.md` pre-commit checklist):
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
    - Direct crate-level fallback remains valid:
      - `cargo run --release -p tools -- run-daemon-mock-ui-live-session`
      - `cargo run --release -p tools -- update-run-perf`
  - For warnings in touched code, either fix/remove the root cause or add a targeted
    `#[allow(...)]` with a short rationale when the API/path is intentionally retained.
  - When `mod.rs` `pub use` re-exports warn as unused, prefer consuming canonical re-export
    paths at call sites (for example `crate::config::*`) before considering `allow(unused_imports)`.
  - If an amended commit has already been pushed, push rewritten history with
    `git push --force-with-lease`.

## Active Backlog (Post-v0.7.0)

### Active tasks

- [x] **Cross-service audit domain model** (`crates/daemon/src/models/audit/`) —
  Replaced single-file `audit_event.rs` with a per-domain module tree: `client`, `config`,
  `connection`, `dns`, `event`, `family`, `firewall`, `kernel`, `kind`, `process`, `rule`,
  `severity`, `stats`, `storage`, `subscription`, `task`, `verdict`. Each domain file owns
  `*Lifecycle` + `*Action` enums; `AuditEventKind` composes all variants; `AuditEvent`
  wraps kind + family + severity + nanosecond timestamp. `AuditSeverity` (Error/Warning/
  Info/Debug) auto-derived from kind via `from_kind`; `AuditEventFamily` (HotPath/ColdPath)
  orthogonal severity tagging.

- [x] **Cross-service audit bus + three-sink architecture** (`crates/daemon/src/services/audit/`) —
  `AuditService`: fail-open sync ingress queue → dispatcher thread → `tokio::sync::broadcast`
  - bounded `AuditRing`. `AuditSinks`: multiplexes to three additive sinks — log-lines
  (tracing, default on), NDJSON file (dedicated thread, default off), syslog LOG_DAEMON
  (dedicated thread, default off, severity-mapped). `AuditSinkConfig` parsed from JSON
  config + CLI flags + env vars with §7 precedence. `AuditService` injected into
  `DaemonRuntime`; `spawn_audit_sink_task` wired in `daemon/tasks.rs`. Lifecycle, flow,
  command, verdict, and subscription audit emit sites added. `SubscriptionService` disabled
  stub updated with `AuditService` parameter for API parity.
  **Audit completeness pass (2026-03-30)**: missing lifecycle variants added
  (`AuditLifecycle::Stopped`, `StorageLifecycle::Initialized`); `ClientAuthorizationAction`
  extended with three `Allowed*` variants per DESIGN_RULES §8; `severity.rs` narrowed to
  classify `Denied*` → Warning and `Allowed*` → Info; kernel flow now emits `DnsAction::ResolutionFailed`
  and `ConnectFlowAction::ConnectionDropped`; all hot-path tracking emits
  (`CacheUpdated`, `ResolutionReceived`, `ProcessTracked`, `ProcessEvicted`,
  `ConnectionTracked`, `FileRead`, `FileWritten`) removed from default code paths —
  reserved for the verbose-audit follow-up below.
  **Deferred debug-audit follow-up (2026-03-31)**: `ProcessAction::ProcessScanFailed`
  now propagates real inspection failures out of `sync_from_proc_event`, and
  `KernelAction::KernelInterfaceReattached` now emits from the NFQUEUE worker path when
  netlink queue startup succeeds after degraded-mode recovery.
  **Audit completion follow-up (2026-03-31)**: DNS cache updates now return truthful
  per-request eviction counts from the generic cache lifecycle hook, and kernel flow
  verbose audit emits `DnsAction::CacheEvicted` only when cache insertion actually evicts
  resident entries.

- [x] **`[AUDIT]`** Verbose hot-path audit mode — gate high-frequency operational events behind
  `Config.audit.verbose_hot_path: bool` (default `false`).
  - **Done (2026-03-30)**: wired `VerboseHotPath` config parsing, `--audit-verbose-hot-path`
    CLI override, and `OPENSNITCH_AUDIT_VERBOSE_HOT_PATH=1` env override.
  - Verbose emits now come from natural sites for `ConnectFlowAction::ConnectionTracked`,
    `DnsAction::CacheUpdated`, `DnsAction::ResolutionReceived`,
    `ProcessAction::ProcessTracked`, `ProcessAction::ProcessEvicted`,
    `StorageAction::FileRead`, and `StorageAction::FileWritten`.
  - Added `AuditSinkConfig::min_severity` threshold and sink-side filtering so file/syslog/
    log-line sinks consistently drop events below the configured severity.

- [x] **`[AUDIT]`** Wire deferred `StorageAction::FileReadFailed/FileWriteFailed` emit sites.
  - **Done (2026-03-30)**: `StorageService` now supports injected `AuditService` wiring,
    daemon bootstrap installs audit into the global storage singleton, and failure-path emits
    were added for `read_to_string_and_notify` and async atomic write branches
    (`write_bytes_atomic`, `write_bytes_atomic_and_notify`).
  - Added regression tests for read/write failure audit emission in
    `tests/services/storage_service.rs`.

- [x] **`DESIGN_RULES.md` per-domain restructure + hot-path Arc/snapshot rule** —
  Reorganised into 4 Parts (§1–§11); added `Hot-Path State Access Rule` to §1
  capturing wait-free read discipline, primitive table, and six violation signals;
  §9 DashMap cross-references §1; §4 naming rule extended with `*_wire.rs`
  exempt suffix and `Raw*` kernel-ingress clarification.

- [x] **Wire-type naming enforcement (§4 violation scan)** — Full DESIGN_RULES
  violation scan completed; all naming violations fixed: `policy_tx.rs` →
  `policy_tx_storage.rs`, `hash_cache.rs` → `hash_cache_storage.rs`,
  `task_payload.rs` → `task_wire.rs` (with `Deserialize` removed), `BpfMap` →
  `RawBpfMap`. Scan confirmed zero hot-path Mutex violations, zero `{:?}` format
  violations, zero `DashMap` iteration on packet path, zero `mod.rs` definition
  leaks, and zero async snapshot accessors.

- [x] **Subscription proto decoupling** — `subscriptions.proto` fully separate from `ui.proto`;
  all subscription types, `Subscriptions` service, `Commands` bidi stream, `SubscriptionStatistics`,
  and `RuleSubscriptionEntry` moved/added; `ui.proto` retains only UIService + telemetry types.
  **Done (v0.7.0)**.

- [x] **Per-subscription metrics export** — `SubscriptionStatistics` three-layer shape
  (scalars + breakdown maps + event ring) exposed across Prometheus text/OpenMetrics/proto,
  push-gateway, and InfluxDB line protocol. **Done (v0.7.0)**.

- [x] **Rule→subscription N:N mapping** — `RuleService::list_rule_data_paths()` +
  `SubscriptionService::build_rule_subscription_entries()` cross-reference active rule list
  operators against `rules.list.d/` tree; exported as `opensnitch_subscription_rule_info`
  gauge (Prometheus/OM/proto) and `opensnitch_subscription_rule` measurement (InfluxDB).
  **Done (v0.7.0)**.

- [x] **Per-rule hit counts in metrics** — `by_rule` map in `Statistics` proto (tag 21);
  `on_rule_hit(rule_name)` in `StatsService`; `opensnitch_rule_hits_by_rule{rule=...}` gauge;
  `opensnitch_by_rule,rule=... connections=Ni` InfluxDB line. **Done (v0.7.0)**.

- [x] **Subscription command layer restructured** — `wire.rs` removed; `CommandRpcPayload`
  model introduced; bidirectional `Commands` stream handler in `subscription.rs`;
  dedicated `flows/subscription/` task. **Done (v0.7.0)**.

- [x] **Metrics test suite** — 74 new tests (547 total, 7 ignored) covering all renderers,
  content negotiation, gzip, HTTP live tests, and N:N rule_info assertions. **Done (v0.7.0)**.

- [x] **`[CRITICAL]`** Eliminate per-connection `bpftool` subprocess fork in eBPF owner lookup.
  - **Done (v0.5.1)**: `libbpf-rs` `MapHandle::from_map_id` + `MapCore::lookup` replaces subprocess; background Arc-swap refresh task for map catalogue.
  - **Follow-up**: migrate `lookup_bpf_owner` and `list_bpf_maps` to aya-first (`aya::maps::MapData::from_id` + `aya::maps::HashMap`); see aya migration task below.
- [x] **`[HIGH]`** Remove `IpAddr → String → parse` round-trip in eBPF key building.
  - **Done (v0.5.1)**: `resolve_owner_by_ebpf_map` takes `IpAddr` directly; `bpf_map_name`/`build_bpf_key` use `is_ipv6()`/`.octets()`; mixed-family handled via `to_ipv6_mapped()`.
- [x] **`[HIGH]`** Reduce `StatsService::inner` mutex contention on hot path.
  - **Done (v0.5.1)**: split into `Mutex<BreakdownCounters>` (per-connection hot path) and `Mutex<EventsState>` (per-verdict hot path) with consistent acquisition order.
- [x] **`[MEDIUM]`** Avoid per-verdict `String` allocation in `source_label()`.
  - **Done (v0.5.1)**: return type changed to `Cow<'static, str>`; common paths borrow static strs.
- [x] **`[MEDIUM]`** Use `Arc<str>` for `VerdictReply::rule_name` instead of `String::clone`.
  - **Done (v0.5.1)**: `ActiveRuleCompiled.name: Arc<str>`; `VerdictReply.rule_name: Option<Arc<str>>`; Arc clone instead of heap allocation at every rule hit.
- [x] **`[MEDIUM]`** Return `Arc<str>` from `DnsService::lookup_ip` instead of `String`.
  - **Done (v0.5.1)**: `lookup_ip` returns `Option<Arc<str>>`; `ConnectionContext.dst_host: Option<Arc<str>>`; DNS query path converts via `Arc::from`.
- [x] **`[MEDIUM]`** Gate per-verdict logging behind `tracing::enabled!` or move to `debug!`.
  - **Done (v0.5.1)**: changed to `tracing::debug!` gated on `tracing::enabled!(Level::DEBUG)`; `source_label` not called when DEBUG is off.
- [x] **`[MEDIUM]`** Defer process binary hashing to background task on cache miss.
  - **Done (v0.5.1)**: `inspect_process_no_hash` fast path returns immediately; background `spawn_blocking(compute_process_hashes)` patches the cache entry when ready.
- [x] **`[HIGH]`** Migrate all eBPF userspace paths to aya-first; drop `bpftool` from production code.
  - **Done (v0.5.1)**: `services/connection/ebpf.rs`: `list_bpf_maps()` and `lookup_bpf_owner()` use aya-first (`loaded_maps()`, `MapData::from_id`, typed `HashMap::try_from`); bpftool functions (`bpftool_list_maps`, `bpftool_lookup_owner`) fully removed.
  - **Done (v0.5.1)**: `workers/runtime/ebpf/control.rs`: added `supervise_runtime_aya()` + `aya_inspect_and_prune_map<const N>()` behind `#[cfg(feature = "aya-ebpf")]`; all bpftool helpers (`prune_map_entries`, `delete_map_key`, `extract_key_bytes`, `collect_u8_values`, `run_capture`, `run_json_capture`, `list_programs`, `list_maps`, `dump_map`), `try_load_object_with_bpftool`, `is_already_pinned_error`, and the bpftool supervisor body in `supervise_runtime()` fully removed.
  - **Done (v0.5.1)**: `tests/smoke/aya_conn_trace.rs` + `aya_tunnel_trace.rs`: bpftool fallback blocks from `map_id_by_name`, `map_dump_keys`, `map_has_entries`, `map_entry_count`, plus `value_to_bytes()` and the `serde_json::Value` cfg import, all removed.
  - **Done (v0.5.1)**: `models/ebpf_state.rs`: `BpfProgram` struct removed (bpftool-only).
  - **Done (v0.5.1)**: `services/ebpf/ebpf.rs`: `conn_pin_root`/`proc_pin_root`/`dns_pin_root` convenience methods removed (sole caller was the bpftool loader).
  - **Done (v0.5.1)**: `tests/firewall/gates.rs`: `bpftool` removed from required-tool preflight.
  - **Done (v0.5.1)**: `libbpf-ebpf` removed from default features — aya-only builds work cleanly; libbpf is opt-in via `--features libbpf-ebpf`.
- [x] **`[HIGH]`** Harden process hashing strategy for verdict safety.
  - **Done (v0.5.1)**: `SimpleHashOptional` dispatch in both `operator_matches_against_compiled` and `operator_matches_against_with_derived` now returns `false` (not `match`) when hash is `None` — falls through to default action.
  - **Done (v0.5.1)**: IMA fast-path added in `compute_process_hashes`: `read_ima_sha256_xattr` checks `security.ima` xattr (type=0x03, algo=4=SHA-256) before falling back to full file read; `compute_md5_sha1` reads file once for md5+sha1 when IMA provides sha256.
  - **Done**: Persistent file-based hash cache implemented (`services/process/hash_cache.rs` + `models/hash_cache.rs`). `DashMap`-backed in-memory cache with periodic JSON flush to `/var/cache/opensnitchd/hash_cache.json` (falls back to `$TMPDIR/opensnitchd/`). Key: `(exe_path, inode, mtime_secs, file_size)` — any binary change (package update, recompile, manual edit) automatically invalidates the cached entry. `spawn_hash_update` checks persistent cache before computing hashes from file I/O, stores results on cache miss. Background flush task (60 s interval) + stale-entry GC (10 min interval) run via `spawn_hash_cache_flush_task`. Atomic write (tmp+rename) for crash safety. Shutdown hook performs final flush. 4 new tests: insert/lookup, flush+reload survive restart, invalidation on size change, GC removes deleted files.
- [x] **`[MEDIUM]`** Evaluate `DashMap` as concurrent map replacement.
  - **Done (v0.5.1)**: Evaluated and resolved all 6 candidate surfaces:
    - `pending_decisions` → **migrated** to `Arc<DashMap<String, u64>>`; epoch helpers converted to sync.
    - `subscription locks` → **migrated** to `Arc<DashMap<String, Arc<AsyncMutex<()>>>>`; outer `StdMutex` removed.
    - `bpf_map_snapshot` → **migrated** to `Arc<ArcSwap<HashMap<String, u32>>>`; hot read path is now a lock-free atomic load; background writer uses `store(Arc::new(new_map))`.
    - `interface_name_cache` → **migrated** to `ArcSwap<HashMap<u32, String>>`; read path is lock-free atomic load; write (on cache miss) uses `store`.
    - `requeue_aliases` (nfqueue) → **migrated** to `DashMap<u64, RequeueAlias>`; O(n) prune scan moved to write path only (`remember_requeue_alias`); `claim_requeue_alias` is now O(1) via atomic `remove` + TTL check.
    - `StorageEventBus` path/prefix maps → **migrated** to `Arc<DashMap<PathBuf, broadcast::Sender<StorageEvent>>>`; concurrent storage events for different paths no longer contend on a single `Mutex`; shard locks released before `send`.
  - `DualLayerLruMap`/`SyncDualLayerLruMap` snapshot layer → **migrated** from `RwLock<Arc<HashMap>>` to `ArcSwap<HashMap>`; `get_snapshot()` (read hot path) is now lock-free; all `publish_*` writers use `store(Arc::new(next))` instead of holding a write lock.
  - `DualLayerLruMap` mutable LRU layer → **migrated** to `quick-cache::sync::Cache` (Hot/Cold eviction, lock-free sharded reads); `lru::LruCache` removed; dual-layer write-lock and ArcSwap snapshot machinery eliminated. See **Done (v0.5.1)** below.
- [x] Replace `DualLayerLruMap`/`SyncDualLayerLruMap` with `quick-cache`.
  - **Done (v0.5.1)**: `lru` crate removed; `quick_cache = "0.6"` added. `DualLayerLruMap`/`SyncDualLayerLruMap` are now type aliases for `ConcurrentLruCache<K,V>`, a thin `Arc<quick_cache::sync::Cache<K,V>>` wrapper. The dual-layer async `mutable`/`snapshot` split, all `publish_*` paths, and the ArcSwap snapshot machinery are gone. All callers updated to synchronous `insert`/`get`/`peek`/`remove_by`/`clear`/`set_capacity`. Eviction tests updated for Hot/Cold approximate semantics (oldest-item-evicted assertions dropped; `len ≤ capacity` bound retained).
  - Root cause (closed): the dual-layer design existed solely because `lru::LruCache` is single-threaded. `quick-cache::sync::Cache` is sharded and concurrent, eliminating both layers.
  - Resolved impact: callers now call `get()`/`peek()` directly on `ConcurrentLruCache`; no snapshot-Arc required.

### Future enhancements

- [x] Add kernel capability self-check diagnostic (Go parity gap).
  - Go `daemon/core/system.go` runs consolidated kprobe/uprobe/nfqueue/netlink/tracefs probes at startup and surfaces results to the user.
  - Rust currently performs implicit capability checks at each subsystem init but has no user-facing diagnostic summary.
  - **Done**: `utils/kernel_caps.rs` — reads kernel config (`/boot/config-{kver}`, `/proc/config.gz`, `/usr/lib/modules/{kver}/config`), checks the same 7 feature groups (kprobes, uprobes, ftrace, syscalls, nfqueue, netlink, net diagnostics) via `regex::bytes::Regex`, checks tracefs mount via `/proc/mounts`; results emitted as structured `tracing` events. Wired in `daemon/bootstrap.rs` immediately after config load. Non-fatal, degrades gracefully when config file absent. 425 tests green.

- [x] **`[LOW]`** Split oversized API-surface files (§3 borderline, split when next touching).
  - `services/storage/storage.rs` (557 lines): extensive low-level I/O helper surface beyond API/orchestration scope.
  - `services/client/client.rs` (477 lines): mixes API with session-state internals, ranking logic, transport internals.
  - `flows/verdict/verdict.rs` (674 lines): many private helper/control functions and deep runtime logic.
  - Fix: extract internal helpers into sibling modules (e.g. `storage/ops.rs`, `client/session.rs`, `verdict/helpers.rs`).
  - **Done**: `storage/ops.rs` (3 I/O helpers), `client/session.rs` (session types + `SessionState`), `verdict/helpers.rs` (17 private helpers). 425 tests green.

- [x] Add concrete stats-snapshot exporter implementations for `StatsExporterPort`.
  - Current state: extension point exists in `platform/ports/stats_exporter_port.rs`, and `StatsFlow` hook is wired (`with_stats_exporter()`).
  - Gating policy: only `/metrics`-style export remains feature-gated (`metrics-export`) to preserve baseline Go parity by default.
  - **Done**: `platform/adapters/stats_exporter_prometheus.rs` — `PrometheusStatsExporter` implementing `StatsExporterPort`:
    - `export_snapshot()` stores a compact snapshot (counters + breakdown maps, no Events slice) atomically via `ArcSwap<Option<CompactStats>>` — zero blocking, zero I/O on the hot path.
    - `spawn_metrics_server(addr, shutdown)` starts a minimal `hyper` 1.x HTTP/1.1 server; `/metrics` returns Prometheus text format 0.0.4; any other path returns 404. Fail-open: bind failure logs a warning and disables the endpoint without affecting daemon operation.
    - Activated via `OPENSNITCH_PROMETHEUS_ADDR` env var (e.g. `127.0.0.1:9100`); absent/empty = no-op.
    - 12 counter/gauge metrics + 6 labeled gauges (by_proto, by_address, by_host, by_port, by_uid, by_executable).
    - Wired into `daemon/tasks.rs:spawn_stats_flow()` under `#[cfg(feature = "metrics-export")]`.
    - Push-style adapter (Mimir/InfluxDB/push-gateway): `platform/adapters/stats_exporter_push.rs` — `PushStatsExporter` implementing `StatsExporterPort`:
      - `export_snapshot()` enqueues a compact snapshot via bounded `tokio::sync::mpsc` channel (capacity 4) — zero blocking, zero I/O on the hot path; drops snapshot if channel full (fail-open).
      - Background `push_worker` task reads from the channel and POSTs to the remote endpoint via `reqwest::Client` (5 s timeout, fail-open on HTTP errors).
      - Two output formats — `OPENSNITCH_PUSH_FORMAT`:
        - `pushgateway` (default): Prometheus text format 0.0.4 POSTed to `{url}/metrics/job/{job}`. Same metric set as the scrape endpoint. Compatible with Prometheus push-gateway, Grafana Mimir, and Grafana Cloud remote-write (set `OPENSNITCH_PUSH_JOB` for job label).
        - `influxdb`: InfluxDB line protocol (integer fields, seconds precision) POSTed to the URL verbatim. Scalar counters/gauges in `opensnitch_stats` measurement; breakdown maps as tagged `opensnitch_by_{key}` measurements. URL is used as-is (user provides full write endpoint, e.g. `/api/v2/write?bucket=...` or `/write?db=...`); `OPENSNITCH_PUSH_BUCKET` / `OPENSNITCH_PUSH_ORG` auto-appended only when `bucket=` is absent from the URL.
      - `OPENSNITCH_PUSH_TOKEN`: bearer (push-gateway) / `Token` (InfluxDB) auth header — optional.
      - `MultiStatsExporter`: fan-out adapter dispatching to multiple inner exporters; used in `tasks.rs` when both Prometheus addr and push URL are set simultaneously.

- [x] Add `PrometheusText1.0.0` scrape format support.
  - Current `negotiate_format()` correctly falls back to `PrometheusText0.0.4` when a client
    requests higher versions (spec-compliant), but some Prometheus 3.x configurations prefer
    version 1.0.0 with UTF-8 escaping.
  - Requires rendering escaped UTF-8 label values + `Content-Type: text/plain; version=1.0.0;
    escaping=allow-utf-8` response header.
  - **Done**: `negotiate_format()` now tracks `best_text100_q`; `ResponseFormat::Text100` added.
    Output body is identical to 0.0.4 (label values already pass UTF-8 through); only
    `Content-Type` differs.
- [x] Add `OpenMetricsText1.0.0` scrape format support.
  - The current Prometheus default `Accept` header prefers `application/openmetrics-text;version=1.0.0`
    (q=0.5) over protobuf and text/plain; implementing it removes the format-downgrade penalty.
  - Requires `# UNIT` lines, `_created` timestamp metrics, and `# EOF` terminator per OpenMetrics 1.0.0 spec.
  - **Done**: `ResponseFormat::OpenMetrics` added; `render_openmetrics_text()` emits base-name
    HELP/TYPE for counters, `_total`/`_created` samples, `# UNIT` for gauges with known units,
    and `# EOF\n` terminator.
- [x] Hot-reload `metrics.json` without daemon restart.
  - Currently `MetricsConfig` is loaded once at bootstrap via `load_sibling()`.
  - A SIGHUP-triggered reload could pick up changes to `metrics.json` and re-wire the
    `StatsFlow` exporter without interrupting inflight connections.
  - **Done**: `DaemonRuntime::metrics_server: Mutex<Option<MetricsServerSlot>>` stores the
    exporter + server CT.  `spawn_stats_flow()` always creates the exporter (hot-reload ready).
    `Daemon::reload_metrics_server()` (called from SIGHUP handler) re-reads `metrics.json`,
    resolves addr via §7, and cancels/restarts the HTTP server as needed.  Push config
    changes still require a daemon restart.
- [x] Migrate `metrics-export` env-var configuration to JSON config + CLI switches (DESIGN_RULES §7).
  - **Done**: `models/metrics_config.rs` — pure serde model (`MetricsConfig`, `PrometheusConfig`,
    `PushExportConfig`, `PushFormatConfig`, `MetricsCliOverrides`, `metrics_json_sibling()`).
  - **Done**: `metrics.json` co-located with daemon config; loaded via `MetricsConfig::load_sibling()`
    in bootstrap (fail-open: absent file → defaults).
  - **Done**: `CliOverrides.metrics: MetricsCliOverrides` + 6 new `--metrics-*` flags in `parse_cli_overrides()`.
  - **Done**: `spawn_stats_flow()` does full §7 resolution (CLI → env var → JSON config baseline).
  - **Done**: `prometheus_addr_from_env()` and `PushConfig::from_env()` removed (dead code after migration).
  - CLI switches (`--metrics-*`) have highest precedence per DESIGN_RULES §7; env vars (`OPENSNITCH_PROMETHEUS_ADDR`, `OPENSNITCH_PUSH_*`) are mid-tier (typically used for CI/testing).

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

- [x] Support AdBlock/AdGuard list format in rule list operators and subscriptions.
  - **Done**: `normalize_domain_list_entry` in `services/rule/utilities.rs` now parses `||domain^` (AdBlock/AdGuard domain anchor) by stripping `||` and terminating at the first `^`, `$`, or `/`. Exception rules (`@@||domain^`) are skipped; cosmetic filters (`##`, `#@#`), header lines (`[Adblock Plus…]`), and `!` comments return `None`. `parse_list_lines` in `services/rule/storage.rs` also skips `!`-prefixed lines for all list types. Wildcard entries (`||*.tracker.net^`) are handled by the existing `wildcard_suffix` + `DomainWildcardTrie` path. Options suffix (e.g. `$third-party`) and URL paths are stripped before domain extraction. Mixed files (hosts + AdBlock) are transparently accepted.
  - `DomainWildcardTrie::insert_domain_and_subdomains`: `required = labels.len()` (not `+1`) so `||example.org^` matches both `example.org` AND `www.example.org` per spec. `is_adblock_domain_anchor` helper routes these to the trie; no separate HashSet entry needed.
  - Additional skip rules per spec: inline `# comments` stripped from plain-domain lines; `/REGEX/` lines routed to `domains_regex` cascade (see below); `|single-anchor|` lines and `*$modifier` wildcard-only rules skipped.
  - **Unified `lists.domains` cascade** (mirrors AdGuard `urlfilter` engine design): `ListPathSlotCache` gains a `domains_regex: Option<ListRegexCache>` sub-cache populated from `/pattern/` lines in the same file. `extract_domain_list_regex_pattern` extracts patterns from AdBlock-style regex entries. Matching cascades: `HashSet` (O(1)) → `DomainWildcardTrie` → `GlobMatcher` → `domains_regex` (Aho/regex, only when all fast-path lookups miss). A single `lists.domains` operator now handles plain domains, `||anchor^` rules, wildcard/glob entries, and `/regex/` patterns from the same mixed file. `lists.domains_regexp` is retained for backward compat (pure-regex list files).
  - Integration tests: `match_attempt_domain_lists_parses_adblock_adguard_format` and `match_attempt_domain_lists_regex_cascade_in_domains_operand` in `tests/rules/rule_service.rs`.

- [ ] Python UI client explicit disconnect on quit/CTRL-C (graceful stream shutdown before process exit).
  - Goal: avoid daemon-side noisy transport warnings during intentional UI termination.
  - Note: future work only; separate PR branch once related Python-client PR is accepted upstream.

- [ ] **`[ARCH]`** Isolate current gRPC UI transport behind a dedicated adapter feature.
  - **Current branch progress (2026-03-30)**:
    - **Done**: added explicit default-on Cargo feature gate for the gRPC wire adapter in `crates/daemon/Cargo.toml` (`transport-wire-grpc-client`).
    - **Done**: `ClientService` transport methods now have `transport-wire-grpc-client`/no-adapter behavior split; no-adapter builds return explicit transport-unavailable errors instead of panicking (`subscribe`, `ping`, `ask_rule`, `post_alert`, subscription RPCs, notification stream open).
    - **Done**: `connect*` helpers now degrade to `ClientService::default()` when `transport-wire-grpc-client` is disabled so policy/runtime paths can continue to apply fallback behavior instead of hard startup failure.
    - **Done**: tonic/rustls dependency wiring moved behind optional `transport-wire-grpc-client` feature deps (`hyper-rustls`, `rustls`, `rustls-pki-types`, `x509-cert`) and transport TLS helpers are now `#[cfg(feature = "transport-wire-grpc-client")]`-scoped.
    - **Pending**: add one `--no-default-features --features ...` CI lane once unrelated no-default eBPF compile errors are fixed.
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

- [ ] **`[ARCH]`** Extract transport/session client port and make transport libraries truly pluggable.
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

- [ ] **`[ARCH]`** Extract loadable-state backend/codec ports and make file formats truly pluggable.
  - **Why**: pluggability must be symmetric with transport. Runtime currently assumes JSON/file-centric load paths for config/rules/network aliases/firewall state in multiple domains. We need explicit multi-format compatibility so OpenWrt-style configuration and control surfaces can plug in cleanly (for example UCI-like config files and ubus JSON-compatible payload contracts) without policy-layer rewrites.
  - **Current branch progress (2026-03-30)**:
    - **Done**: introduced external workspace storage-format crate `crates/storage-format-json` (`opensnitch-storage-format-json`) as a first format library boundary for loadable-state JSON parse/convert operations.
    - **Done**: rewired primary JSON loadable paths to codec-lib APIs without behavior changes: shared storage JSON reads (`services/storage/storage.rs`), rule sync file parsing (`services/rule/storage.rs`), firewall load/save (`services/firewall/storage.rs`), subscription store load/save (`services/subscription/storage.rs`), and config raw decode path (`config/config.rs`).
    - **Done**: added explicit CLI main-format override `--main-storage-format <json|yaml|toml>` and wired it into bootstrap/migration global storage policy (`services/storage/storage.rs`, `daemon/bootstrap.rs`, `daemon/migration.rs`).
    - **Done**: default compatibility now falls back to JSON when extension-based detection is missing/unsupported, while explicit CLI main-format overrides can force parse/convert behavior and rule file extension selection.
    - **Next**: extract domain-facing backend/codec ports (`ConfigStorePort`, `RuleStorePort`, `AliasStorePort`, `FirewallStorePort`) and move remaining direct `serde_json` callsites in service internals behind adapter/codec boundaries.
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
    - `opensnitchd.verdict` — verdict reply method (replaces WS verdict round-trip for Luci);
    - `opensnitchd.stats` — current stats snapshot as ubus response JSON;
    - `opensnitchd.rule_list` / `opensnitchd.rule_apply` — rule CRUD methods;
    - `opensnitchd.subscription_list` — current subscription states.
    - ubus object registration runs inside the HTTP+WebSocket server task when both `http-client`
      and `openwrt` features are enabled.
  - **Luci integration** (companion `luci-app-opensnitchd`):
    - Consumes the HTTP+WebSocket `/ws` endpoint for live verdict pop-up dialogs and stats dashboard.
    - UCI config editor page backed by `opensnitchd.rule_apply` ubus call.
    - Packaged as an opkg `.ipk` targeting OpenWrt 23.05+ (LuCI framework 2.0).
    - Separate repository / submodule; tracked here for scope awareness.
  - Prerequisite: HTTP+WebSocket client task must land first (Luci consumes that endpoint).

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

- [x] **`[LOW]`** `services/lifecycle/` missing `runtime_lifecycle.rs` module (§3 violation).
  - **Done**: `services/lifecycle/` directory collapsed into flat `services/lifecycle.rs` — `lifecycle` is a shared trait/helper layer with no runtime state, so the subdirectory and `runtime_lifecycle.rs` rule both become moot; all `crate::services::lifecycle::*` import paths are unchanged.

- [x] **`[MEDIUM]`** `flows/verdict/verdict.rs` — Arc value clone on proto snapshot (§1 hot-path violation).
  - **Done**: `get_proto_snapshot().as_ref().clone()` replaced with `get_proto_snapshot()` — keeps `Arc<Vec<pb::Rule>>`; downstream `previous_rules.clone()` is now a cheap Arc clone; `&snapshot` still coerces to `&[pb::Rule]` via two deref hops.

- [x] **`[MEDIUM]`** §7 precedence order revised to CLI > env var > JSON config baseline.
  - **Done**: `config.rs::load_from_default_locations_with_override()` now resolves CLI `--config-file` first, then `OPENSNITCH_CONFIG_FILE` env var, then system/dev defaults.
  - **Done**: `main.rs` now sets `overrides.ui_socket = client_addr` only when CLI `--ui-socket` is absent (CLI wins when present).
  - **Done**: all `spawn_stats_flow()` and `reload_metrics_server()` resolution chains use CLI → env var → JSON order.

- [x] **`[LOW]`** §2 trait-first integration boundary violations — rescan (2026-03-30) remediation completed.
  - **Done**: introduced/used explicit port facades (`proto_mapper_port`, `nfqueue_runtime_port`, `net_iface_port`, `audit_netlink_port`, `nft_monitor_port`) so domain/runtime paths consume `platform/ports` instead of direct `platform/adapters` or `platform/ffi` imports.
  - Updated files: `flows/verdict/{helpers,submit,verdict}.rs`, `services/rule/matching_operators.rs`, `services/task/socket_monitor.rs`, `workers/{firewall/watch_worker,process/audit_worker,runtime/nfqueue/worker}.rs`.
  - Verification: `rg -n "platform::(adapters|ffi)" src/services src/flows src/workers` returns no matches.

- [ ] **`[LOW]`** §2 file-size enforcement — rescan (2026-03-30) shows remaining >500-line files after initial split pass.
  - Split progress confirmed: monolith paths `platform/adapters/firewall_nft_netlink.rs`, `workers/runtime/ebpf/control.rs`, `platform/ffi/nfqueue.rs`, and `config.rs` were replaced by directory modules.
  - **Done (2026-03-30)**: `workers/runtime/watch/control.rs` split by extracting inotify trigger machinery to `workers/runtime/watch/control_trigger.rs`; `control.rs` reduced to 295 lines.
  - Still >500 lines: `platform/adapters/stats_exporter_prometheus.rs` (1080), `platform/adapters/stats_exporter_push.rs` (946), `services/task/runtime_handlers.rs` (916), `flows/notification/notification.rs` (861), `platform/adapters/nfqueue_netlink.rs` (709), `platform/adapters/firewall_nft.rs` (677), `models/audit/kind.rs` (674), `services/storage/storage.rs` (668), `daemon/tasks.rs` (631), `services/rule/matching.rs` (621), `platform/adapters/connection_event_logger.rs` (556), `workers/dns/dns_worker.rs` (552), `platform/adapters/firewall_nft_netlink/apply.rs` (539), `workers/runtime/ebpf/control/aya_runtime.rs` (534), `platform/adapters/firewall_nft_netlink/parse.rs` (528).
  - Concrete next-touch split plan for `platform/adapters/nfqueue_netlink.rs`: extract wire/message builders (`nlmsg` + config/verdict encoders) to `platform/adapters/nfqueue_netlink/wire.rs`, packet parsing to `.../parse.rs`, and socket/runtime loop control to `.../runtime.rs`, leaving `mod.rs`/facade-only startup helpers in the main adapter file.
  - Follow-up policy: split on next feature touch; prioritize runtime/flow/service files before adapter-only files when selecting incremental refactor slices.

### Hot-Path Optimization Backlog (rescan 2026-03-26)

Prioritized by estimated impact on per-connection/per-packet latency. Detailed analysis in PERF.md.

- [x] **`[HIGH]`** Eliminate per-probe `format!` allocation in `services/connection/owner.rs` L24 + reduce fallback full /proc scan at L64.
  - **Done**: extracted `pid_owns_inode_at(inode, &Path)`; fallback scan pre-allocates one `PathBuf::with_capacity(24)` and reuses it with `push`/`clear` across all candidate pids.

- [x] **`[HIGH]`** Avoid per-connection `HashSet` allocation in `services/dns/cache_ops.rs` L39 (`lookup_ip` alias-cycle detection).
  - **Done**: replaced `HashSet` with bounded hop-limit loop (`for _ in 0..8`); real alias chains are ≤ 3 hops; no heap allocation.

- [x] **`[HIGH]`** Remove per-rule-eval `String` allocations in `services/rule/matching.rs` (L702 command join, L707 numeric `to_string`).
  - **Done**: added 5 `OnceLock<String>` fields to `AttemptDerived` (`process_command`, `process_id`, `user_id_text`, `dst_port_text`, `src_port_text`); `operator_operand_value` now returns `Cow::Borrowed` pointing into the OnceLock — each string is built at most once per connection across all rule evaluations.

- [x] **`[HIGH]`** Reduce verdict decision key allocation in `flows/verdict/verdict.rs` L105/L118/L141.
  - **Done**: replaced `DashMap<String, u64>` with `DashMap<u64, u64>`; `decision_key_hash()` uses `DefaultHasher` — eliminates one `format!` + two `to_owned()` allocations per connection decision.

- [x] **`[HIGH]`** Reduce `services/process/inspection.rs` L44 contention on `exit_deadlines` mutex under high churn.
  - **Done**: removed `cleanup_expired()` from the `inspect()` hot path; the background cleanup task (10 s interval) handles TTL-based eviction; hot path only acquires the mutex once for the `exit_deadline` check.

- [x] **`[MEDIUM]`** Use stack-allocated fixed buffers for eBPF key building in `services/connection/ebpf.rs` L73.
  - **Done**: `BpfKey { V4([u8; 12]), V6([u8; 36]) }` enum with `Deref/DerefMut → &[u8]`; wildcard + swap mutations use typed match arms.

- [x] **`[MEDIUM]`** Avoid per-event closure capture in `flows/kernel/kernel.rs` L56.
  - **Done**: `dispatch_kernel_pipeline_event` now accepts `counters: &Arc<KernelPipelineCounters>` + `pipeline: KernelPipeline` directly; on-drop counter call is inline, no per-event Arc clone or closure allocation.

- [x] **`[MEDIUM]`** Remove eager clone in `flows/verdict/verdict.rs` L589 before `ask_rule`.
  - **Done**: `pb_conn.get_or_insert_with(...).clone()` replaced with `pb_conn.take().unwrap_or_else(...)`; no backup proto copy held in pb_conn during the gRPC ask_rule round-trip.

- [x] **`[LOW]`** Cold-path improvements: parallel shutdown awaits in `workers/runtime/control/control.rs` L327; `Arc<StorageEvent>` broadcasting in `services/storage/event_bus.rs` L64.
  - **Done**: `join_all()` now uses `tokio::task::JoinSet` for concurrent task awaiting; broadcast channel carries `Arc<StorageEvent>` (one pointer clone per receiver instead of a full struct clone including PathBuf).

- [x] **`[LOW]`** Eliminate `spawn_blocking` hop on inotify-triggered rule reload in `services/rule/rule.rs`.
  - `reload_sync()` routes small-file directory reads through the blocking-pool thread, adding ~3-5 ms scheduling overhead per reload. The rules directory typically holds a handful of JSON files (< 1 KB each) — sync I/O completes in microseconds.
  - **Done**: added `reload_inline()` that calls `load_rules_from_path_sync` directly on the tokio thread; inotify scan path in `RuleWatchControl` switched from `reload_sync` to `reload_inline`. Cold:rule parity median improved from +12 ms to +7 ms (Rust vs Go). `reload_sync` retained for callers that may process larger directories.

- [x] **`[MEDIUM]`** Replace firewall drift-heal polling with event-driven triggers.
  - **Done (v0.5.1)**:
    1. **Inotify on firewall config file**: `FirewallWatchControl::targets()` now returns `WatchWorkerControl::path_targets(&config.firewall_config_path)` — the existing inotify+epoll watch infrastructure wakes immediately on config-file writes. `empty_targets_behavior` changed to `WarnPollFallback`.
    2. **Netlink NFNLGRP_NFTABLES subscription**: new `platform/adapters/nft_monitor.rs` (`spawn_nft_drift_listener`) opens a `MulticastSocketRaw` on `NETLINK_NETFILTER` (12) and subscribes to group 7 (`NFNLGRP_NFTABLES`). On each kernel nftables event, calls `firewall.heal_if_drifted()`. The adapter's `drift_recovery_blocked_until_epoch_ms` atomic provides burst rate-limiting. Gracefully degrades to a log warning if the socket cannot be opened (the 20 s timer loop remains the safety-net fallback). Wired in `workers/firewall/watch_worker.rs::start()`.
    3. **Rule-cache alias refresh hook**: successful explicit firewall reloads, nftables netlink events, and periodic drift-heal recoveries now call `RuleService::rebuild_caches_from_snapshot()` so `network_aliases.json` and future firewall-native alias/zone sources stay synchronized with runtime firewall state without adding work to the verdict hot path.
  - Go parity note: Go uses ticker-based drift polling only; NFNLGRP_NFTABLES subscription is a Rust-only extension beyond Go baseline.

### Hot-Path Optimization Backlog (rescan 2026-03-27)

New findings from systematic hot/cold-path audit. Prioritised by per-connection/per-packet impact.

- [x] **`[HIGH]`** Cache typed eBPF map handles in `services/connection/ebpf.rs`.
  - `MapData::from_id` + `HashMap::try_from` called per `lookup_bpf_owner` invocation, up to 3× per connection (exact key, wildcard dst, swapped). Each call re-opens the map fd and re-validates the BTF type.
  - **Done**: `lookup_bpf_owner` and `aya_lookup_bpf_owner` removed; `resolve_owner_by_ebpf_map` opens one `MapData` fd via `MapData::from_id(map_id)`, converts to a typed `AyaHashMap` once (dispatching on `BpfKey::V4`/`V6`), then calls `.get()` for all three key variants (exact, wildcard dst, swapped) — 2 fd-open syscalls and 2 BTF validations saved per connection. libbpf fallback path similarly opens `MapHandle::from_map_id` once. Free `decode_pid_uid` helper extracted for shared use.

- [x] **`[HIGH]`** Use `BufReader` for `/proc/net/*` fallback in `services/connection/owner.rs`.
  - `resolve_owner_by_connection_fallback` (L132-178) calls `read_to_string(path)` which reads the entire `/proc/net/{tcp,tcp6,udp,udp6,udplite,udp6lite}` file into a heap-allocated `String`, then iterates lines. These files can be large on busy systems with many sockets.
  - **Done**: replaced `std::fs::read_to_string` with `BufReader::new(File::open(path)?)` + `.lines()` iterator; header skipped via `lines.next()`; loop returns on first inode match. Eliminates full-file heap allocation; I/O stops at first match.

- [x] **`[HIGH]`** Eliminate Vec allocation in ICMP packet-socket fallback in `services/connection/owner.rs`.
  - `resolve_owner_from_packet_sockets` (L108-129) builds a `Vec<ConnectionOwner>` just to check `len() == 1`. Under normal operation the vector has 0 or 1 elements.
  - **Done**: replaced `Vec<ConnectionOwner>` + push + `len() == 1` with `Option<ConnectionOwner>` single-slot tracking; on a second different match the function returns `None` immediately — zero heap allocation.

- [x] **`[MEDIUM]`** Bound kernel ingress channels in `flows/kernel/kernel.rs`.
  - `dns_ingress_tx`, `process_ingress_tx`, `firewall_ingress_tx` (L157-165) are `unbounded_channel`. Under sustained producer > consumer rate, memory can grow without bound.
  - **Done**: all three ingress channels changed to bounded `channel(capacity)` reusing the existing downstream tunables (`kernel_dns_queue_capacity`, `kernel_process_queue_capacity`, `kernel_firewall_queue_capacity`). `fanout_kernel_ingress_event` in `dispatch.rs` migrated to `try_send` with `counters.increment_drop` on full (consistent with `dispatch_kernel_pipeline_event` policy). `spawn_pipeline_dispatch_task` switches from `UnboundedReceiver` + `drain_try_recv_burst_unbounded` to `Receiver` + `drain_try_recv_burst`. `probe_fanout_kernel_ingress_event` and two smoke tests updated for new bounded-channel signature.

- [x] **`[MEDIUM]`** Narrow rules-watch mutex scope in `services/rule/storage.rs`.
  - `RuleWatchControl::scan` (L346-380) holds `last_state.lock().await` across diff logging AND `rules.reload().await`. The async mutex blocks other callers during the entire reload I/O.
  - **Done**: clone previous state under a short `last_state.lock().await` (immediately dropped), then perform diff logging and `rules.reload().await` with no lock held; reacquire with `*last_state.lock().await = state` only to write the new state. Lock contention window reduced from the full reload duration to two short clones.

- [x] **`[MEDIUM]`** Parallelise cold-path list file I/O in `services/rule/cache_builder.rs`.
  - `list_path_needs` loop (L61-145) awaits each `load_list_entries_async_plain(&path)` serially. Also performs multiple `collect::<Vec<_>>()` passes over the same entry set for different cache needs.
  - **Done**: two-phase approach — phase 1 spawns one `tokio::task::JoinSet` task per list-path (all reads run concurrently); phase 2 processes results serially for deterministic slot-index assignment. Intermediate `Vec::collect` eliminated for `trimmed_values` and `networks` passes: `trimmed_non_empty` now called directly on the `entries.iter().map(String::as_str)` iterator.

- [x] **`[MEDIUM]`** Avoid per-event `String` allocation in `services/stats/snapshot_ops.rs`.
  - `format_event_time` (L13-24) calls `dt.format(EVENT_TIME_FORMAT)` which allocates a new `String` on every `on_event` call (per-verdict hot path).
  - **Done**: replaced `time::format_description` dispatch with a direct `write!` into a 19-byte stack `[u8; 19]` buffer, then `String::from_utf8_unchecked(buf.to_vec())` — one exact-sized heap allocation, no format-description machinery. `format_description!` macro and `EVENT_TIME_FORMAT` constant removed.

### Codebase Optimization Backlog (rescan 2026-03-27)

New findings from systematic full-codebase audit (services, flows, workers, platform, utils). Prioritised by per-connection impact; cross-referenced against PERF.md deferred items and DESIGN_RULES.md.

- [x] **`[HIGH]`** Avoid double `/proc/{pid}/stat` read on process cache hits in `services/process/inspection.rs`.
  - `inspect()` calls `read_proc_starttime(pid)` at L61 (peek branch) AND L74 (get branch) — two `fs::read_to_string(format!("/proc/{pid}/stat"))` + field-22 parse per cache hit.
  - **Done**: read starttime once at top of `inspect()` before the peek/get branches; both branches reuse the pre-read value. One filesystem read eliminated per cache-hit path.

- [x] **`[HIGH]`** Pool gRPC client connections for UI miss/stats paths (`flows/verdict/verdict.rs` + `flows/stats/stats.rs` + `flows/notification/notification.rs`).
  - `ClientService::connect_with_config(&config_snapshot).await` creates a fresh gRPC connection per `ask_rule` miss (verdict.rs L353), per notification dispatch (notification.rs L270), and per 1-second stats ping (stats.rs L279). Each call incurs TCP+HTTP/2 handshake overhead.
  - **Done**: `GrpcChannelCache` (`ArcSwap<Option<CachedChannel>>`) stores a reusable `tonic::Channel` keyed on config fingerprint (addr + auth type hash). `connect_or_reuse(config, cache)` checks cache first, falls back to fresh connect on miss. Verdict flow and stats flow use `connect_or_reuse` with cache invalidation on transport errors. `connect_with_config` refactored via `connect_channel` + `from_channel` helpers.

- [x] **`[HIGH]`** Reduce proto mapper allocation overhead in `platform/adapters/proto_mapper.rs`.
  - `to_proto_connection` deep-clones `proc_info.env_map`, builds `HashMap` for checksums with `"md5"/"sha1"/"sha256".to_string()`, clones `parent_chain` paths Vec, and calls `attempt.src_addr.to_string()` + `attempt.dst_addr.to_string()`. Called on every UI-miss/ask_rule path.
  - **Done**: extracted shared `build_checksums` (pre-sized `HashMap::with_capacity`, filters empty hashes) and `build_env_map` helpers; both `to_proto_process` and `to_proto_connection` now share the same compact code paths. HashMap growth eliminated.

- [x] **`[MEDIUM]`** Bound proc connector netlink dispatch channels in `workers/process/netlink_worker.rs`.
  - `mpsc::channel()` (unbounded `std::sync::mpsc`) at L29 for 4 round-robin dispatch workers. Under process churn, queues grow without bound.
  - **Done**: `sync_channel(PROC_EVENT_CHANNEL_CAPACITY)` (512) replaces unbounded `channel()`; sender changed from `Sender` to `SyncSender`; dispatch uses `try_send` with silent drop on `TrySendError::Full` (fail-open, consistent with kernel pipeline backpressure policy).

- [x] **`[MEDIUM]`** Reduce DNS dedup O(n) sweep + String allocation in `services/dns/parsing.rs`.
  - `should_emit_at()` calls `recent_events.retain(...)` (O(n) sweep) on every DNS event, plus creates `(ip.to_string(), host.to_string())` as HashMap key.
  - **Done**: `retain()` moved from per-call to overflow-only path (triggered only when `len >= MAX_RECENT_EVENTS`). Under normal operation, the O(n) sweep never runs. Key allocation still needed for inserts (stable Rust lacks `raw_entry`), but dedup hits avoid the retain cost.

- [x] **`[MEDIUM]`** Narrow task-watch mutex scope in `services/task/storage.rs`.
  - `TaskWatchControl::scan` holds `task_handles.lock().await` across entire `sync_storage_tasks()` which does async file reads and task spawn/stop — same pattern as the rules-watch fix from the 2026-03-27 backlog.
  - **Done**: split `sync_storage_tasks` into `load_storage_tasks` (pub, async file I/O, no lock) + `apply_storage_task_diff` (sync mutation). `TaskWatchControl::scan` calls load first (no lock), then acquires mutex only for the short diff-apply phase.

- [x] **`[MEDIUM]`** Store SIEM logger sinks behind `Arc` in `platform/adapters/connection_event_logger.rs`.
  - `on_connection_event()` clones the entire `Vec<SinkHandle>` (including owned `format: String` and `tag: String` per sink) on every connection event before dispatching.
  - **Done**: `LoggerState.sinks` changed from `Vec<SinkHandle>` to `Arc<[SinkHandle]>`; `on_connection_event` does `Arc::clone` (pointer-sized) instead of deep Vec clone. `SinkHandle.tag` changed from `String` to `Arc<str>`.

- [x] **`[MEDIUM]`** Precompute SIEM format as enum in `platform/adapters/connection_event_logger.rs`.
  - `format_message` normalises the format string via `case_folded(format)` on every event (~L319/L321), despite format being static per sink.
  - **Done**: `SinkFormat` enum (`Json`/`Csv`/`Rfc3164`/`Rfc5424`) with `from_str` constructor. Format parsed once at sink build time; hot path dispatches via `format_message_enum` (match on enum). Per-event `case_folded()` + string allocation eliminated.

- [x] **`[MEDIUM]`** Single-pass socket candidate selection in `platform/adapters/socket_diag.rs`.
  - `select_socket_candidates` iterates `sockets` three times with three separate filter conditions, cloning each matched `SocketInfo`.
  - **Done**: single pass with three priority-tiered output buckets (`exact`, `wildcard_dst`, `relaxed_dst`). All sockets pre-filtered on `src_port + src` check. Buckets merged in priority order at the end. 2 redundant iterations eliminated.

- [x] **`[LOW]`** Coalesce inotify watch triggers in `workers/runtime/watch/control.rs`.
  - `tokio::sync::mpsc::unbounded_channel()` at L277 for `()` trigger tokens. Memory risk is minimal (unit-value signals), but semantically these should coalesce.
  - **Done**: `channel(1)` with `try_send(())` replaces unbounded channel. Receiver type updated from `UnboundedReceiver<()>` to `Receiver<()>`.

- [x] **`[LOW]`** Add `connected_sessions_count()` to avoid cloning all sessions for `.len()` in `services/client/client.rs`.
  - `connected_sessions()` returns `Vec<ClientSession>` via `.cloned().collect()`. Stats flow (stats.rs L229) immediately calls `.len()` — unnecessary clone+collect.
  - **Done**: `connected_sessions_count() -> usize` reads `sessions.len()` directly from snapshot. Stats flow telemetry updated to call `connected_sessions_count()` instead of `connected_sessions().len()`.

- [x] **`[LOW]`** Session snapshot full-map clone on mutation in `services/client/client.rs`.
  - `upsert_session` / `disconnect_session` call `owned_snapshot()` which clones the entire `ClientSessionSnapshot` (including `BTreeMap<String, ClientSession>`), mutate, then `publish_snapshot`. Low-frequency path (connect/disconnect events), but violates Arc-read-is-cheap principle for writes.
  - **Done**: replaced `owned_snapshot()` + mutate + `publish_snapshot()` with `modify_snapshot(|s| { ... })` using `watch::Sender::send_modify()` + `Arc::make_mut()`. Copy-on-write: when no reader holds the Arc (common case), mutation is in-place with zero allocation; under contention `Arc::make_mut` clones — the minimum necessary for concurrent correctness. All 4 mutation methods (`upsert_session`, `disconnect_session`, `set_session_default_action`, `set_connected_default_action`) converted. Multi-user concurrent access safe.

- [x] **`[LOW]`** BufReader for `/proc/net/packet` and `/proc/net/xdp` in `utils/proc_net.rs`.
  - `std::fs::read_to_string` reads entire file into heap `String`. Cold/diagnostic path (sockets monitor task).
  - **Done**: `BufReader::new(File::open(...))` + `.lines()` replaces `read_to_string`. Eliminates single large heap allocation; reads line-by-line.

- [x] **`[LOW]`** Stack buffer for autotune `/proc/stat` parse in `tunables.rs`.
  - `read_cpu_stat_snapshot()` (L591) reads `/proc/stat` via `read_to_string`, then `.collect::<Vec<_>>()` for CPU field values. Called twice per autotune sample (startup only).
  - **Done**: fixed-size `[u64; 8]` stack array replaces `Vec` + `resize(8, 0)`. Zero heap allocation for CPU field parsing.

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
- 2026-03-25: Updated eBPF build policy so live/runtime eBPF compilation always runs as root under `target-kernel`; `build_ebpf.sh` now enforces root execution and Make targets route both build paths through the same root-owned kernel target tree.
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
