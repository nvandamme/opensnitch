# Daemon-RS Unified Tracker

This is the single tracker file for backend parity, async/runtime hardening, and future enhancements.

It supersedes:

- `daemon-rs/FEATURE_PARITY.md`
- `daemon-rs/SERVICE_ASYNC_AND_MODEL_SCAN_2026-03-15.md`

Last update: 2026-03-26 (full parity/design-rules/optimization rescan)

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

- Active development: `v0.5.1` — hot-path optimization pass complete (all 8 CRITICAL/HIGH/MEDIUM items from post-v0.5.0 backlog implemented).
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

- [x] **[CRITICAL]** Eliminate per-connection `bpftool` subprocess fork in eBPF owner lookup.
  - **Done (v0.5.1)**: `libbpf-rs` `MapHandle::from_map_id` + `MapCore::lookup` replaces subprocess; background Arc-swap refresh task for map catalogue.
  - **Follow-up**: migrate `lookup_bpf_owner` and `list_bpf_maps` to aya-first (`aya::maps::MapData::from_id` + `aya::maps::HashMap`); see aya migration task below.
- [x] **[HIGH]** Remove `IpAddr → String → parse` round-trip in eBPF key building.
  - **Done (v0.5.1)**: `resolve_owner_by_ebpf_map` takes `IpAddr` directly; `bpf_map_name`/`build_bpf_key` use `is_ipv6()`/`.octets()`; mixed-family handled via `to_ipv6_mapped()`.
- [x] **[HIGH]** Reduce `StatsService::inner` mutex contention on hot path.
  - **Done (v0.5.1)**: split into `Mutex<BreakdownCounters>` (per-connection hot path) and `Mutex<EventsState>` (per-verdict hot path) with consistent acquisition order.
- [x] **[MEDIUM]** Avoid per-verdict `String` allocation in `source_label()`.
  - **Done (v0.5.1)**: return type changed to `Cow<'static, str>`; common paths borrow static strs.
- [x] **[MEDIUM]** Use `Arc<str>` for `VerdictReply::rule_name` instead of `String::clone`.
  - **Done (v0.5.1)**: `ActiveRuleCompiled.name: Arc<str>`; `VerdictReply.rule_name: Option<Arc<str>>`; Arc clone instead of heap allocation at every rule hit.
- [x] **[MEDIUM]** Return `Arc<str>` from `DnsService::lookup_ip` instead of `String`.
  - **Done (v0.5.1)**: `lookup_ip` returns `Option<Arc<str>>`; `ConnectionContext.dst_host: Option<Arc<str>>`; DNS query path converts via `Arc::from`.
- [x] **[MEDIUM]** Gate per-verdict logging behind `tracing::enabled!` or move to `debug!`.
  - **Done (v0.5.1)**: changed to `tracing::debug!` gated on `tracing::enabled!(Level::DEBUG)`; `source_label` not called when DEBUG is off.
- [x] **[MEDIUM]** Defer process binary hashing to background task on cache miss.
  - **Done (v0.5.1)**: `inspect_process_no_hash` fast path returns immediately; background `spawn_blocking(compute_process_hashes)` patches the cache entry when ready.
- [x] **[HIGH]** Migrate all eBPF userspace paths to aya-first; drop `bpftool` from production code.
  - **Done (v0.5.1)**: `services/connection/ebpf.rs`: `list_bpf_maps()` and `lookup_bpf_owner()` use aya-first (`loaded_maps()`, `MapData::from_id`, typed `HashMap::try_from`); bpftool functions (`bpftool_list_maps`, `bpftool_lookup_owner`) fully removed.
  - **Done (v0.5.1)**: `workers/runtime/ebpf/control.rs`: added `supervise_runtime_aya()` + `aya_inspect_and_prune_map<const N>()` behind `#[cfg(feature = "aya-ebpf")]`; all bpftool helpers (`prune_map_entries`, `delete_map_key`, `extract_key_bytes`, `collect_u8_values`, `run_capture`, `run_json_capture`, `list_programs`, `list_maps`, `dump_map`), `try_load_object_with_bpftool`, `is_already_pinned_error`, and the bpftool supervisor body in `supervise_runtime()` fully removed.
  - **Done (v0.5.1)**: `tests/smoke/aya_conn_trace.rs` + `aya_tunnel_trace.rs`: bpftool fallback blocks from `map_id_by_name`, `map_dump_keys`, `map_has_entries`, `map_entry_count`, plus `value_to_bytes()` and the `serde_json::Value` cfg import, all removed.
  - **Done (v0.5.1)**: `models/ebpf_state.rs`: `BpfProgram` struct removed (bpftool-only).
  - **Done (v0.5.1)**: `services/ebpf/ebpf.rs`: `conn_pin_root`/`proc_pin_root`/`dns_pin_root` convenience methods removed (sole caller was the bpftool loader).
  - **Done (v0.5.1)**: `tests/firewall/gates.rs`: `bpftool` removed from required-tool preflight.
  - **Done (v0.5.1)**: `libbpf-ebpf` removed from default features — aya-only builds work cleanly; libbpf is opt-in via `--features libbpf-ebpf`.
- [x] **[HIGH]** Harden process hashing strategy for verdict safety.
  - **Done (v0.5.1)**: `SimpleHashOptional` dispatch in both `operator_matches_against_compiled` and `operator_matches_against_with_derived` now returns `false` (not `match`) when hash is `None` — falls through to default action.
  - **Done (v0.5.1)**: IMA fast-path added in `compute_process_hashes`: `read_ima_sha256_xattr` checks `security.ima` xattr (type=0x03, algo=4=SHA-256) before falling back to full file read; `compute_md5_sha1` reads file once for md5+sha1 when IMA provides sha256.
  - Disk-persisted hash cache (sled/redb keyed on path+inode+mtime+size) remains future work for daemon-restart durability.
- [x] **[MEDIUM]** Evaluate `DashMap` as concurrent map replacement.
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

- [ ] Add kernel capability self-check diagnostic (Go parity gap).
  - Go `daemon/core/system.go` runs consolidated kprobe/uprobe/nfqueue/netlink/tracefs probes at startup and surfaces results to the user.
  - Rust currently performs implicit capability checks at each subsystem init but has no user-facing diagnostic summary.
  - Implement a startup diagnostic routine that probes all required kernel capabilities and reports a consolidated status.

- [ ] **[LOW]** Split oversized API-surface files (§3 borderline, split when next touching).
  - `services/storage/storage.rs` (557 lines): extensive low-level I/O helper surface beyond API/orchestration scope.
  - `services/client/client.rs` (477 lines): mixes API with session-state internals, ranking logic, transport internals.
  - `flows/verdict/verdict.rs` (674 lines): many private helper/control functions and deep runtime logic.
  - Fix: extract internal helpers into sibling modules (e.g. `storage/ops.rs`, `client/session.rs`, `verdict/helpers.rs`).

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

- [ ] Add optional `scope` field to gRPC/proto `Operator` in a dedicated compatibility PR (default dst semantics, backward-compatible wire evolution, Go/Rust/Python client alignment).
  - Note: deferred for now to stay aligned with base opensnitch implementation; revisit in a future dedicated compatibility PR.
- [ ] Support AdBlock/AdGuard list format in rule list operators and subscriptions.
  - AdBlock/AdGuard `||domain^` syntax is common in community blocklists.
  - Requires parser normalization and compatibility-safe operator wiring.
  - Note: deferred for now to stay aligned with base opensnitch implementation; revisit in a future dedicated compatibility PR.
- [ ] Python UI client explicit disconnect on quit/CTRL-C (graceful stream shutdown before process exit).
  - Goal: avoid daemon-side noisy transport warnings during intentional UI termination.
  - Note: future work only; separate PR branch once related Python-client PR is accepted upstream.

### Design Rule Violations (rescan 2026-03-26)

- [x] **[LOW]** `services/lifecycle/` missing `runtime_lifecycle.rs` module (§3 violation).
  - **Done**: `services/lifecycle/` directory collapsed into flat `services/lifecycle.rs` — `lifecycle` is a shared trait/helper layer with no runtime state, so the subdirectory and `runtime_lifecycle.rs` rule both become moot; all `crate::services::lifecycle::*` import paths are unchanged.

- [x] **[MEDIUM]** `flows/verdict/verdict.rs` — Arc value clone on proto snapshot (§1 hot-path violation).
  - **Done**: `get_proto_snapshot().as_ref().clone()` replaced with `get_proto_snapshot()` — keeps `Arc<Vec<pb::Rule>>`; downstream `previous_rules.clone()` is now a cheap Arc clone; `&snapshot` still coerces to `&[pb::Rule]` via two deref hops.

### Hot-Path Optimization Backlog (rescan 2026-03-26)

Prioritized by estimated impact on per-connection/per-packet latency. Detailed analysis in PERF.md.

- [x] **[HIGH]** Eliminate per-probe `format!` allocation in `services/connection/owner.rs` L24 + reduce fallback full /proc scan at L64.
  - **Done**: extracted `pid_owns_inode_at(inode, &Path)`; fallback scan pre-allocates one `PathBuf::with_capacity(24)` and reuses it with `push`/`clear` across all candidate pids.

- [x] **[HIGH]** Avoid per-connection `HashSet` allocation in `services/dns/cache_ops.rs` L39 (`lookup_ip` alias-cycle detection).
  - **Done**: replaced `HashSet` with bounded hop-limit loop (`for _ in 0..8`); real alias chains are ≤ 3 hops; no heap allocation.

- [x] **[HIGH]** Remove per-rule-eval `String` allocations in `services/rule/matching.rs` (L702 command join, L707 numeric `to_string`).
  - **Done**: added 5 `OnceLock<String>` fields to `AttemptDerived` (`process_command`, `process_id`, `user_id_text`, `dst_port_text`, `src_port_text`); `operator_operand_value` now returns `Cow::Borrowed` pointing into the OnceLock — each string is built at most once per connection across all rule evaluations.

- [x] **[HIGH]** Reduce verdict decision key allocation in `flows/verdict/verdict.rs` L105/L118/L141.
  - **Done**: replaced `DashMap<String, u64>` with `DashMap<u64, u64>`; `decision_key_hash()` uses `DefaultHasher` — eliminates one `format!` + two `to_owned()` allocations per connection decision.

- [x] **[HIGH]** Reduce `services/process/inspection.rs` L44 contention on `exit_deadlines` mutex under high churn.
  - **Done**: removed `cleanup_expired()` from the `inspect()` hot path; the background cleanup task (10 s interval) handles TTL-based eviction; hot path only acquires the mutex once for the `exit_deadline` check.

- [x] **[MEDIUM]** Use stack-allocated fixed buffers for eBPF key building in `services/connection/ebpf.rs` L73.
  - **Done**: `BpfKey { V4([u8; 12]), V6([u8; 36]) }` enum with `Deref/DerefMut → &[u8]`; wildcard + swap mutations use typed match arms.

- [x] **[MEDIUM]** Avoid per-event closure capture in `flows/kernel/kernel.rs` L56.
  - **Done**: `dispatch_kernel_pipeline_event` now accepts `counters: &Arc<KernelPipelineCounters>` + `pipeline: KernelPipeline` directly; on-drop counter call is inline, no per-event Arc clone or closure allocation.

- [x] **[MEDIUM]** Remove eager clone in `flows/verdict/verdict.rs` L589 before `ask_rule`.
  - **Done**: `pb_conn.get_or_insert_with(...).clone()` replaced with `pb_conn.take().unwrap_or_else(...)`; no backup proto copy held in pb_conn during the gRPC ask_rule round-trip.

- [x] **[LOW]** Cold-path improvements: parallel shutdown awaits in `workers/runtime/control/control.rs` L327; `Arc<StorageEvent>` broadcasting in `services/storage/event_bus.rs` L64.
  - **Done**: `join_all()` now uses `tokio::task::JoinSet` for concurrent task awaiting; broadcast channel carries `Arc<StorageEvent>` (one pointer clone per receiver instead of a full struct clone including PathBuf).

- [ ] **[MEDIUM]** Replace firewall drift-heal polling with event-driven triggers.
  - Current state: firewall watch worker `targets()` returns empty; drift detection relies on 20s timer loop in `workers/firewall/firewall_worker.rs` + config mtime polling in `services/config/storage.rs`.
  - Two complementary improvements:
    1. **Netlink nft event subscription**: subscribe to `NFNLGRP_NFTABLES` multicast group via `netlink-socket2` `MulticastSocketRaw.listen(7)` for near-instant drift detection when external tools modify nftables rules. No new deps needed (`libc::NFNLGRP_NFTABLES` + existing `netlink-socket2`). This would be a Rust extension beyond Go (Go uses ticker-based drift polling only).
    2. **Inotify on firewall config file**: wire firewall watch worker `targets()` to return the system firewall config path, using the existing generic inotify+epoll watch infra in `workers/runtime/watch/control.rs`. This matches Go's fsnotify behavior for config-file-driven reload.
  - Keep 20s drift-heal timer as a safety-net fallback even after event-driven triggers are added.
  - Adapter boundary: netlink event listener belongs in `platform/adapters/`; firewall watch worker consumes events via existing watch control surfaces.

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

- 2026-03-26: Full codebase rescan: Go/Rust parity audit (COMPATIBILITY.md updated with kernel self-check gap and firewall reload trigger model delta), DESIGN_RULES.md violation scan (3 items: lifecycle/runtime_lifecycle.rs missing, verdict Arc value-clone, API-surface density), hot/cold path optimization analysis (5 HIGH, 6 MEDIUM, 4 LOW items prioritized in PERF.md optimization backlog).  All findings tracked as actionable backlog items.
- 2026-03-26: Complete bpftool subprocess removal (db8970e follow-up): all bpftool-only code (`bpftool_list_maps`, `bpftool_lookup_owner`, `bpftool_lookup_owner`, `try_load_object_with_bpftool`, `is_already_pinned_error`, bpftool supervisor block, 9 `#[cfg(not(aya-ebpf))]`-gated helpers) deleted outright rather than left behind cfg gates.  `BpfProgram` struct removed from `models/ebpf_state.rs`.  `conn_pin_root`/`proc_pin_root`/`dns_pin_root` removed from `services/ebpf/ebpf.rs` (sole caller was bpftool loader).  `bpftool` removed from firewall preflight and smoke test fallback blocks.  623 lines deleted, 0 warnings, 425 passed.
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
- 2026-03-24: Added strict miss/default stats accounting mode for `nfqueue_overload_policy=drop-fast`: miss path now records `rule_misses` and verdict-based accepted/dropped without Go-style pessimistic drop bias; `fail-open` keeps Go parity accounting.
- 2026-03-24: Closed remaining SIEM/event-export parity gap: local `syslog` mode now uses system syslog writer semantics; event-export path parity with Go `log/loggers` + `statistics.OnConnectionEvent` is complete.
- 2026-03-24: Added runtime event-export logger hot-reload parity: `ConnectionEventLoggerAdapter` now refreshes sink workers from current config logger set during verdict-path emission without daemon restart.
- 2026-03-24: Added miss/default-action event export parity in `VerdictFlow`: miss paths now emit `ConnectionEventExporterPort` and stats backlog events with `rule=None` before applying default action.
- 2026-03-24: Implemented SIEM event-export baseline path in default runtime: concrete `ConnectionEventLoggerAdapter` wired into `VerdictFlow`, reconnect/backoff + `max_connect_attempts` behavior implemented, local sink fallback for empty `Server`, and formatter/sink tests added for JSON/CSV/RFC5424/RFC3164 over TCP/UDP.
- 2026-03-24: Added `daemon-rs/DOCS.md` and linked it in TODO `Documentation References`; aligned tracker rules so new canonical docs must be linked there.
- 2026-03-24: Privileged control boundary design finalized in `daemon-rs/DESIGN_RULES.md` (local owner-scoped path, remote capability-based authorization, `auth.*` rollout guard, and `UPDATE_*` naming).
- 2026-03-24: Backlog updated to keep Privileged Control Boundary Rule implementation as active future work.
- 2026-03-24: Older detailed documentation/design migration notes were swept from this tracker to keep TODO active-focused; refer to `git log -- daemon-rs/TODO.md` and canonical docs for historical detail.
