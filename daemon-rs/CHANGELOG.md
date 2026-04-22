# Daemon-RS Changelog

This changelog records release-level changes for the daemon-rs branch line.

Versioning baseline:
- `v0.1.0`
- `v0.1.1`
- `v0.2.0`
- `v0.3.0`
- `v0.4.0`
- `v0.5.0`
- `v0.5.1`

## [v0.5.1] - unreleased

### Added

### Changed
- **[CRITICAL] eBPF map owner lookup — aya-first**: `services/connection/ebpf.rs` fully
  migrated.  `list_bpf_maps()` uses `aya::maps::loaded_maps()` first; `lookup_bpf_owner()`
  uses a new `aya_lookup_bpf_owner()` helper that dispatches on key length (12 → v4,
  36 → v6) using typed `aya::maps::HashMap<_, [u8;N], [u8;16]>::try_from`.  `bpftool`
  fallback functions (`bpftool_list_maps`, `bpftool_lookup_owner`) fully removed (not
  gated — deleted).  Per-connection lookup is now ~1 µs (was 1–5 ms bpftool fork).
- **[CRITICAL] eBPF supervisor — aya-first**: `workers/runtime/ebpf/control.rs` — added
  `supervise_runtime_aya()` (dispatch via `loaded_programs()` + `loaded_maps()`) and
  `aya_inspect_and_prune_map<const N>()` (typed shard-pinned HashMap iteration + TTL
  prune).  Active under `#[cfg(feature = "aya-ebpf")]`; all bpftool helpers
  (`prune_map_entries`, `delete_map_key`, `extract_key_bytes`, `collect_u8_values`,
  `run_capture`, `run_json_capture`, `list_programs`, `list_maps`, `dump_map`),
  `try_load_object_with_bpftool`, `is_already_pinned_error`, the bpftool supervisor body
  in `supervise_runtime()`, and the `resolve_command_path` import fully removed.
  `ensure_ebpf_runtime_loaded()` body stripped to tracefs mount check only.
- **[HIGH] Smoke tests — bpftool blocks removed**: `aya_conn_trace.rs` and
  `aya_tunnel_trace.rs` — `map_id_by_name`, `map_dump_keys`, `map_has_entries`,
  `map_entry_count`: bpftool fallback blocks fully removed (replaced with trivial
  `Vec::new()` / `None` / `false` / `0` for non-aya builds); `value_to_bytes()` deleted;
  `#[cfg(not(feature = "aya-ebpf"))] use serde_json::Value` import removed.
- **[HIGH] libbpf-rs removed from default features**: `libbpf-ebpf` is now opt-in only
  (`--features libbpf-ebpf`); default build is aya-only with zero bpftool or libbpf
  subprocess dependency.
- **[HIGH] Process hash verdict safety**: `services/rule/matching.rs` — `SimpleHashOptional`
  dispatch in both the compiled path (`operator_matches_against_compiled`) and the
  uncompiled path (`operator_matches_against_with_derived`) now returns `false` (not
  `match`) when the process hash is `None`.  Connections where the hash is not yet
  available fall through to the default action instead of incorrectly matching a
  hash-based rule.
- **[HIGH] IMA fast-path for process hashing**: `services/process/details.rs` —
  `compute_process_hashes` now tries `read_ima_sha256_xattr` first: reads the
  `security.ima` xattr (type `0x03`, algo `4` = SHA-256), extracts the 32-byte SHA-256
  digest without a file read.  If IMA is present, only the file-read for MD5 + SHA-1 is
  needed (`compute_md5_sha1`); otherwise falls back to the full `compute_hashes_from_file`
  path.
- **[MEDIUM] DashMap — `pending_decisions` verdict epoch map**: `flows/verdict/verdict.rs`
  — `Arc<RwLock<HashMap<String, u64>>>` replaced with `Arc<DashMap<String, u64>>`.
  `begin_decision_epoch`, `is_decision_epoch_current`, and `end_decision_epoch` are now
  sync (no async lock acquire); check-and-insert in `begin_decision_epoch` is atomic via
  `DashMap::entry`.  Removes async lock overhead from the interactive AskRule verdict path
  under concurrent traffic.
- **[MEDIUM] DashMap — subscription per-id locks**: `services/subscription/subscription.rs`
  — `Arc<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>>` replaced with
  `Arc<DashMap<String, Arc<AsyncMutex<()>>>>`.  `per_sub_lock` now uses `DashMap::entry`
  directly; eliminates the outer mutex and the `"subscription locks poisoned"` panic path.
- **[CRITICAL] eBPF map owner lookup (earlier)**: `services/connection/ebpf.rs` — eliminated
  per-connection `bpftool` subprocess fork (was ~1–5 ms each).  Map-id enumeration now
  uses `libbpf-rs` `MapInfoIter` (or `aya::maps::loaded_maps()` for aya-only builds)
  and per-entry lookup uses `libbpf_rs::MapHandle::from_map_id` + `MapCore::lookup`
  directly, dropping to ~1 µs per call.  Map-id catalogue is refreshed every 30 s by
  a background tokio task.
- **[HIGH] IpAddr round-trip removed**: `resolve_owner_by_ebpf_map` now takes `IpAddr`
  directly (previously converted to `String` then re-parsed inside `bpf_map_name` /
  `build_bpf_key`).  Eliminates one format + one parse per connection on the eBPF path.
  Mixed-family (V4 src / V6 dst) handled via `to_ipv6_mapped()` instead of returning
  `None`.
- **[HIGH] Stats mutex sharding**: `StatsService::inner` (single `Mutex<StatsInner>`)
  split into two independent mutexes with a consistent acquisition order
  (events-state before breakdown):
  - `Mutex<BreakdownCounters>`: `on_connect_attempt`, `on_connection_metadata` — hot
    per-connection writes.
  - `Mutex<EventsState>`: `on_event`, ring-buffer maintenance — hot per-verdict writes.
  `snapshot()` and `apply_config()` acquire both; all other hot-path callers acquire
  only one, halving inter-worker contention.
- **[MEDIUM] `source_label` allocation-free on common paths**: return type changed from
  `String` to `Cow<'static, str>`.  The `fast-allow`, `fast-drop`, and `default` paths
  now return `Cow::Borrowed` (zero allocation); only rule-name paths allocate.
- **[MEDIUM] Rule name cloning eliminated**: `ActiveRuleCompiled.name` changed from
  `String` to `Arc<str>`; `VerdictReply.rule_name` changed to `Option<Arc<str>>`.
  Rule-name propagation from match → reply now clones an `Arc` (atomic refcount) instead
  of allocating a new heap `String`.
- **[MEDIUM] DNS lookup returns `Arc<str>`**: `DnsService::lookup_ip` changed from
  `Option<String>` to `Option<Arc<str>>`, avoiding a `.to_string()` clone on every
  connection that has a reverse-DNS entry.  `ConnectionContext.dst_host` updated to
  `Option<Arc<str>>`; DNS query fast-path converts via `Arc::from`.
- **[MEDIUM] Per-verdict log downgraded to `DEBUG`**: `flows/verdict/submit.rs` —
  changed `tracing::info!` for verdict replies to `tracing::debug!`, gated behind
  `tracing::enabled!(Level::DEBUG)` so `source_label` is not called at all when DEBUG
  is disabled.  Eliminates per-verdict log overhead in production INFO-level runs.
- **[MEDIUM] Process hash computation deferred**: `services/process/inspection.rs` +
  `details.rs` — initial process inspection (`inspect`, `sync_from_proc_event`) now
  returns `ProcessInfo` immediately with `process_hash* = None` via the new
  `inspect_process_no_hash` fast path.  A background `tokio::spawn` +
  `spawn_blocking(compute_process_hashes)` task patches the cache entry when hashes
  are ready, unblocking hash-based rule matching on the second connection from the
  same process.
- **[MEDIUM] ArcSwap — `bpf_map_snapshot`**: `services/connection/connection.rs` /
  `ebpf.rs` — `Arc<RwLock<HashMap<String, u32>>>` replaced with
  `Arc<ArcSwap<HashMap<String, u32>>>`.  The hot per-connection eBPF map-name lookup
  (`ebpf.rs`) is now a lock-free atomic load (`snapshot.load().get(...)`).  Background
  30 s refresh publishes a new map via `store(Arc::new(new_map))`; readers are never
  blocked.
- **[MEDIUM] ArcSwap — `interface_name_cache`**: `platform/adapters/net_iface.rs` —
  static `RwLock<HashMap<u32, String>>` replaced with `ArcSwap<HashMap<u32, String>>`.
  `interface_name_by_index` (called on every incoming packet) reads with a lock-free
  load; cache-miss refresh uses `store(Arc::new(refreshed_map))`.
- **[MEDIUM] DashMap + lazy TTL — `requeue_aliases`** (nfqueue): `platform/ffi/nfqueue.rs`
  — `Mutex<HashMap<u64, RequeueAlias>>` replaced with `DashMap<u64, RequeueAlias>`.
  O(n) `prune_requeue_aliases` scan moved to `remember_requeue_alias` only (cold write
  path); `claim_requeue_alias` (hot repeat-queue callback path) is now O(1): atomic
  `DashMap::remove` + single TTL check, no scan.
- **[MEDIUM] DashMap — `StorageEventBus` path/prefix maps**: `services/storage/event_bus.rs`
  — both `path_tx` and `prefix_tx` changed from `Arc<Mutex<HashMap<PathBuf, Sender>>>` to
  `Arc<DashMap<PathBuf, Sender>>`.  `emit()` for a rule-batch now acquires only the per-
  path DashMap shard, releasing it before calling `send()`; concurrent events for
  different paths no longer serialize behind a single global `Mutex`. Eliminates tail
  latency spikes when a storage worker emits many rule-file events in bulk.
- **[MEDIUM] ArcSwap — `DualLayerLruMap`/`SyncDualLayerLruMap` snapshot layer**:
  `utils/lru_cache.rs` — snapshot field changed from
  `Arc<RwLock<Arc<HashMap<K, V>>>>` to `Arc<ArcSwap<HashMap<K, V>>>` for both async
  (`DualLayerLruMap`) and sync (`SyncDualLayerLruMap`) variants.  `get_snapshot()` (called
  on every cache `get()`) is now a lock-free `load_full()`; all `publish_*` writers use a
  `load_full()` → clone → mutate → `store(Arc::new(next))` pattern, removing the write
  guard entirely from the publish hot path.
- **[MEDIUM] `quick-cache` replaces `lru` — dual-layer cache eliminated**:
  `utils/lru_cache.rs` fully rewritten; `lru = "0.16"` removed and `quick_cache = "0.6"`
  added.  `DualLayerLruMap<K,V>` and `SyncDualLayerLruMap<K,V>` are now type aliases for
  `ConcurrentLruCache<K,V>`, a `Arc<quick_cache::sync::Cache<K,V>>` wrapper.  The
  entire dual-layer split (`mutable` write-lock slab + `snapshot` ArcSwap publish
  machinery) is gone: `insert`, `remove_by`, `clear`, and `set_capacity` are now
  synchronous and lock-free under the shard-level sharding of `quick_cache`.  All
  callers in `dns/cache_ops.rs`, `dns/runtime_lifecycle.rs`, `process/inspection.rs`,
  `process/cache.rs`, and test support updated to drop all `await` call-sites.
  `DualLayerMetricsSnapshot` simplified to `{hits, misses}` from a 9-field struct;
  `stats.rs` updated accordingly.  Eviction semantics use quick_cache's Hot/Cold
  approximate eviction; bounded-capacity tests updated to drop oldest-item-specific
  assertions (which relied on strict FIFO order) and retain only `len ≤ capacity` bounds
  checks.
- **[MEDIUM] Test isolation — `PolicyTxCoordinator::new(PathBuf)` + `RuleCommandService`
  restructure**: `services/policy_tx/policy_tx.rs` — explicit `new(base_dir)` constructor
  added so tests can inject a `TestDir` path rather than relying on the global
  `/tmp/opensnitchd-rs/` path (which broke after prior root daemon runs).
  `commands/rule/rule.rs` — `RuleCommandService` changed from a ZST to a struct holding
  a `PolicyTxCoordinator` field; `Default` uses `global_policy_tx().clone()`;
  `with_base_dir(PathBuf)` constructor added under `#[cfg(test)]`.  Fixes 8 previously
  failing `policy_tx` and `rule_command` tests.
- **[LOW] Semver normalization — all Cargo.toml manifests**: all direct-dependency
  version strings normalized from exact `x.y.z` pins to proper semver range specifiers
  (`"1"` for stable 1.x crates, `"0.x"` for pre-1.0 crates).  Lockfile updated via
  `cargo update` picking up: `aho-corasick 1.1.4`, `aws-lc-rs 1.16.2`,
  `globset 0.4.18`, `hyper-util 0.1.20`, `regex 1.12.3`, `rustix 1.1.4`,
  `tower 0.5.3`, `zerocopy 0.8.47`, and other patch updates.  `sha2`/`sha1`/`md-5`
  intentionally kept at `"0.10"` — sha2 0.11.0 (2026-03-25) requires `digest 0.11`
  with breaking API changes.
- **[MEDIUM] `quick_cache::Weighter` — byte-budget process cache**: `ConcurrentLruCache`
  made generic over `W: Weighter<K, V>` (defaults to `UnitWeighter`); a
  `with_weighter(weight_capacity, estimated_items, weighter)` constructor added using
  `OptionsBuilder` + `Cache::with_options`.  `ProcessInfoWeighter` implemented in
  `services/process/cache.rs`: uses O(1) `.len()` heuristics (`env_map.len() * 64 +
  args.len() * 48 + parent_chain.len() * 64 + path.len() + 512`) to estimate per-entry
  heap footprint.  `ProcessCache` created via `with_weighter` with budget
  `PROCESS_INFO_CACHE_CAPACITY * ESTIMATED_BYTES_PER_ENTRY (4096)`, preventing a small
  number of processes with oversized `env_map` from exhausting the cache budget.  DNS,
  connection, and inode caches retain `UnitWeighter` — their value types have uniform,
  bounded size.  Eviction bound test updated: probe entries now include ~60 env vars
  (≈ `ESTIMATED_BYTES_PER_ENTRY`) to produce representative weight in the byte budget.

- **[HIGH] Hot-path optimization — owner resolution, DNS, rule matching, verdict, inspection**:
  - `services/connection/owner.rs`: extracted `pid_owns_inode_at(inode, &Path)`; fallback
    /proc scan pre-allocates one `PathBuf::with_capacity(24)` reused across all candidate
    pids via `push`/`clear` — eliminates one `format!("/proc/{pid}/fd")` heap allocation per
    candidate pid during owner fallback.
  - `services/dns/cache_ops.rs`: `lookup_ip` alias-cycle guard changed from per-call
    `HashSet<Arc<str>>` to a bounded hop-limit iteration (`for _ in 0..8`); real chains are
    ≤ 3 hops, no heap allocation.
  - `services/rule/matching.rs`: `AttemptDerived` gains 5 `OnceLock<String>` fields
    (`process_command`, `process_id`, `user_id_text`, `dst_port_text`, `src_port_text`);
    `operator_operand_value` returns `Cow::Borrowed` pointing into the locks — each string
    is built at most once per connection across all rule evaluations (was one alloc per
    rule per connection).
  - `flows/verdict/verdict.rs`: `pending_decisions` changed from `DashMap<String, u64>` to
    `DashMap<u64, u64>`; `decision_key_hash()` uses `DefaultHasher` — eliminates one
    `format!` + two `to_owned()` allocations per decision.  `conn_for_ui` construction
    changed from `get_or_insert_with().clone()` to `take().unwrap_or_else()` — no backup
    proto copy kept in `pb_conn` during the gRPC `ask_rule` round-trip.
  - `services/process/inspection.rs`: `cleanup_expired()` removed from the `inspect()` hot
    path; background cleanup task (10 s interval, unchanged) handles TTL-based eviction;
    inspection path reduces to a single `exit_deadline` mutex acquire per cache miss.
- **[MEDIUM] Hot-path optimization — eBPF key and kernel dispatch**:
  - `services/connection/ebpf.rs`: `build_bpf_key` return type changed from `Option<Vec<u8>>`
    to `Option<BpfKey>` where `BpfKey { V4([u8;12]), V6([u8;36]) }` is stack-allocated;
    `Deref/DerefMut → &[u8]` lets `lookup_bpf_owner` call-site coerce without change;
    wildcard and swap mutations use typed match arms replacing runtime `.len()` checks.
    Eliminates two 12–36 byte heap allocations per eBPF owner resolution.
  - `workers/runtime/kernel/dispatch.rs`: `dispatch_kernel_pipeline_event` generic `F:
    FnMut() -> u64` on-drop closure parameter replaced with `counters:
    &Arc<KernelPipelineCounters>` + `pipeline: KernelPipeline`; eliminates one Arc clone
    and one closure allocation per dispatched kernel event.
- **[LOW] Cold-path: parallel shutdown, Arc event broadcast**:
  - `workers/runtime/control/control.rs`: `join_all()` now awaits all spawned tasks
    concurrently via `tokio::task::JoinSet`; tasks already stopped do not delay others.
  - `services/storage/event_bus.rs`: broadcast channel carries `Arc<StorageEvent>`; each
    subscriber now receives an Arc clone (one atomic increment) instead of a full struct
    clone including `PathBuf`.

### Fixed
- **[HIGH] Complete bpftool subprocess removal** (db8970e follow-up): `bpftool` is not
  a standard tool on Alpine Linux, OpenWrt, and other minimal distros.  All remaining
  bpftool code that was guarded behind `#[cfg(not(feature = "aya-ebpf"))]` gates rather
  than deleted has now been fully removed:
  - `models/ebpf_state.rs`: `BpfProgram` struct deleted (bpftool-path only).
  - `services/ebpf/ebpf.rs`: `conn_pin_root`, `proc_pin_root`, `dns_pin_root` removed
    (sole caller was the bpftool eBPF object loader).
  - `tests/firewall/gates.rs`: `bpftool` removed from the required-tool preflight array.
  - Net: 623 lines deleted; zero warnings; 425 tests passed.

### Notes
- **eBPF library policy**: aya is the sole default eBPF runtime; `libbpf-ebpf` is opt-in
  only; `bpftool` subprocess usage is fully and completely eliminated — no bpftool code
  remains in the codebase under any cfg gate.
- **Process hash safety**: no-hash verdict outcome is now consistently `false` (do not
  match → fall through to default action) across all matching paths.
- **Concurrent-map migration complete**: all evaluated surfaces resolved —
  `pending_decisions` and subscription `locks` → `DashMap`;
  `bpf_map_snapshot`, `interface_name_cache` → `ArcSwap<HashMap>`;
  `DualLayerLruMap`/`SyncDualLayerLruMap` → `quick_cache::sync::Cache` (dual-layer
  eliminated entirely, `lru` crate removed);
  `requeue_aliases` → `DashMap` with O(1) claim;
  `StorageEventBus` path/prefix maps → `DashMap`.
- **Stats exporter moved to Future enhancements**: `StatsExporterPort` extension point
  and `StatsFlow` hook are already wired; concrete Prometheus/push-style adapter
  implementations deferred to a dedicated future feature.

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
- CLI flag parity with Go daemon: `--rules-path`, `--config-file`, `--ui-socket` parsed
  from `std::env::args()` in `main.rs` without any additional dependency.  Mirrors the
  Go daemon's `flag.StringVar` surface (`daemon/main.go`).
  - `--rules-path <dir>`: overrides the rules directory after config load, matching Go's
    post-load `rules.Reload(rulesPath)` behaviour.
  - `--config-file <path>`: highest-priority config file path, above
    `OPENSNITCH_CONFIG_FILE` env var and default search locations.
  - `--ui-socket <addr>`: UI gRPC address, same surface as `OPENSNITCH_CLIENT_ADDR` env var.
- `daemon::CliOverrides` struct threaded through `Daemon::start` → `bootstrap`.
- `Config::load_from_default_locations_with_override(cli_path)` and
  `Config::with_rules_path_override(path)` builder methods in `config.rs`.
- Live-test rules isolation: `create_live_test_rules_dir` in
  `crates/tools/src/live_logs.rs` copies only the loopback-allow rules from
  `daemon/data/rules/` to a temp dir and passes them via `-- --rules-path <dir>` in
  `cargo run`.  Replaces the previous `OPENSNITCH_CONFIG_FILE` temp-config approach
  with the new CLI flag.
- Mock UI (`mock_ui_client.py`) AskRule round-trip exercised end-to-end: real TCP SYNs to
  RFC 5737 TEST-NET addresses (`192.0.2.1`, `198.51.100.1`) are intercepted by nfqueue,
  routed to `AskRule`, receive alternating allow/deny verdicts (rules with `dest.ip`
  operator), and the resulting `CHANGE_RULE_FROM_ASK` notification is correlated back to
  the daemon.  Live session score: 17/17 PASS.
- `_ASK_RULE_EXPECTED_DSTS` module-level constant in `mock_ui_client.py`: background
  (non-TEST-NET) `AskRule` calls are silently allowed to preserve machine connectivity
  during isolated-rules test runs.

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
- `Daemon::start` signature updated from `()` to `CliOverrides`.
- `Config::load_from_default_locations` now delegates to
  `load_from_default_locations_with_override(None)` to eliminate duplication.
- `parse_cli_overrides()` supports both `--flag value` and `--flag=value` forms.
- `mock_ui_client.py` phase-1 break condition: exits the acknowledgement polling loop
  when only the `LOG_LEVEL` notification remains unacknowledged (late-arriving ack no
  longer blocks the loop).
- `mock_ui_client.py` Notifications stream: removed all `yield NONE` keepalives (action
  value `0` is interpreted by the daemon as a stream-close request); phase-2 handler now
  issues an explicit `return` after printing the recap to close the stream gracefully.
- `proto/Makefile`: added `subscriptions_pb2.py` / `subscriptions_pb2_grpc.py` /
  `subscriptions_pb2.pyi` build target and corresponding `clean` entries; `all` target
  updated to include the new artifact.
- `DOCS.md` mock-ui session description expanded to list all validated handshake markers
  (`Subscribe`, `Ping`, `PingStats`, `Notifications`, `NotificationCommandReply(LOG_LEVEL)`).
- `daemon-rs/crates/tools/Cargo.toml`: added `subscriptions` feature flag scaffold.
- `cargo ost` live daemon flags: `--rules-path=PATH`, `--config-file=PATH`, and
  `--ui-socket=PATH` added to `cli.rs` (`apply_value_flag` + help text).  These set
  `OPENSNITCH_DAEMON_RULES_PATH`, `OPENSNITCH_DAEMON_CONFIG_FILE`, and
  `OPENSNITCH_DAEMON_UI_SOCKET` / `OPENSNITCH_MOCK_UI_SOCKET` respectively.
  `launch_daemon_live_logs` in `live_logs.rs` now reads these env vars and forwards them
  as `--rules-path`, `--config-file`, `--ui-socket` to the daemon binary.  The default
  isolated rules dir is still created automatically when `--rules-path` is not provided.
- `daemon/cmd/gotools`: same `--rules-path`, `--config-file`, `--ui-socket` flags added
  to `applyValueFlag` and `forwardedEnvKeys`; help text updated.  The env vars are
  forwarded across any sudo/pkexec re-exec so they reach any daemon subprocess a Go test
  may launch.
- `daemon-rs/data/init/opensnitchd-rs.service.in`: templated systemd unit for
  `opensnitchd-rs`.  Uses `Type=notify` (matches the daemon's `sd_notify` integration:
  `READY=1` on startup, `RELOADING=1`/`READY=1` on SIGHUP, `STOPPING=1` on shutdown),
  `ExecReload=/bin/kill -HUP $MAINPID` for live-config-reload, and a capability set
  (`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`, `CAP_BPF`, `CAP_PERFMON`,
  `CAP_SYS_ADMIN` for pre-5.8 kernels) with hardening directives.  Placeholders
  `@PREFIX@` and `@SYSCONFDIR@` substituted via `sed` at install time.
- `daemon-rs/data/init/opensnitchd-rs.openrc.in`: templated OpenRC init script for
  Alpine Linux and other non-systemd distros.  Uses `start-stop-daemon` with a pid file,
  `reload()` sends SIGHUP (matching the daemon's live-reload path), and `start_pre()`
  enforces correct ownership/permissions on the config and socket directories.  Same
  `@PREFIX@`/`@SYSCONFDIR@` substitution as the systemd template.
- `daemon-rs/data/init/opensnitchd-rs.procd.in`: templated procd init script for
  OpenWrt.  Uses `USE_PROCD=1` / `procd_open_instance` with `respawn`, `reload_signal
  HUP`, `file` config tracking, and `service_triggers` for network-up reload.  Adds
  `@BINDIR@` placeholder (rendered as `sbin` for OpenWrt) alongside `@PREFIX@` and
  `@SYSCONFDIR@`.  procd does not forward `NOTIFY_SOCKET`; the daemon's existing
  log-based lifecycle fallback activates automatically.
- `Makefile` `install-rs`: init system detection added; probes `/run/systemd/private`
  for systemd and `/run/openrc` / `openrc-run` for OpenRC; falls back to `none` (binary
  + config only).  Override with `INIT_SYSTEM=systemd|openrc|procd|none`.  Added
  `BINDIR` variable (default `bin`; set to `sbin` for OpenWrt).  `systemctl
  daemon-reload` is skipped when `DESTDIR` is set (staging builds).  `PREFIX` defaults
  to `/usr/local`; packagers use `PREFIX=/usr SYSCONFDIR=/etc DESTDIR=<staging>`;
  OpenWrt packagers use `PREFIX=/usr BINDIR=sbin CARGO_PROFILE=release-embedded INIT_SYSTEM=procd DESTDIR=<staging>`.
- `daemon-rs/Cargo.toml`: added `[profile.release-embedded]` inheriting from `release`
  with `opt-level = "z"`, `lto = true` (fat), `codegen-units = 1`, `strip = "symbols"`,
  `panic = "abort"` — targets constrained/embedded deployments (OpenWrt/musl).  The
  default `release` profile (`lto = "thin"`) is unchanged to preserve hot-path
  performance and parity harness baselines.  Build with
  `cargo build --profile release-embedded -p opensnitchd-rs`.
- `Makefile`: added `CARGO_PROFILE` variable (default `release`); `install-rs` now
  resolves the binary via `DAEMON_RS_CARGO_TARGET_DIR` (default `target-kernel`) and an
  optional `CARGO_TARGET_TRIPLE` segment so the path always matches what `daemon-rs-build`
  produced.  Short lowercase Make aliases added (`profile=`, `target=`, `rounds=`,
  `repeats=`, `rust_log=`, `go_log=`, `live_log=`, `pressure_secs=`, `sweep_secs=`,
  `smoke_timeout=`, `toolchain=`, `ebpf_target=`, `priv_cmd=`, `prefix=`, `sysconfdir=`,
  `bindir=`).
- `Makefile`: `export` block bridges all Makefile variable names to their
  `OPENSNITCH_*` env counterparts so recipe lines no longer need per-target `KEY=$(VAR)`
  prefixes; all parity/harness/go-test recipe lines simplified to bare `$(DAEMON_RS_TOOLS_RUN) <cmd>`.
- `cargo ost build` / `build-all`: added `--profile=PROFILE` (`OPENSNITCH_BUILD_PROFILE`,
  default `release`) and `--target=TRIPLE` (`OPENSNITCH_BUILD_TARGET`) flags.  Both
  commands now pass `--profile` and optionally `--target` to Cargo, replacing the
  hardcoded `--release`.  `daemon-rs-build` Makefile target forwards
  `OPENSNITCH_BUILD_PROFILE=$(CARGO_PROFILE)` and `OPENSNITCH_BUILD_TARGET=$(CARGO_TARGET_TRIPLE)`
  so the full build+install flow is driven by a single consistent variable pair.
- `build_cmds.rs`: `build_profile()` helper reads `OPENSNITCH_BUILD_PROFILE` with
  empty-string guard (defaults to `release`).

### Fixed
- `.gitignore`: added `ui/opensnitch/proto/subscriptions_pb2.py`,
  `subscriptions_pb2_grpc.py`, and `subscriptions_pb2.pyi` to ignore list alongside
  existing `ui_pb2*` entries so generated proto artifacts are not tracked by git.

- `inotify` watch thread was sleeping 50 ms on `EWOULDBLOCK` (non-blocking fd, nothing
  to read) before retrying `read()`.  This added up to 50 ms latency per
  `wait_until_rule_count` barrier in the cold-path parity harness and in production rule
  reload paths.  The thread now opens an `epoll` descriptor, adds the inotify fd with
  `EPOLLIN`, and calls `epoll_wait` with a 10 ms timeout instead — reacting to file
  events in effectively zero time.  Cold-path rule reload delta in the parity harness
  improved from +50 ms to +12 ms (Go 0.101 s → Rust 0.112 s).
- `RuleWatchControl::scan()` was re-reading every JSON rule file on every scan tick
  (every 2 s poll interval and every inotify event) purely to collect list directory
  paths for mtime tracking.  The in-memory snapshot's `rules: Vec<RuleRecord>` already
  holds the same operator data.  The new `snapshot_list_dirs` helper derives list dirs
  from the snapshot; the new `read_rules_dir_file_state_with_hint` scan variant uses it,
  eliminating N async JSON reads per scan pass.  The full-directory reload on change
  detection is unchanged.
- `GenericWatchWorkerControl` used two async tasks separated by a channel: a trigger
  task (inotify/poll) and a scan task (executes `spec.scan()`).  The channel hop added
  latency on every event.  The scan task is removed; the trigger task now calls
  `spec.scan()` directly in its callback — matching Go's `liveReloadWorker` pattern
  where the goroutine receiving the fsnotify event executes the handler inline.
  Coalescing is preserved: the trigger loop calls the callback once per iteration and
  inotify events accumulate while scan runs.
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
- Parity harness `wait_until_rule_count` / `waitForRuleCount` poll interval tightened
  from 50 ms to 5 ms in both the Rust and Go cold-path tests.  With epoll delivering
  inotify events near-instantly the 50 ms interval was the dominant term in the
  measured `cold-profile component=rule elapsed_s`, masking actual reload latency with
  poll-tick jitter.  After: Go ~0.010 s, Rust ~0.021 s — stable, comparable measurements.
- Firewall drift-heal loop behavior after backend-toggle churn: recovery now validates post-reload convergence and applies bounded retry backoff when interception rules remain invalid.
- Warning profile cleanup for touched slices: removed dead helper code where not needed
  and kept explicit `#[allow(dead_code)]` only for intentional compatibility/API
  placeholders (`Config::load_from_default_locations`,
  `RuleService::collect_rule_list_dirs`,
  `RuleService::read_rules_dir_file_state_async`).

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
