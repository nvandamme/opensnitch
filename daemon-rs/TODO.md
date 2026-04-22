# Daemon-RS Unified Tracker

This is the single tracker file for backend parity, async/runtime hardening, and future enhancements.

It supersedes:
- `daemon-rs/FEATURE_PARITY.md`
- `daemon-rs/SERVICE_ASYNC_AND_MODEL_SCAN_2026-03-15.md`

Last update: 2026-03-23 (entry 459)

## Scope

Track parity and runtime behavior between:
- Go backend: `daemon/`
- Rust backend: `daemon-rs/crates/daemon/`

Out of scope for now:
- Replacing NFQUEUE verdicting with a non-FFI backend.
- Replacing `libbpf-rs` usage with a full Aya runtime path as default.
- Replacing proc connector path with a high-level netlink crate.

## Design Rule: Domain Boundary + Trait-First Architecture (Tracking)

This is the architectural rule for ongoing refactors in `daemon-rs/crates/daemon/`.
This section is the single source of truth for design rules; other sections may only reference these rules and must not redefine them.

1. Domain boundaries own behavior and runtime state
- Runtime orchestration/state should live in the owning domain/service boundary (connection/process/dns/firewall/tasks/commands), not in root wiring.
- Daemon root should orchestrate wiring and lifecycle, not encode domain behavior.
- `intent` is an architectural term for ownership/responsibility, not a symbol naming convention: do not encode it into type names, method names, or module names unless it adds concrete semantic value beyond the domain/service role itself.
- Domain behavior should stay where it is clearest (often in `services/<service>/<service>.rs`), and should not force a dedicated `intent.rs` file or `*Intent*` symbols.
- Boundaries should be `trait-first` where polymorphism is needed: stateful runtime/domain structs implement explicit traits/ports instead of relying on closure aliases.
- Long-lived service runtime control must use a trait-based lifecycle surface (`init/start/pause/resume/stop/reload/quiesce/drain/health_check/status/reset`) instead of global mutable singleton functions.
- Service observability should use lifecycle-provided subscriptions (`subscribe_status` via watch channel + `subscribe_events` via broadcast channel), not dedicated per-service monitor threads hidden inside trait internals.
- Subscription lifecycle should support explicit subscribe/unsubscribe hooks through scoped subscription handles (drop-based unsubscribe) and expose active subscriber counters via lifecycle monitor stats.
- Avoid top-level module free functions for stateful boundary behavior; prefer methods on domain/runtime structs.
- Enforce generics-first helper design for shared cross-domain logic when it improves reuse without hiding domain semantics or reducing readability.
- Shared functions that do not have clear domain ownership must be migrated to `utils/`; these helpers should be generic by default when type-safe and maintainable, rather than service-specific duplicates.
- Arc read cloning is evil at runtime: snapshot reads in runtime/hot paths must be pure Arc memreads over immutable snapshots, with no mutex/lock path, no async getter wrappers, and no clone-at-read call sites.
- Extend this philosophy to all immutable state access (state/cache/snapshot): when read-only data can be held as immutable shared state, prefer lock-free sync memread access and avoid async getter wrappers in runtime paths.
- API naming must express domain semantics, not ownership/copy mechanics: avoid implementation-leaking suffixes like `_cloned`, `_copy`, `_arc`; use semantic names (`get`, `peek`, `snapshot`, etc.) and let callers clone only where ownership requires it.
- Helper design rule (utils/helpers):
  - avoid one-line passthrough wrappers that only rename or forward a single call without adding domain semantics, invariants, or error-context value,
  - avoid compatibility shims/aliases; when call sites are migrated, remove legacy helper wrappers in the same slice.

2. Trait-first integration boundaries
- Infra integrations must be consumed through `platform::ports::*` traits.
- `platform::adapters::*` and `platform::ffi::*` are implementation details behind those traits.
- Application/services/flows/workers should depend on ports, not concrete adapters/ffi modules.

3. Module structure follows architecture
- Domain code: services/flows/models and other domain-owned boundary modules when they add concrete semantic value.
- Infra code: `platform/{ports,adapters,ffi}`.
- Helpers only in `utils/`; integrations are not `utils`.
- Data contract ownership rule:
	- Shared data contracts must live under `models/` (or `models/<domain>/` when present), including:
		- DTO-like structs/enums passed across service/flow/worker boundaries,
		- serde-backed payload/config/transport structs,
		- reusable runtime memory/state snapshot structs consumed by more than one domain.
	- Data contracts may implement shape-consistency helpers (for example parsing/validation/normalization) when these functions only enforce or preserve contract invariants.
	- Keep data-contract helpers side-effect free: no cross-domain orchestration, IO, or runtime ownership inside `models/` contract impls.
	- Keep file-local/private execution helpers near usage only when they are not cross-boundary contracts.
	- When touching a module with contract drift, prefer migrating contract types to `models/` in the same slice or add an explicit follow-up entry.
- Worker layout decision: keep `src/workers/` as the runtime execution layer (shared worker contracts, lifecycle helpers, daemon wiring touchpoints), but organize worker implementations by domain/service subfolders for clarity.
- Avoid splitting worker ownership across both `services/*` and `workers/*` for the same concern at the same time; pick one location per worker family and keep imports stable per refactor slice.
- Worker ownership rule:
	- `workers/` owns reusable execution primitives (long-running loops, queue consumers/producers, watcher engines, OS/FFI adapters, backpressure/retry mechanics),
	- workers should be policy-agnostic where possible and expose small control/port surfaces.
- `services/` layout rules:
  - one folder per service (`services/<service>/`), no `*_service` suffix in folder names,
  - `services/<service>/mod.rs` stays thin (module wiring/re-exports only),
  - concrete implementation lives in `services/<service>/<service>.rs`,
  - avoid feature-split file churn: if a service is understandable as one unit, prefer co-locating runtime orchestration in `<service>.rs` instead of forcing `intent.rs` or `*Intent*` naming,
  - service-internal split parts live in service submodules/files (not as root-level service files),
  - UI-facing gRPC client/session concerns live under `services/client` (`Client`, notification stream, UI session state).
- `mod.rs` linker-only rule:
	- `mod.rs` files are module wiring surfaces only (module declarations + re-exports),
	- functional code (`struct`/`enum`/`impl`/runtime logic) belongs in dedicated sibling files,
	- apply this consistently to `services/*`, `commands/*`, `flows/*`, and `workers/*` as those areas are touched.
- `commands/` contains mapping only:
  - gRPC command mappings,
  - daemon terminal/CLI command mappings,
  - high-level IPC command mappings.
- `commands/` should not contain long-lived runtime state or service orchestration.
- `flows/` is the hot-path caller-orchestration layer:
	- flow modules coordinate service and worker callers for latency-sensitive runtime paths,
	- daemon root should prefer wiring/spawn only and delegate per-path orchestration loops to flows,
	- flow boundaries must consume services/workers through explicit ports/traits where polymorphism is needed,
	- flows own decision/policy orchestration (routing, fallback choice, sequencing, cross-service composition),
	- when flow internals become generic/reusable execution machinery, extract those internals into `workers/` and keep only orchestration policy in `flows/`,
	- `flows/<domain>/mod.rs` stays linker-only; functional code lives in dedicated sibling files.

Flow-vs-worker extraction heuristic:
- Keep in `flows/` when logic answers "what should happen" (policy/decision path, domain orchestration, cross-service sequencing).
- Move to `workers/` when logic answers "how to run repeatedly" (generic loop engine, batching/drain mechanics, retry/backoff, channel pump, OS event polling).
- If a flow loop is specific to one domain but has reusable sub-mechanics, split the mechanics into `workers/runtime/*` helper(s) and keep the domain policy path in `flows/<domain>/*`.
- Runtime control stance for connect/kernel:
	- keep `connect` and `kernel` as flow-owned task orchestration (no dedicated `WorkerControl` implementations yet),
	- reconsider `WorkerControl` adapters only if explicit start/stop/probe lifecycle commands are required for those domains.
- `commands/<domain>/mod.rs` must remain linker-only; implementations live in `commands/<domain>/<domain>.rs`.
- API-surface file rule (services/flows/commands):
	- Main domain file (`services/<name>/<name>.rs`, `flows/<name>/<name>.rs`, `commands/<name>/<name>.rs`) should expose public API and orchestration entrypoints only.
	- Non-API implementation details (helpers, worker control structs, parsing/state utilities, internal execution logic) must live in domain-specific sibling files (`storage.rs`, `runtime.rs`, `parsing.rs`, `internal.rs`, etc.).
	- Keep exported signatures stable in main files; move implementation by delegation to sibling modules.
	- Exception: keep tiny modules in one file when extraction would create trivial indirection (document rationale in review/entry notes).

4. Refactor safety rule
- Prefer extraction via stable wrappers first, then collapse wrappers in a second pass.
- Do not keep compatibility shims once call sites are migrated in the same refactor slice (including one-line helper aliases kept only for transitional naming).
- Keep behavior parity first; run `cargo check`/tests each slice.

5. Cache selection rule (dual-layer policy)
- Dual-layer cache (`DualLayerLruMap` / `SyncDualLayerLruMap`) is preferred by
  default for read-dominant, shared runtime caches where lock-free immutable
  snapshot reads are important and eventual recency convergence is acceptable.
- Dual-layer is not mandatory for every cache: choose plain `LruCache` or plain
  map-based cache when caller profile is write-heavy/high-churn, strict
  mutation/recency semantics are required, or ownership is local/ephemeral.
- Capacity and rollout guidance for dual-layer-backed caches:
  - tune capacity with publish cost in mind (snapshot publish work scales with
    live entry count),
  - avoid broad dual-layer rollout to high-churn writers until publish-path
    optimization and metrics instrumentation are in place,
  - keep domain-level capacity tunables explicit and documented when dual-layer
    is selected.
- Required observability for dual-layer evolution:
  - expose touch-drop rate / touch-queue pressure signals,
  - expose publish-path cost signals (latency and allocation/churn-oriented
    counters) for regression tracking.
- Caller-class matrix (keep updated as cache-bearing domains change):

| Cache caller class | Read/Write profile | Concurrency/ownership | Semantics tolerance | Preferred implementation |
|---|---|---|---|---|
| DNS shared lookup cache | read-heavy with periodic writes | shared across runtime paths | eventual recency acceptable | dual-layer |
| Process inspection cache | read-heavy with mutation side bookkeeping | shared service cache | eventual recency acceptable; strict coherence guarded by service checks | dual-layer + dedicated mutable side-state |
| Connection owner PID caches | read-heavy with moderate writes | shared sync runtime access | eventual recency acceptable | sync dual-layer |
| Write-heavy churn cache (generic) | write-heavy/high churn | any | strict recency/mutation visibility required | plain LRU or plain map |
| Local ephemeral cache (generic) | mixed/local | single owner or short-lived scope | no shared snapshot requirement | plain LRU or plain map |

## Current Status Snapshot

- Baseline parity reference: commit tag "release: prepare v0.1.0" is treated as the basic functional parity-aligned release baseline (without full functional eBPF module parity).
- Latest parity scan status: no open backend parity gaps in the scanned slice.
- Async/runtime hardening status: all high-priority 2026-03-15 verdict-path items are implemented.
- Test baseline after latest runtime changes: `cargo test -p opensnitchd-rs` passes (392/392 + 8 ignored); nfqueue_netlink_adapter suite contributes 18 new tests.
- Latest full-suite verification status: `sudo make go-test-full` and `make parity-hot-cold-matrix STRESS_ROUNDS=500` both passed on 2026-03-16 with no new Go-vs-Rust parity drift identified in the follow-up inventory pass.
- Root orchestration now auto-restores `daemon/ui/testdata/default-config.json` after full Go and cold-path parity runs so the Go UI reload test no longer leaves the worktree dirty.
- Rust parity-heavy tests now have a reusable tracing bootstrap via `utils::test_support::init_test_logging()` so reload/runtime tests can emit inspectable logs similar to Go's verbose test flows.
- Rust now parses and applies Go logging config fields (`LogUTC`, `LogMicro`, `Server.LogFile`, `Server.Loggers`) and supports active file/UDP sink routing through the daemon logging subsystem.
- DNS worker now includes a direct systemd-resolved varlink socket monitor path (`/run/systemd/resolve/io.systemd.Resolve.Monitor`) with `resolvectl monitor` fallback for compatibility.
- Detailed performance run history, hot/cold deltas, and harness notes are maintained in `daemon-rs/PERF.md`.

## Perf Regression Baselines (Machine-Readable)

Perf regression baselines and run-history details are maintained in `daemon-rs/PERF.md`.
TODO no longer carries machine-readable perf baseline keys.

## Active Backlog

1. eBPF backend evolution
- [x] Add optional `aya-ebpf` implementation path as a high-level replacement candidate for current `libbpf-rs` integration.
  - Completed (entry 441): optional Aya feature and runtime backend selection/fallback wiring are in place (`Cargo.toml` feature gate + eBPF runtime fallback chain + runtime-mode tests).
- [x] Provisional policy: prefer Aya backend by default, keep libbpf as automatic fallback until Aya path reaches runtime parity.
  - Completed (entry 442): parity cross-check aligned Rust Aya attach specs and runtime flows with the current C module probe families (DNS/process/connection), and focused runtime/path tests passed (`ebpf_runtime_mode`, `ebpf_paths`).
- [x] Document resolved Aya eBPF probe relocation quirk: avoid `.text.unlikely` relocation targets in probe sections by using explicit section wrappers and panic-path-safe probe code patterns.
  - Completed (entry 439): added eBPF quirk documentation in `crates/ebpf/QUIRKS.md`, including detection commands and coding patterns used for DNS/process probe stabilization.

2. Future enhancements
- [ ] Add optional `scope` field to gRPC/proto `Operator` in a dedicated compatibility PR (default dst semantics, backward-compatible wire evolution, Go/Rust/Python client alignment).
  - Note: deferred for now to stay aligned with base opensnitch implementation; revisit in a future dedicated compatibility PR.
- [ ] Support AdBlock/AdGuard list format in rule list operators and subscriptions.
	- AdBlock/AdGuard `||domain^` syntax is by far the most common format in community blocklists (e.g. EasyList, AdGuard DNS Filter, OISD).
	- Requires a parser that strips `||`/`@@||` prefixes and `^` suffix anchors into plain domain/wildcard entries, feeding them into the existing `lists.domains` trie+glob index.
	- Exception entries (`@@||...^`) should map to allow-list rule operators.
	- Subscription `format` field: add `"adblock"` canonical value → `normalize_format` + `is_adblock_list_like` validator.
	- Rule operator side: extend `normalize_domain_list_entry` to strip AdBlock/AdGuard decorators before trie insertion (backward-compatible: plain entries already parse).
	- References: AdGuard DNS filter syntax — `||example.com^`, `||*.example.com^$important`.
	- Note: deferred for now to stay aligned with base opensnitch implementation; revisit in a future dedicated compatibility PR.
- [ ] Python UI client explicit disconnect on quit/CTRL-C (graceful stream shutdown before process exit).
  - Add explicit client-side disconnect/stream-close handling on normal quit paths and signal paths (`SIGINT`/Ctrl-C).
  - Goal: avoid daemon-side noisy transport warnings (`h2 protocol error`/broken-pipe) during intentional UI termination.
  - Note: tracked as future work only; do not implement in this branch. Land in a separate PR branch once the related Python-client PR is accepted by maintainers.

3. Active netfilter/netlink backlog
- [x] Explore nftables handling over netlink (replace/augment `nft` CLI shelling in firewall adapter).
  - References:
    - https://raw.githubusercontent.com/one-d-wide/netlink-bindings/refs/heads/main/netlink-socket/examples/nftables.rs
    - https://raw.githubusercontent.com/one-d-wide/netlink-bindings/refs/heads/main/netlink-socket/examples/nftables-api.rs
  - Scope:
    - model table/chain/rule lifecycle using chained netlink transactions (`batch begin/end` + generation-id guard),
    - preserve existing behavior and rule semantics from current `firewall_nft` adapter,
    - add parity tests against current CLI-backed implementation before any default-path switch.
  - Status (entry 443): promoted from Future enhancements into active backlog.
  - Progress (entry 444): landed first implementation slice with a dedicated netlink adapter seam (`platform/adapters/firewall_nft_netlink.rs`) and env-gated integration path (`OPENSNITCH_NFT_NETLINK_EXPERIMENT`) in firewall ports, with automatic fallback to the current `nft` CLI adapter on errors.
  - Progress (entry 445): replaced netlink adapter stubs with a concrete first execution slice: operation-plan modeling for interception/system firewall paths, NETLINK_NETFILTER socket preflight checks, compatibility execution delegation to the existing nft adapter, and focused plan-shape unit tests (`tests/firewall/firewall_nft_netlink.rs`).
  - Progress (entry 446): implemented typed nftables netlink transaction execution for supported lifecycle operations (generation-id guarded batch begin/end with table/chain ensure and table delete) using `netlink-bindings` nftables API; the adapter now executes supported operations via netlink and falls back to the existing nft CLI adapter only for currently unsupported rule-expression operations.
  - Progress (entry 447): expanded rule-expression parity and chain semantics in the netlink adapter while preserving CLI fallback: native `queue` expression encoding, interception rule ensure/validation in netlink, base-chain hook/type/policy/priority handling, userdata-based dedupe/clear paths, IPv4+IPv6 CIDR/range support, ICMP/ICMPv6 type list handling, and expression-level unsupported telemetry.
  - Progress (entry 448): added parity/observability guardrails for staged rollout: differential CLI-normalized support tests, Go nftables testdata shape parity test, strict env-gated shipped coverage threshold (`OPENSNITCH_NFT_NETLINK_MIN_AUDIT_COVERAGE`), and stable contract tests for unsupported-expression family classification + fallback summary shape counters.
  - Completed (entry 449): closure criteria for this backlog scope are satisfied with green checks: focused netlink test suite passing, strict shipped-shape coverage gate at 100%, and explicit Go-side testdata shape parity coverage in Rust tests. CLI fallback remains intentionally enabled and default-path switch/privileged runtime rollout is tracked separately.
  - Progress (entry 451): promoted nftables netlink to netlink-first runtime behavior in firewall ports (default-enabled unless explicitly disabled with `OPENSNITCH_NFT_NETLINK_EXPERIMENT=0`), and added bounded request timeout fallback (`2s`) so missed netlink ACK/request paths degrade quickly to the legacy `nft` CLI adapter instead of stalling.
  - Progress (entry 452): tuned runtime fallback policy in firewall ports for graceful degradation with explicit warn-level fallback logging and non-aggressive retry cadence: after a netlink failure/timeout, calls continue through the legacy `nft` CLI path while netlink retries are delayed by a short cooldown window (`5s`) before being attempted again.
  - Progress (entry 453): tightened nftables netlink fallback/recovery timings to deterministic sub-second bounds for call-path responsiveness and short recovery loop behavior: request timeout is now `800ms` and retry cooldown is `800ms`.
  - Progress (entry 454): switched nftables recovery probing to failure-only polling semantics: no steady-state polling while healthy; on first netlink failure the port enters degraded mode, logs warn-level fallback, starts a short recovery poll loop (now tunable; default `800ms`) that runs only during degraded state, and automatically resumes netlink-first calls once preflight probe succeeds.
  - Progress (entry 455): optimized recovery-loop lifecycle to avoid repeated thread spawn costs: a single long-lived recovery loop thread is started once and remains idle while healthy; it performs preflight polling only when degraded/fallback state is active and clears degraded mode automatically on recovery.
  - Progress (entry 457): extracted a shared lock-free recovery primitive (`utils/netlink_recovery.rs::NetlinkRecoveryGate`) and rewired nftables + NFQUEUE domains to use per-domain static instances (each domain keeps its own degraded flag/probe policy/interval, while sharing the same one-time loop + degraded-only polling mechanics).
  - Progress (entry 458): split netlink recovery timing controls into explicit runtime tunables and applied them in both fallback domains: `netlink_fallback_retry_delay_ms` (initial retry delay after fallback) and `netlink_recovery_poll_interval_ms` (steady degraded-mode probe interval), with matching env overrides `OPENSNITCH_TUNE_NETLINK_FALLBACK_RETRY_DELAY_MS` and `OPENSNITCH_TUNE_NETLINK_RECOVERY_POLL_INTERVAL_MS`.
- [x] Explore NFQUEUE handling via netlink abstractions (reduce direct C/ffi coupling where practical).
  - Scope:
    - evaluate a typed netlink path for queue lifecycle/configuration and telemetry while preserving packet verdict semantics,
    - keep current behavior/performance parity with the existing runtime path,
    - stage migration behind parity harness checks before considering any default-path switch.
  - Status (entry 443): promoted from Future enhancements into active backlog.
  - Progress (entry 450): landed `platform/adapters/nfqueue_netlink.rs` — a pure-Rust `NETLINK_NETFILTER` NFQUEUE backend that requires no `libnetfilter_queue` C library: typed netlink message builder (`NlMsg`), NLA attribute parser (`parse_nfq_packet`), raw socket lifecycle (open, PF_BIND, BIND with ACK, copy-mode/maxlen/flags config, UNBIND on drop), recv loop reusing all existing verdict/metrics/parser logic from `platform::ffi::nfqueue` without modification, and verdict send (`NFQNL_MSG_VERDICT`).  Worker now selects between FFI and netlink backend with automatic fallback on error.  18 focused unit tests covering wire-shape, alignment helpers, NLA flag stripping, full-field packet parsing, and preflight socket check all pass.
  - Progress (entry 451): promoted NFQUEUE netlink to netlink-first runtime behavior (default-enabled unless explicitly disabled with `OPENSNITCH_NFQUEUE_NETLINK_EXPERIMENT=0`) and hardened worker startup fallback so netlink startup failures degrade gracefully to legacy FFI backend, with dedicated timeout-path logging retained for ACK/request miss signals.
  - Progress (entry 456): reused the same lock-free degraded-state recovery primitive as nftables in NFQUEUE startup control: single atomic degraded flag + one-time recovery loop starter, with preflight polling only while degraded (now tunable; default `800ms`) so subsequent startup attempts can resume netlink path after recovery without mutex/lock hot-path overhead.

4. Design-rule backlog (active)
- [x] Cache strategy policy codification (caller-class matrix + default-not-mandatory dual-layer stance).
  - Decision baseline (2026-03-22 review): dual-layer is preferred/default for shared read-heavy caches with lock-free immutable reads, but is not the only allowed cache implementation.
  - Selection rule: allow plain `LruCache` or map-based caches for write-heavy/high-churn or strictly local ownership paths when dual-layer publish overhead would dominate.
  - Deliverable: add and keep updated a short caller-class matrix (read/write profile, ownership, required semantics) for cache-bearing domains (`dns`, `process`, `connection owner`, and other runtime caches touched in future slices).
  - Completed (entry 434): added explicit design-rule cache policy and matrix under `Design Rule: Domain Boundary + Trait-First Architecture (Tracking)`.
- [x] Dual-layer publish-path optimization (`utils/lru_cache.rs`).
  - Current behavior to improve: publish rebuilds full immutable snapshots (`HashMap::from_iter(...)`) on write/publish paths for both async and sync dual-layer variants.
  - Goal: reduce write amplification and allocator churn while preserving lock-free read semantics and eventual touch recency convergence.
  - Suggested direction: evaluate incremental snapshot update or bounded batched publish policies with explicit tunables and focused perf regression checks.
  - Exploration add-ons (entry 434):
    - add optional metrics for touch-drop rate and publish-path cost,
    - add explicit capacity guidance/checkpoints for dual-layer-backed caches.
  - Progress (entry 435): landed first implementation slice for both add-ons:
    - metrics hooks added to dual-layer caches (touch enqueue/drop, reconcile batches/keys, full vs incremental publish counters, reconcile scan/removed counters, cumulative publish time),
    - incremental publish prototype added for common mutation paths (single-key insert with eviction reconciliation, remove, clear) for async and sync variants,
    - full mutable snapshot rebuild retained as fallback for multi-entry/capacity-reset paths.
  - Progress (entry 436): landed second slice and observability wiring:
    - bounded `insert_many` optimization: small batches now use incremental publish path; large batches still fall back to full rebuild,
    - global dual-layer metrics export surface added and wired into existing periodic stats telemetry flow (`flows/stats/stats.rs`) with delta logging,
    - focused tests extended for small-batch incremental behavior, large-batch fallback, and global metrics export visibility.
  - Progress (entry 437): synthetic harness tests added for continued measurement and regression detection:
    - read-heavy synthetic workload validates touch-queue pressure dominates publish activity for hot-key reads,
    - write-heavy batched synthetic workload validates full-publish pressure under large-batch write churn,
    - manual ignored trend harness prints reproducible workload reports for periodic perf tracking.
  - Progress (entry 438): codebase application pass for cache strategy points 1/2/3:
    - kept dual-layer/keyed caches on lookup-critical domains (`dns`, `process`, `connection owner`),
    - migrated append-heavy telemetry/event overflow paths to explicit bounded ring buffers (`utils/ring_buffer.rs`) in stats and UI alert overflow queues,
    - retained dual-layer for keyed cache semantics and ring buffers for latest-N stream semantics.
  - Completed (entry 440): optimization target is now considered closed for this branch scope after incremental publish-path updates, snapshotting refinements, bounded batch handling, and publish/touch metrics instrumentation landed across entries 435-438.
- [x] Continue trait-first boundary rollout: remove remaining stateful top-level functions as services/domains are touched.
  - Migrated from stale `Tracking checklist`.
  - Assumption check (2026-03-22): `make -C .. daemon-rs-policy-audit` passes, and naming/layout scan still reports no `RuntimeIntent` symbols or `intent.rs` files under `crates/daemon/src`.
- [x] Audit service-level shared free functions and migrate non-domain helpers to `utils/`, enforcing generics-first helper extraction where sensible while keeping domain-specific policy in service modules.
  - Migrated from stale `Tracking checklist`.
  - Assumption check (2026-03-22): helper/contract policy gate passes; spot scan of `services/*` free functions remains consistent with domain-policy/lifecycle helpers rather than cross-domain utility leakage.
- [x] Migrate shared data-contract types into `models/` as slices are touched (serde payloads, cross-domain state structs, transport DTOs) and reduce contract drift in services/flows/workers.
  - Migrated from stale `Tracking checklist`.
  - Assumption check (2026-03-22): serde-derive scan outside `models/*` remains limited to expected generic helper internals (`utils/serde_helpers.rs`).
- [x] Design-rule enforcement pass: migrate shared, non-domain service helpers into `utils/` and enforce generics-first deduplication where it improves reuse/readability.
  - Completed in entries 422–424: extracted shared task/subscription helper surfaces into `utils/*` (including shared HTTP response helpers), removed shim helpers, and applied no-one-liner/no-compat-shim helper policy in touched areas.
  - Rescan note: remaining `services/*` free functions are domain-policy/lifecycle conversions or orchestration APIs, not cross-domain generic helper leakage.
- [x] Design-rule enforcement pass: migrate shared data contracts into `models/`.
  - Completed in entries 422–424: migrated task runtime JSON payload contracts to `models/task_payload.rs` and rewired service call sites.
  - Rescan note: serde-backed contract types are now owned by `models/*` (with only generic serde utility internals in `utils/serde_helpers.rs` by design).
- [x] Crate-wide immutable state access rollout (beyond snapshot-specific rule).
  - Target: move read-mostly state/cache runtime reads to immutable Arc snapshot-style memread surfaces where feasible; avoid lock-based read paths in hot/runtime flows.
  - Assumption check (2026-03-22): `workers/runtime/watch/control.rs` remains a coordination lock (`spec.scan().await`) rather than immutable-read state drift.
  - Progress: `workers/network/netlink_addr_worker.rs` migrated to immutable snapshot storage (`Arc<Vec<String>>`) with sync snapshot reads (no async lock-based read path).
  - Progress: DNS dual-layer access now uses reusable utility abstraction (`utils/lru_cache.rs::DualLayerLruMap`) instead of domain-specific dual-layer plumbing.
  - Progress: utility dual-layer now supports async touch reconciliation so hot-path snapshot reads can keep effective LRU recency without lock-bound read paths.
  - Completed (entry 432): process cache no longer uses outer async read/write lock for runtime reads; immutable dual-layer entries remain lock-free read path and deadline bookkeeping moved to dedicated async mutex.
- [x] Service API surface audit for async getter-style immutable reads.
  - Target: keep immutable read access sync and lock-free where possible; reserve async methods for IO/mutation/coordination paths.
  - Assumption check (2026-03-22): scan remains clean for non-test async getter surfaces (`async fn ...snapshot|state|cache|status`) except expected mutators (`set_snapshot`, `build_and_publish_snapshot`).
  - Keep this as an ongoing guard in policy audits/new slices.

## Parity Matrix and Compatibility

| Area | Scope / Signal | Current Rust Path | Status | Tracking / Evidence | Guidance / Next Step |
|---|---|---|---|---|---|
| Netlink parity | `NETLINK_ROUTE` (iface lookup) | `rtnetlink` | Stable | daemon runtime + parity harness | Keep current stack (`rtnetlink` + typed route packets) |
| Netlink parity | `NETLINK_AUDIT` (audit event stream) | `audit`, `netlink-packet-core` | Stable | daemon runtime + parity harness | Keep current stack |
| Netlink parity | `NETLINK_CONNECTOR` (proc fork/exec/exit) | `netlink-sys` | Stable | daemon runtime + parity harness | Keep current stack; add typed packet crate only if required |
| Netlink parity | `NETLINK_SOCK_DIAG` (socket dump/destroy) | `netlink-sys`, `netlink-packet-sock-diag` | Stable | daemon runtime + parity harness | Keep current stack |
| Netlink parity | `NETLINK_NETFILTER` (verdict path) | libc + FFI boundary | Stable | daemon runtime + parity harness | Keep current path for now |
| Kernel/libbpf compatibility | Kernel 6.19 DNS eBPF hook downgrade | libbpf auto-attach probe path | Degraded with fallback | live log evidence: `logs/daemon-rs-live-20260319-161248-stdout.log` | Treat `kernel + bpftool + libbpf + compiled BPF object` as one compatibility unit |
| Runtime fallback behavior | DNS monitoring under eBPF hook failure | DNS service worker path | Resilient | daemon behavior checks | Keep systemd-resolved varlink (`/run/systemd/resolve/io.systemd.Resolve.Monitor`) + `resolvectl monitor` fallback |
| OpenSnitch eBPF quirk tracking | Upstream issue thread and repro notes | eBPF module/runtime compatibility | Open external signal | issue: https://github.com/evilsocket/opensnitch/issues/1537#issuecomment-3905087273 | Track upstream outcome and mirror actionable mitigations in this tracker |
| Packaging / ecosystem compatibility | AUR eBPF module package behavior | out-of-tree package integration | External signal | package: https://aur.archlinux.org/packages/opensnitch-ebpf-module-git | Track packaging deltas against upstream expectations before enabling stricter defaults |

- Compatibility interpretation:
  - DNS eBPF-hook downgrade is typically probe auto-attach / userspace tooling format mismatch, not a generic netlink breakage.
  - Netlink workers (`NETLINK_CONNECTOR`, `NETLINK_SOCK_DIAG`, `NETLINK_ROUTE`) are independent from libbpf hook viability and should be evaluated separately.
- Implementation guidance:
  - Keep netlink protocol handling on typed netlink crates; avoid ad-hoc raw-byte replacements unless a verified parser bug requires it.
  - Keep `rustix` usage scoped to syscall/fd helpers, not as a replacement for typed netlink protocol decoding.
  - Keep external quirk tracking (upstream issue + AUR package) visible here until compatibility behavior is stable across target kernels/distributions.

## Tracker Retention

- Resolved milestone details and historical slice-by-slice changelog entries are pruned from this tracker to keep it focused on active backlog, current parity state, and open milestone blockers.
- Use `git log` for completed implementation history when detailed slice provenance is needed.
- [x] Recorded the architectural constraint that subscription schema should be extracted from `proto/ui.proto` into a dedicated external proto surface.

## Update Rules

1. Update this file directly after each parity or async/runtime change.
2. Prune closed items and resolved audit slices so this tracker stays focused on active work.
3. Keep behavior references concrete (file + behavior), not generic.
4. Keep this as the only active tracker file.
5. Separate-PR items are excluded from milestone gating.

## 421 — Post-squash governance rescan/remap (design rules + parity + milestone)

- Trigger/context:
  - after history squash to `release: v0.1.1`, reran governance and parity
    checks to confirm design-rule compliance and tracker completeness.

- Tracker/remap findings:
  - resolved historical slice entries were pruned from this tracker to keep it
    lightweight; numbering is intentionally non-contiguous.
  - corrected top metadata to `Last update: 2026-03-22 (entry 421)` so header
    tracks the latest retained audit entry.
  - merged compatibility coverage into unified section
    `Parity Matrix and Compatibility` (netlink parity + kernel/libbpf notes)
    and added explicit external eBPF quirk trackers:
    - `https://github.com/evilsocket/opensnitch/issues/1537#issuecomment-3905087273`
    - `https://aur.archlinux.org/packages/opensnitch-ebpf-module-git`

- Design-rule rescan results:
  - data-contract ownership guard test passes:
    - `cargo test -p opensnitchd-rs data_contract_ownership -- --nocapture`
  - `mod.rs` linker-only rule scan across
    `services/*`, `commands/*`, `flows/*`, `workers/*` reports no direct
    functional declarations outside explicit allowlisted macro/test surfaces.
  - remaining serde/prost markers outside `models` are in expected helper/
    generic storage utility surfaces (`services/storage/storage.rs` generic
    `DeserializeOwned` bounds and `utils/serde_helpers.rs`).

- Parity/diagnostics rescan results:
  - build baseline passes:
    - `cargo check -p opensnitchd-rs`
  - latest full rerun after compatibility-matrix update:
    - `cargo test -p opensnitchd-rs data_contract_ownership -- --nocapture`
      passes (`1 passed`).
    - `make parity-hot-cold-delta-once STRESS_ROUNDS=50` passes end-to-end:
      - `PARITY HOT-PATH STATUS: PASS`
      - `PARITY COLD-PATH STATUS: PASS`
      - `PARITY DELTA STATUS: PASS`
      - delta snapshot:
        `PARITY DELTA HOT MIXED: go_verdict_ms=0.008 rust_verdict_ms=0.023 delta_ms=+0.015`
        `PARITY DELTA COLD: go_total_s=4.100 rust_total_s=4.163 delta_s=+0.063`
  - remapped focused parity-adjacent Rust tests pass:
    - `cargo test -p opensnitchd-rs config_service -- --nocapture`
      (`5 passed`)
    - `cargo test -p opensnitchd-rs firewall_service -- --nocapture`
      (`13 passed`)
    - `cargo test -p opensnitchd-rs tests::client -- --nocapture`
      (`2 passed`)
  - parity runner mapping now fixed:
    - `make rust-parity-tests` selectors were updated to
      `tests::config_service::`, `tests::firewall_service::`, and
      `tests::client::`.
    - post-fix rerun executes real tests and passes:
      - config selector: `5 passed`
      - firewall selector: `13 passed`
      - client selector: `2 passed`
  - amended rerun after Go proto bootstrap correction:
    - root build/test flow now bootstraps Go proto tools via
      `scripts/bootstrap_go_proto_tools.sh`, which reads `daemon/go.mod` and
      installs generator versions compatible with the daemon baseline
      (`google.golang.org/grpc v1.32.0`,
      `google.golang.org/protobuf v1.26.0`).
    - reruns continue to confirm end-to-end parity pass status on this branch.
    - generated Go gRPC stubs are now baseline-compatible again:
      `daemon/ui/protocol/ui_grpc.pb.go` is generated by
      `protoc-gen-go-grpc v1.3.0` and asserts
      `grpc.SupportPackageIsVersion7` instead of the previous incompatible
      `SupportPackageIsVersion9` marker.
  - diagnostics policy audit now passes:
    - `make daemon-rs-policy-audit` now reports:
      - `async-send policy check: pass`
      - `snapshot-clone policy check: pass`
      - `daemon-rs policy audit: pass`
    - audit scripts were remapped to current source layout and include
      explicit allowlisted startup/control-path snapshot clone call sites
      that are intentionally retained.

- Milestone verdict:
  - **At milestone gate for current branch scope**.
  - milestone gating excludes items explicitly deferred to a separate PR or
    marked as future implementation work in Active Backlog; those remain tracked
    but are not counted as blockers for this branch milestone.
  - blockers for milestone declaration:
    - none currently open in this retained tracker scope.

- Next actions queued:
  1. keep the Go proto bootstrap flow in place for local parity/build/test
     paths; defer any full `google.golang.org/grpc` dependency upgrade to a
     dedicated upstream PR against main opensnitch repo.
  2. keep policy-audit allowlists synchronized with source-file moves so
    governance checks stay signal-rich instead of path-stale.
  3. rerun parity + policy gates on each substantive runtime/parity slice.

## 422 — Design-rule backlog execution (task payload contracts + helper cleanup)

- Trigger/context:
  - started active design-rule backlog execution for data-contract ownership and
    non-domain helper cleanup in task runtime surfaces.

- Changes in this slice:
  - migrated task JSON contract payloads out of service internals into
    `models/task_payload.rs`:
    - `LegacyTaskResultPayload` (`Type`/`Data` payload used for Go-compatible
      task results logging shape)
    - `TaskErrorPayload` (`Task`/`Error` payload used by task runtime error
      notifications)
  - rewired task runtime call sites to consume model-owned contracts:
    - `services/task/reply.rs` now builds legacy downloader payload through
      `LegacyTaskResultPayload`.
    - `services/task/runtime_handlers.rs` now emits task-error payloads through
      `TaskErrorPayload`.
  - removed now-unused non-domain JSON helper
    `utils/json_value.rs::object_field_str` after the refactor.

- Validation:
  - focused runtime tests pass:
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs task_runtime -- --nocapture`
      (`24 passed`, `0 failed`).

- Backlog impact:
  - advances active design-rule backlog item
    "migrate shared data contracts into `models/`" with concrete task-runtime
    payload contract migration in this slice.
  - advances active design-rule backlog item
    "migrate shared, non-domain service helpers into `utils/`" by extracting
    subscription HTTP response helpers into shared utility surface.

- Continuation slice (same entry):
  - extracted non-domain HTTP response helpers from
    `services/subscription/http_helpers.rs` into
    `utils/http_response.rs` (`header_value`, `summarize_http_error`).
  - rewired `services/subscription/refresh_execution.rs` to consume
    `crate::utils::http_response` and removed the service-local helper module.

- Additional validation:
  - focused subscription tests pass:
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs subscription -- --test-threads=1 -q`
      (`52 passed`, `0 failed`).

## 423 — Design-rule wording update (utils/helpers strictness)

- Trigger/context:
  - governance wording update requested for helper policy clarity.

- Rule amendments:
  - explicitly forbids one-line passthrough helper wrappers in `utils/` unless
    they add concrete semantic value (intent/invariants/error context).
  - explicitly forbids keeping compatibility shims/aliases after call-site
    migration; transitional helper wrappers must be removed within the same
    refactor slice.

- Enforcement slice (codebase pass):
  - removed compatibility shim helper `utils::notification_reply::status_ok_payload`
    and rewired command call sites to explicit `status_payload("ok")` usage.
  - refactored helper one-liners in `utils/` touched by this slice into explicit
    logic (`utils/time_nonce.rs`, `utils/list_shape.rs`,
    `utils/nul_terminated.rs`) to align with the updated helper rule.
  - scan/audit note: rule scan no longer reports shim-style wrappers in
    `utils/` for this migrated set; remaining scan hit is
    `utils/config_reload::has_firewall_runtime_change`, which is retained as a
    real policy predicate (not a passthrough compatibility alias).

- Validation:
  - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs subscription -- --test-threads=1 -q` (`52 passed`, `0 failed`).
  - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs task_runtime -- --nocapture` (`24 passed`, `0 failed`).

## 424 — Non-future backlog closure (design-rule items)

- Trigger/context:
  - requested closure of remaining non-future backlog entries.

- Closure status:
  - closed `Design-rule backlog (active)` helper-migration item as complete for
    current branch scope (entries 422–424).
  - closed `Design-rule backlog (active)` data-contract migration item as
    complete for current branch scope (entries 422–424).

- Scope note:
  - future-enhancement backlog items remain intentionally open and unchanged.

## 425 — Full design-rule policy rescan (post-closure verification)

- Trigger/context:
  - one more full governance/policy rescan requested after non-future backlog
    closure.

- Full rescan results:
  - policy gates:
    - `make daemon-rs-policy-audit` passes (`async-send` pass,
      `snapshot-clone` pass).
  - boundary naming/layout:
    - no `RuntimeIntent` symbol matches.
    - no `intent.rs` usage under daemon runtime sources.
    - `intent` is treated as design vocabulary, not default symbol naming.
    - no `services/*_service` directory names.
  - linker-only module surfaces:
    - no functional declarations found in
      `services/*/mod.rs`, `flows/*/mod.rs`, `commands/*/mod.rs`,
      `workers/*/mod.rs`.
  - helper strictness (`utils/` one-line passthrough wrappers):
    - no shim-style compatibility aliases found in current migrated set.
    - remaining regex hit in `utils/config_reload.rs::has_firewall_runtime_change`
      is retained as a domain policy predicate (not a compatibility shim).
  - data-contract ownership:
    - no serde-backed contract drift found outside `models/*` except expected
      generic serde utility internals in `utils/serde_helpers.rs`.

- Alignment verdict:
  - current branch is aligned with the tracked design-rule policies for
    non-future backlog scope.

## 426 — Crate-wide immutable-state audit (state/cache/snapshot philosophy extension)

- Trigger/context:
  - extended immutable-state philosophy beyond snapshot-only access and audited
    daemon crate runtime state/cache read patterns.

- Audit scope and commands:
  - lock/read-write scan:
    - `rg -n --no-heading '\\.lock\\(\\)\\.await|\\.read\\(\\)\\.await|\\.write\\(\\)\\.await' daemon-rs/crates/daemon/src -g '!**/tests/**'`
  - async state/cache getter signature scan:
    - `rg -n --no-heading '\\basync fn [A-Za-z0-9_]*(snapshot|state|cache|status)\\b' daemon-rs/crates/daemon/src -g '!**/tests/**'`

- Findings:
  - snapshot-specific policy remains clean after prior refactors and checker
    tightening.
  - broader crate scan identified remaining lock/read-write state/cache access
    patterns that should be evaluated for immutable-snapshot migration in
    read-mostly runtime paths, notably:
    - `services/process/cache.rs`, `services/process/inspection.rs`
    - `services/dns/cache_ops.rs`
    - `workers/network/netlink_addr_worker.rs`
    - `workers/runtime/watch/control.rs`
    - mutation/control locks retained by design in rule/task/config paths are
      tracked as coordination locks, not immutable-read surfaces.
  - non-test async getter-style state/cache signatures are currently minimal
    (`set_snapshot` mutator and snapshot publish/build internals), with no
    broad async read-getter surface drift found.

- Backlog impact:
  - reopened active design-rule backlog for crate-wide immutable-state rollout
    beyond the snapshot-only slice, with concrete candidate modules listed above.

- Validation:
  - `make daemon-rs-policy-audit` passes, including:
    - `async-send policy check: pass`
    - `snapshot-clone policy check: pass`
    - `design-rule policy check: pass`
    - `design-rule helper/contract check: pass`
    - `immutable-state policy check: pass`

## 427 — Immutable-state rollout slice 1 (netlink local address store)

- Trigger/context:
  - started implementing concrete fixes from entry 426 findings, prioritizing
    read-mostly state where lock-free immutable snapshot reads are feasible
    without changing behavior.

- Changes in this slice:
  - migrated netlink local-address state storage from async `RwLock<HashSet<_>>`
    to immutable snapshot storage `RwLock<Arc<Vec<String>>>` in
    `workers/network/netlink_addr_worker.rs`.
  - runtime reads now use sync snapshot memread API:
    - `snapshot_local_addrs()` is sync (no async lock/await read path).
  - writer path keeps periodic refresh semantics and logs add/remove deltas, but
    publishes sorted immutable snapshots for readers.

- Findings reassessment (post-slice):
  - resolved from active candidate set:
    - `workers/network/netlink_addr_worker.rs`
  - remaining likely mutable-by-design areas:
    - `services/process/*` and `services/dns/cache_ops.rs` use LRU/cache update
      patterns where reads may mutate recency or alias traversal state.
  - remaining coordination locks (not immutable-read surfaces):
    - watcher/control and mutation guards in rule/task/config runtime paths.

- Validation:
  - `make daemon-rs-policy-audit` passes.
  - `cargo check --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs` passes.
  - focused test:
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs netlink_addr_worker -- --nocapture`
      (`1 passed`, `0 failed`).

## 428 — Immutable-state rollout slice 2 (DNS dual-layer + process reassessment)

- Trigger/context:
  - execute next immutable-state slice using dual-layer strategy for DNS cache,
    then reassess process cache feasibility under same philosophy.

- Changes in this slice:
  - DNS cache dual-layer implementation:
    - writer layer remains mutable LRU caches for insertion/eviction mechanics,
    - read layer now publishes immutable Arc snapshots for runtime lookups.
  - DNS runtime lookup path now uses sync immutable snapshot memreads:
    - `lookup`/`lookup_ip` no longer await lock-based cache getters.
  - runtime caller updates:
    - connection destination-host resolution now uses sync DNS lookup reads.
  - tests updated for sync DNS lookup API.

- Process cache reassessment:
  - `services/process/*` cache paths remain likely mutable-by-design in current
    shape because read operations participate in recency/expiry and PID-starttime
    coherence checks.
  - feasible next step is a dual-layer process cache read view (immutable probe
    snapshot) while preserving mutable LRU bookkeeping on write/update paths.
  - keep current process cache items in active backlog pending dedicated slice.

- Validation:
  - `make daemon-rs-policy-audit` passes.
  - `cargo check --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs` passes.
  - focused tests pass:
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs dns_service -- --nocapture`
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs kernel_flow -- --nocapture`

## 429 — Utility-first dual-layer LRU rollout (DNS migration + process reassessment)

- Trigger/context:
  - requested to generalize dual-layer approach at utility level rather than
    keep domain-specific snapshot plumbing in DNS.

- Changes in this slice:
  - added reusable utility abstraction in `utils/lru_cache.rs`:
    - `DualLayerLruMap<K, V>` (mutable async LRU writer + immutable Arc snapshot
      read layer).
  - migrated DNS service to utility-backed dual-layer caches:
    - replaced domain-local dual-layer fields with
      `Arc<DualLayerLruMap<IpAddr, String>>` and
      `Arc<DualLayerLruMap<String, String>>`.
    - retained sync immutable DNS runtime lookup reads (`lookup`/`lookup_ip`).
  - updated DNS probe/test helper to use utility-backed cache length methods.

- Process cache reassessment (after utility generalization):
  - utility abstraction now exists and is reusable for read-mostly key/value
    cache slices.
  - process cache remains pending because current semantics combine:
    - LRU recency behavior,
    - expiry/deadline mutation,
    - PID starttime coherence validation.
  - next process slice should introduce a derived immutable read-view snapshot
    while preserving mutable bookkeeping for expiry/recency paths.

- Validation:
  - `make daemon-rs-policy-audit` passes.
  - `cargo check --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs` passes.
  - focused tests pass:
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs dns_service -- --nocapture`
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs kernel_flow -- --nocapture`

## 430 — Utility touch-reconciler rollout (effective LRU on snapshot reads)

- Trigger/context:
  - hot-path concern: pure snapshot reads bypass LRU recency updates, which can
    degrade eviction quality under sustained lookup-heavy traffic.

- Changes in this slice:
  - extended `utils/lru_cache.rs::DualLayerLruMap` with async touch
    reconciliation:
    - hot-path snapshot read API now supports touch submission
      (`get` on immutable snapshot read path),
    - touches are queued and reconciled in a background async worker,
    - reconciliation updates mutable LRU recency in batches off hot path.
  - DNS lookup path now uses touch-aware snapshot reads so frequent lookups can
    refresh effective recency without lock-bound read awaits.

- Process cache reassessment:
  - this utility capability now directly supports a process-cache next slice
    where read probes can publish touches asynchronously while keeping mutable
    expiry/starttime coherence logic intact.
  - process cache remains open because expiry and PID coherence still require
    dedicated design for dual-layer publish boundaries.

- Validation:
  - `make daemon-rs-policy-audit` passes.
  - `cargo check --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs` passes.
  - focused tests pass:
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs dns_service -- --nocapture`
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs kernel_flow -- --nocapture`
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs lru_cache -- --nocapture`

## 431 — Backlog assumption verification + active backlog reduction

- Trigger/context:
  - requested to commit and continue non-future backlog handling with explicit
    assumption validation before keeping/closing items.

- Verification executed in this slice:
  - policy gate:
    - `make -C .. daemon-rs-policy-audit` passes (`async-send`,
      `snapshot-clone`, `design-rule`, `helper/contract`, and
      `immutable-state` checks).
  - immutable-state candidate refresh:
    - lock/read-write scan rerun on non-test sources;
      `workers/runtime/watch/control.rs` classified as coordination-lock usage,
      not immutable-read state drift.
    - active immutable-state backlog scope narrowed to remaining process-cache
      surfaces (`services/process/*`).
  - async getter surface refresh:
    - non-test `async fn ...snapshot|state|cache|status` scan rerun;
      no read-getter drift found.
    - only expected mutation/publish methods remain (`set_snapshot`,
      `build_and_publish_snapshot`).

- Backlog impact:
  - closed active item:
    - `Service API surface audit for async getter-style immutable reads`.
  - refined active item scope:
    - `Crate-wide immutable state access rollout` now targets process-cache
      paths as the principal remaining non-future slice.

- Validation:
  - `cargo check --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs` passes.

## 432 — Process cache immutable-read rollout completion

- Trigger/context:
  - execute the remaining non-future immutable-state backlog slice for
    `services/process/*` after entry 431 narrowed scope.

- Changes in this slice:
  - removed outer `RwLock<ProcessCache>` gating in `ProcessService`.
  - refactored process cache storage to split responsibilities:
    - immutable/read-mostly process entries remain in
      `Arc<DualLayerLruMap<u32, CachedProcessEntry>>`,
    - mutable exit-deadline bookkeeping moved to a dedicated
      `tokio::sync::Mutex<HashMap<u32, Instant>>`.
  - updated process inspection/event-sync paths to avoid lock-based read access
    around cache entries and use narrow deadline mutex operations.
  - updated process probe-support tests to match the refactored cache surface.

- Backlog impact:
  - closes active item `Crate-wide immutable state access rollout
    (beyond snapshot-specific rule)` for the currently tracked non-future
    candidate set.

- Validation:
  - `cargo check --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs` passes.
  - focused process tests pass:
    - `cargo test --manifest-path daemon-rs/Cargo.toml -p opensnitchd-rs process_service -- --nocapture`

## 433 — Cache caller strategy decision + optimization backlog seed

- Trigger/context:
  - requested full review of cache callers (including dual-layer users) and a
    strategy decision on whether dual-layer should be the only cache
    implementation.

- Review findings (caller inventory + operation patterns):
  - dual-layer utilities are now the primary shared cache abstraction in active
    read-heavy runtime domains (`dns`, `process`, `connection owner`).
  - lock-free immutable read paths are working as intended for hot-path lookups.
  - key risk remains dual-layer publish cost under churn: immutable snapshot
    publish currently rebuilds full map state on write/publish paths.

- Strategy decision recorded:
  - **do not promote dual-layer as the only cache implementation**.
  - keep dual-layer as preferred default for shared read-mostly runtime caches.
  - permit simpler cache forms (plain LRU/map) when caller profile is
    write-heavy, local, or semantics do not justify dual-layer publish overhead.

- Backlog impact:
  - added active design-rule items to codify cache selection policy and to land
    dual-layer publish-path optimization in `utils/lru_cache.rs`.

- Validation/evidence:
  - strategy derived from source inventory/operation scans and implementation
    review in this slice; no behavior change code landed in this entry.

## 434 — Cache selection design rule codification

- Trigger/context:
  - requested to explore/operationalize the recommended cache strategy and
    consider adding an explicit design rule.

- Changes in this slice:
  - added explicit `Cache selection rule (dual-layer policy)` under design
    rules with:
    - default-not-mandatory dual-layer stance,
    - decision criteria for dual-layer vs plain LRU/map,
    - dual-layer capacity guidance,
    - required observability signals (touch-drop and publish-path cost),
    - short caller-class matrix covering current key cache domains and generic
      caller profiles.
  - marked active backlog item `Cache strategy policy codification` complete.
  - refined active backlog exploration scope for dual-layer optimization to
    include metrics + capacity checkpoints.

- Validation/evidence:
  - tracker/design-rule update only (no runtime behavior change in this slice).

## 435 — Dual-layer internals slice 1 (metrics hooks + incremental publish prototype)

- Trigger/context:
  - requested to execute both next steps: add metrics hooks and prototype
    incremental publish behavior in dual-layer cache internals.

- Changes in this slice:
  - updated `utils/lru_cache.rs` for both `DualLayerLruMap` and
    `SyncDualLayerLruMap`:
    - added dual-layer metrics snapshot surface and counters:
      - touch enqueue/drop,
      - touch reconcile batches/keys,
      - publish full vs incremental counts,
      - publish reconcile scans/removed keys,
      - cumulative publish time (ns).
    - added incremental publish paths for:
      - single-key insert (including eviction reconciliation against mutable
        state),
      - remove-by-key,
      - clear.
    - retained full publish rebuild path for `insert_many` and `set_capacity`
      where broad mutable reshaping remains expected.
  - added focused tests in `tests/parsing/lru_cache.rs` to validate:
    - eviction correctness under incremental publish reconciliation,
    - metrics surface visibility on hot-path usage.

- Validation:
  - `cargo test --manifest-path Cargo.toml -p opensnitchd-rs lru_cache -- --nocapture`
    passes (`5 passed`, `0 failed`).

## 436 — Dual-layer internals slice 2 (insert_many optimization + stats-flow export)

- Trigger/context:
  - requested execution order: (2) bounded `insert_many` optimization first,
    then (1) metrics export wiring into existing observability flow.

- Changes in this slice:
  - `utils/lru_cache.rs`:
    - added bounded `insert_many` optimization for async and sync dual-layer
      maps:
      - small batches use incremental publish path,
      - large batches fall back to full mutable snapshot rebuild.
    - added module-level global dual-layer metrics snapshot surface so runtime
      observability can sample aggregate cache behavior without invasive
      plumbing through each service.
    - wired global counter updates for touch enqueue/drop, touch reconcile,
      publish mode, reconcile cleanup, and cumulative publish time.
  - `flows/stats/stats.rs`:
    - integrated global dual-layer metrics into the existing 30-second
      telemetry debug path with delta reporting.
  - `tests/parsing/lru_cache.rs`:
    - added tests for bounded `insert_many` behavior and global metrics export.

- Validation:
  - `cargo test --manifest-path Cargo.toml -p opensnitchd-rs lru_cache -- --nocapture`
    passes (`8 passed`, `0 failed`).

## 437 — Synthetic cache harness tests (publish/reconcile pressure tracking)

- Trigger/context:
  - requested synthetic harness coverage to keep measuring dual-layer
    publish/reconcile overhead after recent optimization slices.

- Changes in this slice:
  - `tests/parsing/lru_cache.rs` now includes synthetic workload harnesses:
    - read-heavy hot-key workload (`run_read_write_workload`) with explicit
      touch-vs-publish pressure checks,
    - write-heavy batched workload (`run_batched_write_workload`) with explicit
      full-publish pressure checks,
    - ignored manual trend snapshot harness for periodic measurement captures.
  - harness reports are based on dual-layer metrics snapshot counters so tests
    can detect drift in publish mode pressure and reconcile behavior.

- Validation:
  - `cargo test --manifest-path Cargo.toml -p opensnitchd-rs lru_cache -- --nocapture`
    passes (`10 passed`, `0 failed`, `1 ignored` manual trend harness).

## 438 — Strategy application pass (1/2/3) + verification harness run

- Trigger/context:
  - requested explicit codebase application (not only policy) for:
    1) keep dual-layer/keyed caches where lookup semantics matter,
    2) use ring buffers for append-heavy telemetry/event streams,
    3) keep latest-N write-heavy stream behavior on ring surfaces,
    and validate through harness/tests.

- Changes in this slice:
  - kept keyed dual-layer cache usage unchanged for lookup-critical services:
    - `services/dns/dns.rs`
    - `services/process/cache.rs`
    - `services/connection/owner.rs`
  - added reusable bounded ring utility `utils/ring_buffer.rs` and migrated
    append-heavy queues:
    - stats event backlog now uses ring buffer semantics (`services/stats/*`),
    - UI alert overflow queue now uses ring buffer semantics
      (`services/client/alerts.rs`).
  - added ring-buffer utility tests (`tests/parsing/ring_buffer.rs`).

- Verification/harness:
  - focused test runs:
    - `cargo test --manifest-path Cargo.toml -p opensnitchd-rs ring_buffer -- --nocapture`
    - `cargo test --manifest-path Cargo.toml -p opensnitchd-rs stats_service -- --nocapture`
    - `cargo test --manifest-path Cargo.toml -p opensnitchd-rs lru_cache -- --nocapture`
  - results:
    - ring_buffer: `3 passed`,
    - stats_service: `10 passed`,
    - lru_cache: `10 passed`, `1 ignored` manual trend harness.

## 439 — Ring-buffer tunables parity (stats event + alert overflow capacities)

- Trigger/context:
  - requested tunables parity so ring-buffer-backed surfaces can be sized via
    the same runtime tunables model already used by cache capacities.

- Changes in this slice:
  - extended tunables schema/models:
    - `models/effective_tunables.rs`
    - `models/runtime_tunables.rs`
    - new fields:
      - `stats_event_ring_capacity`
      - `alert_overflow_ring_capacity`
  - extended tunables resolution in `tunables.rs`:
    - defaults, raw-file parsing, env overrides, and clamp bounds for both
      ring capacities,
    - added unit tests validating raw parse + clamp behavior.
  - wired bootstrap application in `daemon/bootstrap.rs`:
    - logs both new effective tunables,
    - applies runtime configuration via:
      - `StatsService::configure_event_ring_capacity(...)`
      - `client::configure_alert_overflow_ring_capacity(...)`.
  - added runtime hooks:
    - `services/stats/internal.rs` + `services/stats/stats.rs`:
      - tunable-backed static capacity default for event ring,
      - `apply_config()` now enforces tunable cap when applying `max_events`.
    - `services/client/alerts.rs`:
      - tunable-backed static capacity for alert overflow ring,
      - applies to existing queue instance if already initialized.
  - updated tunables samples:
    - `data/tunables.example.json`
    - `data/tunables.json`.

- Validation:
  - `cargo test -p opensnitchd-rs tunables::tests -- --nocapture`
  - `cargo test -p opensnitchd-rs ring_buffer -- --nocapture`
  - `cargo test -p opensnitchd-rs stats_service -- --nocapture`
  - results:
    - tunables tests: `2 passed`,
    - ring_buffer target: `5 passed` (includes tunables module tests),
    - stats_service: `10 passed`.

## 458 — Netlink recovery timing split tunables + perf tracker consistency

- Trigger/context:
  - requested separation between initial fallback retry delay and degraded-mode
    recovery polling cadence, and TODO tracker consistency after moving detailed
    perf history out to `PERF.md`.

- Changes in this slice:
  - split netlink recovery timing tunables:
    - `netlink_fallback_retry_delay_ms`
    - `netlink_recovery_poll_interval_ms`
  - wired both tunables into nftables and NFQUEUE netlink recovery paths:
    - first degraded probe waits `netlink_fallback_retry_delay_ms`,
    - subsequent degraded probes run every
      `netlink_recovery_poll_interval_ms`.
  - updated tunables schema/models and example tunables file:
    - `models/effective_tunables.rs`
    - `models/runtime_tunables.rs`
    - `tunables.rs`
    - `data/tunables.example.json`
  - added matching env overrides:
    - `OPENSNITCH_TUNE_NETLINK_FALLBACK_RETRY_DELAY_MS`
    - `OPENSNITCH_TUNE_NETLINK_RECOVERY_POLL_INTERVAL_MS`
  - updated TODO perf guidance to keep detailed run history in `PERF.md` while
    retaining machine-readable baseline keys in TODO for harness checks.

- Validation:
  - `cargo check -p opensnitchd-rs` passes after the split-tunable wiring.

## 459 — Stress baseline source moved from TODO to PERF

- Trigger/context:
  - Go stress test guard failed after removing TODO perf baseline keys:
    `runtime_profile_test.go:532: missing GO stress baseline keys in TODO baseline file`.
  - policy decision: Go and Rust harnesses should no longer require perf-key
    maintenance in `TODO.md`.

- Changes in this slice:
  - switched Go stress guard default baseline source from
    `daemon-rs/TODO.md` to `daemon-rs/PERF.md` in
    `daemon/runtimeprofile/runtime_profile_test.go`.
  - switched Rust stress guard default baseline source from
    `daemon-rs/TODO.md` to `daemon-rs/PERF.md` in
    `crates/daemon/src/tests/smoke/daemon_runtime.rs`.
  - added `OPENSNITCH_STRESS_BASELINE_PATH` override in both harnesses, while
    keeping `OPENSNITCH_STRESS_TODO_PATH` as a backward-compatible fallback.
  - moved machine-readable baseline keys to `daemon-rs/PERF.md` regression
    policy section and marked TODO as non-owner for perf baseline keys.

- Validation:
  - `go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1` passes.
  - `cargo check -p opensnitchd-rs` passes.
