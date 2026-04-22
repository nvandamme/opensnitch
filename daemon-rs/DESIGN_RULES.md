# Daemon-RS Design and Maintenance Rules

This document defines maintenance rules for tracker, compatibility, and design documentation.

## Document Ownership

- [daemon-rs/TODO.md](TODO.md): active tracker only (status snapshot, active backlog, concise dated entries).
- [daemon-rs/COMPATIBILITY.md](COMPATIBILITY.md): full parity/compatibility reference (all large tables and rationale).
- [daemon-rs/DESIGN_RULES.md](DESIGN_RULES.md): governance rules for how tracker and compatibility docs are maintained.
- [daemon-rs/CHANGELOG.md](CHANGELOG.md): archived version-by-version notes.
- [daemon-rs/PERF.md](PERF.md): performance/stress baselines and perf history.

## Architecture Rules

This section restores the richer architectural policy that previously lived inline in [daemon-rs/TODO.md](TODO.md).

### 1. Domain Boundaries Own Behavior And Runtime State

- Runtime orchestration/state should live in the owning domain/service boundary (`connection`, `process`, `dns`, `firewall`, `tasks`, `commands`), not in root wiring.
- Daemon root should orchestrate wiring and lifecycle, not encode domain behavior.
- `intent` is an architectural term for ownership/responsibility, not a symbol naming convention: do not encode it into type names, method names, or module names unless it adds concrete semantic value beyond the domain/service role itself.
- Domain behavior should stay where it is clearest (often in `services/<service>/<service>.rs`), and should not force a dedicated `intent.rs` file or `*Intent*` symbols.
- Boundaries should be trait-first where polymorphism is needed: stateful runtime/domain structs implement explicit traits/ports instead of relying on closure aliases.
- Trait-object erasure helpers belong on the owning trait/type surface; avoid root-wiring helpers that only box a concrete type into its trait object.
- Long-lived service runtime control must use a trait-based lifecycle surface (`init/start/pause/resume/stop/reload/quiesce/drain/health_check/status/reset`) instead of global mutable singleton functions.
- Every service façade must expose a uniform runtime control contract with `start`/`stop`/`reload` semantics via shared lifecycle traits; `reload` must be the canonical hot-reload verb across services.
- Service construction must use shared factory traits (instead of ad-hoc constructor-only contracts) so lifecycle orchestration and dependency wiring can remain generic and testable; prefer `ServiceFactory::init` as the canonical initialization entrypoint name.
- Public lifecycle entrypoints on daemon/service/worker boundaries should use lifecycle semantics such as `start`/`stop`/`reload`; reserve `run` for inner execution loops and `shutdown` for lower-level cancellation plumbing or external protocol vocabulary.
- Stateful daemon/service boundaries should own a single explicit runtime struct and expose clonable handles to that runtime when shared access is required; prefer names such as `*Runtime` over vague wrappers such as `*Inner`.
- Keep service façade, runtime data, and lifecycle tracking conceptually distinct: the service handle composes them, runtime structs own domain snapshot/cache/worker state, and lifecycle surfaces own `ServiceState`, status/event channels, and subscriber accounting.
- When a boundary exposes both a shared runtime snapshot/store and lifecycle observability as separate concerns, model them as separate holders behind the service façade rather than collapsing snapshot transport and lifecycle bookkeeping into one hybrid type.
- For boundaries with non-trivial lifecycle behavior, keep lifecycle implementation in a dedicated `runtime_lifecycle.rs` module so service façade and runtime-state files stay focused on domain/runtime concerns.
- Every concrete `services/<service>/` directory must include a `runtime_lifecycle.rs` module as the canonical lifecycle/reload split point (even when current runtime hooks are lightweight), so hot-reload capacity remains explicit and uniform across services.
- Service-level process-singleton holders (when unavoidable) must be managed behind `runtime_lifecycle.rs` and expose explicit replace/reload entrypoints so singleton state can be hot-reloaded without process restart.
- Enforcement rule: in `src/services/**`, process-wide singleton statics (for example `OnceLock`/`LazyLock`) are only allowed in `runtime_lifecycle.rs` files. CI tests must fail when singleton statics appear in other service files.
- Distinguish runtime ownership from singleton enforcement: avoid hidden process-global mutable singletons, but when exclusivity is required, enforce it explicitly at the boundary bootstrap layer (for example daemon-instance guards), not through ambient static state.
- In-process service handles are not OS/process singletons: they may be cheaply cloned as façades over one owned runtime, and should not maintain their own competing runtime instances.
- Process-wide exclusivity belongs only to boundaries that actually require it. For the daemon entrypoint, enforce single-process startup explicitly in bootstrap/launch code; for ordinary services, prefer one runtime per daemon instance rather than global registries or ambient statics.
- If a future service truly needs exclusivity, define the ownership scope first (per call, per daemon runtime, per machine, or per external resource) and enforce it with an explicit guard/lease at that boundary rather than by naming or by hidden mutable globals.
- Current audit outcome: the existing non-daemon services in this crate (`connection`, `process`, `dns`, `firewall`, `tasks`, `rules`, `stats`, `config`, `subscription`) do not require extra process-wide exclusivity guards beyond daemon bootstrap; they should remain scoped to one runtime per daemon instance.
- Service observability should use lifecycle-provided subscriptions (`subscribe_status` via watch channel + `subscribe_events` via broadcast channel), not dedicated per-service monitor threads hidden inside trait internals.
- Subscription lifecycle should support explicit subscribe/unsubscribe hooks through scoped subscription handles (drop-based unsubscribe) and expose active subscriber counters via lifecycle monitor stats.
- Avoid top-level module free functions for stateful boundary behavior; prefer methods on domain/runtime structs.
- Enforce generics-first helper design for shared cross-domain logic when it improves reuse without hiding domain semantics or reducing readability.
- Shared functions that do not have clear domain ownership must be migrated to `utils/`; these helpers should be generic by default when type-safe and maintainable, rather than service-specific duplicates.
- Arc read cloning is evil at runtime: snapshot reads in runtime/hot paths must be pure Arc memreads over immutable snapshots, with no mutex/lock path, no async getter wrappers, and no clone-at-read call sites.
- Extend this philosophy to all immutable state access (state/cache/snapshot): when read-only data can be held as immutable shared state, prefer lock-free sync memread access and avoid async getter wrappers in runtime paths.
- API naming must express domain semantics, not ownership/copy mechanics: avoid implementation-leaking suffixes like `_cloned`, `_copy`, `_arc`; use semantic names (`get`, `peek`, `snapshot`, etc.) and let callers clone only where ownership requires it.
- Helper design rule:
	- avoid one-line passthrough wrappers that only rename or forward a single call without adding domain semantics, invariants, or error-context value,
	- avoid compatibility shims/aliases; when call sites are migrated, remove legacy helper wrappers in the same slice.

### 2. Trait-First Integration Boundaries

- Infra integrations must be consumed through `platform::ports::*` traits.
- `platform::adapters::*` and `platform::ffi::*` are implementation details behind those traits.
- Application/services/flows/workers should depend on ports, not concrete adapters/ffi modules.

### 3. Module Structure Follows Architecture

- Domain code lives in `services/`, `flows/`, `models/`, and other domain-owned boundary modules when they add concrete semantic value.
- Infra code lives in `platform/{ports,adapters,ffi}`.
- Helpers live only in `utils/`; integrations are not `utils`.

#### Data Contract Ownership Rule

- Shared data contracts must live under `models/` (or `models/<domain>/` when present), including:
	- DTO-like structs/enums passed across service/flow/worker boundaries,
	- serde-backed payload/config/transport structs,
	- reusable runtime memory/state snapshot structs consumed by more than one domain.
- Data contracts may implement shape-consistency helpers (for example parsing/validation/normalization) when these functions only enforce or preserve contract invariants.
- Keep data-contract helpers side-effect free: no cross-domain orchestration, I/O, or runtime ownership inside `models/` contract impls.
- Keep file-local/private execution helpers near usage only when they are not cross-boundary contracts.
- When touching a module with contract drift, prefer migrating contract types to `models/` in the same slice or add an explicit follow-up entry.

#### Worker Layout Decision

- Keep `src/workers/` as the runtime execution layer (shared worker contracts, lifecycle helpers, daemon wiring touchpoints), but organize worker implementations by domain/service subfolders for clarity.
- Avoid splitting worker ownership across both `services/*` and `workers/*` for the same concern at the same time; pick one location per worker family and keep imports stable per refactor slice.
- `workers/` owns reusable execution primitives (long-running loops, queue consumers/producers, watcher engines, OS/FFI adapters, backpressure/retry mechanics).
- Workers should be policy-agnostic where possible and expose small control/port surfaces.

#### `services/` Layout Rules

- One folder per service (`services/<service>/`), no `*_service` suffix in folder names.
- `services/<service>/mod.rs` stays thin (module wiring/re-exports only).
- Concrete implementation lives in `services/<service>/<service>.rs`.
- Avoid feature-split file churn: if a service is understandable as one unit, prefer co-locating runtime orchestration in `<service>.rs` instead of forcing `intent.rs` or `*Intent*` naming.
- Service-internal split parts live in service submodules/files, not as root-level service files.
- UI-facing gRPC client/session concerns live under `services/client` (`Client`, notification stream, UI session state).

#### `mod.rs` Linker-Only Rule

- `mod.rs` files are module wiring surfaces only (module declarations + re-exports).
- Functional code (`struct`/`enum`/`impl`/runtime logic) belongs in dedicated sibling files.
- Apply this consistently to `services/*`, `commands/*`, `flows/*`, and `workers/*` as those areas are touched.

#### `commands/` And `flows/` Rules

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
	- when flow internals become generic/reusable execution machinery, extract those internals into `workers/` and keep only orchestration policy in `flows/`.
- `flows/<domain>/mod.rs` stays linker-only; functional code lives in dedicated sibling files.

#### Flow-vs-Worker Extraction Heuristic

- Keep in `flows/` when logic answers "what should happen" (policy/decision path, domain orchestration, cross-service sequencing).
- Move to `workers/` when logic answers "how to run repeatedly" (generic loop engine, batching/drain mechanics, retry/backoff, channel pump, OS event polling).
- If a flow loop is specific to one domain but has reusable sub-mechanics, split the mechanics into `workers/runtime/*` helpers and keep the domain policy path in `flows/<domain>/*`.
- Runtime control stance for `connect` and `kernel`:
	- keep `connect` and `kernel` as flow-owned task orchestration,
	- reconsider `WorkerControl` adapters only if explicit start/stop/probe lifecycle commands are required for those domains.
- `commands/<domain>/mod.rs` must remain linker-only; implementations live in `commands/<domain>/<domain>.rs`.

#### API-Surface File Rule

- Main domain file (`services/<name>/<name>.rs`, `flows/<name>/<name>.rs`, `commands/<name>/<name>.rs`) should expose public API and orchestration entrypoints only.
- Non-API implementation details (helpers, worker control structs, parsing/state utilities, internal execution logic) must live in domain-specific sibling files (`storage.rs`, `runtime.rs`, `parsing.rs`, `internal.rs`, etc.).
- Keep exported signatures stable in main files; move implementation by delegation to sibling modules.
- Exception: keep tiny modules in one file when extraction would create trivial indirection.

#### Test Placement Rule

- All tests for a crate must live under the `src/tests/` directory of that crate (e.g. `src/tests/parsing/`, `src/tests/workers/`, `src/tests/services/`, etc.).
- Implementation files must not contain inline `mod tests { ... }` blocks with actual test functions.
- The **only** `#[cfg(test)]` or `#[tokio::test]` annotations permitted inside implementation files are:
	- `#[cfg(test)] #[path = "..."] mod <name>;` — a module declaration that wires a `src/tests/` file into the impl module's namespace for visibility (giving tests access to private items).
	- `#[cfg(test)] pub(super) ...` / `#[cfg(test)] pub(crate) ...` — visibility shims that expose private helpers or types exclusively to the test module above.
- Any annotation beyond those two forms (actual test functions, test harness setup, inline `#[test]` items) constitutes a violation and must be extracted to `src/tests/`.

### 4. Refactor Safety Rule

- Prefer extraction via stable wrappers first, then collapse wrappers in a second pass.
- Do not keep compatibility shims once call sites are migrated in the same refactor slice, including one-line helper aliases kept only for transitional naming.
- Keep behavior parity first; run `cargo check` and tests each slice.

### 5. Privileged Control Boundary Rule

- The daemon currently treats the connected UI client as a trusted control plane for `UPDATE_RULE`, `DELETE_RULE`, `UPDATE_CONFIG`, `ENABLE_FIREWALL`, `DISABLE_FIREWALL`, `RELOAD_FW_RULES`, and shutdown/log-level mutations once they arrive on the notification stream.
- This is an elevated-boundary risk, not a stable design target: those commands can mutate shared on-disk rules, runtime config, and system firewall state that are not scoped to a single desktop user session.
- Hardening direction: the Python UI must be treated as unprivileged-by-default for system-wide mutations until an explicit authorization model exists end-to-end.
- Nuance: owner-scoped policy is a valid future exception class, not a reason to keep the current broad trust model. Rule matching already supports `user.id`, and Linux firewall backends can express socket-owner filters for locally generated traffic (`nft` `meta skuid` / `meta skgid`, `iptables` `-m owner --uid-owner/--gid-owner`).
- Privileged mutations must be separated from ordinary user-interaction commands:
	- unprivileged/user-plane: prompt replies, per-connection verdict participation, read-only inspection, non-system UI state,
	- privileged/control-plane: rule persistence, rule deletion, config apply, firewall enable/disable, firewall payload reload, daemon shutdown, and any future host-wide task or backend reconfiguration.
- Owner-scoped rule or firewall mutation is an explicit supported path when all of the following are true:
	- the daemon has an authenticated caller identity (UID and optionally GID/capability context),
	- the requested mutation is statically proven to target only that caller's own UID/GID scope,
	- the backend semantics are limited to locally generated traffic where owner matching is meaningful,
	- rule insertion/update cannot escape its declared owner scope through raw parameters, broad chain policy edits, target changes, or precedence side effects.
- Locality boundary: the owner-scoped UID/GID exception applies only to local daemon + local UI client control paths where OS identity can be directly verified from local peer credentials.
- If those conditions are met, user-scoped rule and firewall updates from the Python client should be accepted without elevated privileges, because they are constrained to the authenticated caller scope.
- Non-user-scoped mutations (global rules, shared firewall policy, config apply, shutdown, chain policy edits, or any rule that cannot be proven owner-scoped) must require elevated authorization.
- Privileged control must not rely on transport connectivity alone. TLS or local socket reachability authenticates the peer/channel; it does not by itself authorize host-wide mutations.
- Any future privileged path must carry an explicit privilege signal at the command/session boundary and enforce it in the daemon before dispatch into services.
- Do not bury privilege checks inside `RuleService` or `FirewallService`; enforce them at ingress (`NotificationFlow` / command mapping / command control) so domain services can assume already-authorized calls.
- Elevated authorization should use OS-backed identity and policy checks instead of ad-hoc bearer secrets. Preferred primitives on Linux are peer credentials on local sockets (`SO_PEERCRED`/SCM credentials), process capabilities, and a policy authorization service (for example polkit via D-Bus) for admin-grant decisions.
- Backend caveat: owner matching is not a universal firewall primitive. `iptables` owner matching is for locally generated packets and valid in `OUTPUT` / `POSTROUTING`; nftables socket-owner matching is likewise tied to the originating socket context. Do not generalize owner-scoped authorization to arbitrary forwarded/input policy edits.
- Remote-node caveat: do not project local UID/GID owner scope directly across machines. For remote daemons, authorization must be principal/capability based for that node, not raw caller UID trust from the management host.
- Until the Python client protocol supports privilege separation, prefer one of these transitional stances:
	- reject privileged notification commands by default, or
	- gate them behind an explicit local-admin/experimental config flag with loud audit logging.
- Required future design properties for privileged commands:
	- explicit command classification (`unprivileged` vs `privileged`),
	- daemon-side authorization check before command queueing or dispatch,
	- auditable logs for allow/deny decisions,
	- explicit feature/tunable gate for privileged-path rollout with secure defaults.

#### Privileged Rollout Guard Rule

- Privileged command enforcement and exposure must be guarded by explicit rollout controls:
	- compile-time or feature-flag guard for privileged command path enablement,
	- runtime config/tunable guard for deployment policy.
- Secure defaults:
	- privileged mutation path disabled by default for remote management,
	- local privileged path denied by default unless authorization mode is explicitly enabled.
- Suggested tunable surface:
	- `auth.mode = disabled | local-only | local+remote-capabilities`,
	- `auth.remote.require_pop = true|false` (default `true`),
	- `auth.remote.token_max_ttl_seconds`,
	- `auth.audit.enforce = true|false` (default `true`).
- Any mode that enables privileged mutations without capability checks must be marked experimental/unsafe and emit loud startup/runtime warnings.

#### Remote Node Authorization Rule

- Scope split:
	- local daemon + local UI client: enforce UID/GID owner-scope validator model,
	- remote daemon management: enforce delegated capability model; no implicit owner-scope shortcut.
- Remote authorization model must include:
	- authenticated principal identity (user/service account) via strong channel auth (mTLS or equivalent),
	- explicit per-node capability grants (`rules.owner.write`, `rules.global.write`, `firewall.owner.write`, `firewall.global.write`, `config.write`, `daemon.control.stop`, etc.),
	- command authorization as capability check against the requested mutation class,
	- optional owner-scope capability constraints (`owner_uid_set`, `owner_gid_set`) for delegated user-limited administration.
- Proof token guidance for remote control:
	- if tokens are used, require short-lived signed tokens with audience = target daemon/node,
	- require proof-of-possession binding (for example mTLS-bound token or DPoP-style key confirmation) so intercepted bearer strings are insufficient,
	- include nonce/jti + expiry and enforce replay protection at daemon ingress.
- Remote decision pipeline:
	- authenticate channel principal,
	- validate token/session proof (if present),
	- resolve node-scoped capability grants,
	- classify command,
	- run scope validator when command claims owner-scoped mutation,
	- enforce allow/deny and emit audit reason codes.
- Default fail-closed posture for remote daemons:
	- missing capability mapping, unverifiable proof token, or ambiguous scope semantics => deny,
	- never downgrade a remote privileged mutation into local-style owner shortcut unless node policy explicitly allows that exact delegation.

#### Ingress Enforcement Matrix (Implementation Blueprint)

- Enforce authorization at notification ingress before `ClientCommand` queueing.
- Suggested command classes:
	- `user_scoped_allowed`: caller-authenticated, owner-scope-validated rule/firewall mutations,
	- `elevated_required`: global/shared policy mutations,
	- `always_allowed`: non-mutating or session-local commands,
	- `always_denied`: malformed or scope-escaping payloads.
- Suggested default mapping:
	- `UPDATE_RULE`, `ENABLE_RULE`, `DISABLE_RULE`, `DELETE_RULE`:
		- allow only when payload is proven owner-scoped to caller UID/GID,
		- otherwise require elevated authorization,
	- `ENABLE_FIREWALL`, `DISABLE_FIREWALL`, `RELOAD_FW_RULES`:
		- allow only for owner-scoped local-socket owner matches,
		- global chain/table/policy or ambiguous expressions require elevated authorization,
	- `UPDATE_CONFIG`, `STOP`, runtime-wide worker reconfiguration: always elevated,
	- read-only/session-local notifications: always allowed.

#### Identity And Elevation Flow (Linux)

- Caller identity:
	- local socket mode: require peer credentials (`SO_PEERCRED`/SCM credentials) and bind command decisions to effective UID/GID,
	- remote/TLS mode: bind commands to authenticated principal identity and node-scoped capability grants; do not rely on raw remote UID/GID equivalence.
- Elevation proof:
	- prefer policy-authorization service checks (polkit via D-Bus) for admin-grant decisions,
	- optionally accept root-equivalent caller context only when explicitly configured for local-admin mode,
	- for remote mode, require capability-bearing authorization context and (when tokenized) proof-of-possession token validation;
	- do not treat transport encryption alone as elevation proof.
- Decision pipeline per command:
	- parse and normalize payload,
	- classify command,
	- derive caller identity,
	- run scope validator (owner-only containment),
	- if needed run elevation check,
	- emit allow/deny audit event with reason code,
	- enqueue only authorized command.

#### Scope Validator Requirements

- Rule payload validator must prove all operands/targets stay within caller UID/GID scope.
- Firewall payload validator must reject or escalate when encountering:
	- broad chain policy edits,
	- raw parameter fragments that cannot be normalized/understood,
	- targets that affect non-owner traffic or routing behavior,
	- mixed-scope expression sets (owner + non-owner predicates).
- Validation mode should be fail-closed: unknown expression semantics => `elevated_required` or deny.

#### Audit Fields

- Emit structured audit records for every authorization decision with:
	- command/action,
	- caller identity source and UID/GID,
	- classification result,
	- scope validation result,
	- elevation check result,
	- final decision and denial reason code.

### 6. Cache Selection Rule

- Dual-layer cache (`DualLayerLruMap` / `SyncDualLayerLruMap`) is preferred by default for read-dominant, shared runtime caches where lock-free immutable snapshot reads are important and eventual recency convergence is acceptable.
- Dual-layer is not mandatory for every cache: choose plain `LruCache` or plain map-based cache when caller profile is write-heavy/high-churn, strict mutation/recency semantics are required, or ownership is local/ephemeral.
- Not every immutable snapshot is a cache. For small whole-runtime state that is rebuilt only on explicit control/config transitions, prefer build-once/publish-once `Arc<...>` snapshots over dual-layer cache machinery.
- Capacity and rollout guidance for dual-layer-backed caches:
	- tune capacity with publish cost in mind,
	- avoid broad dual-layer rollout to high-churn writers until publish-path optimization and metrics instrumentation are in place,
	- keep domain-level capacity tunables explicit and documented when dual-layer is selected.
- Required observability for dual-layer evolution:
	- expose touch-drop rate / touch-queue pressure signals,
	- expose publish-path cost signals (latency and allocation/churn-oriented counters) for regression tracking.

#### Cache Caller Matrix

| Cache caller class | Read/Write profile | Concurrency/ownership | Semantics tolerance | Preferred implementation |
|---|---|---|---|---|
| DNS shared lookup cache | read-heavy with periodic writes | shared across runtime paths | eventual recency acceptable | dual-layer |
| Process inspection cache | read-heavy with mutation side bookkeeping | shared service cache | eventual recency acceptable; strict coherence guarded by service checks | dual-layer + dedicated mutable side-state |
| Connection owner PID caches | read-heavy with moderate writes | shared sync runtime access | eventual recency acceptable | sync dual-layer |
| Firewall runtime snapshot | low-churn control/config writes; frequent reads | shared service/runtime readers | strict whole-state replacement on publish; no recency queue needed | whole-runtime Arc snapshot via watch publish |
| Write-heavy churn cache | write-heavy/high churn | any | strict recency/mutation visibility required | plain LRU or plain map |
| Local ephemeral cache | mixed/local | single owner or short-lived scope | no shared snapshot requirement | plain LRU or plain map |

## Tracker Retention Rules

- [daemon-rs/TODO.md](TODO.md) stays tracker-focused and keeps only:
	- active backlog
	- current status snapshot
	- concise dated history entries
- Compatibility matrices and long-form rationale live in [daemon-rs/COMPATIBILITY.md](COMPATIBILITY.md).
- Version history is archived in [daemon-rs/CHANGELOG.md](CHANGELOG.md).
- User-facing installation/runtime guide lives in [daemon-rs/DOCS.md](DOCS.md).
- Use `git log -- daemon-rs/TODO.md` for tracker edit provenance.

## Update Rules

These preserve the original tracker intent and add extraction-aware rules.

1. Update [daemon-rs/TODO.md](TODO.md) directly after each parity or async/runtime change.
2. Prune closed items so the tracker stays focused on active work.
3. Keep behavior references concrete (file + behavior), not generic.
4. Keep [daemon-rs/TODO.md](TODO.md) as the single active tracker file.
5. Separate-PR items are excluded from milestone gating.
6. Keep large matrices out of TODO; link to [daemon-rs/COMPATIBILITY.md](COMPATIBILITY.md).
7. Any mapping change in tracker scope must update compatibility tables in the same commit.
8. When introducing a new canonical project document (`*.md`) used by operators/contributors, add or update its link in TODO's `Documentation References` section in the same commit.

## Compatibility Authoring Rules

- Core parity belongs in the main matrix in [daemon-rs/COMPATIBILITY.md](COMPATIBILITY.md).
- Out-of-core deltas belong in Extended Feature/Behavior Matrix.
- Architecture rationale belongs in Architecture Delta Notes.
- File-level mapping stays scoped to critical paths; avoid full repo-wide inventory noise.
- Mark non-equivalent mappings explicitly (`Rust-only`, `Go-only`).

## Compatibility Table Quality Gates

Before finalizing compatibility updates:

1. Every new Rust area in tracker scope has either:
	- a mapped Go counterpart, or
	- an explicit `Rust-only` marker.
2. Every intentionally unmatched Go behavior has an explicit `Go-only` note (main matrix or file-level appendix).
3. Mapping cardinality is explicit in file-level appendix (`1:1`, `1:N`, `N:1`, `N:N`).
4. High-risk runtime paths remain present in file-level appendix:
	- process/audit ingest
	- netlink/socket-diag/NFQUEUE
	- command and verdict paths
	- orchestration startup/shutdown

## Design Boundary Rules

- Keep orchestration concerns in Rust `daemon/` layer; avoid leaking startup/shutdown policy into domain services.
- Keep protocol/kernel specifics in `platform/adapters/` and `platform/ffi/` (legacy fallback), not in business services.
- Keep `platform/ports/` as minimal abstraction seams; avoid embedding adapter specifics in ports.
- Keep `bus.rs` typed and narrow; no domain decision logic in bus transport.
- Keep `utils/` as helper layer; avoid shifting domain ownership into utility functions.

## Change Workflow

When behavior changes affect parity:

1. Update code.
2. Update [daemon-rs/COMPATIBILITY.md](COMPATIBILITY.md) tables.
3. Add concise dated tracker entry in [daemon-rs/TODO.md](TODO.md).
4. If release-facing, add corresponding note in [daemon-rs/CHANGELOG.md](CHANGELOG.md).

---

## Violation Tracker

Open violations found during the 2026-03-24 crate-wide audit. Each entry includes the rule violated, the file(s) affected, a description, and current status.

> **Status key**: `OPEN` — not yet addressed · `IN-PROGRESS` — work started · `RESOLVED` — fixed and verified.

---

### Rule 2 — Trait-First Integration Boundaries

#### V-01 · `workers/runtime/nfqueue/worker.rs` — direct adapter import
- **Rule**: Application/services/flows/workers must depend on ports, not concrete adapters/ffi.
- **Location**: `src/workers/runtime/nfqueue/worker.rs:14` — `use crate::platform::adapters::nfqueue_netlink;`
- **Detail**: `NfqueueWorker` directly calls `nfqueue_netlink::nfqueue_netlink_experiment_enabled()`, `NfqueueNetlinkAdapter::run()`, and `NfqueueNetlinkAdapter::preflight()` — all concrete adapter methods with no port trait in front. This couples the nfqueue worker to the adapter implementation.
- **Fix direction**: Extract a `NfqueueNetlinkPort` (or extend an existing port) for `preflight`/`run`/`experiment_enabled`, inject it into `NfqueueWorker`.
- **Status**: `RESOLVED`

#### V-02 · `workers/network/netlink_addr_worker.rs` — direct adapter import
- **Rule**: Application/services/flows/workers must depend on ports, not concrete adapters/ffi.
- **Location**: `src/workers/network/netlink_addr_worker.rs:12` — `use crate::platform::adapters::net_iface::NetIfaceAdapter;`
- **Detail**: `NetlinkAddrWorkerControl::fetch_local_addrs()` calls `NetIfaceAdapter` directly, bypassing any port abstraction.
- **Fix direction**: Introduce a `LocalAddrPort` trait for address enumeration, inject into the worker. Or — if the worker's callers only consume the published `Arc<Vec<String>>` snapshot — keep the FFI call internal but gate it behind a thin port-backed helper in `platform/`.
- **Status**: `RESOLVED`

---

### Rule 1 — Domain Boundaries Own Behavior And Runtime State

#### V-03 · `workers/dns/dns_worker.rs` — global mutable DNS monitor state
- **Rule**: Long-lived service runtime control must use a trait-based lifecycle surface, not global mutable singleton functions. Avoid top-level module free functions/globals for stateful boundary behavior.
- **Location**: `src/workers/dns/dns_worker.rs:40` — `static DNS_MONITOR_STATE: AtomicU8`
- **Detail**: DNS monitor FSM state (`IDLE → VARLINK_CONNECTING → SUBSCRIBED → DISCONNECTED → STOPPED`) is stored in a crate-global `AtomicU8`. This mutable runtime state is invisible to the lifecycle/subscription observe surface and cannot be queried or reset without reading global.
- **Fix direction**: Move monitor FSM state into the worker runtime struct (or a `DnsMonitorRuntime` struct). Expose state via the `WorkerControl::state()` or a `subscribe_status` watch channel.
- **Status**: `RESOLVED`

#### V-04 · `workers/network/netlink_addr_worker.rs` — global mutable address store
- **Rule**: Domain runtime state must not be hidden in crate-global singletons; prefer lifecycle-managed runtime structs.
- **Location**: `src/workers/network/netlink_addr_worker.rs:17` — `static LOCAL_ADDRS: OnceLock<RwLock<Arc<Vec<String>>>>`
- **Detail**: Local network address state is held in a module-level global `RwLock<Arc<Vec<String>>>`. Callers retrieve it via a free function `NetlinkAddrWorkerControl::local_addrs()`. Neither the state nor the readership is accounted for in any service lifecycle.
- **Fix direction**: Lift the address store into a runtime struct owned by the worker and returned on `spawn()`. Callers receive an `Arc<RwLock<...>>` (or a `watch::Receiver`) from the spawn return value rather than from a global.
- **Status**: `RESOLVED`

#### V-05 · `services/connection/ebpf.rs` — global BPF map id cache
- **Rule**: Domain state must not be hidden behind global mutable singletons.
- **Location**: `src/services/connection/ebpf.rs:13` — `static BPF_MAP_IDS: OnceLock<Mutex<BpfMapIdCache>>`
- **Detail**: BPF map id resolution is backed by a TTL-refresh cache stored in a crate-global `OnceLock<Mutex<...>>`. The cache is never surfaced through the `ConnectionService` API or any lifecycle mechanism; it is silently shared across all call sites.
- **Fix direction**: Move `BpfMapIdCache` into `ConnectionService` state; expose it through the existing service struct rather than a global. Allows capacity tuning and test isolation.
- **Status**: `RESOLVED`

#### V-06 · `services/client/alerts.rs` — global alert overflow ring
- **Rule**: Domain runtime state must live in the owning domain/service boundary, not global mutable singletons.
- **Location**: `src/services/client/alerts.rs:14-15` — `static ALERT_OVERFLOW: OnceLock<Mutex<RingBuffer<UiAlert>>>`, `configure_alert_overflow_ring_capacity()` free function
- **Detail**: The alert overflow ring is a global `OnceLock<Mutex<...>>` configured via a free function out-of-band from `ClientService` lifecycle. Capacity is likewise stored in a global `AtomicUsize`. This prevents test isolation and hides runtime state from the service boundary.
- **Fix direction**: Move the overflow ring into `ClientService` (or `AlertsState`) state; configure capacity at construction time via the lifecycle API.
- **Status**: `RESOLVED`

#### V-07 · `services/task/reply.rs` — global alert sender singleton
- **Rule**: Domain state must not be configured via top-level free functions outside the lifecycle surface.
- **Location**: `src/services/task/reply.rs:12` — `static ALERT_TX: OnceLock<tokio::sync::mpsc::Sender<UiAlert>>`, `configure_alert_sender()` free function
- **Detail**: The task-reply module sets a global `OnceLock` channel sender via `configure_alert_sender()` called from startup wiring. This couples task reply to a side-channel global rather than an explicit dependency on the service struct.
- **Fix direction**: Pass `alert_tx` as an explicit argument to the task reply constructor or inject it into the `TaskService` (or `TaskRuntimeService`), eliminating the global configure call.
- **Status**: `RESOLVED`

#### V-08 · `daemon/kernel_pipeline.rs` — global drop/ingress counter singletons
- **Rule**: Domain counters belonging to on a pipeline boundary must live in a named runtime struct, not module-level `static OnceLock<...>`.
- **Location**: `src/daemon/kernel_pipeline.rs:79,88` — `static KERNEL_PIPELINE_DROP_COUNTERS` and `static KERNEL_PIPELINE_INGRESS_COUNTERS`
- **Detail**: Pipeline-level drop and ingress counters are stored as `static OnceLock<...>` in the daemon root. These global statics initialise on first use and cannot be reset or inspected through a lifecycle surface.
- **Fix direction**: Elevate the counters into a `KernelPipelineCounters` struct held by the `Daemon` (or `KernelPipeline` runtime struct) and pass them through the relevant pipeline paths rather than reading from globals.
- **Status**: `RESOLVED`

---

### Rule 3 — Module Structure Follows Architecture

#### V-09 · `workers/runtime/ebpf/mod.rs` — macro defined in mod.rs (linker-only violation)
- **Rule**: `mod.rs` files are module wiring surfaces only; functional code belongs in dedicated sibling files.
- **Location**: `src/workers/runtime/ebpf/mod.rs`
- **Detail**: `mod.rs` contains a `#[macro_export] macro_rules! ebpf_worker_newtype! { ... }` — a 60-line functional macro. Macros are functional code and their definitions should live in a dedicated sibling file (e.g. `macros.rs` or `newtype.rs`), not in `mod.rs`.
- **Fix direction**: Move `ebpf_worker_newtype!` to `src/workers/runtime/ebpf/newtype.rs` (or `macros.rs`); `mod.rs` becomes a pure `pub mod control; pub use newtype::*;`.
- **Status**: `RESOLVED`

#### V-10 · `workers/runtime/control/control.rs` — top-level free functions for state derivation
- **Rule**: Avoid top-level module free functions for boundary behavior; prefer methods on domain/runtime structs.
- **Location**: `src/workers/runtime/control/control.rs:17-51` — four `pub fn` free functions: `worker_state_from_thread_handle`, `worker_join_status_from_thread_result`, `restartable_worker_state_from_runtime`, `restartable_worker_is_finished_from_runtime`
- **Detail**: These are pure derivation helpers called inside the `impl_restartable_thread_worker_control!` macro. They are stateless and individually simple, but exposing them as free public functions rather than internal helpers or associated functions leaks implementation detail and invites unguarded call sites.
- **Fix direction**: Make these `pub(crate)` or `pub(super)` helpers, or pull them inline into the macro body / an internal trait helper, depending on what reduces public surface most cleanly.
- **Status**: `RESOLVED`

#### V-11 · `services/lifecycle.rs` — flat file outside subfolder convention
- **Rule**: Service-internal split parts live in service submodules/files; `services/<service>/mod.rs` stays thin.
- **Location**: `src/services/lifecycle.rs` (207 lines)
- **Detail**: `lifecycle.rs` sits as a flat file under `services/` rather than in a `services/lifecycle/` subfolder. It contains shared subscription/lifecycle primitives (`StatusSubscription`, `EventSubscription`) used by multiple services. It does not represent a runnable service, so a full subfolder conversion may be overkill — but if this file grows it should migrate to `services/lifecycle/` for consistency.
- **Fix direction**: Low priority. If the file grows beyond ~300 lines or gains submodules, migrate to `services/lifecycle/lifecycle.rs` pattern. Otherwise tolerated.
- **Status**: `RESOLVED`

---

### Rule 5 — Privileged Control Boundary

#### V-12 · Notification flow — no privilege classification at ingress
- **Rule**: Privileged mutations must be separated from unprivileged commands at ingress; domain services must assume already-authorized calls.
- **Location**: `src/flows/notification/notification.rs` (and `src/commands/*/`)
- **Detail**: `UPDATE_RULE`, `DELETE_RULE`, `UPDATE_CONFIG`, `ENABLE_FIREWALL`, `DISABLE_FIREWALL`, `RELOAD_FW_RULES` and daemon control commands arrive on the notification stream and are dispatched without any caller identity check or command classification. The entire notification stream is implicitly trusted.
- **Fix direction**: See §5 Privileged Control Boundary Rule and Ingress Enforcement Matrix. This is a known architectural risk tracked as an open work item in [daemon-rs/TODO.md](TODO.md). Adding the entry here as a cross-reference.
- **Status**: `OPEN` (tracked in TODO.md → Privileged Control Boundary backlog)
