# Daemon-RS Design and Maintenance Rules

This document defines maintenance rules for tracker, compatibility, and design documentation.

## Document Ownership

- [daemon-rs/TODO.md](TODO.md): active tracker only (status snapshot, active backlog, concise dated entries).
- [daemon-rs/COMPATIBILITY.md](COMPATIBILITY.md): full parity/compatibility reference (all large tables and rationale).
- [daemon-rs/DESIGN_RULES.md](DESIGN_RULES.md): governance rules for how tracker and compatibility docs are maintained.
- [daemon-rs/CHANGELOG.md](CHANGELOG.md): archived version-by-version notes.
- [daemon-rs/PERF.md](PERF.md): performance/stress baselines and perf history.


## Part I — Cross-Cutting Architectural Rules

This section captures rules that span all service, flow, worker, and platform
boundaries. They govern how the codebase is organized, how domain responsibility is
distributed, and how infrastructural primitives are selected and named.

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
- API naming must express domain semantics, not ownership/copy mechanics: avoid implementation-leaking suffixes like `_cloned`, `_copy`, `_arc`; use semantic names (`get`, `peek`, `snapshot`, etc.) and let callers clone only where ownership requires it.
- Helper design rule:
	- avoid one-line passthrough wrappers that only rename or forward a single call without adding domain semantics, invariants, or error-context value,
	- avoid compatibility shims/aliases; when call sites are migrated, remove legacy helper wrappers in the same slice.

#### Hot-Path State Access Rule

Hot paths — verdict matching, packet ingest, DNS resolution, connection lookup — have
strict latency requirements. All shared state reads on these paths must satisfy the
following constraints without exception.

**Read discipline:**
- **Wait-free or lock-free.** No mutex acquisitions (`Mutex::lock()`, `RwLock::read()`),
  no async primitive waits (`.lock().await`, `.read().await`), no channel receives inside
  `flows/verdict/`, `flows/connect/`, `flows/kernel/`, `workers/runtime/ebpf/`, or any
  per-packet / per-verdict code path.
- **Snapshot-based.** Shared rule, config, and firewall state must be held as immutable
  `Arc<T>` snapshots. The hot path loads the snapshot pointer atomically and reads from
  the immutable value — it never modifies shared state and never waits for a writer.
- **No deep clone at read.** `Arc::clone()` (atomic refcount increment) is acceptable when
  shared ownership of the snapshot is needed downstream. Cloning the underlying `T`
  (dereferencing and copying a full struct, `Vec`, `HashMap`, etc.) inside a hot-path
  read is a violation.
- **No async getter wrappers.** Service-handle methods that `.await` a lock or channel
  just to return a snapshot value must not be called from hot-path code. Expose the
  snapshot through a synchronous accessor returning `Arc<T>` or the result of
  `ArcSwap::load()`.

**Preferred read primitives by state type:**

| State type | Hot-path read | Notes |
|---|---|---|
| Rule / config snapshot | `ArcSwap<T>::load()` (wait-free) | Write path replaces the whole snapshot atomically |
| DNS / process / connection cache | `ConcurrentLruCache::get()` (lock-free per shard) | Never iterate on hot path |
| Per-connection epoch / alias map | `DashMap::get()` or `remove()` (per-shard lock) | Iteration forbidden on hot path — see below |
| Firewall runtime snapshot | `Arc::clone()` from `watch::Receiver::borrow()` | `borrow()` is synchronous; clone is refcount only |
| eBPF map catalogue / interface name | `ArcSwap<HashMap>::load()` | Refresh off hot path; store full replacement |

**Violation signals** (code-review flags in `flows/`, `workers/runtime/`, hot-path service methods):
- `Mutex::lock()`, `RwLock::read()`, `.read().await`, or `.lock().await` inside per-packet or per-verdict code.
- `.clone()` on a non-`Arc` snapshot value (cloning a `Vec`, `HashMap`, `Config`, `RuleMatchCaches`, etc.) at read time.
- `DashMap` iteration (`iter()`, `iter_mut()`, `retain()`) on a per-packet or per-verdict call path.
- An `async fn` accessor on a service handle that is the only path to read shared rule/config state.
- `tokio::sync::Mutex` guarding read-dominant immutable state where `ArcSwap` would serve.
- `tokio::sync::RwLock` used for a snapshot that is written infrequently but read on every connection.

**Cross-reference:** §9 Cache And Shared State Selection defines the full primitive matrix
and per-use-case guidance for write paths and capacity sizing. This rule establishes the
*mandatory latency constraint* that hot-path code must satisfy regardless of which
primitive is chosen.


### 2. Module Layout Rules

Rules for where code lives, how responsibilities are split across files, and how
module surfaces are bounded.

#### Placement Rules

- Domain code lives in `services/`, `flows/`, `models/`, and other domain-owned boundary modules when they add concrete semantic value.
- Infra code lives in `platform/{ports,adapters,ffi}`.
- Helpers live only in `utils/`; integrations are not `utils`.

#### `services/` Layout Rules

- One folder per service (`services/<service>/`), no `*_service` suffix in folder names.
- `services/<service>/mod.rs` stays thin (module wiring/re-exports only).
- Concrete implementation lives in `services/<service>/<service>.rs`.
- Avoid feature-split file churn: if a service is understandable as one unit, prefer co-locating runtime orchestration in `<service>.rs` instead of forcing `intent.rs` or `*Intent*` naming.
- Service-internal split parts live in service submodules/files, not as root-level service files.
- UI-facing client/session concerns live under `services/client` (`Client`, notification stream, UI session state); transport-specific adapters (current gRPC/tonic path, future non-gRPC frontends) hang off that boundary rather than owning daemon policy directly.


#### Worker Layout Decision

- Keep `src/workers/` as the runtime execution layer (shared worker contracts, lifecycle helpers, daemon wiring touchpoints), but organize worker implementations by domain/service subfolders for clarity.
- Avoid splitting worker ownership across both `services/*` and `workers/*` for the same concern at the same time; pick one location per worker family and keep imports stable per refactor slice.
- `workers/` owns reusable execution primitives (long-running loops, queue consumers/producers, watcher engines, OS/FFI adapters, backpressure/retry mechanics).
- Workers should be policy-agnostic where possible and expose small control/port surfaces.


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


#### `mod.rs` Linker-Only Rule

- `mod.rs` files are module wiring surfaces only (module declarations + re-exports).
- Functional code (`struct`/`enum`/`impl`/runtime logic) belongs in dedicated sibling files.
- Apply this consistently to `services/*`, `commands/*`, `flows/*`, and `workers/*` as those areas are touched.


#### API-Surface File Rule

- Main domain file (`services/<name>/<name>.rs`, `flows/<name>/<name>.rs`, `commands/<name>/<name>.rs`) should expose public API and orchestration entrypoints only.
- Non-API implementation details (helpers, worker control structs, parsing/state utilities, internal execution logic) must live in domain-specific sibling files (`storage.rs`, `runtime.rs`, `parsing.rs`, `internal.rs`, etc.).
- Keep exported signatures stable in main files; move implementation by delegation to sibling modules.
- Exception: keep tiny modules in one file when extraction would create trivial indirection.

#### File-Size Enforcement Rule

- Files in `services/`, `flows/`, `commands/`, and `workers/` exceeding ~500 lines (excluding blank lines, doc comments, and `#[cfg(test)]` wiring) are a split signal.
- The main domain file must be split by extracting non-API implementation into named sibling files per the API-Surface File Rule above.
- Splitting has non-trivial incremental build benefits: Rust recompiles at the file (CGU) boundary, so keeping files under the split threshold reduces unnecessary recompilation cascades.
- Enforcement is incremental: each PR that touches a file over the threshold must either reduce it or add a follow-up entry to TODO.md with a concrete split plan.
- CI validation: run `find src -name '*.rs' ! -path '*/tests/*' | xargs wc -l | awk '$1 > 500 && $2 != "total"'` in `crates/daemon/` as a review gate; failing files must be justified or split.


#### Test Placement Rule

- All tests for a crate must live under the `src/tests/` directory of that crate (e.g. `src/tests/parsing/`, `src/tests/workers/`, `src/tests/services/`, etc.).
- Implementation files must not contain inline `mod tests { ... }` blocks with actual test functions.
- The **only** `#[cfg(test)]` or `#[tokio::test]` annotations permitted inside implementation files are:
	- `#[cfg(test)] #[path = "..."] mod <name>;` — a module declaration that wires a `src/tests/` file into the impl module's namespace for visibility (giving tests access to private items).
	- `#[cfg(test)] pub(super) ...` / `#[cfg(test)] pub(crate) ...` — visibility shims that expose private helpers or types exclusively to the test module above.
- Any annotation beyond those two forms (actual test functions, test harness setup, inline `#[test]` items) constitutes a violation and must be extracted to `src/tests/`.


### 3. Trait-First Integration Boundaries
- Infra integrations must be consumed through `platform::ports::*` traits.
- `platform::adapters::*` and `platform::ffi::*` are implementation details behind those traits.
- Application/services/flows/workers should depend on ports, not concrete adapters/ffi modules.


### 4. Data Contract Rules

#### Data Contract Ownership Rule

- Shared data contracts must live under `models/` (or `models/<domain>/` when present), including:
	- DTO-like structs/enums passed across service/flow/worker boundaries,
	- serde-backed payload/config/transport structs,
	- reusable runtime memory/state snapshot structs consumed by more than one domain.
- Data contracts may implement shape-consistency helpers (for example parsing/validation/normalization) when these functions only enforce or preserve contract invariants.
- Keep data-contract helpers side-effect free: no cross-domain orchestration, I/O, or runtime ownership inside `models/` contract impls.
- Keep file-local/private execution helpers near usage only when they are not cross-boundary contracts.
- When touching a module with contract drift, prefer migrating contract types to `models/` in the same slice or add an explicit follow-up entry.

#### Canonical Domain Model And Wire Contract Rule

- Canonical runtime/domain data contracts live in `models/`; they are the source of truth for invariants and semantics.
- **Every external serialization format is a wire contract, not the internal domain model.**  This applies equally to:
  - Protobuf (`*.proto`) / gRPC transport — generated `pb::*` types.
  - JSON file storage (on-disk config, rules, firewall) — `Raw*` / `Persisted*` serde shapes.
  - JSON notification payloads arriving over the gRPC `Notifications` stream — `Incoming*` serde shapes.
  - Future OpenWrt UCI config files — `RawUci*` serde shapes (TBD).
  - Future ubus RPC messages — `RawUbus*` serde shapes (TBD).
  - Any future wire format (XML, CBOR, MessagePack, etc.) follows the same convention.
- **Wire types must stay at adapter boundaries.**  They must not appear inside core service / flow / policy logic.
  - Protobuf: `pb::*` constrained to transport handlers, gRPC stubs, and explicit mapper modules.
  - JSON file: `Raw*` / `Persisted*` constrained to file storage adapters (`services/*/storage.rs`, `services/storage/storage.rs`).
  - JSON notification data: `Incoming*` constrained to command mapper modules (`commands/*/`).
  - Future UCI/ubus: `RawUci*` / `RawUbus*` constrained to the OpenWrt adapter layer (`platform/adapters/openwrt/` or similar, once that adapter is introduced).
- **Every non-trivial wire ingress/egress path must map explicitly through domain models** (`wire → model` on ingress, `model → wire` on egress).
- **Naming convention for wire types in `models/`:**
  - `Raw*` — ingress-only serde shapes (deserialize from external source; no `Serialize` derive unless it is also a round-trip persisted format).  Also applies to kernel / OS state read from system interfaces (e.g. `RawBpfMap` from `procfs`/`bpffs`).
  - `Persisted*` — egress-only serde shapes (serialize to storage; companion to `Raw*` when in/out shapes differ materially).
  - `Incoming*` — short-lived serde shapes for inbound notification / RPC data payloads.
  - Domain types (`RuleRecord`, `Config`, `RuleOperator`, etc.) — must **not** carry `#[derive(Serialize, Deserialize)]` for external wire shapes.  `Serialize` / `Deserialize` on a domain type is a violation signal requiring justification or extraction to a wire companion type.
- **File-level naming exemptions** — the following `models/` file patterns are exempt from per-type naming requirements because the file name itself signals intent:
  - `models/*_storage.rs` — on-disk / database persistence types.
  - `models/*_config.rs` — configuration-file deserialization shapes.
  - `models/*_wire.rs` — outgoing transient IPC/RPC payloads serialized but not stored (e.g. task result frames sent to the UI over gRPC).  Types in `*_wire.rs` must carry only `Serialize`, never `Deserialize`, unless the payload is genuinely bidirectional.
- **Violation signal:** `Serialize` or `Deserialize` on a type outside `models/*_storage.rs`, `models/*_config.rs`, `models/*_wire.rs`, or an `Incoming*` / `Raw*` / `Persisted*` type name is a code-review flag.  The reviewer must confirm it is a deliberate cross-boundary choice or require extraction.
- **Add/maintain mapping modules near adapter boundaries** so alternate wire formats (JSON/WebSocket, ubus, UCI, CLI/TUI IPC) can reuse domain policy without duplicating authorization or business rules.
- External API stability can still be anchored on protobuf or JSON file compatibility, but internal refactors must preserve domain-model ownership and avoid bleeding wire-only fields into core runtime structs.
- **OpenWrt target notes:** UCI config files use a flat INI-like text format; ubus uses a JSON-over-Unix-socket RPC protocol.  When these adapters are introduced:
  - UCI ingress must parse into `RawUci*` wire types then map to domain models via an explicit conversion function, analogous to `rule_record_from_proto` for protobuf.
  - ubus RPC handlers must parse their JSON arguments into `RawUbus*` types at the adapter boundary; the same domain policy functions (owner scope, authorization, classification) apply unchanged.
  - No UCI or ubus format assumptions must leak into `services/`, `flows/`, or `models/` domain types.


### 5. Refactor Safety Rule

- Prefer extraction via stable wrappers first, then collapse wrappers in a second pass.
- Do not keep compatibility shims once call sites are migrated in the same refactor slice, including one-line helper aliases kept only for transitional naming.
- Keep behavior parity first; run `cargo check` and tests each slice.


## Part II — Per-Domain Rules

Rules scoped to a specific domain's model layout, audit taxonomy, firewall
semantics, or UI/authorization contract. These complement the cross-cutting rules
above and take precedence within their domain.

### 6. Audit Domain

- `models/audit/` is the canonical audit contract package.
- `models/audit/mod.rs` is linker-only (module declarations + re-exports), with no functional definitions.
- The audit envelope and cross-cutting taxonomy must stay explicit and stable:
	- `event.rs` owns `AuditEvent`.
	- `family.rs` owns `AuditEventFamily` (`HotPath` / `ColdPath`) and is used as a cross-cutting tag only.
	- `kind.rs` owns `AuditEventKind` and composes per-domain payload enums.
- Domain payload ownership is one file per domain in `models/audit/` (for example `client.rs`, `verdict.rs`, `storage.rs`, `kernel.rs`, `config.rs`, `rule.rs`, etc.).
- Service lifecycle/operational audit payloads must be domain-intrinsic, not generic catch-all wrappers (avoid `ServiceBoundary`-style multiplexing enums).
- **Design imperative — naming convention:** domain payload enums must follow the `<Domain>Lifecycle` / `<Domain>Action` split:
	- `<Domain>Lifecycle`: service lifecycle transitions — `Initialized`, `Started`, `Stopped`, `ReloadStarted`, `ReloadCompleted`, `ReloadFailed`, and service-level structural events (e.g. `WorkersConfigured`, `FlowStarted`).
	- `<Domain>Action`: runtime domain behaviors — CRUD, cache mutations, I/O, policy decisions, counters, and any event tied to user- or system-triggered work rather than service state transitions.
	- `<Domain>FlowLifecycle`: flow-level lifecycle transitions (`Started`, `Stopped`, `Failed`, `Reconnected`, etc.).
	- `<Domain>FlowAction`: flow-level runtime observations (packet drops, queue overflow, snapshot published, etc.).
	- The split is reflected in `AuditEventKind` variant grouping: service lifecycles → service actions → flow lifecycles → flow actions.
- New auditable behavior must prefer semantically meaningful action events over only lifecycle markers like `Initialized`.
- **Design imperative:** flow audit payloads must be co-located in their broad domain files under `models/audit/` and must not create standalone `*_flow.rs` model files. Examples: notification/command flow signals belong in `client.rs`; connect/verdict flow signals belong in `connection.rs`; kernel flow signals belong in `kernel.rs`; stats flow signals belong in `stats.rs`; subscription flow signals belong in `subscription.rs`; lifecycle flow signals belong in `task.rs`.
- Flow lifecycle/operational payloads must cover concrete action events (start/failure/reconfigure) for each active runtime flow.
- Runtime emitters must always classify events with explicit family tagging (`AuditEvent::hot(...)` / `AuditEvent::cold(...)`) rather than ad hoc struct literals.
- **Design imperative — lifecycle coverage:** every domain signal enum must cover the full service lifecycle arc: `Initialized → Started → Stopped` and reload transitions (`ReloadStarted → ReloadCompleted | ReloadFailed { reason }`). Failure states must always carry a `reason: &'static str` field so the audit log is actionable without source-code lookup.
- **Design imperative — domain behavior coverage:** each domain file must also model its observable runtime behaviors beyond lifecycle markers. Required examples by domain:
	- `storage.rs`: file I/O actions (`FileRead`, `FileWritten`, `FileReadFailed`, `FileWriteFailed`).
	- `config.rs`: file I/O actions (`FileRead`, `FileWritten`) and field mutation (`FieldUpdated`).
	- `rule.rs`: CRUD actions (`RuleAdded`, `RuleUpdated`, `RuleDeleted`) and their failure counterparts (`RuleAddFailed`, `RuleUpdateFailed`, `RuleDeleteFailed`).
	- `firewall.rs`: drift-heal transitions (`HealStarted`, `HealCompleted`, `HealFailed`), rule management (`RuleAdded`, `RuleDeleted`, `RuleAddFailed`, `RuleDeleteFailed`), and chain management (`ChainAdded`, `ChainDeleted`, `ChainFlushFailed`).
	- `dns.rs`: cache mutations (`CacheUpdated`, `CacheEvicted`) and resolution outcomes (`ResolutionReceived`, `ResolutionFailed`).
	- `process.rs`: tracking actions (`ProcessTracked`, `ProcessEvicted`, `ProcessScanFailed`).
	- `task.rs`: managed-task supervision (`TaskPanicked`, `TaskRestarted`).
	- `kernel.rs`: queue pressure (`PacketDropped`, `QueueOverflow`) and interface reattach (`KernelInterfaceReattached`).
- **Design imperative — Copy vs Clone discipline:** use `#[derive(Debug, Clone, Copy)]` for signal enums whose variants carry only primitive or `&'static str` fields. Use `#[derive(Debug, Clone)]` (without `Copy`) for enums with heap-allocated fields (`Box<str>`, `String`). Do not force `Copy` by eliminating semantically necessary dynamic data.


### 7. Firewall Domain

- `FirewallConfig` in `models/firewall_config.rs` is the canonical domain type for firewall configuration.
  `pb::SysFirewall` and related proto types (`pb::FwChains`, `pb::FwRule`, `pb::FwChain`, etc.) are
  wire-only and must not appear inside core service, flow, or policy logic.
- The deprecated `pb::FwChains` compat wrapper (originally introduced for iptables/nftables backward compatibility)
  is **flattened at ingress**: `pb::SysFirewall.system_rules: Vec<FwChains>` maps into two flat fields:
  `FirewallConfig.rules: Vec<FirewallRule>` (iptables-style flat rules) and
  `FirewallConfig.chains: Vec<FirewallChain>` (nftables chain definitions).
  Domain code must never see or reconstruct the `FwChains` wrapper; reconstruction is an egress-only adapter
  detail in `services/firewall/conversions.rs`.
- Network alias resolution belongs to the rule engine cache, not the firewall adapter hot path.
	File-defined aliases (`network_aliases.json`) and future firewall-native alias/zone sources must merge during
	`RuleService` cache rebuilds (`RuleMatchCaches::network_aliases`), not during per-verdict matching.
	Rebuild triggers must include explicit firewall reload commands, firewall drift recovery, and nftables netlink
	rule-change notifications so the rule engine sees updated alias inputs whenever firewall state changes.
- **Future `FirewallZone` concept** (firewalld / OpenWrt / VyOS style): when zone-based firewall support is
  added, introduce a `FirewallZone` domain type in `models/firewall_config.rs` as a separate top-level field
  on `FirewallConfig` (do not repurpose `FirewallChain` or add zone-semantics fields to existing types).
  Zone-aware adapters (firewalld D-Bus, OpenWrt ubus, VyOS NETCONF) belong in `platform/adapters/` and must
  map their zone concepts into and out of `FirewallZone` at their own adapter boundary without touching the
  iptables or nftables flat-rule path.


### 8. UI, Client Transport And Authorization Domain

#### UI Transport Adapter Rule

- UI/client transport is an adapter choice, not a core domain assumption.
- Current gRPC transport remains the default adapter while the daemon still uses the inverted UI connection model, but it must be isolated so future frontends can reuse the same session/control ports.
- Keep proto/domain message models transport-neutral where practical; do not leak tonic/h2 client concerns into authorization, session registry, or command-classification logic.
- Feature-gate transport implementations independently when that reduces binary/dependency footprint (`grpc-ui` for tonic-based UI transport, later `http-client`, `openwrt`, or similar), but do not feature-gate the core session/auth policy they consume.
- `services/client` should converge toward a transport-agnostic UI session port plus adapter implementations, rather than permanently binding daemon behavior to a single gRPC client stack.
- Remote principal binding and capability authorization are transport-independent rules: the same mapped-principal policy must apply regardless of whether the session arrived over gRPC, WebSocket, ubus, or another frontend adapter.

#### Client-Domain Terminology Rule

- Use `client` terminology for client session, authorization, and privileged-mutation behavior in code, logs, comments, and docs.
- Do not introduce legacy privileged-transport wording for client authorization/session concerns; treat prior terminology as deprecated vocabulary in this repository.
- Naming guidance: prefer `client_*` or `*_client` symbols over `control_*` when the behavior is specifically about client-originated command authorization.


#### Privileged Control Boundary Rule

- The daemon currently treats the connected UI client as a trusted client for `UPDATE_RULE`, `DELETE_RULE`, `UPDATE_CONFIG`, `ENABLE_FIREWALL`, `DISABLE_FIREWALL`, `RELOAD_FW_RULES`, and shutdown/log-level mutations once they arrive on the notification stream.
- This is an elevated-boundary risk, not a stable design target: those commands can mutate shared on-disk rules, runtime config, and system firewall state that are not scoped to a single desktop user session.
- Hardening direction: the Python UI must be treated as unprivileged-by-default for system-wide mutations until an explicit authorization model exists end-to-end.
- Nuance: owner-scoped policy is a valid future exception class, not a reason to keep the current broad trust model. Rule matching already supports `user.id`, and Linux firewall backends can express socket-owner filters for locally generated traffic (`nft` `meta skuid` / `meta skgid`, `iptables` `-m owner --uid-owner/--gid-owner`).
- Privileged mutations must be separated from ordinary user-interaction commands:
	- unprivileged/user-plane: prompt replies, per-connection verdict participation, read-only inspection, non-system UI state,
	- privileged/client: rule persistence, rule deletion, config apply, firewall enable/disable, firewall payload reload, daemon shutdown, and any future host-wide task or backend reconfiguration.
- Owner-scoped rule or firewall mutation is an explicit supported path when all of the following are true:
	- the daemon has an authenticated caller identity (UID and optionally GID/capability context),
	- the requested mutation is statically proven to target only that caller's own UID/GID scope,
	- the backend semantics are limited to locally generated traffic where owner matching is meaningful,
	- rule insertion/update cannot escape its declared owner scope through raw parameters, broad chain policy edits, target changes, or precedence side effects.
- Locality boundary: the owner-scoped UID/GID exception applies only to local daemon + local UI client control paths where OS identity can be directly verified from local peer credentials.
- Identity anchor rule: authenticated local owner scope is anchored on UID. GID and group membership may narrow which local principals are admitted, but they are coarse selection filters only and must not be treated as standalone proof of owner scope for privileged mutation.
- Config-scope rule: daemon configuration may select which existing system principals/groups are permitted (`AllowedPrincipals`, `AllowedGroups`), but it must remain supplementary gating over OS-derived identity (peer credentials + syscall-backed account/group resolution) and must never act as an independent identity authority.
- If those conditions are met, user-scoped rule and firewall updates from the Python client should be accepted without elevated privileges, because they are constrained to the authenticated caller scope.
- Compatibility rule for current UI clients: when a local non-root UI submits a compatible rule mutation without an explicit owner selector, the daemon should transparently inject the authenticated caller UID scope rather than requiring the UI to pre-populate `user.id`.
- Migration rule for pre-existing policy: already-loaded ownerless rules are not automatically trustworthy proof of caller scope. Hardened modes need an explicit arbitration/migration path for legacy global-or-ambiguous rules so compatibility fallback remains clean and auditable.
- Legacy rule migration rule: migration of pre-existing ownerless rules must be an explicit operator action, not an automatic side effect of ordinary daemon startup or UI connect activity.
- Migration execution rule: prefer a dedicated one-shot daemon migration mode (or equivalent tools subcommand) over a steady-state runtime toggle. The migration entrypoint should require an explicit target owner UID and should separate preview from write mode.
- Minimum migration guardrails:
	- require explicit operator intent (`--migrate-ownerless-rules` or equivalent),
	- require explicit target owner (`--migrate-owner-uid <uid>`),
	- support dry-run/report-only mode before any write,
	- emit a full summary of rewritten, skipped, ambiguous, and conflicting rules,
	- never auto-claim legacy ownerless rules for the currently connected UI user.
- Non-user-scoped mutations (global rules, shared firewall policy, config apply, shutdown, chain policy edits, or any rule that cannot be proven owner-scoped) must require elevated authorization.
- Privileged control must not rely on transport connectivity alone. TLS or local socket reachability authenticates the peer/channel; it does not by itself authorize host-wide mutations.
- Any future privileged path must carry an explicit privilege signal at the command/session boundary and enforce it in the daemon before dispatch into services.
- Do not bury privilege checks inside `RuleService` or `FirewallService`; enforce them at ingress (`NotificationFlow` / command mapping / command control) so domain services can assume already-authorized calls.
- Service-role rule: the daemon is a long-lived background system service, not the interactive authority for deciding which desktop user may elevate. It may classify commands, validate owner scope, request elevation, and consume the result, but it must defer ultimate elevation eligibility to host authorization backends.
- Elevated authorization should use OS-backed identity and policy checks instead of ad-hoc bearer secrets. Preferred primitives on Linux are peer credentials on local sockets (`SO_PEERCRED`/SCM credentials), process capabilities, and a policy authorization service (for example polkit via D-Bus) for admin-grant decisions.
- Local interactive elevation rule: for desktop-style deployments, any interactive privilege prompt must be initiated by a UI client and resolved through a host authorization backend such as polkit/pkexec. The daemon must not present its own password prompt, infer elevation from coarse group membership, or invent a daemon-local allowlist that overrides existing user-space elevation guards.
- Backend caveat: owner matching is not a universal firewall primitive. `iptables` owner matching is for locally generated packets and valid in `OUTPUT` / `POSTROUTING`; nftables socket-owner matching is likewise tied to the originating socket context. Do not generalize owner-scoped authorization to arbitrary forwarded/input policy edits.
- Remote-node caveat: do not project local UID/GID owner scope directly across machines. For remote daemons, authorization must be principal/capability based for that node, not raw caller UID trust from the management host.
- Until the Python client protocol supports privilege separation, prefer one of these transitional stances:
	- run in explicit `auth.mode = legacy` compatibility mode with loud audit logging for privileged notification commands, or
	- run in explicit `auth.mode = local-only` hardening mode and enforce every local check the daemon can actually verify today.
- Required future design properties for privileged commands:
	- explicit command classification (`unprivileged` vs `privileged`),
	- daemon-side authorization check before command queueing or dispatch,
	- auditable logs for allow/deny decisions,
	- explicit runtime tunable for privileged-path rollout with secure defaults.

#### Privileged Rollout Guard Rule

- Privileged command enforcement and exposure must be guarded by explicit rollout controls:
	- runtime config/tunable guard for deployment policy,
	- compile-time feature flags are optional implementation details, not the primary policy surface.
- Secure defaults:
	- privileged mutation path disabled by default for remote management,
	- local privileged enforcement is enabled only through an explicit `auth.mode`,
	- legacy compatibility must be an explicit, documented choice and must emit loud startup/runtime warnings for privileged mutations.
- Suggested tunable surface:
	- `auth.mode = legacy | local-only | local+remote`,
	- `auth.remote.require_pop = true|false` (default `true`),
	- `auth.remote.token_max_ttl_seconds`,
	- `auth.audit.enforce = true|false` (default `true`).
- Startup override rule:
	- daemon CLI switch `--auth-mode <mode>` is an explicit operational override and has higher precedence than config file mode,
	- this override exists to preserve emergency compatibility rollback (`--auth-mode legacy`) during phased rollout,
	- invalid CLI mode values must not silently coerce to `legacy`; keep config mode and emit warning.
- Mode semantics:
	- `legacy`: preserve current OpenSnitch trust model for compatibility; do not infer this mode from missing allowlist fields.
	- `local-only`: enforce all locally verifiable authorization signals (peer credentials, owner-scope validators, local principal/group policy) and deny/require elevation for anything that cannot be proven local-owner-scoped.
	- `local+remote`: extends `local-only` with explicit remote principal/capability authorization; remote privileged control remains deny-by-default until that model exists.
- Policy data rule:
	- `AllowedPrincipals`, `AllowedUsers`, and `AllowedGroups` are authorization data, not rollout switches.
	- `AllowedPrincipals.UID` is the local principal identity anchor; `AllowedPrincipals.GID` and `AllowedGroups` narrow admission by broad group membership (primary or supplementary) and are not by themselves owner-scope proof.
	- Missing/empty principal data must not silently change `auth.mode`; the mode decides whether compatibility or enforcement is active.
- Any mode that enables privileged mutations without full capability checks must be marked experimental/unsafe and emit loud startup/runtime warnings.

#### Remote Node Authorization Rule

- Scope split:
	- local daemon + local UI client: enforce UID/GID owner-scope validator model,
	- remote daemon management: enforce delegated capability model; no implicit owner-scope shortcut.
- Transitional posture for remote management:
	- in `legacy`, retain current compatibility behavior only as a temporary migration stance,
	- in `local-only`, remote privileged mutations are not part of the trust boundary and must be denied or treated as elevated-not-implemented,
	- in `local+remote`, remote privileged mutations require authenticated principal identity plus explicit capability grants.
- Remote authorization model must include:
	- authenticated principal identity (user/service account) via strong channel auth (mTLS or equivalent),
	- server-side principal binding from remote identity to an existing daemon-host principal or dedicated service account,
	- explicit per-node capability grants (`rules.owner.write`, `rules.global.write`, `firewall.owner.write`, `firewall.global.write`, `config.write`, `daemon.control.stop`, etc.),
	- command authorization as capability check against the requested mutation class,
	- optional owner-scope capability constraints (`owner_uid_set`, `owner_gid_set`) for delegated user-limited administration.
- Remote identity binding rule:
	- the remote UI must never be allowed to claim arbitrary local `uid`/`gid` ownership in request payloads,
	- the daemon must derive remote manager identity from strong channel authentication (for example mTLS client cert fingerprint / SAN / subject),
	- the daemon must then map that remote identity server-side to a preconfigured local principal or dedicated service account on the node,
	- owner-scoped authorization for remote managers must run against that mapped principal's OS-resolved UID/GID/group set, not user-supplied fields,
	- if no mapping exists, the remote privileged request fails closed.
- Preferred remote-manager posture:
	- use dedicated daemon-host service principals for remote managers instead of impersonating ordinary desktop users,
	- keep owner-scoped operations and elevated/global operations as separate authorization lanes,
	- elevated/global operations require explicit elevated capability or session-bound elevation grant even when the remote manager identity is valid.
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
	- never accept raw remote username/uid/gid claims as identity; remote payload owner selectors are claims to validate against the mapped principal, not an impersonation surface.

#### Remote Elevation Service Rule

- Remote elevation must use a dedicated RPC surface, not the existing `Notifications` bidi command stream.
- Reason: password-bearing or challenge/response-bearing elevation exchange must be separable from ordinary UI command traffic, replay-protected, auditable, and independently rate-limited.
- Preferred shape: a dedicated `auth.proto` service owned by the daemon-side client boundary in server mode.
- Linux-first authorization backend can use PAM on the target node, but only as one step in minting a daemon-scoped elevation grant; PAM success alone must not flip the whole client session into permanently privileged mode.
- Local desktop elevation posture:
	- prefer UI-mediated host authorization (`polkit`/`pkexec` or equivalent) for local interactive elevation,
	- the Python UI or a future UI client is the component that may present/forward the prompt UX,
	- the daemon consumes only the resulting authorization decision/grant and must remain usable as a non-interactive background service.
- PAM-backed remote elevation requirements:
	- authenticate against the target node's PAM stack,
	- bind the successful elevation result to the authenticated client principal and transport session,
	- mint a short-lived grant scoped to command classes/capabilities,
	- emit structured audit records for attempt/success/failure/expiry/revocation,
	- reject reusable passwords or secrets on the `Notifications` stream.

#### `auth.proto` Sketch (Design Anchor Only)

- Initial sketch for future daemon-served auth RPCs:

```proto
service Auth {
  rpc BeginElevation(ElevationBeginRequest) returns (ElevationBeginReply);
  rpc CompletePamElevation(PamElevationRequest) returns (ElevationGrantReply);
  rpc RevokeElevation(ElevationRevokeRequest) returns (ElevationRevokeReply);
  rpc GetElevationState(ElevationStateRequest) returns (ElevationStateReply);
}
```

- Required request/response properties:
	- session identifier bound to the authenticated transport principal,
	- requested capability set (`rules.global.write`, `firewall.global.write`, `config.write`, `daemon.control.stop`, ...),
	- nonce/challenge material for replay protection,
	- short TTL and explicit grant id,
	- denial reason codes suitable for audit/event export.
- Do not treat this as wire-contract approval yet; it is a planning sketch to anchor the PAM/capability task decomposition.

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
	- local loopback TCP mode: when the daemon is still acting as a client to a local UI endpoint, use locally verifiable ownership signals (`/proc/net/tcp*`, socket inode -> pid where available, supplementary groups from `/proc/<pid>/status`) as a transitional local-only hardening mechanism,
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

#### Verdict Fallback Interaction Rule

- Control-plane authorization hardening must preserve the daemon's selected packet-verdict fallback strategy; auth denial is not allowed to silently create a third, implicit fallback mode.
- Required alignment with runtime verdict policy:
	- when `nfqueue_overload_policy = fail-open`, denial of privileged client mutations must remain scoped to the mutation itself; packet verdict handling must continue to use existing UI-miss / default-action fallback behavior and must not become fail-closed just because a privileged command was rejected,
	- when `nfqueue_overload_policy = drop-fast`, auth-related slow paths must not introduce blocking/retry behavior in the hot packet path; rejected or unavailable privileged control must preserve the existing fail-closed/strict-accounting posture for verdict misses,
	- `AskTimeoutPolicy` remains a verdict/UI-miss safeguard only; it must not be repurposed as an authorization decision surface for privileged mutations.
- Audit requirement:
	- when an authorization outcome is relevant to fallback behavior or operator diagnosis, logs/events should include enough context to distinguish `auth denied` from `UI miss` and from NFQUEUE overload fallback policy.

#### Scope Validator Requirements

- Rule payload validator must prove all operands/targets stay within caller UID/GID scope.
- For compatibility with existing UI create/update flows, the validator may run after daemon-side normalization that injects caller owner constraints when those constraints are absent and the command is otherwise eligible for non-elevated owner-scoped mutation.
- If the submitted payload already contains owner constraints that conflict with the authenticated caller UID/GID, validation must fail closed rather than merge or override the client payload.
- PID-scoped rules need a separate semantic class from durable UID/GID-scoped policy: Linux PIDs are ephemeral, so automatic `pid` injection must be limited to ephemeral/session-bound rules unless a stronger lifecycle model is introduced.
- Firewall payload validator must reject or escalate when encountering:
	- broad chain policy edits,
	- raw parameter fragments that cannot be normalized/understood,
	- targets that affect non-owner traffic or routing behavior,
	- mixed-scope expression sets (owner + non-owner predicates).
- Firewall compatibility normalization may auto-add owner matches (`--uid-owner/--gid-owner`, `meta skuid/skgid`) only for local, non-elevated, owner-scoped updates where backend semantics are fully understood.
- Validation mode should be fail-closed: unknown expression semantics => `elevated_required` or deny.

#### Audit Fields

- Emit structured audit records for every authorization decision with:
	- command/action,
	- caller identity source and UID/GID,
	- classification result,
	- scope validation result,
	- elevation check result,
	- final decision and denial reason code.

#### Hardening Sequencing Rule

- Authorization and scope semantics must be stabilized before seccomp enforcement is treated as a release gate.
- Required ordering for this client hardening track:
	1. finalize command classification and elevated-vs-owner-scoped policy behavior,
	2. finalize local scope validators and compatibility normalization/injection semantics,
	3. finalize remote elevation model (`auth.proto` boundaries, grant lifecycle, PAM/capability decisions),
	4. stabilize audit/event reason codes and integration tests for all auth modes,
	5. only then derive and enforce seccomp profiles from measured runtime syscall traces.
- Rationale: seccomp is blast-radius containment, not business-logic authorization. Applying strict filters before auth/scope behavior converges creates churn and false-negative breakage with weak security signal.
- During early phases, seccomp can run in discovery/logging mode for trace collection, but enforcement should remain non-blocking until steps 1-4 are complete.


## Part III — Infrastructure Rules

Rules for selecting and using shared runtime infrastructure: caches, shared state
primitives, and configuration surfaces.

### 9. Cache And Shared State Selection

The codebase uses three concurrency primitives for caches and shared state.  Choose
based on caller profile and access pattern:

#### `ConcurrentLruCache<K, V>` (`utils/lru_cache.rs`)

A thin `Arc<quick_cache::sync::Cache<K, V>>` wrapper.  Internally sharded; `get`,
`peek`, `insert`, `remove_by`, and capacity operations are all synchronous and
lock-free at the entry level.  Eviction uses Hot/Cold approximation (bounded-capacity
guarantees preserved; strict oldest-item eviction not guaranteed — tests must not
assert a specific evicted item, only `len ≤ capacity`).

**Use when**: a shared runtime LRU cache is needed by multiple async tasks with
read-dominant access and bounded-size requirements (DNS lookups, process inspection,
connection owner PID trie). `ConcurrentLruCache` replaces the former
`DualLayerLruMap` / `SyncDualLayerLruMap` dual-layer design (removed in v0.5.1).

Size guidance:
- tune capacity through a named `RuntimeTunables` field — keep capacity limits explicit
  and documented;
- use `ProcessInfoWeighter` pattern (byte-budget via `quick_cache::Weighter`) when
  individual entries have variable heap footprint;
- DNS, connection, and inode caches retain `UnitWeighter` — their value types are
  uniformly bounded.

#### `DashMap<K, V>` (`dashmap` crate)

A sharded concurrent `HashMap` with per-shard `RwLock`.  `insert`, `remove`,
`entry`, and `get` are O(1) and do not require the caller to hold any external lock.
Iteration acquires one shard lock at a time — **forbidden on hot paths** (see §1
Hot-Path State Access Rule).

**Use when**: a shared map requires concurrent insertions, removals, or atomic
check-and-insert (e.g. verdict epoch tracking, subscription per-id locks, nfqueue
requeue aliases, StorageEventBus path/prefix dispatch maps).  Do **not** use when
whole-map snapshot reads are frequent — prefer `ArcSwap<HashMap<K, V>>` instead.

#### `ArcSwap<T>` (`arc-swap` crate)

Wraps an `Arc<T>` behind an atomic pointer that supports wait-free loads.
`.load()` / `load_full()` never block; `.store(Arc::new(new_value))` replaces the
whole snapshot atomically.  Using `load_full()` → clone → mutate → `store(Arc::new(next))`
on the write path is intentional — it is the correct pattern for low-churn immutable
snapshot replacement.

**Use when**: state is written infrequently (config refresh, 30 s background cycles,
reconnect) but read on every connection, packet, or per-tick path (eBPF map snapshot,
interface-name cache, Prometheus stats snapshot).  Not suitable for write-heavy / high-
churn paths.

#### Caller Matrix

| Cache caller class | Read/write profile | Preferred implementation |
|---|---|---|
| DNS shared lookup cache | read-heavy with periodic writes | `ConcurrentLruCache` |
| Process inspection cache | read-heavy + mutation side-bookkeeping | `ConcurrentLruCache` with `ProcessInfoWeighter` |
| Connection owner PID caches | read-heavy with moderate writes | `ConcurrentLruCache` |
| Verdict epoch map | write-per-connection, remove-per-verdict | `DashMap` |
| Subscription per-id locks | occasional insert/check | `DashMap` |
| nfqueue requeue aliases | hot O(1) remove on packet path | `DashMap` (lazy TTL prune on write) |
| StorageEventBus path/prefix tables | concurrent event dispatch | `DashMap` (per-shard lock, released before send) |
| eBPF map catalogue | read every connection, refresh every 30 s | `ArcSwap<HashMap>` |
| Interface-name lookup | read on every packet, miss refresh | `ArcSwap<HashMap>` |
| Prometheus stats snapshot | read on every scrape, written every tick | `ArcSwap<Option<CompactStats>>` |
| Firewall runtime snapshot | low-churn control writes; frequent reads | whole-runtime `Arc` snapshot via `watch` publish |
| Write-heavy / high-churn map | write-heavy, any | plain `HashMap` behind `Mutex` or single-writer pattern |


### 10. Configuration Surface Precedence

Any parameter that must be set externally — by an operator, integrator, or end-user — **must follow this precedence order** (highest → lowest):

1. **CLI switches / daemon flags** — highest precedence; explicit per-invocation override.
   - When a switch is passed on the command line, it overrides any env var or config file value for that run.
   - Must be forwarded to the relevant subsystem through structured `*Overrides` / `*Flags` structs, not as ad-hoc ambient globals.
   - Names must mirror the JSON field hierarchy when there is a one-to-one mapping (e.g. `--metrics-addr` ↔ `metrics.addr`).
2. **Environment variables** — mid-tier override; typically used for testing, CI orchestration, and ephemeral deployment injection.
   - When an env var is set and non-empty, it overrides the corresponding JSON config file value.
   - Acceptable primary uses: automated test setups, CI pipelines, container/pod bootstrapping where a config file cannot be bind-mounted, one-shot secret injection.
   - Env vars are a valid configuration surface, but for production deployments operators should prefer JSON config files for auditability and reproducibility.
3. **Dedicated JSON config file** — the baseline config provider.
   - Per-crate or per-subsystem files are preferred over a single monolithic config: `metrics.json`, `tunables.json`, `push.json`, etc.
   - Field names must be stable, versioned, and documented.
   - Config files are loaded at startup (and on `reload` when the subsystem supports hot-reload).
   - If no CLI switch or env var overrides a parameter, the JSON config file value is used.

#### Applicability

- The rule applies to all crates under `daemon-rs/` that expose externally settable parameters.
- It does not apply to internal compile-time constants or parameters that are exclusively set by other crates at a defined API boundary.

#### Migration Policy For Legacy Parameters

- Parameters that exist only in code (no config file field, no CLI switch, no env var) should be migrated to at least a JSON config field before the owning feature is considered stable.
- Every config-surface parameter should have a JSON config field as the baseline.  CLI switches and env var overrides are optional but recommended for parameters that operators commonly tweak per-invocation or in CI.

#### Precedence Merge Semantics

- A parameter value from a higher-precedence source completely overrides the lower-precedence value for that key (last-writer-wins, no merging of partial objects across sources).
- Resolution order in code: check CLI switch first → check env var → fall back to JSON config value.
- Exception: array/list fields in JSON may be *extended* (not replaced) by a CLI switch when the switch is explicitly documented as additive.
- CLI switches and env vars never extend JSON arrays; they always replace the field value.

#### Config File Location Policy

- Config files must be locatable via the daemon's `--config-file` override and its standard search path (`/etc/opensnitchd/`, `~/.config/opensnitchd/`, and the running binary's directory in that order).
- Subsystem-specific files (e.g. `metrics.json`) must be co-located with the primary daemon config file or in a well-known sibling directory; their path may be overridden by a dedicated CLI switch.


## Part IV — Implementation Quality Rules

Rules for implementation discipline: trait design, display vs debug contracts, and
any future code-quality invariants.

### 11. Trait Implementation Rules

This section captures implementation discipline rules for Rust standard traits on domain types.
Additional trait implementation rules may be added here as the codebase evolves.

#### Display vs Debug Discipline

- **`#[derive(Debug)]` is a developer introspection aid, not a presentation surface.**  It is permitted anywhere, but production code paths (`Display`, sinks, serialization, log output) must never rely on `{:?}` / `{:#?}` to produce their output.
- **Implement `Display` for any type whose string representation is consumed outside of a `Debug` print session:**
	- audit event kinds and sub-enums emitted to NDJSON or syslog,
	- classification/family/severity/level enums emitted to logs or wire formats,
	- error condition types surfaced in log messages or RPC replies,
	- any enum or struct rendered by a sink, codec, or formatter.
- `Display` implementations must produce stable, human-readable strings, independent of Rust's derived `Debug` output (which is not a stability commitment and may change with compiler versions).
- Constrained / OpenWrt targets may strip `Debug` reflective information under LTO + profile optimisations; code that works only when `Debug` is available is not target-portable.
- **Violation signal:** `format!("{:?}", value)` or `{:?}` in any sink, serialization, or log emission code path is a code-review flag requiring replacement with an explicit `Display` impl or a dedicated `fn as_str(&self) -> &'static str` method.
- **Acceptable uses of `Debug` formatting:**
	- `#[derive(Debug)]` on all types is encouraged for diagnostic tooling (debuggers, `dbg!()`, internal developer `assert_*` helpers).
	- `{:?}` in test-failure messages (`assert_eq!`, `panic!`) is fine.
	- `{:?}` in development-only code paths or behind a `#[cfg(debug_assertions)]` guard is fine.
	- `tracing::debug!(?value, ...)` spans/events (the `?` sigil explicitly uses `Debug`) are fine for developer instrumentation.
	- `{:?}` for `std` or external-crate types that **do not implement `Display`** (e.g. `std::time::Duration`, `std::time::Instant`, third-party error types that only derive `Debug`) is an accepted exception. The violation target is domain-owned types: if the type is defined in this codebase and emitted to a log or wire format, it needs a `Display` impl.


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

## Pre-Commit Checklist

Before every commit in `daemon-rs/`, verify all of the following:

1. **`cargo fmt`** — run `cargo fmt` in `daemon-rs/` to normalize formatting. Python or
   other text-based patching tools produce non-canonical indentation and import ordering.
   Commit the fmt diff in the same commit or as a separate formatting commit immediately
   before the feature commit.

2. **`cargo build` with zero warnings** — the build must be warning-free (`cargo build 2>&1 |
   grep '^warning'`). Unused imports, dead code, and type annotation gaps introduced by
   mechanical edits must be resolved before committing.
	 - **Warning triage policy**: for each warning in touched scope, either (a) remove/fix the
		 root cause, or (b) keep the code and add a targeted `#[allow(...)]` with a brief rationale
		 explaining why the API/path is intentionally retained.
	 - **Re-export hygiene**: if `pub use` re-exports in `mod.rs` trigger unused warnings, prefer
		 aligning call sites to consume the canonical re-export surface (for example `crate::config::*`)
		 instead of importing the same type through parallel internal paths. Use broad module-level
		 `allow(unused_imports)` only as a last resort.

3. **DESIGN_RULES violation scan** — review changed files against the rules in this document:
   - `mod.rs` linker-only: no `impl`/`fn`/`struct`/`enum`/`const`/`static` blocks in any
     `mod.rs` file under `services/`, `commands/`, `flows/`, `workers/`, or `tunables/`.
   - File-size gate: `find src -name '*.rs' ! -path '*/tests/*' | xargs wc -l | awk '$1 > 500 && $2 != "total"'`.
     Every violation must either be split in the same commit or have a concrete plan added to
     `TODO.md` referencing the file and target split.
   - Test placement: `#[test]` / `#[tokio::test]` blocks only in `src/tests/`; implementation
     files may only carry `#[cfg(test)] #[path = "..."] mod tests;` wiring declarations.
   - API-Surface File Rule: check that new `impl` blocks in existing split modules have not
     accumulated domain logic that belongs in a sibling file.

4. **Derive CHANGELOG and commit message from actual diffs** — use `git diff --stat` and
   `git diff HEAD -- <files>` to enumerate what actually changed. The commit message subject
   must be `daemon-rs: <scope> — <action>` and the body must enumerate the concrete changes,
   not restate intent. The CHANGELOG `[Unreleased]` section must be updated in the same commit
   using the same enumeration. The commit message body and CHANGELOG entry can share wording.
	- **Amend + push policy**: if `git commit --amend` rewrites a commit that has already been
	  pushed to the remote branch, update the remote with `git push --force-with-lease` (not plain
	  `--force`) so rewritten history is explicit and remote-tracking safety checks are preserved.

5. **`cargo test`** — all tests must pass. Regressions introduced by mechanical splits must be
   fixed before committing.
