# Daemon-RS Changelog

This changelog records release-level changes for the daemon-rs branch line.

Versioning baseline:
- `v0.1.0`
- `v0.1.1`
- `v0.2.0`
- `v0.3.0`
- `v0.4.0`
- `v0.5.0`
- `v0.6.0`
- `v0.7.0`

## [Unreleased]

### Added

- **OpenWrt UCI co-management reconciliation hardening + terminology governance update**
  (`crates/daemon/src/platform/adapters/openwrt_uci_firewall.rs`,
  `crates/daemon/src/tests/firewall/{firewall_service.rs,openwrt_uci_firewall_adapter.rs}`,
  `DESIGN_RULES.md`):
  - OpenWrt managed section naming now uses an explicit `opensnitch_` prefix and removes non-standard UCI rule options (`opensnitch_managed`, `uuid`) from generated firewall sections.
  - Added sidecar rule-section identity mapping (`<firewall path>.opensnitch.rule-map.json`) so reconcile logic can keep tracking daemon-managed rules even when section names are renamed externally via LuCI/UCI.
  - Reconcile plan now prefers in-place updates for matched managed sections (including sidecar-map matches), preserves unknown/non-daemon fields on those sections, and only deletes stale managed sections no longer present in desired state.
  - Added adapter regression coverage for in-place unknown-field preservation, renamed-section reconciliation via sidecar map, and updated managed-section command expectations.
  - Added terminology governance rule banning metaphor-based infrastructure wording (for example `sidecar`, `control plane`) and requiring concrete technical wording (`metadata`, `client`, `transport`, `wire`, `runtime`, `storage`, `rule-section mapping`) in code/docs/review artifacts.

- **Firewall persistence authority routing — manager-based durable persistence with zone/app-profile expression support, stale-rule removal, and live-only shutdown cleanup**
  (`crates/daemon/src/daemon.rs`,
  `crates/daemon/src/daemon/bootstrap.rs`,
  `crates/daemon/src/config/{config.rs,enums.rs,mod.rs}`,
  `crates/daemon/src/models/{config_runtime.rs,config_storage.rs}`,
  `crates/daemon/src/main.rs`,
  `crates/daemon/src/services/firewall/{config_ops.rs,firewall.rs,mod.rs,persistence_authority.rs,storage.rs}`,
  `crates/daemon/src/utils/config_reload.rs`,
  `crates/daemon/src/tests/firewall/{firewall_probe_support.rs,firewall_service.rs}`,
  `crates/daemon/src/tests/parsing/config_parsing.rs`,
  `TODO.md`):
  - Added `FirewallPersistenceMode` enum (`LiveOnly` | `Durable`) with `from_name`/`as_name`
    round-trip helpers and `Durable` as the default; wired as a first-class config field across
    `Config`, `ConfigStorage`, bootstrap CLI override (`--firewall-persistence-mode`), and
    config-reload plumbing.
  - Added `FirewallPersistenceAuthority` (`Firewalld` | `Ufw` | `DirectBackend`) — the host-probing
    resolution layer that selects the active system firewall manager at persist time by checking
    `firewall-cmd --state`, `systemctl is-active firewalld`, and `ufw status` in order; OpenWrt
    with `FirewallBackend::OpenWrtUci` always resolves to `Durable`/`DirectBackend`.
  - Added instance-level `authority_override: Option<FirewallPersistenceAuthority>` and
    `#[cfg(test)] with_test_manager(manager: &str)` builder on `FirewallService` so parallel tests
    can pin a manager without mutating process-global state.
  - **Firewalld durable path**: applies firewall rules as `--direct` IPv4/IPv6 rules and as rich
    rules when a zone is present or the rule carries a service-name expression; ensures named zones
    exist (creating them with `--permanent --new-zone` when missing); removes stale rules on config
    update by diffing current vs. previous rich rules via a sidecar `.firewalld.rich.rules` state
    file (tab-separated `zone\trule` entries, saved after each successful persist); both runtime
    and permanent forms are applied/removed so a `--reload` brings them into permanent state.
  - **UFW durable path**: clears only OpenSnitch-tagged rules by scanning `ufw status numbered` for
    `opensnitch-sysfw:` comment tags, deleting by numeric ID in reverse order, then re-applying all
    enabled rules; supports app-profile expression via `ufw allow ... app <profile>` token form.
  - **Live-only mode** (`FirewallPersistenceMode::LiveOnly`): `Daemon::stop()` calls
    `cleanup_runtime_rules_for_shutdown()` before cancelling the runtime token, removing all
    runtime-applied firewall rules so they do not outlive the daemon process; skipped for
    `FirewallBackend::OpenWrtUci` under the `openwrt` feature.
  - `config_ops.rs` now guards `save_system_firewall_to_backend_and_path` behind
    `effective_firewall_persistence_mode == Durable`; `LiveOnly` mode takes the
    `reconcile_with_system_firewall` path instead, applying rules at runtime without touching
    the on-disk state.
  - Authority is resolved on the Tokio async thread before entering `spawn_blocking` so the
    per-instance override remains visible across the thread boundary.
  - **OpenWrt/UCI durable path**: persistence now reconciles daemon-managed UCI sections against
    the current firewall file by deleting stale OpenSnitch-managed sections before recreating the
    desired managed set, then running `uci commit firewall` and runtime reload. This closes stale
    rule removal parity for the daemon-owned OpenWrt section set while preserving non-OpenSnitch
    firewall sections.
  - Added 5 new firewall service tests (23 total, all pass): zone rich-rule expression,
    `--zone` argument injection, stale rich-rule removal via sidecar diff, UFW manager
    activation, and UFW app-profile token form; all parallel-safe via `with_test_manager`.
  - Added concrete `persistence_authority.rs` (868 lines) split plan to `TODO.md` §2 to
    satisfy DESIGN_RULES 500-line gate without blocking this commit.

- **Runtime target split rename and privilege/build boundary cleanup**
  (`Makefile`, `daemon-rs/DOCS.md`, `daemon-rs/TODO.md`,
  `daemon-rs/scripts/build_ebpf.sh`, `daemon-rs/crates/tools/src/{build_cmds.rs,main.rs,cli.rs,harness_cmds.rs}`):
  - Renamed the runtime/test artifact split from `target-kernel` to `target-runtime`
    across Make defaults, tools environment defaults, and docs/tracker guidance.
  - Kept eBPF build user-scoped (`build_ebpf.sh` now rejects root execution), while
    preserving elevated daemon live-session and privileged kernel test paths.
  - Removed next-release compatibility shim/fallbacks for `DAEMON_RS_KERNEL_TARGET_DIR`
    so runtime target selection now uses the `DAEMON_RS_RUNTIME_TARGET_DIR` path only.

- **Firewall zone baseline before OpenWrt expansion**
  (`crates/daemon/src/models/firewall_config.rs`,
  `crates/daemon/src/models/firewall_storage.rs`,
  `crates/daemon/src/services/firewall/{conversions.rs,storage.rs}`,
  `crates/daemon/src/platform/adapters/{firewall_nftables.rs,firewall_iptables.rs,firewall_netlink/adapter.rs}`,
  `crates/daemon/src/tests/firewall/{firewall_netlink.rs,firewall_service.rs}`,
  `DESIGN_RULES.md`, `TODO.md`):
  - Added top-level `FirewallConfig.zones: Vec<FirewallZone>` as the canonical zone domain surface.
  - Extended storage ingress/egress to load and persist `Zones` payloads.
  - Extended nftables (CLI + netlink planner) and iptables apply/clear paths to process zone-owned chains.
  - Added tests for zone planner behavior and zone storage round-trip coverage.

- **Firewall backend extraction into canonical DTO model**
  (`crates/daemon/src/platform/adapters/{firewall_nftables.rs,firewall_netlink/adapter.rs,firewall_iptables.rs}`,
  `crates/daemon/src/platform/ports/firewall_port.rs`,
  `crates/daemon/src/services/firewall/runtime.rs`,
  `crates/daemon/src/tests/firewall/{firewall_nftables.rs,firewall_iptables.rs}`):
  - Added backend snapshot extraction APIs for nftables and iptables so runtime rules can be reflected
    into `FirewallConfig` DTOs.
  - Wired nftables extraction through the netlink+fallback port path and implemented native netlink
    chain/rule dump translation (`op_getchain_dump` + `op_getrule_dump`) into canonical DTOs.
  - Added parser coverage for zone-chain grouping (`zone_<name>_*`) and top-level chain/rule extraction.

- **Explicit OpenWrt runtime firewall backend branch**
  (`crates/daemon/src/models/firewall_state.rs`,
  `crates/daemon/src/services/firewall/{conversions.rs,runtime.rs}`,
  `crates/daemon/src/tests/{firewall/firewall_service.rs,parsing/config_parsing.rs}`):
  - Added `FirewallBackend::OpenWrtUci` as an explicit runtime backend marker.
  - Feature-guarded OpenWrt config/backend parsing aliases (`openwrt-uci`, `openwrt`, `firewall4`, `uci`) and authority-mode handling behind `openwrt`.
  - Updated firewall runtime backend resolution to preserve OpenWrt authority mode while continuing runtime
    interception/health/extraction through the nftables/netlink path, and to route to generic Linux
    backend resolution when `openwrt` is not enabled.
  - Added focused regression tests for OpenWrt backend parsing and runtime backend resolution.

- **Netlink-first firewall introspection promotion**
  (`crates/daemon/src/services/firewall/runtime.rs`,
  `crates/daemon/src/tests/firewall/firewall_service.rs`):
  - Promoted firewall introspection/live state extraction into a detached netlink-first domain independent
    from persistence backend ownership.
  - Added target-scoped fallback extraction order:
    generic Linux (`netlink` -> `nftables` -> `iptables`), OpenWrt (`netlink` -> `openwrt-uci`).
  - Introduced consistent service naming with `introspect_system_firewall()` while keeping
    `extract_system_firewall_from_backend()` as a compatibility wrapper.

- **Formatting normalization for OpenWrt/UCI touched slices**
  (`crates/daemon/src/{platform/adapters/mod.rs,platform/ports/openwrt_uci_firewall_port.rs,tests/mod.rs,tests/firewall/*}`,
  `crates/storage-format-uci/src/{parser.rs,serde_bridge.rs,tests/storage_format_uci.rs}`):
  - Applied `cargo fmt` normalization to previously modified OpenWrt/UCI adapter,
    parser bridge, and related test files so commit-time formatting hygiene stays
    aligned with the project pre-commit checklist.

- **OpenWrt UCI planner ownership correction**
  (`crates/daemon/src/platform/adapters/openwrt_uci_firewall.rs`,
  `crates/daemon/src/tests/firewall/openwrt_uci_firewall_adapter.rs`,
  `crates/daemon/Cargo.toml`, `Cargo.toml`, `TODO.md`):
  - Moved firewall UCI CLI plan compilation fully into the daemon platform adapter layer.
  - Removed the intermediate `transport-wire-openwrt-uci` crate so UCI CLI admin/control
    semantics no longer sit in a transport-wire boundary.
  - Kept UCI file parsing in `storage-format-uci` and ubus runtime wire concerns in
    `transport-wire-openwrt-ubus`.

- **Transport-wire test ownership and daemon stub-first flow coverage**
  (`DESIGN_RULES.md`,
  `crates/daemon/src/tests/{mod.rs,flows/notification_flow.rs,flows/stats_flow.rs,flows/verdict_flow.rs}`,
  `crates/transport-wire-grpc-client/src/tests/transport_wire_grpc_client.rs`):
  - Codified test-placement governance: daemon flow tests default to stub/wire-core paths,
    protobuf/tonic conversion assertions live in `transport-wire-*` adapter tests, and
    daemon transport-runtime exceptions must stay feature-gated with minimal protobuf usage.
  - Moved notification/stats flow tests away from in-test live protobuf gRPC harnesses to
    stub transport behavior so they run under default no-feature daemon test builds.
  - Added transport-wire gRPC client E2E coverage for notifications hello-handshake and
    `ask_rule` protobuf-to-wire mapping responsibilities.
  - Reduced protobuf payload coupling in daemon `verdict_flow` orchestration coverage while
    preserving the feature-gated in-flight gating/fallback behavior test.

- **Tools/live-session and Aya smoke regression hardening** (`DESIGN_RULES.md`,
  `TODO.md`, `PERF.md`, `crates/tools/src/{live_logs.rs,build_cmds.rs,cli.rs}`,
  `crates/transport-wire-core/src/{wire_helpers.rs,tests/wire_helpers.rs}`,
  `crates/daemon/src/tests/smoke/{aya_proc_trace.rs,aya_dns_trace.rs,aya_conn_trace.rs,aya_tunnel_trace.rs}`,
  `crates/daemon/src/tests/metrics/{stats_exporter_prometheus.rs,stats_exporter_push.rs}`,
  `crates/daemon/src/tests/flows/stats_flow.rs`):
  - Added explicit commit-gate guidance requiring the tools orchestration smoke,
    repo-level `cargo ost` launcher regressions, and serial execution for direct
    elevated ignored Aya smoke runs.
  - Fixed mock UI live-session compatibility by realigning `WireCommandAction`
    numeric values with `proto/ui.proto`, restoring `LOG_LEVEL`, `STOP`,
    `TASK_START`, and `TASK_STOP` interoperability.
  - Bounded tools live-session and Aya smoke watchdog/runtime defaults so
    launcher failures surface quickly without reporting false timeouts after the
    child process has already exited.
  - Reduced Aya smoke runtime budgets and accepted log-confirmed connection
    activity as fallback evidence where direct BPF map inspection is unstable on
    some hosts.
  - Updated all-features daemon test fixtures to use wire-core statistics and
    connection DTOs instead of stale protobuf-only types.
  - Refreshed perf baseline rows through the mandatory `update-run-perf`
    launcher flow.

- **Main storage-format override and compiled default policy** (`crates/daemon/src/main.rs`,
  `crates/daemon/src/daemon.rs`, `crates/daemon/src/daemon/bootstrap.rs`,
  `crates/daemon/src/daemon/migration.rs`, `crates/daemon/src/services/storage/storage.rs`,
  `crates/daemon/src/config/config.rs`):
  - Added CLI flag `--main-storage-format <json|yaml|toml>` and threaded it through daemon
    overrides, bootstrap, and migration entrypoints.
  - `StorageService` now carries process-global `main_storage_format` policy and resolves
    effective format as: CLI override → file extension → compiled default.
  - Added `StorageFormat::compiled_default()` to make runtime defaults feature-aware without
    scattering `#[cfg]` logic at call sites.
  - Config default-path loading now prefers format-matched system/dev defaults
    (`/etc/opensnitchd/default-config.<ext>`, `daemon/data/default-config.<ext>`).

- **Storage codec packaging feature-gating** (`crates/daemon/Cargo.toml`,
  `crates/daemon/src/services/storage/storage.rs`, `DESIGN_RULES.md`):
  - Added optional storage codec features: `storage-format-json`, `storage-format-yaml`,
    `storage-format-toml`.
  - Codec dependencies are now optional and linked only when their feature is enabled.
  - Added compile-time guard for invalid zero-codec builds.
  - Added/expanded packaging governance in design rules with explicit feature-gating and
    warning-resolution policies.

- **DNS varlink multi-address batching** (`crates/daemon/src/workers/dns/dns_worker.rs`,
  `crates/daemon/src/models/dns_payload.rs`,
  `crates/daemon/src/tests/workers/workers_dns.rs`):
  - Varlink DNS answers for the same host are now batched into one
    `DnsPayload::answers(host, Arc<[IpAddr]>)` payload instead of emitting one payload per IP.
  - Event ordering between answer and alias records is preserved via ordered parsed-event staging.
  - Added regression coverage for multi-address host batching behavior.

- **Cross-service audit domain model** (`crates/daemon/src/models/audit/`):
  - Replaced single-file `audit_event.rs` with a per-domain module tree under `models/audit/`:
    `client.rs`, `config.rs`, `connection.rs`, `dns.rs`, `event.rs`, `family.rs`, `firewall.rs`,
    `kernel.rs`, `kind.rs`, `process.rs`, `rule.rs`, `severity.rs`, `stats.rs`, `storage.rs`,
    `subscription.rs`, `task.rs`, `verdict.rs`.
  - Each domain file contains a `*Lifecycle` enum (service lifecycle transitions: `Initialized`,
    `Started`, `Stopped`, `ReloadStarted`, `ReloadCompleted`, `ReloadFailed`, etc.) and a
    `*Action` enum (runtime behavior: CRUD, I/O, cache, pressure, authorization decisions).
  - `AuditEventKind` in `kind.rs` is the top-level sum type, composing every per-domain
    `*Lifecycle` and `*Action` variant into a single exhaustive enum.
  - `AuditEvent` in `event.rs` wraps kind + family + severity + nanosecond timestamp.
    Constructors `AuditEvent::hot(kind)` / `AuditEvent::cold(kind)` tag events as hot-path
    or cold-path; severity is auto-derived from kind via `AuditSeverity::from_kind`.
  - `AuditSeverity` in `severity.rs`: `Error` / `Warning` / `Info` / `Debug` — drives syslog
    level selection; computed automatically, never chosen by emit sites.
  - `AuditEventFamily` in `family.rs`: `HotPath` / `ColdPath` — latency tagging orthogonal to severity.

- **Cross-service audit bus (phase 1)** (`crates/daemon/src/services/audit/`):
  - `AuditService` (`audit.rs`): non-blocking fan-out over a sync ingress queue +
    dedicated dispatcher thread → `tokio::sync::broadcast` + bounded `AuditRing`.
    `emit` is fail-open (`TrySendError::Full` is silently dropped); `subscribe()` returns
    a broadcast receiver for downstream sinks; `ring().drain_recent()` for UI query/drain.
  - `AuditSinks` (`sink.rs`): multiplexes broadcast output to three independent additive sinks:
    - **log-lines** (default on): emits `tracing` log lines at the event's severity level.
    - **NDJSON file** (default off, `--audit-sink-file <path>` / `OPENSNITCH_AUDIT_SINK_FILE`):
      dedicated worker thread appends `{"ts":..,"path":..,"level":..,"event":..}` lines.
    - **syslog** (default off, `--audit-sink-syslog` / `OPENSNITCH_AUDIT_SINK_SYSLOG`):
      dedicated worker thread emits to `LOG_DAEMON` via `syslog::Formatter3164`; severity maps
      `Error→LOG_ERR`, `Warning→LOG_WARNING`, `Info→LOG_NOTICE`, `Debug→LOG_DEBUG`.
    - Workers are detached std threads; channels are fail-open bounded queues.
  - `ServiceFactory` impl in `runtime_lifecycle.rs` constructs `AuditService` via the standard
    lifecycle factory pattern (`init(capacity)`).
  - `AuditSinkConfig` added to `models/config_runtime.rs` (`sink_file`, `sink_syslog`,
    `sink_log_lines`); parsed in `config.rs` with full `SinkFile`/`SinkSyslog`/`SinkLogLines`
    field alias normalisation; CLI flags (`--audit-sink-file`, `--audit-sink-syslog`,
    `--audit-sink-log`) and env vars (`OPENSNITCH_AUDIT_SINK_*`) added to `main.rs` with
    §7 precedence (CLI > env > config file).
  - Audit bootstrap + runtime wiring (`daemon/bootstrap.rs`, `daemon/tasks.rs`,
    `daemon/worker_startup.rs`, `daemon/serve.rs`): `AuditService` injected into `DaemonRuntime`;
    `spawn_audit_sink_task` launches the subscriber/sink task; `AuditLifecycle::SinkStarted`
    emitted on ready.
  - Notification flow now emits audit events for owner-scope normalization denials and
    authorization-policy denials before replying with error.
  - Verdict flow now emits `VerdictAction::AskTimeoutFallback` audit events when the ask-timeout
    fallback policy is applied.
  - Command flow emits `CommandFlowLifecycle` and `ClientLifecycle` startup events.
  - Stats flow, connect flow, kernel flow, verdict-reply flow, and notification flow each emit
    `*FlowLifecycle::Started` events on task launch.
  - Subscription command flow (feature-gated) emits `SubscriptionFlowLifecycle::CommandStreamFailed`
    on bidi stream errors.
  - `SubscriptionService::spawn_scheduler` in the disabled stub now accepts `AuditService`
    parameter for API parity with the gated implementation.
  - Added runtime tunable `audit_ring_capacity` (existing configuration surface).

- **Debug audit coverage for deferred process/kernel paths** (`crates/daemon/src/services/process/inspection.rs`,
  `crates/daemon/src/workers/runtime/kernel/process.rs`,
  `crates/daemon/src/workers/runtime/nfqueue/worker.rs`,
  `crates/daemon/src/platform/ports/nfqueue_netlink_port.rs`):
  - `ProcessService::sync_from_proc_event` now returns a real failure result for failed
    proc inspection warmups, and kernel process consumers emit
    `ProcessAction::ProcessScanFailed` from those runtime failures.
  - `ProcessAction::ProcessScanFailed` and `KernelAction::KernelInterfaceReattached`
    are now classified as `Debug` severity.
  - NFQUEUE degraded-mode recovery now signals the owning worker path, which emits
    `KernelAction::KernelInterfaceReattached` when netlink queue startup actually succeeds
    after recovery.

- **Truthful DNS cache-eviction audit accounting** (`crates/daemon/src/utils/lru_cache.rs`,
  `crates/daemon/src/services/dns/{dns.rs,cache_ops.rs}`,
  `crates/daemon/src/flows/kernel/kernel.rs`):
  - Added a generic eviction-counting cache lifecycle so cache users can obtain exact
    per-request eviction counts without embedding domain audit logic into cache utilities.

- **Transport-agnostic notification inbound seam** (`crates/daemon/src/platform/ports/client_transport_port.rs`,
  `crates/daemon/src/services/client/notifications.rs`,
  `crates/daemon/src/flows/notification/notification.rs`):
  - Added `NotificationInboundPort` in `platform/ports` and switched notification flow
    consumption to the port API (`recv`) instead of tonic stream methods.
  - `NotificationStream` now exposes `Box<dyn NotificationInboundPort>`; gRPC-specific
    stream adaptation is constrained to client adapter code.

- **Transport-agnostic subscription command stream seam + flow trait adoption**
  (`crates/daemon/src/platform/ports/client_transport_port.rs`,
  `crates/daemon/src/services/client/client.rs`,
  `crates/daemon/src/flows/subscription/command_flow.rs`,
  `crates/daemon/src/flows/{notification,stats,verdict}/`,
  `crates/daemon/src/flows/subscription/subscription.rs`):
  - Added `SubscriptionCommandInboundPort` and moved subscription command stream
    wire shaping (`ReceiverStream`, `tonic::Streaming`) behind
    `ClientService::subscription_commands_open()`.
  - `SubscriptionCommandFlow` now consumes command ingress via
    `SubscriptionCommandInboundPort::recv_command()` instead of tonic stream methods.
  - Added `ClientTransportPort` and routed active flow call sites through this
    transport contract (`subscribe`, `post_alert`, `ping`, `ask_rule`,
    `subscription_execute`) to reduce direct coupling to concrete client
    transport APIs.

- **Connector-port decoupling for client acquisition**
  (`crates/daemon/src/platform/ports/client_transport_port.rs`,
  `crates/daemon/src/services/client/client.rs`,
  `crates/daemon/src/flows/{stats,subscription,verdict}/`):
  - Added `ClientTransportConnectorPort` and concrete cache-backed
    `ClientTransportConnector` to abstract transport client acquisition.
  - `StatsFlow`, `SubscriptionFlow`, `SubscriptionCommandFlow`, and `VerdictFlow`
    now acquire/invalidate transport clients through connector-port methods
    (`connect_or_reuse`, `invalidate`) instead of calling concrete
    `ClientService::connect_or_reuse` directly.

- **Transport/wire core library extraction**
  (`crates/transport-wire-core`,
  `crates/daemon/src/services/client/`, `crates/daemon/src/flows/`,
  `crates/daemon/src/utils/notification_reply.rs`):
  - Added `opensnitch-transport-wire-core` as the unified workspace transport
    core library, with separated submodules for transport-facing traits
    (`ClientTransportPort`, `ClientTransportConnectorPort`,
    `NotificationInboundPort`, `SubscriptionCommandInboundPort`, `PortFuture`)
    and shared wire helper functions (`build_notification_reply`,
    `is_ok_reply_code`, `status_payload`).
  - Rewired daemon flow/service modules and notification utilities to consume
    this external library; removed the in-crate
    `platform/ports/client_transport_port.rs` module.

- **Naming-aligned gRPC client transport-wire crate**
  (`crates/transport-wire-grpc-client`, `crates/daemon/Cargo.toml`,
  `crates/daemon/src/services/client/transport.rs`):
  - Added `opensnitch-transport-wire-grpc-client` following the
    `transport-wire-[kind]` naming convention.
  - Daemon default features now include `transport-wire-grpc-client`; the
    existing `grpc-ui` feature remains available for compatibility.
  - gRPC client keepalive constants are now sourced from the named adapter
    crate when enabled.

- **Feature merge: grpc-ui into transport-wire-grpc-client**
  (`crates/daemon/Cargo.toml`, `crates/daemon/src/services/client/`):
  - Removed the standalone daemon `grpc-ui` feature and moved all source-level
    feature gates to `transport-wire-grpc-client`.
  - `transport-wire-grpc-client` now directly owns gRPC client dependency
    activation and transport code-path gating.

- **Client wire-orchestrator split for transport pluggability**
  (`crates/daemon/src/services/client/{client,notifications,wire}.rs`):
  - Added `services/client/wire.rs` as the transport-wire runtime boundary;
    gRPC client/channel/stream mechanics now live in the wire adapter layer.
  - `ClientService` now acts as an orchestrator over `ClientWire`, delegating
    transport operations (`subscribe`, `ping`, `ask_rule`, `post_alert`,
    notification stream open, subscription command stream/RPC calls) through
    the adapter boundary.
  - `NotificationStream::open` now consumes transport channels through
    `ClientService` wire APIs instead of shaping gRPC stream types directly.
  - Added a second runtime-selectable stub wire adapter (`stub://` client_addr)
    to prove multi-wire orchestration without policy-flow changes; selection
    now happens in `connect_with_config*` / `connect_or_reuse`.
  - Added a centralized wire-selection strategy helper (`ClientWireKind` +
    `select_wire_kind`) so adapter routing remains explicit and isolated from
    client call-site orchestration methods.
  - Added an adapter-local `subscriptions` feature gate in
    `transport-wire-grpc-client` and routed daemon `subscriptions` feature into
    that adapter feature.
  - Relocated subscription command-stream/RPC wire calls from daemon client
    wire runtime to `transport-wire-grpc-client` helper APIs, keeping daemon
    service/flow layers on orchestrator-only boundaries.
  - Relocated remaining UI gRPC wire calls (`subscribe`, `ping`, `ask_rule`,
    `post_alert`, notification stream open) into `transport-wire-grpc-client`
    helper APIs with a base adapter `ui` feature gate; daemon wire runtime now
    delegates all gRPC call surfaces through adapter exports.
  - Added adapter-owned test coverage for `transport-wire-grpc-client` under
    `src/tests/`, and feature-gated daemon flow-consistency test modules that
    depend on gRPC transport runtime wiring.
  - Added workspace-level dependency reuse baseline for transport/storage
    adapters (`[workspace.dependencies]`) and migrated adapter/storage crates
    to `workspace = true` dependency declarations to avoid avoidable version
    drift as new transport/storage libs are added.
  - `DnsService::track_answers` and `track_alias` now return cache mutation summaries,
    including truthful eviction counts.
  - Kernel flow verbose DNS audit now emits `DnsAction::CacheEvicted` only when a DNS cache
    insert actually evicts resident entries.

- **Canonical firewall domain model + transport discriminator model** (`crates/daemon/src/models/firewall_config.rs`,
  `crates/daemon/src/models/command_action.rs`):
  - Added proto-free `FirewallConfig` / `FirewallRule` / `FirewallChain` /
    `FirewallExpression` / `FirewallStatement` / `FirewallStatementValue` domain types.
  - Added transport-neutral `CommandAction` discriminant for notification/control policy.
  - Notification authorization, owner-scope normalization, and firewall command handling now operate on
    canonical domain models instead of `pb::*` wire types.

- **Config-driven network alias file path** (`crates/daemon/src/models/config_storage.rs`,
  `crates/daemon/src/models/config_runtime.rs`, `crates/daemon/src/config.rs`,
  `crates/daemon/src/daemon/bootstrap.rs`, `crates/daemon/src/services/rule/rule.rs`):
  - Added `Rules.NetworkAliasesFile` to config parsing and canonical key normalization.
  - Added runtime `network_aliases_path` and bootstrap wiring into `RuleService`.
  - `RuleService` now resolves aliases from config first and falls back to the system/dev defaults.

- **Explicit client authorization modes** (`crates/daemon/src/models/config_runtime.rs`,
  `crates/daemon/src/models/config_storage.rs`, `crates/daemon/src/config.rs`):
  - New runtime `AuthMode` model with `legacy`, `local-only`, and `local+remote`.
  - `Server.Authentication.Mode` is parsed case-insensitively and defaults to `legacy`.
  - Runtime config now carries explicit rollout state for client authorization instead of
    inferring behavior from missing allowlist fields.

- **Local client principal/group policy in runtime config** (`crates/daemon/src/models/config_runtime.rs`,
  `crates/daemon/src/models/config_storage.rs`, `crates/daemon/src/config.rs`):
  - New runtime model `LocalPrincipal { uid, gid }`.
  - New auth config fields in storage model: `AllowedPrincipals`, `AllowedUsers`, `AllowedGroups`.
  - New runtime fields: `local_control_allowed_principals: Option<Vec<LocalPrincipal>>` and
    `local_control_allowed_group_gids: Option<Vec<u32>>`.
  - Case-insensitive canonical key normalization added for `AllowedPrincipals`, `AllowedUsers`,
    `AllowedGroups`, `UID`, and `GID`.
  - `AllowedUsers` resolves usernames to `(uid,gid)` via libc account lookup; `AllowedGroups`
    resolves group names to GIDs via libc group lookup; invalid/unresolvable entries are ignored
    with warnings; resolved sets are sorted and deduplicated.

- **Notification flow peer-identity enforcement for local endpoints** (`crates/daemon/src/flows/notification/notification.rs`):
  - UNIX peer extraction upgraded from UID-only to full SO_PEERCRED tuple `(uid,gid,pid)`.
  - Supplementary group extraction added via `/proc/<pid>/status` (`Groups:` line).
  - New local policy gate `local_peer_principal_allowed` applied before notification reconnect/handshake.
  - Session binding now receives config and binds as `LocalUid` for verified local UNIX and loopback TCP listeners.

- **Loopback TCP ownership hardening path** (`crates/daemon/src/flows/notification/notification.rs`):
  - For local `http(s)://127.0.0.1` / `::1` endpoints, daemon can inspect `/proc/net/tcp*`
    to resolve listener owner UID (+ inode) and enforce principal policy.
  - Optional group policy for loopback TCP uses inode-to-pid resolution through `/proc/<pid>/fd/*`
    and then supplementary groups from `/proc/<pid>/status`.

- **Privileged notification ingress authorization** (`crates/daemon/src/flows/notification/notification.rs`):
  - Privileged notification actions are classified before command queueing.
  - In hardened modes, remote privileged commands are denied by default.
  - Non-root local rule mutations are accepted only when every rule payload is provably scoped to
    the caller via `user.id` / `user.name`.
  - Non-root local firewall reloads are accepted only for explicit owner-matched rule payloads
    (`--uid-owner`, `meta skuid`); chain/table/policy edits remain elevated-only.

- **Authorization-mode bootstrap warnings** (`crates/daemon/src/daemon/bootstrap.rs`):
  - Startup logs now emit explicit warnings for `legacy`, transitional `local-only`, and
    `local+remote` fallback behavior.
  - `local+remote` warnings now distinguish between an empty remote binding table and a configured
    `RemotePrincipalBindings` foundation that still lacks enforcement wiring.

- **Remote principal binding config foundation** (`crates/daemon/src/models/config_storage.rs`,
  `crates/daemon/src/models/config_runtime.rs`, `crates/daemon/src/config.rs`,
  `crates/daemon/src/flows/notification/notification.rs`):
  - Added `Server.Authentication.RemotePrincipalBindings` to the storage model with certificate
    fingerprint / subject / SAN selectors, resolved local principal targets, and capability lists.
  - Added runtime `RemotePrincipalBinding` records for future `local+remote` authorization.
  - Config parsing resolves `LocalUser` through libc account lookup, accepts explicit `LocalPrincipal`
    UID/GID tuples, normalizes capability names, and fails closed on invalid/incomplete bindings.
  - Auth reload fingerprints now include auth mode, local allowlists, and remote principal bindings so
    client policy changes are treated as auth-relevant session state.

- **Phase-2 ingress authorization and owner-scope hardening** (`crates/daemon/src/flows/notification/notification.rs`):
  - Added explicit privileged-action classification at notification ingress with
    `AlwaysAllowed`, `UserScopedAllowed`, `ElevatedRequired`, and `AlwaysDenied` classes.
  - Added owner-scope normalization for non-root local rule mutations, including
    compatibility injection of `user.id=<caller uid>` for eligible payloads.
  - Added conservative firewall owner-scope normalization for compatible payloads,
    including nftables statement-path support (`meta skuid == <uid>`).
  - Added auth decision logging aligned with verdict fallback context, improving
    operator visibility across `legacy` and hardened modes.

- **Legacy ownerless rule migration mode** (`crates/daemon/src/daemon/migration.rs`,
  `crates/daemon/src/main.rs`, `crates/daemon/src/daemon.rs`):
  - Added one-shot CLI migration entrypoint:
    `--migrate-ownerless-rules --migrate-owner-uid <uid>` (dry-run by default),
    with `--migrate-write` for persistence.
  - Migration planning classifies rules into eligible/already-scoped/ambiguous/conflicting,
    emits a full report, and fails closed in write mode when ambiguous/conflicting rules remain.

- **Action-scoped schema hardening for rule mutations** (`crates/daemon/src/flows/notification/notification.rs`):
  - `CHANGE_RULE` now requires explicit operand semantics (non-empty operator operands)
    in hardened modes; payloads without operands are denied.
  - `ENABLE_RULE` / `DISABLE_RULE` / `DELETE_RULE` retain legacy minimal-stub compatibility
    via owner-scope/elevated arbitration.
  - Authorization for legacy rule stubs now resolves against stored rules by name,
    allowing non-elevated operations when stored owner scope matches caller identity.

- **Group-scoped owner authorization with syscall-backed resolution** (`crates/daemon/src/flows/notification/notification.rs`):
  - Added `user.gid` owner-scope support for rule authorization when caller UID is
    a member of the referenced group.
  - Extended firewall owner-scope checks/conflict detection to support group selectors
    (`--gid-owner`, `meta skgid`).
  - Group membership is derived from OS account/group resolution (`getpwuid` +
    `getgrouplist`) rather than ad-hoc group-file parsing.

- **Nested firewall-chain payloads kept elevated-only** (`crates/daemon/src/flows/notification/notification.rs`):
  - Nested `FwChain.rules` payloads remain elevated-required in hardened modes even when
    inner rules carry owner matches.
  - Compatibility normalization continues to apply only to flat owner-matchable firewall
    rule payloads, not chain-bearing payloads that can create or reshape global chain metadata.

- **Remote capability-based authorization for `local+remote` mode** (`crates/daemon/src/flows/notification/`,
  `crates/daemon/src/models/auth_capability.rs`, `crates/daemon/src/services/client/session.rs`,
  `crates/daemon/src/services/client/transport.rs`):
  - Added canonical capability constants model (`auth_capability.rs`): 10 capability strings
    (`rules.owner.write`, `rules.global.write`, `firewall.owner.write`, `firewall.global.write`,
    `config.write`, `daemon.control.stop`, `task.control`, `log.level`, `firewall.toggle`,
    `interception.toggle`) with `required_capability(action, class)` mapping.
  - Extended `ClientPrincipal` with `RemoteCert { binding_name, mapped_uid }` variant.
  - Extended `ClientSession` with `capabilities` field, `for_remote_principal()` constructor,
    and `has_capability()` method.
  - Added `resolve_remote_principal_binding()` matching cert identity against configured
    `RemotePrincipalBindings` (priority: fingerprint > subject > SAN).
  - `notification_command_allowed` routes `RemoteCert` sessions with capabilities through
    `check_remote_capability_authorization` instead of local peer-principal gate.
  - Owner-scope normalization and classification handle `RemoteCert { mapped_uid }` for
    remote sessions.
  - Added TLS cert identity extraction infrastructure (`CapturedServerCertIdentity`,
    `CertCapturingVerifier`, `extract_identity_from_pem`) using `x509-cert` + `sha2`.
  - Config-based remote principal resolution wired into `session_binding_from_client_addr`.
  - Added 3 audit event variants: `AllowedRemoteCapability`, `DeniedRemoteCapability`,
    `RemotePrincipalResolved` with Display formatting and notification flow emit sites.
  - 24 new tests covering remote principal binding resolution, capability mapping,
    remote authorization allow/deny paths, session construction, and audit formatting.
  - Full test suite: 515 passed, 0 failed, 7 ignored.

### Changed

- **Rule/file storage paths now honor selected main storage format**
  (`crates/daemon/src/services/rule/storage.rs`,
  `crates/daemon/src/services/rule/mutations.rs`,
  `crates/daemon/src/daemon/migration.rs`):
  - Rule scan filters now use storage-format-aware extension matching instead of hard-coded
    `.json` checks.
  - Rule file output extension now follows active main storage format.
  - Migration read/write paths now use storage service format conversions for parity across
    enabled codecs.

- **Dead-code arbitration and suppression hygiene**
  (`crates/daemon/src/models/lifecycle_contract.rs`,
  `crates/daemon/src/daemon/{tasks.rs,probes.rs,kernel_pipeline.rs}`,
  `crates/daemon/src/workers/runtime/watch/control.rs`,
  `crates/tools/src/main.rs`):
  - Removed suppressions from production-used APIs, removed truly unused helpers, and narrowed
    intentional suppressions with explicit one-line justifications.
  - Test-only helper wiring now prefers `#[cfg(test)]` where applicable.

- **Config default-location API remains first-class** (`crates/daemon/src/config/config.rs`,
  `crates/daemon/src/daemon/{bootstrap.rs,migration.rs}`):
  - Restored `Config::load_from_default_locations()` and made it the direct path when no
    CLI config-file or storage-format override is supplied.

- **Packaging-profile warning/error cleanup**
  (`crates/daemon/src/{services,workers,models,utils}/**`):
  - Resolved pre-existing non-default profile eBPF/runtime compile errors and warnings for
    `--no-default-features --features storage-format-yaml` by tightening feature-gated imports,
    fixing no-backend code paths, and adding explicit feature-scoped dead-code justifications for
    dormant surfaces.
  - Fixed default-profile unreachable-code warning in
    `services/connection/ebpf.rs::resolve_owner_by_ebpf_map`.

- **Firewall wire/file compatibility now maps through the canonical domain model** (`crates/daemon/src/services/firewall/conversions.rs`,
  `crates/daemon/src/services/firewall/storage.rs`, `crates/daemon/src/platform/ports/firewall_port.rs`,
  `crates/daemon/src/services/client/client.rs`, `crates/daemon/src/models/firewall_storage.rs`):
  - `pb::SysFirewall` was removed from core firewall/runtime/policy code and retained only at gRPC/adapter boundaries.
  - The deprecated `pb::FwChains` wrapper is flattened at ingress into `FirewallConfig.rules` and `FirewallConfig.chains`,
    then reconstructed only for wire/file egress compatibility.
  - Legacy `system-fw.json` nested chain rules now inherit missing `Table` / `Chain` values from the parent chain,
    matching the Go daemon's compatibility behavior.

- **Client transport/wire boundary decoupling completed for notifications/subscriptions + metrics boundary clarified**
  (`crates/transport-wire-core/src/{ports.rs,wire_helpers.rs}`,
  `crates/transport-wire-grpc-client/src/lib.rs`,
  `crates/daemon/src/services/client/{client.rs,transport.rs,wire.rs,notifications.rs,alerts.rs}`,
  `crates/daemon/src/flows/{notification/notification.rs,subscription/command_flow.rs,stats/stats.rs}`,
  `crates/daemon/src/models/metrics_snapshot.rs`,
  `crates/daemon/src/platform/adapters/{stats_exporter_prometheus.rs,stats_exporter_push.rs}`):
  - `transport-wire-core` no longer depends on OpenSnitch protobuf types for notification/rule/firewall payload helpers; core now exposes wire-native DTOs and transport-port associated types.
  - gRPC/protobuf mapping for notification/rule/firewall/subscription payloads is now adapter-owned in `transport-wire-grpc-client`, including stream bridge conversions for notification replies and subscription command acks.
  - Daemon client/flow code paths now consume wire aliases and domain mappers at service boundaries instead of directly coupling orchestration surfaces to protobuf request/reply types.
  - Metrics-facing code now uses explicit metrics aliases (`MetricsProtoStats`, `MetricsProtoSubscriptionStats`) and documents the protocol split: OpenSnitch transport stats payloads vs Prometheus `io.prometheus.client.MetricFamily` protobuf output.

- **Firewall-triggered rule-cache refresh now includes alias inputs** (`crates/daemon/src/commands/control/control.rs`,
  `crates/daemon/src/platform/adapters/nft_monitor.rs`, `crates/daemon/src/workers/firewall/watch_worker.rs`,
  `crates/daemon/src/workers/firewall/firewall_worker.rs`, `crates/daemon/src/services/rule/rule.rs`,
  `crates/daemon/src/services/firewall/firewall.rs`):
  - Added `RuleService::rebuild_caches_from_snapshot()` to rebuild match caches without reloading rules from disk.
  - Successful explicit firewall reloads, nftables netlink events, and drift-heal recoveries now refresh rule caches.
  - This keeps `network_aliases.json` and future firewall-native alias/zone sources synchronized with runtime firewall state
    without adding work to the verdict hot path.

- `Config::default()` now initializes `auth_mode` to `legacy` and preserves allowlist defaults as `None`.
- Hardened local modes now fall back to root-only local privileged access when no explicit principal/group policy is configured.

- **Transport/storage boundary decoupling and adapter crate normalization**
  (`crates/daemon/src/{commands,flows,models,platform,services,utils}/**`,
  `crates/transport-wire-core/**`, `crates/transport-wire-grpc-client/**`,
  `crates/storage-format-core/**`, `crates/storage-format-{json,yaml,toml}/**`):
  - Removed remaining runtime-facing `pb::*` dependencies from daemon command/flow/service code
    for notifications, rules, subscriptions, stats, alerts, and connection-event export paths;
    daemon/runtime code now consumes explicit wire-core DTOs and domain mappers instead.
  - Moved protobuf-only firewall/rule compatibility mappers into dedicated adapter-boundary modules
    (`platform/adapters/firewall_proto.rs`, `platform/adapters/rule_proto.rs`) so runtime services
    stay on canonical domain or wire-core shapes.
  - Split `transport-wire-grpc-client` into thin-root adapter modules (`client.rs`, `rpc.rs`,
    `tls.rs`, `transport.rs`, `wire_protos.rs`) and added adapter-local conversion tests.
  - Split `storage-format-core` and all `storage-format-*` crates into thin `lib.rs` roots with
    dedicated `codec.rs` / `error.rs` modules plus crate-local `src/tests/mod.rs` entrypoints.
  - Added direct tests in `transport-wire-core` and `storage-format-core`, and fixed daemon
    feature/profile drift so both default and minimal storage-format build profiles stay green.

### Changed

- **Wire-type naming: `policy_tx`, `hash_cache`, `task_payload` modules renamed** (`crates/daemon/src/models/`):
  - `models/policy_tx.rs` → `models/policy_tx_storage.rs`: `PolicyChangeSet`, `PolicyOwner`, and `TxPhase` are persisted-changeset types; file name now matches the `*_storage.rs` exemption in §4.
  - `models/hash_cache.rs` → `models/hash_cache_storage.rs`: on-disk JSON cache format types (`HashCacheKey`, `HashCacheEntry`, `HashCacheFile`, `HashCacheRecord`) correctly signal storage intent via file name.
  - `models/task_payload.rs` → `models/task_wire.rs`: `LegacyTaskResultPayload` and `TaskErrorPayload` are outgoing transient IPC frames sent to the UI over gRPC, never stored.  Unused `Deserialize` derive removed from both types; `*_wire.rs` suffix now codified as a §4 exempt file pattern.
  - `models/ebpf_state.rs`: `BpfMap` renamed to `RawBpfMap` to follow the `Raw*` prefix convention for ingress-only serde shapes sourced from kernel/OS state (`bpffs`/`procfs`).
  - All import sites updated (`services/policy_tx/policy_tx.rs`, `services/client/session.rs`, `services/process/hash_cache.rs`, `services/task/reply.rs`, `services/task/runtime_handlers.rs`, `workers/runtime/ebpf/control.rs`).

- **Storage event bus refactored to async ingress queue** (`crates/daemon/src/services/storage/event_bus.rs`):
  - `StorageEventBus` now uses a bounded sync ingress queue (`SyncSender<StorageIngressEvent>`) +
    dedicated dispatcher thread instead of dispatching inline on every emit call.
  - Added `dropped_ingress_events` `AtomicUsize` counter exposed via
    `StorageService::dropped_ingress_events_count()` for health monitoring.
  - Prefix-keyed broadcast routing and path-keyed fan-out moved into the dispatcher thread;
    emit sites are fully non-blocking.

- **Stats diagnostic counters expanded** (`crates/daemon/src/services/stats/`, `crates/daemon/src/services/stats/snapshot_ops.rs`):
  - `StatsService` now records `dropped_events_contention` (lock-contention drops on the event
    ring) and surfaces it as `diag.stats.dropped_events_contention` in stat snapshots.
  - Storage event bus dropped-ingress count added as `diag.storage.event_bus.dropped_ingress`
    in stat snapshots via `StorageService` reference.

### Documentation

- **Tracker and release notes updated for storage-format + warning-rule slices**
  (`TODO.md`, `CHANGELOG.md`, `DESIGN_RULES.md`):
  - Added condensed history entries for main storage-format override wiring, codec
    feature-gating, DNS answer batching, and warning arbitration outcomes.
  - Added explicit compiler warning resolution rule (promote/remove/justify) and
    suppression hygiene constraints.

- **`DESIGN_RULES.md` restructured into four parts** (`DESIGN_RULES.md`):
  - Reorganised from a flat section list into **Part I — Cross-Cutting Architectural Rules** (§1–§5), **Part II — Per-Domain Rules** (§6–§8), **Part III — Infrastructure Rules** (§9–§10), and **Part IV — Implementation Quality Rules** (§11).
  - Added `#### Hot-Path State Access Rule` to §1: codifies wait-free/lock-free read discipline for per-packet paths, a primitive table (`ArcSwap`, `ConcurrentLruCache`, `DashMap::get`, firewall `watch::Receiver`, eBPF `ArcSwap<HashMap>`), six violation signals (mutex in hot path, deep clone at read, `DashMap` iteration, `async fn` snapshot accessor, `tokio::sync::Mutex`/`RwLock` on read-dominant state), and a cross-reference to §9.
  - §9 `DashMap` entry updated to cross-reference the §1 hot-path iteration prohibition.
  - §4 naming rule extended with: `*_wire.rs` as a new file-level exempt suffix (outgoing transient IPC payloads, `Serialize`-only), clarification that `Raw*` prefix also applies to kernel/OS ingress state (e.g. `RawBpfMap`), and an updated violation-signal line that includes `*_wire.rs` in the exempt-file list.

- **Firewall domain + alias refresh docs updated** (`DESIGN_RULES.md`, `COMPATIBILITY.md`, `DOCS.md`, `TODO.md`):
  - Documented the canonical flattened firewall domain model and the future `FirewallZone` design anchor.
  - Documented `Rules.NetworkAliasesFile` and runtime alias-cache rebuild behavior.
  - Documented that explicit firewall reloads, nftables netlink events, and drift-heal recovery all refresh rule caches.

- **Privileged-command authorization docs updated** (`DOCS.md`, `TODO.md`, `DESIGN_RULES.md`):
  - Added `Server.Authentication.Mode`, `AllowedPrincipals`, `AllowedUsers`, and `AllowedGroups`
    to config documentation.
  - Documented conservative owner-scope enforcement, elevated-only command classes, and loopback
    TCP local identity handling.
  - Added planning guidance for dedicated `auth.proto` elevation RPCs, PAM-backed remote grants,
    and daemon-side owner-scope injection for backward-compatible UI rule creation.

  - **Adapter crate structure rules codified in `DESIGN_RULES.md`** (`DESIGN_RULES.md`):
    - Added explicit thin-root and sibling-module rules for all `transport-wire-*` and
      `storage-format-*` crates.
    - Added the `storage-format-core` internal separation rule and adapter-test entrypoint rule via
      `src/tests/mod.rs`.
    - Documented that pure shared boundary models may remain compiled across packaging profiles when
      they are side-effect-free and preserve stable boundary/API contracts.

- **Phase-2 policy clarification docs** (`DESIGN_RULES.md`, `DOCS.md`, `TODO.md`):
  - Clarified local principal semantics: UID is the identity anchor; GID/group selectors are
    supplementary gating and not an independent identity authority.
  - Clarified service/elevation boundary: daemon enforces authorization but does not host
    interactive elevation prompts; UI-mediated host backends (polkit/pkexec) remain the model.
  - Documented explicit ownerless-rule migration workflow and fail-closed write semantics.

### Testing

- **Audit service coverage** (`crates/daemon/src/tests/services/audit.rs`,
  `crates/daemon/src/tests/services/audit_sink.rs`):
  - `audit.rs`: ring-overwrite eviction (capacity-2 ring discards oldest on overflow), broadcast
    subscriber receives cold-path `ClientAuthorizationAction` events, `VerdictAction::AskRuleRulePersisted`
    payload round-trip survives ring store/drain.
  - `audit_sink.rs`: NDJSON render produces valid JSON with correct `ts`/`path`/`level`/`event` fields;
    severity labels (`error`/`warn`/`info`) from `AuditSeverity`; JSON escaping for `\"` and `\\`;
    syslog message uses `Display` (not `Debug`) output; disabled-sink config spawns no worker threads.

- **Firewall domain + alias compatibility coverage** (`crates/daemon/src/tests/firewall/firewall_service.rs`,
  `crates/daemon/src/tests/rules/rule_service.rs`, `crates/daemon/src/tests/services/client.rs`,
  `crates/daemon/src/tests/flows/notification_flow.rs`):
  - Added legacy `system-fw.json` chain inheritance coverage for nested rules missing `Table` / `Chain`.
  - Added `network_aliases.json` smoke coverage for `LAN` CIDR matching.
  - Updated firewall/client/notification tests to use canonical domain models instead of proto firewall payloads.

- **Config parsing coverage** (`crates/daemon/src/tests/parsing/config_parsing.rs`):
  - Added tests for missing/null local allowlist behavior, UID/GID pair parsing, username resolution,
    and `auth.mode` parsing/defaults.

- **Notification flow coverage** (`crates/daemon/src/tests/flows/notification_flow.rs`):
  - Updated session binding tests to pass config context.
  - Added UNIX local principal allow/deny tests.
  - Added Linux loopback TCP principal allow/deny test.
  - Added coverage for remote privileged denial in `local-only`, legacy compatibility behavior,
    root-only fallback, owner-scoped local rule/firewall mutation acceptance, elevated-only global
    firewall commands, and loopback TCP local-UID session binding.

- **Additional authorization and migration coverage** (`crates/daemon/src/tests/flows/notification_flow.rs`,
  `crates/daemon/src/tests/rules/rule_migration.rs`):
  - Added tests for action-scoped `CHANGE_RULE` operand hard denial.
  - Added tests proving legacy `ENABLE_RULE`/`DISABLE_RULE`/`DELETE_RULE` stubs can resolve
    to stored owner-scoped rules without elevation, including group-scoped owner selectors.
  - Added tests proving nested `FwChain.rules` firewall payloads remain elevated-required and
    are not owner-scope normalized for non-root local clients.
  - Added migration tests for dry-run/write paths, owner-scope injection, and fail-closed
    behavior on ambiguous/conflicting legacy rules.

- **Inline rule reload on inotify fast path** (2026-03-30):
  - Added `RuleService::reload_inline()`: reads rule JSON files directly on the tokio thread
    (no `spawn_blocking` scheduling hop). Rules directories hold a handful of small files
    (< 1 KB) — sync I/O completes in microseconds, well within tokio's cooperative budget.
  - Inotify-triggered scan path in `RuleWatchControl` switched from `reload_sync` to
    `reload_inline`, eliminating ~3-5 ms blocking-pool round-trip per reload.
  - Cold:rule parity median improved from +12 ms to +7 ms (Rust vs Go).

- **§2 file-size enforcement splits** (2026-03-30):
  - `services/task/runtime_handlers.rs` (1181 → 913 lines): extracted socket-table helper functions
    (`ensure_process_entry`, `resolve_cached_socket_pid/iface_name`, `fetch_iface_name_map_rtnetlink`,
    `prepare_socket_monitor_row`, `socket_monitor_{row,diag_row,packet_row,xdp_row}_json`,
    `AF_XDP_FAMILY`) to new `services/task/socket_monitor.rs` as `pub(super)` free functions.
  - `tunables.rs` (755 lines) converted to a directory module: `tunables/mod.rs` (linker-only,
    re-exports `RuntimeTunables` and `NfqueueOverloadPolicy`); `tunables/tunables.rs` (457 lines,
    all impl: `publish_global`, `global`, `reload_global`, `load_effective`, `apply_raw`,
    `apply_env_overrides`, `parse_env_usize`, `parse_env_bool`, `clamp`); `tunables/autotune.rs`
    (308 lines: `maybe_autotune_on_startup`, `check_autotune_preflight`, preflight probes,
    autotune subprocess control, `env_flag`, `resolve_optin_tunables_path`, `load_raw_tunables`).
  - `commands/control/control.rs` (812 → 383 lines): extracted `set_firewall`, `reload_firewall`,
    `collect_firewall_errors{,_impl}` to `commands/control/firewall_cmd.rs` (295 lines);
    `apply_config` and `set_log_level` to `commands/control/config_cmd.rs` (169 lines).
    Private helpers (`policy_tx`, `owner_from_client`, `tx_error_message`, `selective_reload_services`,
    `audit` field) made `pub(super)` for cross-impl access within the module.
  - `flows/notification/notification.rs` (1965 → 1309 lines): extracted peer credential and
    principal check functions (`try_unix_peer_credentials`, `try_loopback_tcp_listen_socket`,
    `find_pid_for_socket_inode`, `peer_group_memberships`, `local_policy_explicitly_configured`,
    `unix_principal_allowed`, `loopback_tcp_principal_allowed`, `username_for_uid`,
    `group_memberships_for_uid`) to `flows/notification/authorization.rs` (pub(super) impl blocks);
    operator/rule/firewall owner-scope functions to `flows/notification/owner_scope.rs`; action
    classification discriminants (`is_privileged_notification_action`, `is_rule_mutation_action`,
    `is_rule_toggle_or_delete_action`, `is_firewall_reload_action`) to `flows/notification/classification.rs`.
    `UnixPeerCredentials` made `pub(super)` for cross-submodule access.
  - Deferred split plans for 14 remaining over-threshold files documented in `TODO.md`.
  - All `mod.rs` files in affected areas comply with the linker-only rule.
  - `cargo fmt` applied codebase-wide.
  - 491 tests passing, zero warnings.

## [v0.7.0] - 2026-03-27

### Added

- **Dedicated subscription proto surface** (`proto/subscriptions.proto`, `proto/ui.proto`):
  - All subscription types (`Subscription`, `SubscriptionRequest`, `SubscriptionReply`,
    `SubscriptionAction`, `SubscriptionStatus`, `SubscriptionRefreshMetadata`,
    `SubscriptionCommand`, `SubscriptionCommandAck`) moved from `ui.proto` into a separate
    `subscriptions.proto` with its own `Subscriptions` service and bi-directional
    `Commands` streaming RPC.
  - `ui.proto` retains only connection/verdict/ping-stats wire types — no subscription
    coupling in the core telemetry path.
  - New proto messages: `SubscriptionEvent` (lifecycle event record, mirrors `ui.Event`
    shape) and `SubscriptionStatistics` (mirrored three-layer shape: scalars + breakdown
    maps + event ring, matches `Statistics`).
  - New `RuleSubscriptionEntry` message for N:N rule→subscription mapping:
    `rule: string` + `repeated string subscriptions` (sorted, deduplicated).

- **Per-subscription metrics export** (`services/subscription/`, `platform/adapters/stats_exporter_*`):
  - `SubscriptionStatistics` populated from `SubscriptionService` at every stats collection
    cycle (bootstrap + refresh-scheduler tick).
  - Scalar gauges: `opensnitch_subscription_total / ready / error / refresh_count / refresh_errors`.
  - Labeled breakdown gauges: `opensnitch_subscription_by_status{status=...}`,
    `opensnitch_subscription_by_group{group=...}`, `opensnitch_subscription_by_node{node=...}`.
  - Emitted across all export formats: Prometheus text 0.0.4, OpenMetrics 1.0.0,
    Prometheus protobuf (length-delimited), push-gateway push, and InfluxDB line protocol.
  - Subscription event ring (`repeated SubscriptionEvent events`, capacity 64, newest-first)
    records lifecycle events (apply/refresh/delete/error) with RFC 3339 timestamp + action +
    Unix nanosecond for deduplication, mirroring `ui.Event` semantics.
  - `MetricsSnapshot` model (`models/metrics_snapshot.rs`) unifies `pb::Statistics` +
    `Option<pb::SubscriptionStatistics>` for single-pass snapshot hand-off to exporters.

- **Rule→subscription N:N mapping in metrics** (`services/subscription/subscription.rs`,
  `services/rule/rule.rs`, `proto/subscriptions.proto`):
  - `RuleService::list_rule_data_paths()` scans active rules for `lists.*` operators
    (recursive into composite `list` operators) and returns `(rule_name, data_path)` pairs.
  - `SubscriptionService::build_rule_subscription_entries()` cross-references those paths
    against `<root>/rules.list.d/` (groups: `sanitize(filename)`, `"all"`, and explicit
    groups per `layout.rs`), collecting the full N:N mapping per rule via `HashSet`
    deduplication.
  - `subscription_stats_with_rules(list_rule_paths)` produces `SubscriptionStatistics`
    with the `rule_subscriptions` field populated; called from `bootstrap.rs` at startup
    and from `refresh_scheduler.rs` after each refresh cycle (now accepts `RuleService`).
  - Exported as: `opensnitch_subscription_rule_info{rule=...,subscription=...} 1` gauge
    (one row per rule×subscription pair, Prometheus/OpenMetrics/proto);
    `opensnitch_subscription_rule,rule=...,subscription=... info=1i` (InfluxDB).

- **Per-rule hit counts in metrics export** (`services/stats/`, `platform/adapters/stats_exporter_*`,
  `proto/ui.proto`):
  - New `by_rule` map in `Statistics` proto (tag 21) tracking per-rule connection hit counts.
  - `on_rule_hit(rule_name)` in `StatsService` bumps a `LimitedCountersString` breakdown.
  - Exposed as `opensnitch_rule_hits_by_rule{rule="<name>"}` gauge across all metrics
    formats: Prometheus text 0.0.4, OpenMetrics 1.0.0, Prometheus protobuf, push-gateway,
    and InfluxDB line protocol (`opensnitch_by_rule,rule=<name> connections=<n>i`).
  - Subject to `max_stats` top-N eviction like existing breakdown maps.
  - Provides per-rule observability for Grafana dashboards without requiring syslog parsing.

- **Subscription command layer restructured** (`commands/subscription/`, `models/command_rpc.rs`):
  - `commands/subscription/wire.rs` removed; wire-protocol concerns inlined into
    `commands/subscription/subscription.rs` alongside the bidirectional `Commands` stream.
  - `SubscriptionCommandServiceImpl` handles the `Commands` stream with per-command dispatch,
    full error propagation, and graceful shutdown on cancellation.
  - `CommandRpcPayload` model (`models/command_rpc.rs`) replaces the old `subscription_wire`
    model — carries `id`, `action`, `data`, and `accepted` field for ack construction.

- **Subscription flow** (`flows/subscription/`):
  - Dedicated `SubscriptionFlow` task wired in `daemon/tasks.rs`; drives the `Commands`
    bidirectional stream, dispatching each `SubscriptionCommand` to `SubscriptionService`
    and writing back `SubscriptionCommandAck` inline.

- **Mock UI client subscription + metrics coverage** (`scripts/mock_ui_client.py`):
  - `MOCK_UI PingStats` markers log all `pb.Statistics` wire fields (scalars, map row
    counts, one event sample) for live-session observability.
  - Subscription state (`pb.ListReply`, subscription event counts) logged via `MOCK_UI`
    markers for integration-level traceability.
  - Client handles graceful `GOAWAY` / `RpcError` on shutdown without noisy stack traces.

- **Metrics test suite** (`tests/metrics/stats_exporter_prometheus.rs`,
  `tests/metrics/stats_exporter_push.rs`):
  - 74 new tests (total: **547** tests, 7 ignored):
    - Prometheus text 0.0.4: scalar correctness, TYPE/HELP lines, label escaping,
      subscription gauges, breakdown maps, rule_info N:N rows, absent-when-empty guards.
    - OpenMetrics 1.0.0: counter base-name TYPE line, `_created` timestamp, EOF sentinel,
      subscription scalars, rule_info emission.
    - Prometheus protobuf: MetricFamily stream decoding, scalar counters, by_status labels,
      rule_info family presence/count/two-label validation, absent-when-empty guard.
    - Content negotiation: OpenMetrics beats plain-text, proto explicit-param detection,
      wildcard/empty fallback to text.
    - Gzip helper: round-trip compress/decompress, empty input sentinel.
    - HTTP live tests: `GET /metrics` text, proto, gzip, `HEAD` method, 404 on unknown path.
    - Push text/proto: subscription gauges, breakdowns, rule_info N:N rows.
    - InfluxDB: stats measurement line fields, subscription breakdown tags, rule tags,
      tag-value escaping, timestamp format, absent-when-empty guard.
    - `build_endpoint`: pushgateway/proto path construction, InfluxDB bucket+precision query
      append, duplicate prevention.
    - HTTP integration tests (mock server): pushgateway POST, InfluxDB POST body, gzip,
      bearer auth.

### Changed

- `SubscriptionService::spawn_scheduler` now accepts `RuleService` alongside `StatsService`
  to enable rule→subscription cross-reference on every refresh cycle without daemon restart.
- `bootstrap.rs` initial stats snapshot uses `subscription_stats_with_rules` to populate
  `rule_subscriptions` from the startup rule set.
- `services/stats/` internal split: `StatsService` now carries `update_subscription_stats`
  method; `MetricsSnapshot` is the hand-off type between `StatsFlow` and exporters.
- `stats_exporter_prometheus.rs` and `stats_exporter_push.rs` updated to consume
  `MetricsSnapshot` (carrying `Option<pb::SubscriptionStatistics>`) instead of raw
  `pb::Statistics`; both adapters are feature-gated under `metrics-export`.
- `proto/ui.proto`: subscription message types removed; file now contains only
  `UIService` RPC surface, `Statistics`, `Event`, `Rule`, and connection/verdict types.
- Notification flow (`flows/notification/`) stripped of now-superseded subscription
  bridging logic; notification tests pruned accordingly.

## [v0.6.0] - 2026-03-27

### Added
- **Persistent file-based hash cache** (`services/process/hash_cache.rs`, `models/hash_cache.rs`):
  - `PersistentHashCache` stores process binary checksums (md5/sha1/sha256) to disk as JSON,
    surviving daemon restarts.
  - Cache key: `(exe_path, inode, mtime_secs, file_size)` — any binary change from a package
    update, recompile, or manual edit automatically invalidates the cached entry.
  - `DashMap`-backed in-memory store with periodic JSON flush (60 s) to
    `/var/cache/opensnitchd/hash_cache.json` (falls back to `$TMPDIR/opensnitchd/`).
  - Stale-entry GC every 10 minutes: re-stats each cached path and removes entries whose
    on-disk metadata no longer matches (covers in-flight package upgrades).
  - Atomic write (tmp file + rename) for crash safety; shutdown hook performs final flush.
  - `spawn_hash_update` checks persistent cache before computing hashes from file I/O;
    stores results on cache miss.
  - Background flush/GC task wired via `spawn_hash_cache_flush_task` in `daemon/tasks.rs`.
  - 4 new tests: insert/lookup, flush+reload persistence, invalidation on binary size
    change, GC removes entries for deleted files.

- **Session snapshot copy-on-write** (`services/client/client.rs`, `services/client/session.rs`):
  - Replaced `owned_snapshot()` + mutate + `publish_snapshot()` pattern with
    `modify_snapshot(|s| { ... })` using `watch::Sender::send_modify()` + `Arc::make_mut()`.
  - Under no contention (common case), the inner data is mutated in-place with zero
    allocation. Under contention, `Arc::make_mut` clones — the minimum necessary for
    concurrent correctness.
  - All 4 mutation methods converted: `upsert_session`, `disconnect_session`,
    `set_session_default_action`, `set_connected_default_action`.

- **AdBlock/AdGuard list format support** (`services/rule/utilities.rs`, `services/rule/storage.rs`):
  - `normalize_domain_list_entry` parses `||domain^` (AdBlock/AdGuard domain anchor) by
    stripping `||` and terminating at the first `^`, `$`, or `/`.
  - Exception rules (`@@||domain^`), cosmetic filters (`##`, `#@#`), header lines
    (`[Adblock Plus…]`), and `!` comments return `None`.
  - Wildcard entries (`||*.tracker.net^`) handled by existing `DomainWildcardTrie` path.
  - `||domain^` now matches both `domain` AND `sub.domain` per AdBlock spec.

- **Unified `lists.domains` cascade** — a single `lists.domains` operator now handles plain
  domains, `||anchor^` rules, wildcard/glob entries, and `/regex/` patterns from the same
  mixed file.  Matching cascades: `HashSet` (O(1)) → `DomainWildcardTrie` → `GlobMatcher`
  → `domains_regex` (Aho/regex, only when all fast-path lookups miss).

### Changed (Performance)
- **Inotify-hint fast path for rule watch reload** — When the kernel's inotify
  event tells us the rules directory changed, skip the redundant readdir+stat
  state-comparison and go straight to reload.  Adds `set_inotify_hint()` to the
  `WatchWorkerControl` trait, `load_rules_from_path_sync()` / `reload_sync()`
  methods that batch all file I/O into a single `spawn_blocking` call, and sync
  writes in the measured parity test section (matching Go's synchronous `Copy()`).
- **Hot/cold path optimizations** — 7 items (3 HIGH, 4 MEDIUM):
  - Eliminate per-probe `format!` allocation in `services/connection/owner.rs`.
  - Replace per-connection `HashSet` with bounded hop-limit loop in DNS alias-cycle detection.
  - Remove per-rule-eval `String` allocations via `OnceLock<String>` fields in `AttemptDerived`.
  - Reduce verdict decision key allocation: `DashMap<String, u64>` → `DashMap<u64, u64>`.
  - Remove `cleanup_expired()` from `inspect()` hot path (background task handles it).
  - Stack-allocated eBPF key building (`BpfKey { V4, V6 }` enum).
  - Avoid per-event closure capture in kernel pipeline dispatch.
  - Remove eager clone before `ask_rule` in verdict flow.

- **Codebase optimization pass** — 14 items (3 HIGH, 6 MEDIUM, 5 LOW):
  - **HIGH**: Single `/proc/{pid}/stat` read in process inspection; pool gRPC client
    connections via `GrpcChannelCache` (`ArcSwap` + config fingerprint); shared
    `build_checksums`/`build_env_map` helpers in proto mapper with `HashMap::with_capacity`.
  - **MEDIUM**: Bound netlink dispatch channels (`sync_channel(512)` + `try_send`);
    DNS dedup overflow-only `retain`; narrow task-watch mutex scope (load/apply split);
    SIEM sinks `Arc<[SinkHandle]>` clone; `SinkFormat` enum precomputed at build time;
    single-pass socket candidates with priority-tiered buckets.
  - **LOW**: Coalesce inotify triggers via bounded(1) channel; `connected_sessions_count()`
    for zero-alloc count; `BufReader` for `/proc/net/packet` and `/proc/net/xdp`;
    stack buffer `[u64;8]` for `/proc/stat` CPU parsing; session snapshot CoW via
    `Arc::make_mut`.

- **Cache typed eBPF map handles** in `services/connection/ebpf.rs` — `MapData::from_id`
  opened once per connection instead of 3× (exact key, wildcard dst, swapped); 2 fd-open
  syscalls and 2 BTF validations saved per connection.
- **`BufReader` for `/proc/net/*` fallback** in `services/connection/owner.rs`.
- **Eliminate Vec allocation in ICMP packet-socket fallback** — `Option<ConnectionOwner>`
  single-slot tracking replaces `Vec`.
- **Bound kernel ingress channels** — `channel(capacity)` reusing downstream tunables.
- **Narrow rules-watch mutex scope** — clone-drop-reacquire pattern.
- **Parallelise cold-path list file I/O** via `tokio::task::JoinSet`.
- **Avoid per-event String allocation in `format_event_time`** — stack `[u8; 19]` buffer.

### Fixed
- `||domain^` entries now match subdomains (`www.example.org`) in addition to the exact
  domain — `DomainWildcardTrie::insert_domain_and_subdomains` uses `required = labels.len()`
  instead of `labels.len() + 1`.

#### Included from unreleased v0.5.1

### Added
- **Prometheus `/metrics` scrape endpoint** (`platform/adapters/stats_exporter_prometheus.rs`,
  feature-gated `metrics-export`):
  - `PrometheusStatsExporter` implements `StatsExporterPort` — stores a stats snapshot
    atomically via `ArcSwap`; the snapshot is never written on the hot-path request handler.
  - `spawn_metrics_server(addr, shutdown)` starts a minimal `hyper` 1.x HTTP/1.1 listener;
    `/metrics` serves the snapshot; any other path returns 404; bind failure logs a warning
    and disables the endpoint without affecting daemon operation (fail-open).
  - **Content negotiation** per the [Prometheus scrape protocol spec](https://prometheus.io/docs/instrumenting/content_negotiation/):
    - `negotiate_format(accept)` parses `Accept` q-values; selects the richest supported
      format at the highest q-value; tie-breaks: OpenMetrics > Text1.0.0 > Text0.0.4 > Proto.
    - Supported formats:
      - `PrometheusText0.0.4` (`text/plain; version=0.0.4; charset=utf-8`) — default fallback.
      - `PrometheusText1.0.0` (`text/plain; version=1.0.0; charset=utf-8; escaping=allow-utf-8`)
        — identical output to 0.0.4; label values already pass UTF-8 through.
      - `OpenMetricsText1.0.0` (`application/openmetrics-text; version=1.0.0; charset=utf-8`)
        — counter MetricFamilies use base names (no `_total`) for HELP/TYPE; samples include
        `<base>_total` and `<base>_created` (Unix float); gauges with a known unit get a
        `# UNIT` line; output terminates with `# EOF\n`.
      - `PrometheusProto` (`application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited`).
    - `PrometheusProto` wins only when its weight strictly exceeds text;
      among text formats, richest wins on ties.
  - **Gzip compression**: `Accept-Encoding: gzip` (or `*`) triggers `flate2` gzip
    compression; `Content-Encoding: gzip` is set on the response.  Falls back silently to
    uncompressed body on compression failure.
  - **Metric set**: 7 counters (`_total` suffix), 5 gauges, 6 labeled gauges
    (breakdown by protocol, address, host, port, uid, executable).  All prefixed `opensnitch_`.
  - Wired in `daemon/tasks.rs:spawn_stats_flow()` under `#[cfg(feature = "metrics-export")]`.

- **Push-style stats exporter** (`platform/adapters/stats_exporter_push.rs`,
  feature-gated `metrics-export`):
  - `PushStatsExporter` implements `StatsExporterPort` — non-blocking `export_snapshot`
    enqueues a compact snapshot onto a bounded channel (capacity 4); drops silently on full
    (fail-open).
  - Background `push_worker` task drains the channel and POSTs to the remote endpoint via
    `reqwest::Client` with 5 s timeout; HTTP errors are logged at DEBUG — never fatal.
  - Three push formats:
    - `pushgateway` (default): Prometheus text 0.0.4 POSTed to `{url}/metrics/job/{job}`.
      Compatible with Prometheus Pushgateway, Grafana Mimir, and Grafana Cloud remote-write.
    - `pushgateway-proto`: Prometheus protobuf (`io.prometheus.client.MetricFamily`, delimited)
      — preferred by Prometheus-native backends.
    - `influxdb`: InfluxDB line protocol POSTed to the URL verbatim per the
      [InfluxDB v2 write API](https://docs.influxdata.com/influxdb/v2/get-started/write/):
      - integer field suffix `i` on all fields,
      - tag values escaped (comma, space, equals, backslash),
      - `?precision=s` appended when absent,
      - `Authorization: Token <token>` header for InfluxDB v2 auth.
  - `MultiStatsExporter`: fan-out adapter that routes each snapshot to an ordered
    `Vec<Arc<dyn StatsExporterPort>>`; used when both Prometheus and push are enabled.
  - Gzip push bodies optional (`Content-Encoding: gzip`); shared `gzip_compress()` helper
    from the scrape adapter.

  - **`metrics.json` hot-reload on SIGHUP** (`daemon/reload.rs`, `daemon.rs`, `daemon/tasks.rs`):
    - `DaemonRuntime` gains a `metrics_server: Mutex<Option<MetricsServerSlot>>` field
      (feature-gated `metrics-export`).  `MetricsServerSlot` stores the long-lived
      `PrometheusStatsExporter` Arc, the current bound address, and the server's
      `CancellationToken`.
    - `spawn_stats_flow()` always creates the `PrometheusStatsExporter` (even when no
      address is configured) so that a subsequent SIGHUP that adds an address does not
      require a flow restart.  The scrape HTTP server is only started when an address
      is resolved.  A child `CancellationToken` (not `daemon.shutdown`) is used for the
      server so it can be independently cancelled on reload.
    - `Daemon::reload_metrics_server()` (called from `reload_runtime_after_sighup`):
      re-reads `metrics.json`, performs §7 resolution, and compares the resolved address
      to the current one:
      - **Addr unchanged** → no-op.
      - **Addr added or changed** → cancel old server (if any), spawn new listener,
        store new `MetricsServerSlot`; the existing exporter Arc is reused so the
        `StatsFlow` continues delivering snapshots uninterrupted.
      - **Addr removed** → cancel server; exporter remains wired (snapshots continue
        accumulating, server-less).
    - Push exporter configuration is not hot-reloaded; a daemon restart is required
      for push URL / format / credential changes.

- **DESIGN_RULES §7 — Configuration Surface Precedence Rule** (`DESIGN_RULES.md`):
  - Mandates CLI switches → env vars → JSON config file (baseline) precedence for any
    externally-settable parameter.  CLI switches have highest precedence; env vars
    are mid-tier (typically used for testing, CI, and ephemeral deployment injection).

- **`metrics.json` config file + CLI switches for metrics-export** (`models/metrics_config.rs`):
  - New `MetricsConfig` serde model (`PrometheusConfig.addr`, `PushExportConfig.{url,format,
    job,token,gzip,bucket,org}`); loaded from `metrics.json` co-located with the daemon
    config at startup via `MetricsConfig::load_sibling()` (fail-open: absent file → defaults).
  - `CliOverrides.metrics: MetricsCliOverrides` + 6 new `--metrics-*` flags parsed in
    `parse_cli_overrides()`.
  - `spawn_stats_flow()` performs full §7 resolution: CLI → env var → JSON config
    baseline.
  - `prometheus_addr_from_env()` and `PushConfig::from_env()` removed — dead code after
    migration.  CLI switches (`--metrics-*`) have highest precedence; env vars
    (`OPENSNITCH_PROMETHEUS_ADDR`, `OPENSNITCH_PUSH_*`) are mid-tier.

### Changed
- **Kernel capability self-check diagnostic** (`utils/kernel_caps.rs`, Go parity gap closed):
  - Reads kernel config from `/boot/config-{kver}`, `/proc/config.gz` (gzip-decoded via
    `flate2`), or `/usr/lib/modules/{kver}/config` — same search order as Go daemon.
  - Checks 7 feature groups (kprobes, uprobes, ftrace, syscalls, nfqueue, netlink,
    net diagnostics) via `regex::bytes::Regex` against the raw config bytes; checks
    tracefs mount via `/proc/mounts`.
  - Results emitted as `tracing` structured events (`info` on pass, `warn` on miss);
    non-fatal and gracefully degrades when config file is absent.
  - Wired in `daemon/bootstrap.rs` immediately after config load, mirroring Go's
    `core.CheckSysRequirements()` call position.
  - `flate2 = "1"` added as a direct dependency.
- **Refactor: split oversized API-surface files** (DESIGN_RULES §3):
  - `services/storage/ops.rs` (new) — 3 free-function I/O helpers (`option_if_not_found`,
    `bool_if_not_found`, `exists_if_not_found`) extracted from `StorageService` private methods.
  - `services/client/session.rs` (new) — session types (`ClientPrincipal`, `ClientSession`,
    `ClientSessionSnapshot`) + `SessionState` (watch channel wrapper + principal-ranking logic)
    extracted from `client.rs`.  `ClientService` now holds `session: Arc<SessionState>`.
  - `flows/verdict/helpers.rs` (new) — 17 private `VerdictFlow` helper methods extracted from
    `verdict.rs` (decision-epoch bookkeeping, miss accounting, alert enqueuing, action
    application, ask-timeout policy).  Methods remain `impl VerdictFlow` in a sibling module;
    accessed fields/methods are `pub(super)`.
  - 425 tests green; no API surface change.

### Added
- **Event-driven firewall drift detection** (`workers/firewall/watch_worker.rs` +
  new `platform/adapters/nft_monitor.rs`):
  - `FirewallWatchControl::targets()` now returns `WatchWorkerControl::path_targets`
    for the firewall config file (+ parent directory), enabling the existing
    inotify+epoll watch infrastructure to wake immediately on config-file writes.
    `empty_targets_behavior` changed to `WarnPollFallback` (empty target list is now
    anomalous rather than expected).
  - `platform/adapters/nft_monitor.rs` — new `spawn_nft_drift_listener(firewall,
    shutdown)` opens a `MulticastSocketRaw` on `NETLINK_NETFILTER` (12) and subscribes
    to `NFNLGRP_NFTABLES` (group 7).  On each kernel nftables rule-change event the
    adapter calls `firewall.heal_if_drifted()`.  The service's existing
    `drift_recovery_blocked_until_epoch_ms` atomic provides burst rate-limiting; rapid
    bursts collapse to a single heal call.  Socket-open or listen failure degrades
    gracefully (warning log) — the 20 s timer loop remains the safety-net fallback.
    Wired in `workers/firewall/watch_worker.rs::start()`.
  - Go parity note: Go uses ticker-based drift polling only; NFNLGRP_NFTABLES
    subscription is a Rust extension beyond the Go baseline.

### Changed
- **`async-trait` removed as a production dependency** (`crates/daemon/Cargo.toml` +
  13 service runtime files):
  - All 34 `#[async_trait::async_trait]` attributes removed from
    `services/lifecycle.rs` (trait definitions for `ServiceLifecycle`,
    `ServiceFactory`, `ServiceRuntimeControl`) and every `services/*/runtime_lifecycle.rs`
    impl file.  Native AFIT (`async fn` in traits, stable since Rust 1.75) handles these
    traits without any proc-macro.
  - `async-trait = "0.1"` removed from `[dependencies]` and moved to
    `[dev-dependencies]`.  It remains there solely because `tonic-prost-build 0.14`
    still desugars `#[async_trait]` on generated server traits; the three tonic Ui
    test-server impls in `tests/flows/` therefore still require the attribute.  The
    production binary carries zero async-trait overhead.
  - Tested against: Rustc 1.93.1, edition = "2024".
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
  and config only).  Override with `INIT_SYSTEM=systemd|openrc|procd|none`.  Added
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
