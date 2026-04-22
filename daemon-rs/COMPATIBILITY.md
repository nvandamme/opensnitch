# Daemon-RS Compatibility Reference

This document contains Go <-> Rust compatibility mappings and parity rationale.

## Navigation Index

- [Parity Matrix and Compatibility](#parity-matrix-and-compatibility)
- [Extended Feature/Behavior Matrix (Out Of Core Compatibility Scope)](#extended-featurebehavior-matrix-out-of-core-compatibility-scope)
- [Rule Operator Parity (Go -> Rust)](#rule-operator-parity-go---rust)
	- [Core operands](#core-operands)
	- [Operator types](#operator-types)
	- [lists.* parity specifics](#lists-parity-specifics)
	- [Live reload and verdict propagation](#live-reload-and-verdict-propagation)
	- [Rust-only extensions](#rust-only-extensions)
	- [Out-of-scope / not active](#out-of-scope--not-active)
- [Stats Parity (Go -> Rust)](#stats-parity-go---rust)
- [Architecture Delta Notes (Rescan Rationale)](#architecture-delta-notes-rescan-rationale)
- [File-Level Critical Path Mapping (Scoped Appendix)](#file-level-critical-path-mapping-scoped-appendix)

## Parity Matrix and Compatibility

| Area | Scope / Signal | Go counterpart | Current Rust Path | Status | Guidance |
|---|---|---|---|---|---|
| `services/process` + `flows/kernel` | Netlink: `NETLINK_CONNECTOR` (proc fork/exec/exit) + `NETLINK_AUDIT` (audit event stream) | `daemon/procmon/` + `procmon/audit/` | `netlink-bindings` + `netlink-socket2` | Stable | Keep unified stack; process service owns both netlink families; kernel flow ingests eBPF probe events |
| `services/process` + `flows/kernel` | eBPF: process probe chain | `daemon/procmon/ebpf/` | Aya (integrated process probe) | Stable | Fallback: Aya integrated -> Aya C `ebpf_prog` module -> libbpf C `ebpf_prog` module -> userspace adapter/syscall surface (`libc` FFI) |
| `services/connection` + `flows/connect` | Netlink: `NETLINK_ROUTE` (iface lookup) + `NETLINK_SOCK_DIAG` (socket dump/destroy) | `daemon/netlink/` + `daemon/netstat/` | `netlink-bindings` + `netlink-socket2` | Stable | Keep unified stack; connection service owns both netlink families; connect flow owns hot-path connection dispatch |
| `services/connection` + `flows/connect` + `flows/kernel` | eBPF: connection probe chain | `daemon/procmon/ebpf/` (conn probe) | Aya (integrated connection probe) | Stable | Fallback: Aya integrated -> Aya C `ebpf_prog` module -> libbpf C `ebpf_prog` module -> userspace adapter/syscall surface (`libc` FFI) |
| `services/firewall` + `flows/verdict` | Netlink: `NETLINK_NETFILTER` (nftables verdict/control path) | `daemon/firewall/nftables/` + `daemon/netfilter/` | `netlink-bindings` + `netlink-socket2` (FFI bridge retained where required) | Stable | Keep unified stack; firewall service owns nftables path; verdict flow owns allow/deny decision dispatch |
| `services/dns` + `flows/kernel` | eBPF: DNS probe chain | `daemon/dns/ebpfhook.go` | Aya (integrated DNS probe) | Stable | Fallback: Aya integrated -> Aya C `ebpf_prog` module -> libbpf C `ebpf_prog` module -> userspace adapter/syscall surface (`libc` FFI) |
| `services/dns` | Runtime: DNS monitoring under eBPF hook failure | `daemon/dns/track.go` + `dns/parse.go` | DNS service worker path | Resilient | Keep varlink + `resolvectl monitor` fallback |
| `services/ebpf` | eBPF object availability probing, pin-domain management, ring-buffer worker | `daemon/core/ebpf.go` | Aya + libbpf feature-gated loading | Stable | Owns probe load/pin lifecycle; consumed by `flows/kernel` and `services/process`/`dns`/`connection` |
| `services/rule` | Rule matching and operator dispatch on connection attempts | `daemon/rule/` | In-process LRU-backed match engine (trie + glob + regex) | Stable | No external protocol dependency; keep rule cache coherent with `services/config` reload signals |
| `services/config` + `flows/lifecycle` | Config file loading, watch-based reload, daemon lifecycle sequencing | `daemon/core/core.go` | inotify/poll hybrid watcher + tokio watch channel | Stable | Keep hybrid watcher; lifecycle flow coordinates ordered start/stop/reload across domains |
| `services/stats` + `flows/stats` | Connection event accounting, ring-buffer-backed event backlog, 30s telemetry export | `daemon/statistics/` | In-process ring buffer + gRPC stats stream to UI | Stable | Keep ring capacity tunable via `stats_event_ring_capacity`; stats flow owns export cadence |
| `services/client` | gRPC UI client session, alert overflow queue, notification stream | `daemon/ui/client.go` + `ui/alerts.go` | tonic gRPC + ring-buffer alert queue | Stable | Multi-user session arbitration is explicit: control session takes precedence, otherwise lowest principal-rank session provides effective connected defaults and owner attribution for command/verdict mutations |
| `services/task` | Remote/local task runtime (downloader, IOC scanner, etc.), task lifecycle and reply | `daemon/tasks/` | Async task runner + gRPC notification reply | Stable | No external protocol dependency; task service owns execution and result surfacing to UI |
| `services/policy_tx/policy_tx.rs` + `commands/{rule,control}` | Transactional policy mutation envelope (idempotency, serialized apply, rollback, audit trail, revisioning) | None (Go applies rule/firewall mutations directly without this envelope) | In-process transaction coordinator + command-path integration | Stable | Rust hardening layer: command mutations are applied through a single serialized transaction coordinator to avoid partial/mixed state across concurrent UI clients |
| `services/storage` | Shared filesystem event bus and file I/O primitives for rules/config/tasks | `daemon/core/` (file ops) | inotify/poll event bus + sync file ops | Stable | Keep storage event bus as the single shared FS-event fan-out; consumers register typed watchers |
| `services/lifecycle/lifecycle.rs` | Shared lifecycle trait/subscription contracts used by service boundaries | No direct equivalent shared lifecycle trait package in Go backend | In-process lifecycle trait/helper layer | Stable | `services/*/mod.rs` remains linker-only per design rules; lifecycle implementation lives in sibling file |
| `services/subscription` | List subscription refresh, format normalization, schedule management | None (Rust-only feature) | HTTP(S) via `reqwest`; feature-gated (`subscriptions`) | Stable | Keep HTTP client behind feature flag; subscription service owns refresh schedule and format dispatch |
| `daemon/` | Top-level process orchestration: bootstrap, startup handshake, serve loop, worker bring-up, task wiring, reload/shutdown coordination | `main.go` + `core/core.go` + `ui/client.go` + `tasks/main.go` | `daemon/{bootstrap,proc_workers,reload,serve,signals,startup,tasks,worker_startup}` | Stable | Keep process lifecycle coordination centralized here; services and flows should stay domain-focused |
| `bus.rs` | Typed event bus and channel fan-out between workers, flows, services, and UI reply path | None (Rust-specific abstraction) | Tokio `mpsc` bus carrying `KernelEvent`, `ConnectionAttempt`, `ClientCommand`, `UiAlert`, `VerdictReply` | Stable | Keep the bus narrow and typed; avoid pushing domain logic into the transport layer |
| `config.rs` + `tunables.rs` + `logging.rs` + `main.rs` | Binary bootstrap and process-wide concerns: config loading, runtime tunables, logging sinks, entrypoint wiring | `main.go` + `core/core.go` + `core/system.go` + `core/version.go` + `log/log.go` | In-process bootstrap/config/tunable/logging layer | Stable | Keep process-wide concerns centralized; avoid duplicating config/logging/tunable semantics across services |
| `models/` | Shared contract and state layer: RPC payloads, kernel event enums, rule records, config/runtime structs, task payloads, worker state snapshots | `daemon/core/` + `daemon/rule/` + `daemon/ui/` + `daemon/tasks/` + `daemon/statistics/` + `daemon/procmon/` | In-process typed data contracts used across `services/`, `flows/`, `workers/`, and `platform/` | Stable | Include only parity-relevant shared contracts here; Go spreads equivalent structs across domain packages, so this is a cross-cutting mapping rather than a 1:1 package match |
| `flows/command` | gRPC command ingestion: decode incoming UI commands and route to `commands/` handler layer | `daemon/ui/client.go` (command recv path) | tonic gRPC + in-process command routing | Stable | Transport only; no business logic lives here; delegates immediately to `commands/*` |
| `commands/` (`client`, `control`, `rule`, `subscription`, `task`) | Command handler layer: fulfills each routed command (rule CRUD, task dispatch, subscription management, control/reload, client notification reply) | `daemon/ui/` (`config_utils.go`, `notifications_tasks.go`) | In-process handler dispatch, calling into `services/*` | Stable | Keep handlers thin; each submodule owns exactly one command domain; no shared mutable state between submodules |
| `flows/notification` | Outbound UI notification dispatch and dedup/rate-limit logic | `daemon/ui/notifications.go` | In-process VecDeque + gRPC notification stream | Stable | Keep notification flow stateless w.r.t. domain logic; dedup window tunable |
| `workers/process` + `workers/dns` + `workers/connection` + `workers/firewall` + `workers/network` | Execution layer: long-running thread workers consuming netlink streams and eBPF ring buffers, emitting kernel events into the service bus | `daemon/procmon/` + `daemon/dns/` + `daemon/netlink/` + `daemon/firewall/` | Thread-per-worker model; each domain worker owns one or more dedicated OS threads feeding `services/*` via `Bus` channels | Stable | Workers are owned by `daemon/` startup; each domain worker mirrors its `services/*` counterpart |
| `workers/runtime/` | Shared worker runtime primitives: cancellation tokens, connect/verdict/nfqueue/kernel/eBPF/watch loop scaffolding used by all domain workers | None (Rust-specific abstraction) | `workers/runtime/{connect,control,ebpf,kernel,nfqueue,support,verdict,watch}` | Stable | Keep as pure infrastructure; no domain logic here; domain workers compose these primitives rather than duplicating loop/control boilerplate |
| `utils/` | Shared operational helpers: reload application, conntrack flush, netlink recovery gates, systemd notify, path/command resolution, parsing helpers | `core/` + `netfilter/` + `log/` + scattered helpers in `procmon/`, `rule/`, and `tasks/` | Cross-cutting helper layer consumed by all major modules | Stable | Keep helpers reusable and side-effect scoped; do not move domain ownership into `utils/` |
| `platform/adapters/` | Kernel protocol adapters: proc connector, audit netlink, socket diag, nft/iptables backends, pure-Rust NFQUEUE netlink, iface enumeration, proto mapper | `daemon/procmon/` (proc/audit), `daemon/netlink/` + `daemon/netstat/` (socket diag, iface), `daemon/firewall/` (nft/iptables), `daemon/netfilter/` (nfqueue), `daemon/conman/` (proto) | `netlink-bindings` + `netlink-socket2` for netlink adapters; `Command` subprocess for iptables/nft CLI fallback | Stable | Adapters are the single boundary between kernel protocols and domain workers/services; no business logic here; `nfqueue_netlink` is the preferred pure-Rust NFQUEUE path replacing the C FFI |
| `platform/ports/` | Internal capability interfaces for proc connector, socket diag, and firewall implementations | None (Rust-specific abstraction) | Trait-style ports used to decouple services/workers from adapter implementations | Stable | Keep ports minimal and implementation-agnostic; adapters own kernel specifics and concrete I/O |
| `platform/ffi/` | C FFI bridge for `libnetfilter_queue` (legacy NFQUEUE verdict + packet parsing path) | `daemon/netfilter/` (via `libnetfilter_queue` C library) | `libc` FFI via `nix`; retained as fallback behind `nfqueue_netlink` adapter | Stable | Keep as legacy fallback only; `platform/adapters/nfqueue_netlink.rs` is now preferred; do not expand FFI surface |
| `tests/` | Integration and unit test suite: `parsing/`, `firewall/`, `flows/`, `rules/`, `services/`, `workers/`, `smoke/`, `watch_reload/`, `nfqueue/`, `runtime_tasks/` | `daemon/rule/`, `daemon/procmon/`, `daemon/firewall/`, `daemon/netfilter/`, `daemon/statistics/`, `daemon/tasks/` (no Go counterpart for `flows/`, `smoke/`, `watch_reload/` groups) | Rust integration test harness; `smoke/` requires privileged context; `parsing/` and `rules/` are unprivileged | Stable | Keep test subgroups aligned with source module boundaries; `smoke/aya_*` requires eBPF-capable kernel |

## Extended Feature/Behavior Matrix (Out Of Core Compatibility Scope)

This table tracks extra capabilities and behavior differences that are intentionally outside the core Go<->Rust parity matrix above.

| Feature / Behavior | Rust side | Go side | Parity impact | Notes |
|---|---|---|---|---|
| Subscription engine (`subscriptions` feature) | Built-in `services/subscription` with refresh scheduler, wire normalization, and reqwest transport | No equivalent package in baseline daemon | Rust extension | Feature-gated to avoid baseline behavior drift when disabled |
| Pure-Rust NFQUEUE netlink path | `platform/adapters/nfqueue_netlink.rs` preferred path | `daemon/netfilter/queue.go` via `libnetfilter_queue` C library | Equivalent behavior, different implementation | C FFI path remains available in Rust as fallback (`platform/ffi/`) |
| Split netlink recovery tunables | Separate `netlink_fallback_retry_delay_ms` and `netlink_recovery_poll_interval_ms` runtime controls | Coarser retry behavior in legacy daemon | Rust hardening extension | Preserves parity defaults while improving operational control surface |
| Watch-based runtime reload pipeline | Explicit config/lifecycle + watch workers + apply-stage reporting | Reload logic spread across `core/` and runtime loops | Equivalent intent, different composition | Rust pipeline is more explicit in sequencing and observability |
| AskTimeoutPolicy daemon safeguard | `config_runtime::AskFallbackPolicy` + `flows/verdict` UI-miss fallback handling (`apply_ask_timeout_policy`) for connect/RPC/stale-decision miss paths | No dedicated daemon-side ask-timeout policy field in baseline Go config model (`DefaultAction`/`DefaultDuration`/`InterceptUnknown`) | Rust hardening extension | Used only when daemon cannot obtain a valid UI rule; when UI returns a concrete rule, that rule remains authoritative |
| Test harness depth | Structured integration suites (`flows/`, `services/`, `workers/`, `watch_reload/`, `smoke/`) | Go has tests in domain packages, fewer runtime-flow groupings | Validation-depth delta | Not runtime behavior; affects confidence and regression detection |
| Event export pipeline | Concrete adapter: `platform/adapters/connection_event_logger.rs` implementing `ConnectionEventExporterPort`, wired through `VerdictFlow::with_event_exporter()` in default runtime path | `daemon/log/loggers/` `LoggerManager` with `remote`/`remote_syslog`/`syslog` loggers; formats: RFC5424, RFC3164, JSON, CSV; transports: UDP, TCP | PARITY | Rust adapter ships JSON/CSV/RFC5424/RFC3164 formatting over UDP/TCP; fail-open non-blocking queue preserves verdict path latency; reconnect/backoff honors `max_connect_attempts` (`0` => indefinite); miss/default-event export parity is implemented; runtime logger-sink reconfiguration is applied by exporter refresh; local `syslog` mode now uses system syslog writer semantics |
| Multi-user session precedence + owner attribution | `services/client`: explicit principal ranking and control-session priority for effective connected defaults; `primary_owner()` used by command and verdict transactional mutations for ownership tagging | Go tracks connected nodes and default-action config but does not expose an equivalent owner-priority transaction attribution layer | Rust hardening extension | Prevents ambiguous owner attribution across concurrent UI sessions while keeping deterministic fallback/default-action resolution |
| Transactional policy mutation coordinator | `services/policy_tx` (`PolicyTxCoordinator`) with idempotency-key dedup (`DuplicateInFlight`/`DuplicateCommitted`), serialized execution, rollback callbacks, revision tracking, and persisted changeset/audit records | No equivalent transaction coordinator in baseline Go command path | Rust hardening extension | Used by command handlers (`commands/rule`, `commands/control`) and async verdict rule persistence worker to avoid partial policy writes under concurrent clients |
| Verdict in-flight decision gate + async rule persist | `flows/verdict`: per-connection pending-decision key/epoch gate to discard stale concurrent AskRule outcomes; immediate verdict emission with background transactional rule upsert | Go path effectively serializes via UI interaction model and direct write path; no explicit epoch gate + async transactional persistence split | Rust hardening extension | Keeps verdict path lightweight under multi-client contention while still preserving durable rule writes via shared transaction coordinator |
| Stats snapshot export pipeline | `platform/ports/stats_exporter_port.rs` `StatsExporterPort` trait + `StatsFlow::with_stats_exporter()` builder — no concrete adapter yet | No equivalent in Go daemon; stats go to UI gRPC only | Rust extension point (gated rollout) | `/metrics`-style export remains intentionally feature-gated (`metrics-export`); adapters planned: Prometheus `/metrics` scrape server, Grafana Mimir push, InfluxDB line protocol |

## Rule Operator Parity (Go -> Rust)

This section is the canonical location for Go <-> Rust rule-operator parity details.

Scope:
- Go source of truth: `daemon/rule/operator.go`, `daemon/rule/operator_lists.go`, `daemon/rule/operator_aliases.go`, `daemon/rule/rule.go`
- Rust matcher path: `crates/daemon/src/services/rule/matching.rs` + `crates/daemon/src/services/rule/dispatch.rs`
- Rust live reload path for list-backed operators: `crates/daemon/src/workers/rule_watch_worker.rs` + `crates/daemon/src/workers/watch_worker_control.rs`

Status legend:
- PARITY: behavior replicated in Rust verdict flow
- EXTENDED: Rust implements the Go behavior and adds capability Go does not have
- N/A: not active in Go runtime path (commented/TODO)

### Core operands

| Operand | Go behavior summary | Rust status | Evidence |
|---|---|---|---|
| true | unconditional true | PARITY | tests/rules/rule_service_match_engine.rs: true operator upsert/match tests |
| process.id | exact/case-insensitive simple compare | PARITY | services/rule/matching.rs + tests/rules/rule_service_match_engine.rs |
| process.path | simple/regexp with sensitivity flag | PARITY | services/rule/matching.rs + tests/rules/rule_service_match_engine.rs |
| process.parent.path | walk parent chain and match any ancestor | PARITY | tests/rules/rule_service_match_engine.rs parent path test |
| process.command | join args with space and compare | PARITY | services/rule/matching.rs + tests/rules/rule_service_match_engine.rs |
| process.env.\<KEY\> | lookup env var by key and compare | PARITY | tests/rules/rule_service_match_engine.rs env present/missing |
| process.hash.md5 | hash compare; Go iterates ALL checksums (md5+sha1 together) and returns true if any matches or if hash unavailable; Rust checks the specific md5 field only, returns **false** when field is absent (intentional safety hardening: missing hash → no match → falls through to default action) | EXTENDED | services/rule/matching.rs SimpleHashOptional + tests/rules/rule_service_match_engine.rs |
| process.hash.sha1 | same compile-time semantics as md5; Go iterates all checksums (not specific to sha1 operand); Rust checks process_hash_sha1 field specifically, returns **false** when field is absent (same safety hardening as md5) | EXTENDED | services/rule/matching.rs + tests/rules/rule_service_match_engine.rs |
| user.id | uid compare | PARITY | services/rule/matching.rs + tests/rules/rule_service_match_engine.rs |
| user.name | resolve username to uid at compile time and compare uid at match time | PARITY | services/rule/matching.rs + tests/rules/rule_service_match_engine.rs |
| source.ip | simple compare | PARITY | tests/rules/rule_service_match_engine.rs |
| source.port | simple compare | PARITY | tests/rules/rule_service_match_engine.rs |
| source.network | Go: `network` type is compile-rejected for this operand (only `dest.network` allowed); `source.network` in Go `Match()` is dead code (cbGeneric is nil, would panic). Rust fully supports `network` type with `source.network`. | EXTENDED | services/rule/dispatch.rs Network{source:true} + tests/rules/rule_service_match_engine.rs validate_operator_accepts_source_network_operand |
| dest.ip | simple compare | PARITY | services/rule/matching.rs + tests/rules/rule_service_match_engine.rs |
| dest.host | simple/regexp compare including empty-host edge case | PARITY | services/rule/matching.rs + tests/rules/rule_service_match_engine.rs |
| dest.port | simple and range compare | PARITY | tests/rules/rule_service_match_engine.rs range tests |
| dest.network | network compare (CIDR or alias) | PARITY | tests/rules/rule_service_match_engine.rs alias/network tests |
| protocol | Go emits upper-case protocol text (TCP/UDP); Rust matches same casing | PARITY | tests/rules/rule_service_match_engine.rs protocol-sensitive + insensitive |
| iface.in | resolve interface index -> name and compare | PARITY | tests/rules/rule_service_match_engine.rs |
| iface.out | resolve interface index -> name and compare | PARITY | tests/rules/rule_service_match_engine.rs |

### Operator types

| Type | Go behavior summary | Rust status | Evidence |
|---|---|---|---|
| simple | exact compare with sensitivity rules | PARITY | services/rule/matching.rs + tests/rules/rule_service_match_engine.rs |
| regexp | sensitive: raw regex; insensitive: lowercase pattern + lowercase candidate | PARITY | services/rule/matching.rs regexp parity tests |
| list | AND semantics across children | PARITY | services/rule/matching.rs list child test |
| lists | domains/domains_regexp/ips/nets/hash.md5 list-backed matching | PARITY | tests/rules/rule_service_match_engine.rs + tests/watch_reload/watch_workers.rs |
| network | Go: only valid with `dest.network` operand; compile error for any other operand. Rust: valid with both `dest.network` and `source.network` (extension). Both are alias-aware (CIDR or named alias). | EXTENDED | services/rule/dispatch.rs + tests/rules/rule_service_match_engine.rs |
| range | min-max numeric parsing and comparison | PARITY | tests/rules/rule_service_match_engine.rs |
| complex | placeholder in Go, not active | N/A | Go comment/TODO |

### lists.* parity specifics

| Operand | Go behavior summary | Rust status | Evidence |
|---|---|---|---|
| lists.domains | hosts-file style rows (0.0.0.0/127.0.0.1 prefix), localhost exclusions, candidate lowercase when insensitive; Go: exact string match only | EXTENDED | tests/rules/rule_service_match_engine.rs domain list case/filter tests; Rust also adds wildcard trie + glob (see extensions below) |
| lists.domains_regexp | compile regex lines, candidate lowercase when insensitive | PARITY | tests/rules/rule_service_match_engine.rs regexp list case tests |
| lists.ips | Go: simple string entry lookup only (no CIDR). Rust: unified with lists.nets (string + CIDR in one pass). | EXTENDED | services/rule/matching.rs match_ip_or_net + tests/rules/rule_service_match_engine.rs |
| lists.nets | Go: CIDR entry match only against destination IP. Rust: unified with lists.ips (string + CIDR in one pass, and supports source scope). | EXTENDED | services/rule/matching.rs match_ip_or_net + tests/rules/rule_service_match_engine.rs |
| lists.hash.md5 | md5 list entry match against process hash | PARITY | tests/rules/rule_service_match_engine.rs hash list test |

### Live reload and verdict propagation

| Feature | Go behavior summary | Rust status | Evidence |
|---|---|---|---|
| rule file add/remove/modify reload | live watch and reload rules | PARITY | tests/watch_reload/watch_workers.rs rules_watch_task_* |
| list file content updates affect verdict | monitored list sources trigger re-evaluation via reload | PARITY | tests/watch_reload/watch_workers.rs domains/regexp/nested list tests |
| nested list sub-rule list change propagation | list(type=list) children with lists.* update verdict | PARITY | tests/watch_reload/watch_workers.rs nested subrule test |

### Rust-only extensions

These behaviors exist in Rust but have no equivalent in the Go runtime (Go either rejects them at compile time or does not implement them).

| Feature | Description | Evidence |
|---|---|---|
| `network` type + `source.network` operand | Go's `Compile()` rejects `network` type unless operand is exactly `dest.network`; `source.network` in Go `Match()` is dead code (cbGeneric would be nil -> panic). Rust `dispatch.rs` recognizes `source: operand == "source.network"` and routes to the same network-match path. | services/rule/dispatch.rs Network{source:bool} + tests/rules/rule_service_match_engine.rs validate_operator_accepts_source_network_operand |
| `scope: "src"` field on list operators | Rust `RuleOperator` has an optional `scope` field. When `scope = "src"`, `lists.ips` and `lists.nets` match against the source IP instead of the destination. Not in Go; not yet in proto wire format (tracked as future backlog in TODO.md). | services/rule/matching.rs list_scope_is_source + tests/rules/rule_service_match_engine.rs lists_ips_scope_src_matches_source_address |
| `lists.ips` + `lists.nets` unified matching | Go separates them: `lists.ips` does string lookup only; `lists.nets` does CIDR match only. Rust handles both operands via `match_ip_or_net()` which does string match and CIDR prefix match in a single pass via a `CidrTrieIndex`. | services/rule/matching.rs match_ip_or_net + cache_types.rs CidrTrieIndex |
| `lists.domains` wildcard trie + glob fallback | Go does exact string lookup after hosts-file parsing. Rust also builds a `DomainWildcardTrie` for `*.example.com`-style entries and a `Vec<GlobMatcher>` for extended glob patterns. | services/rule/matching.rs match_domain_list + cache_types.rs domain_wildcards/domain_globs + tests/rules/rule_service_match_engine.rs lists_domains_wildcard_fallback_matches_subdomains_only + lists_domains_glob_fallback_matches_extended_patterns |
| Hash operand checks specific field + missing-hash safety | Go's `hashCmp` iterates ALL entries in `con.Process.Checksums` (both md5 and sha1 if present) and returns true if any matches; Go also returns true when hash is unavailable. Rust resolves the specific field (`process_hash_md5` or `process_hash_sha1`) named by the operand and only compares that one. Rust returns **false** when the hash field is absent (intentional v0.5.1 safety hardening: missing hash → no match → default action), diverging from Go's permissive behavior. | services/rule/matching.rs operator_operand_value + SimpleHashOptional dispatch + TODO.md hash safety hardening entry |

### Out-of-scope / not active

| Operand | Note |
|---|---|
| quota | commented TODO in Go |
| quota.sent.over | commented TODO in Go |
| quota.recv.over | commented TODO in Go |

## Stats Parity (Go -> Rust)

Scope:
- Go source of truth: `daemon/statistics/stats.go`, `daemon/statistics/event.go`, and `daemon/ui/client.go` ping path
- Rust source of truth: `crates/daemon/src/services/stats/*`, `crates/daemon/src/flows/stats/stats.rs`, `crates/daemon/src/flows/connect/connect.rs`, `crates/daemon/src/flows/verdict/verdict.rs`

Status legend:
- PARITY: behavior replicated in Rust stats/ping pipeline
- EXTENDED: Rust implements Go behavior and adds capability not present in Go

### Core counters and aggregation

| Signal | Go behavior summary | Rust status | Evidence |
|---|---|---|---|
| Config defaults (`MaxEvents`, `MaxStats`, `Workers`) | defaults 150/25/6 in stats ctor + `SetLimits` | EXTENDED | Go: `daemon/statistics/stats.go`; Rust defaults 250/25/6 in `config.rs` + ring-cap guard in `services/stats/internal.rs` |
| Connection count | increment once per intercepted connection | PARITY | Go `onConnection()`; Rust `StatsService::on_connect_attempt()` in `services/stats/stats.rs` |
| Rule hit/miss accounting | hit on matched rule; miss on unmatched/default path | PARITY | Go `onConnection(wasMissed)`; Rust `on_rule_hit()` + `on_missed_default_action()` in `services/stats/counters.rs` and wired from `flows/verdict/verdict.rs` |
| Accepted/dropped accounting | allow increments accepted, else dropped; DNS and ignored count as accepted | PARITY | Go `OnDNSResponse()`, `OnIgnored()`, `onConnection()`; Rust `on_dns_resolved()`, `on_ignored()`, `on_verdict()` |
| Top-N maps (`ByProto`, `ByAddress`, `ByHost`, `ByPort`, `ByUID`, `ByExecutable`) | bounded maps with least-hit eviction at `max_stats` | PARITY | Go `incMap()`; Rust `LimitedCountersString/Copy::bump()` + `trim_to_limit()` |
| Event backlog | fixed-cap event buffer, overwrite oldest when full | PARITY | Go shifts slice when full; Rust ring buffer `push_overwrite()` |
| Event serialization and drain | ping sends stats only when new events exist, then empties event list | PARITY | Go `Serialize()` returns nil when no new events and drains events; Rust `snapshot_if_pending()` returns `None` when empty and drains via `build_snapshot()` |
| Uptime/rules/daemon_version in payload | include daemon version, uptime, and current rules count | PARITY | Go `Serialize()` fields; Rust `build_snapshot()` fields |

### Pipeline and transport parity

| Feature | Go behavior summary | Rust status | Evidence |
|---|---|---|---|
| Periodic UI ping transport | 1s polling loop, sends ping only when stats snapshot exists | PARITY | Go `ui/client.go` `poller()` + `ping()`; Rust `flows/stats/stats.rs` 1s loop + `snapshot_if_pending()` |
| Config reload applies stats limits live | runtime config updates max_events/max_stats/workers | PARITY | Go `ui/config_utils.go -> stats.SetLimits()`; Rust `utils/config_reload.rs -> stats.apply_config()` |
| Event ingestion split | accounting and event emission performed across connection/verdict paths | PARITY | Rust uses `flows/connect` (`on_connect_attempt`) + `flows/verdict` (`on_connection_metadata`, `on_event`) mirroring Go's `OnConnectionEvent` composite path |

### Rust-only stats extensions

| Feature | Description | Evidence |
|---|---|---|
| Fast-path counters | separate fast-allow and fast-deny counters for short-circuit verdict telemetry | EXTENDED | `services/stats/counters.rs` (`on_fast_allow`, `on_fast_deny`), observed in `flows/stats/stats.rs` |
| Subscription counters in stats payload | `subscription_total`, `subscription_ready`, `subscription_error` exported with each snapshot | EXTENDED | `services/stats/stats.rs` (`update_subscription_counts`) + `services/stats/snapshot_ops.rs` |
| Storage event counters | read/write/delete/scan counters tracked from storage event bus | EXTENDED | `services/stats/counters.rs` (`on_storage_event`) + `flows/stats/stats.rs` storage observer |
| Ring-cap guard tunable | `max_events` is clamped by global runtime ring capacity (`STATS_EVENT_RING_CAPACITY`) | EXTENDED | `services/stats/stats.rs::apply_config()` + `services/stats/internal.rs` |

### Compatibility notes

- Rust keeps Go-compatible miss semantics intentionally: `on_missed_default_action()` increments `rule_misses` and `dropped` even when runtime default policy may later allow traffic.
- Accounting policy note for miss/default path:
	- `nfqueue_overload_policy = fail-open` keeps Go parity semantics (`rule_misses++`, `dropped++`, default-action verdict emitted with `count_stats=false`).
	- `nfqueue_overload_policy = drop-fast` enables strict accounting semantics (`rule_misses++` plus final verdict-based accepted/dropped via `count_stats=true`), avoiding pessimistic dropped-overcount on default-allow misses.
- Python UI AskRule timeout behavior caveat (mixed Rust daemon + Python UI deployments):
	- `AskRule()` in `ui/opensnitch/service.py` delegates to `PromptDialog.promptUser(...)`; timeout calls `on_timeout_triggered()` which invokes `_send_rule()` in `ui/opensnitch/dialogs/prompt/dialog.py`.
	- `_send_rule()` maps popup default action `ACTION_DROP_IDX` to rule action `deny`; config default is `ACTION_DROP_IDX` in `ui/opensnitch/config.py`.
	- Result: timeout responses are effectively deny by default unless UI default action is explicitly changed to allow. This can make observed behavior look less "fail-open" than daemon-side policy naming suggests.
	- `AskTimeoutPolicy` in Rust daemon is intentionally retained as a default safeguard for ambiguous/no-decision paths only (UI connect failure, AskRule RPC failure, stale/discarded decision). Supported keyword values are `allow`, `drop`, and `default` (plus missing/null as default behavior). When UI returns a concrete rule, that rule remains authoritative and `AskTimeoutPolicy` is not consulted.
- Multi-user handling note:
	- `services/client` resolves connected defaults deterministically: control session first, otherwise lowest-priority principal rank (with stable tie-break by session id).
	- Policy mutations (rule/control command path and async verdict rule persistence) carry ownership from `primary_owner()` into transaction audit records, which avoids ambiguous attribution across concurrent UI sessions.
	- Verdict flow uses a per-connection decision key/epoch gate so concurrent AskRule responses cannot race into conflicting verdict persistence.
- Rust currently stores `workers` in stats config/state for compatibility with config schema, but does not spawn dedicated stats worker goroutines like Go; stats emission is handled by the async `StatsFlow` loop.
- The Go daemon ships a `log/loggers/` per-connection event export pipeline (`LoggerManager`, `Remote`, `RemoteSyslog`, `Syslog` with RFC5424/RFC3164/JSON/CSV formats over UDP/TCP). Rust ships a concrete adapter at `platform/adapters/connection_event_logger.rs`, implementing `platform::ports::connection_event_exporter_port::ConnectionEventExporterPort` and wired into `VerdictFlow` via `with_event_exporter()` in the default runtime path.
- The Go daemon has no Prometheus scrape endpoint; stats go to the UI via gRPC ping only. Rust keeps this parity by default and reserves `/metrics`-style export as an explicit feature-gated extension (`metrics-export`) via `platform::ports::stats_exporter_port::StatsExporterPort` and `StatsFlow::with_stats_exporter()`.

## Architecture Delta Notes (Rescan Rationale)

| Previously missing in matrix | Why it was missed earlier | Current matrix row(s) | Implementation choice rationale |
|---|---|---|---|
| Orchestration layer (`daemon/`) | Early matrix focused on domain services/flows and protocol paths, not process lifecycle composition | `daemon/` | Rust isolates orchestration to keep startup, serve, and shutdown contracts explicit and testable |
| Process-wide glue (`main.rs`, `config.rs`, `tunables.rs`, `logging.rs`) | Initially treated as bootstrap scaffolding rather than parity-relevant behavior | `config.rs` + `tunables.rs` + `logging.rs` + `main.rs` | Rust centralizes process concerns for deterministic wiring and shared runtime policy |
| Internal helper layer (`utils/`) | Considered utility-only at first pass | `utils/` | Helpers encode behavior-critical operations (reload apply, conntrack flush, recovery gates), so they matter for parity reasoning |
| Internal abstraction layer (`platform/ports/`) | Not visible in surface feature mapping because it is a decoupling seam, not a runtime endpoint | `platform/ports/` | Rust uses explicit ports to separate domain logic from concrete adapters and improve substitution/testing |
| Event bus (`bus.rs`) | Implicitly assumed within services/workers rows, not listed as a first-class layer | `bus.rs` | Typed bus is a core runtime contract in Rust; making it explicit improves traceability of cross-domain flow |
| Kernel capability self-check pipeline | Go `daemon/core/system.go` runs kprobe/uprobe/nfqueue/netlink/tracefs capability probes at startup; not mapped because Rust boot-up always relies on runtime feature detection rather than a pre-flight diagnostic | No dedicated matrix row yet | Rust performs implicit capability checks at each subsystem init (eBPF load, nfqueue bind, netlink open) but does not surface a consolidated user-facing diagnostic report like Go does; tracked as future backlog in TODO.md |
| Firewall config reload trigger model | Go `daemon/firewall/config/config.go` uses fsnotify-driven immediate reload; difference not previously called out because both sides reload configs at runtime | `services/firewall` + `services/config` rows | Go uses fsnotify for immediate push-based reload; Rust uses drift-heal loops (20s interval) + config mtime watch + manual commands as trigger mechanisms. Nft backend *operations* (ensure/disable/health/clear) are netlink-first with nft CLI adapter fallback, but the trigger model itself is poll/timer-based, not netlink-event-driven. Behavior is equivalent (config changes are applied and drift is healed), but timing characteristics differ |

## File-Level Critical Path Mapping (Scoped Appendix)

This appendix is intentionally scoped to high-risk runtime paths. It is not a full repository-wide per-file inventory.

| Rust file(s) | Go file(s) | Mapping | Scope / Why it matters |
|---|---|---|---|
| `platform/adapters/proc_connector.rs` + `workers/process/netlink_worker.rs` | `procmon/process.go` + `procmon/parse.go` | 1:N | Process lifecycle ingestion path (fork/exec/exit) |
| `platform/adapters/audit_netlink.rs` + `workers/process/audit_worker.rs` | `procmon/audit/*` | 1:N | Audit event ingestion and decode path |
| `platform/adapters/socket_diag.rs` + `platform/adapters/socket_diag_bindings.rs` + `services/connection/connection.rs` | `netstat/find.go` + `netstat/parse.go` + `netstat/parse_packet.go` | N:N | Connection identity/socket state resolution |
| `platform/adapters/net_iface.rs` + `workers/network/netlink_addr_worker.rs` | `netlink/ifaces.go` | 1:N | Interface/address inventory and refresh |
| `platform/adapters/firewall_nft_netlink.rs` + `services/firewall/firewall.rs` + `flows/verdict/verdict.rs` | `firewall/rules.go` + `netfilter/queue.go` | N:N | Verdict enforcement and rule synchronization |
| `platform/adapters/nfqueue_netlink.rs` | `netfilter/queue.go` | 1:1 (impl-different) | Primary NFQUEUE packet I/O path |
| `platform/ffi/nfqueue.rs` | `netfilter/queue.go` | 1:1 (fallback) | Legacy C FFI NFQUEUE compatibility path |
| `services/dns/dns.rs` + `workers/dns/dns_worker.rs` | `dns/track.go` + `dns/parse.go` | N:N | DNS monitor and parser behavior |
| `services/ebpf/ebpf.rs` + `workers/*/ebpf_worker.rs` + `flows/kernel/kernel.rs` | `core/ebpf.go` + `dns/ebpfhook.go` + `procmon/ebpf/*` | N:N | Probe load/pin and kernel event intake |
| `flows/command/command.rs` + `commands/*/*.rs` | `ui/client.go` + `ui/config_utils.go` + `ui/notifications_tasks.go` | N:N | Command transport and command fulfillment semantics |
| `flows/notification/notification.rs` + `services/client/client.rs` | `ui/notifications.go` + `ui/alerts.go` | N:N | UI alert/notification emission semantics |
| `daemon/{bootstrap,serve,startup,reload,signals,worker_startup}.rs` | `main.go` + `core/core.go` + `ui/client.go` + `tasks/main.go` | N:N | Process orchestration, startup handshake, shutdown/reload behavior |
| `bus.rs` | none | Rust-only | Typed in-process event bus contract |
| `services/subscription/subscription.rs` + `commands/subscription/subscription.rs` | none | Rust-only | Feature-gated subscription refresh and dispatch |
| none | `conman/connection.go` | Go-only | Legacy Go connection manager split not mirrored as a standalone Rust package |

Mapping legend: `1:1` same main responsibility, `1:N` one source maps to multiple targets, `N:1` multiple sources map to one target, `N:N` cross-cutting many-to-many.
