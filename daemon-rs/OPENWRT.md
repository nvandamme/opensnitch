# Daemon-RS OpenWrt Guidance

This document captures OpenWrt-specific development constraints for daemon-rs.
It is not a backlog tracker. Use it to preserve platform facts, packaging assumptions,
and integration rules that should remain stable across implementation slices.

## Scope

Use this document when work targets any of the following:

- OpenWrt packaging or feed integration
- OpenWrt SDK / toolchain build workflows
- UCI-backed configuration storage
- ubus / rpcd / uhttpd integration
- LuCI-facing transport or control surfaces

Keep feature planning and phased execution in [daemon-rs/TODO.md](TODO.md).
Keep architecture governance in [daemon-rs/DESIGN_RULES.md](DESIGN_RULES.md).

## Platform Baseline

- OpenWrt is a constrained target environment. Development assumptions must favor
  small dependencies, explicit packaging, and runtime integration with native
  OpenWrt facilities instead of generic Linux desktop/server expectations.
- The upstream OpenWrt "Hello, world!" guidance assumes:
  - a Linux development host,
  - either the full OpenWrt build system or the OpenWrt SDK,
  - a target device that is already supported by OpenWrt,
  - shell usage split between `bash` on the development host and `ash` on target.
- For daemon-rs, OpenWrt work should assume package-oriented delivery rather than
  ad-hoc binary copying. Build, install, init, ACL, and web integration concerns
  must be expressed in package/runtime assets that OpenWrt already understands.

## Build And Packaging Model

- Treat OpenWrt as a package-build target first.
- Preferred build paths:
  - OpenWrt build system integration when full target image/feed work is needed.
  - OpenWrt SDK integration when iterating on package builds for an already-supported target.
- Do not assume systemd, desktop Linux paths, or generic distro service conventions.
- OpenWrt-facing slices should plan for:
  - package metadata,
  - init/runtime integration with procd,
  - config/runtime integration with UCI/rpcd/ubus where appropriate,
  - small, explicit dependency sets.

### Package Makefile Contract

- Package Makefiles `include $(TOPDIR)/rules.mk` and `include $(INCLUDE_DIR)/package.mk`,
  and must end with `$(eval $(call BuildPackage,<name>))`.
- `define Package/<name>` declares `SECTION`, `CATEGORY`, `TITLE`, and `DEPENDS`.
- `define Package/<name>/install` places binaries via `$(INSTALL_DIR)` / `$(INSTALL_BIN)`;
  standard daemon binary path is `$(1)/usr/bin`.
- `define Build/Compile` invokes cross-compilation; for Rust this would call `cargo build`
  with the appropriate target triple instead of `$(TARGET_CC)`.
- `PKG_NAME`, `PKG_VERSION`, `PKG_RELEASE` define package identity.
- For source packages built from VCS snapshots, set both `PKG_SOURCE_DATE`
  (`YYYY-MM-DD`) and `PKG_SOURCE_VERSION` (revision/commit).
- `PKG_RELEASE` starts at `1`, increments for package-only output changes,
  and resets to `1` when `PKG_VERSION` or `PKG_SOURCE_VERSION` changes.

### Feeds

- A feed is a collection of packages configured in `feeds.conf` (or `feeds.conf.default`).
- Line format: `<method> <name> <source>` (e.g., `src-git packages https://...`).
- Methods: `src-git` (shallow), `src-git-full`, `src-link` (local symlink, absolute path),
  `src-cpy`, `src-svn`, `src-hg`, `src-bzr`, `src-darcs`, `src-gitsvn`.
- `src-git` supports pinning: `url;branch_name` or `url^commit_hash`.
- `scripts/feeds update <name>` downloads into `feeds/<name>/`;
  `scripts/feeds install -a -p <name>` symlinks into `package/feeds/<name>/`.
- `scripts/feeds update` also generates feed index metadata used by
  `scripts/feeds list` and `scripts/feeds search`.
- For local development: `src-link custom /absolute/path/to/feed/`.

### Packaging Implications For daemon-rs

- Runtime ownership should stay split:
  - daemon core logic remains in `crates/daemon/`.
  - OpenWrt-specific storage/transport surfaces live in dedicated adapter crates.
- OpenWrt package work should not force daemon core APIs to depend on OpenWrt-only
  libraries, paths, or protocol types.
- If a feature only exists to support OpenWrt packaging/runtime behavior, keep it
  behind adapter or packaging boundaries rather than broadening daemon-core assumptions.

## Native OpenWrt IPC And Configuration Stack

### UCI (Unified Configuration Interface)

- All UCI config files live in `/etc/config/`. Each file is a "package".
- File syntax:
  - `config <type> ['<name>']` — starts a section (named or anonymous).
  - `option <name> '<value>'` — sets a scalar option within a section.
  - `list <name> '<value>'` — appends to a list option within a section.
- Anonymous sections auto-generate names like `cfg0e3777`.
- All `uci set/add/rename/delete` operations stage in `/tmp/.uci` and only write to
  flash on `uci commit`. `reload_config` triggers service restarts for changed configs.
- UCI accessed via ubus goes through rpcd, which has its own apply/confirm/rollback
  mechanism. With a `ubus_rpc_session`, staged changes are stored in
  `/tmp/run/rpcd/uci-<session>` instead of `/tmp/.uci`.
- libuci depends on libubox. UCI itself is ~7 KB, libuci ~19 KB.

#### UCI Surface Split (Storage vs Runtime Commands)

- Treat UCI as two distinct adapter surfaces:
  - **Storage format surface**: text file shape (`config`/`option`/`list`) for
    `/etc/config/*` and static export-style snapshots.
  - **Runtime command surface**: imperative command/RPC operations
    (`set`/`add`/`delete`/`commit`/`apply`/`rollback`) via `uci` CLI or
    `ubus uci.*` methods.
- `crates/storage-format-uci` owns the storage format surface only.
- Runtime command/RPC behavior belongs in transport/runtime adapters
  (`transport-wire-openwrt-ubus` and related command mappers), not in storage codecs.
- OpenWrt firewall remains a special authority-owned UCI domain; daemon-rs must
  interoperate with it rather than treating it as a normal daemon-owned storable.
- Read/introspection path note: adapter read surfaces may use
  `uci show firewall` (broad) or `uci show firewall.@rule[<idx>]` (targeted)
  as committed/staged runtime-visible CLI views, then map those key/value lines
  back into canonical firewall domain types.

#### Firewall4 Authority Model

- Persistence authority for OpenWrt firewall behavior is `firewall4` + UCI
  (`/etc/config/firewall`) with apply/commit lifecycle.
- Direct nft/netlink/syscall writes are runtime-ephemeral and can be replaced by
  subsequent firewall4 reload/apply operations; they are not the persistent source
  of truth on OpenWrt.
- Adapter policy for daemon-rs:
  - persistent rule mutations: issue UCI-compatible operations via runtime adapters,
  - direct netlink/syscall paths: limit to runtime observation, health checks,
    reconciliation checks, and optional emergency fallback behavior.

#### OpenWrt Adapter Behavior Under `openwrt`

- The `openwrt` feature implies both of the current adapter behaviors:
  - after `uci commit firewall`, run an explicit runtime apply/reload step
    (`fw4 reload` when available, else `/etc/init.d/firewall reload`) so kernel
    runtime state converges immediately,
  - map canonical firewall rule parameters to OpenWrt-native UCI rule fields
    (`src`, `dest`, `proto`, `src_ip`, `dest_ip`, `src_port`, `dest_port`) and
    reconstruct canonical parameters from those native fields on the read path.
- Rationale: OpenWrt firewall support is fundamentally UCI-owned, so these
  adapter behaviors are part of the base OpenWrt contract rather than optional
  sub-modes.

### procd Init Scripts

- Init scripts live in `/etc/init.d/<name>` and must start with `#!/bin/sh /etc/rc.common`.
- `USE_PROCD=1` enables procd-style service management.
- `START=<nn>` / `STOP=<nn>` control boot/shutdown ordering; enabling creates
  `S<nn><name>` symlinks in `/etc/rc.d/`.
- If multiple scripts share the same `START` value, execution order falls back
  to alphabetical script name.
- `start_service()` is the main entry point. Instances are defined between
  `procd_open_instance` / `procd_close_instance`.
- Key `procd_set_param` directives:
  - `command /path/to/binary [args...]` — daemon command line.
  - `stdout 1` / `stderr 1` — redirect to syslog (logd).
  - `file /etc/config/<name>` — watch config; auto-restart on `reload` if changed.
  - `respawn ${threshold:-3600} ${timeout:-5} ${retry:-5}` — auto-restart on crash;
    crashes after `threshold` respawn indefinitely.
  - `pidfile $PIDFILE` / `env KEY=value` / `limits core="unlimited"` / `user nobody`.
- Config is loaded with `config_load` and values extracted with `config_get`.
- Only two users on stock OpenWrt: `root` (default) and `nobody`.
- Init scripts can run on the build host during package/image enable/disable
  actions. Use `IPKG_INSTROOT` as the build-host discriminator and guard
  target-only runtime side effects.

### libubox (Foundation Library)

- libubox is the core utility library underlying most of OpenWrt userspace.
- **uloop**: main event loop (epoll/kqueue backends); ubus and procd build on it.
- **blob/blobmsg**: binary TLV serialization with endian-safe encoding. blobmsg adds
  tables and arrays — this is the actual wire format for ubus messages.
- **usock**: single-call socket creation (TCP/UDP/Unix, client/server, IPv4/v6).
- **list.h**: double-linked list matching the Linux kernel API.
- **kvlist**: key-value list (string keys) built on AVL trees.
- libuci depends on libubox; libubus depends on libubox.
- A Rust daemon interacting with ubus via its Unix socket will need to understand the
  blobmsg wire format or use JSON-RPC over HTTP as an alternative path.

### ubus

- `ubusd` is the OpenWrt micro bus daemon.
- `libubus` is the client/server development library used to connect to it.
- ubus uses a Unix socket transport and TLV message framing internally.
- Rust reference for basic call/building primitives: `ubus` crate docs
  (`docs.rs/ubus`, for example `Connection`, `Method`, `UbusMsgBuilder`,
  `BlobMsgBuilder`). Treat this as a baseline API reference for adapter design.
- The canonical conceptual model is:
  - namespaces / object paths,
  - methods / procedures with arguments,
  - replies,
  - events,
  - subscriptions / notifications.

### ubus CLI Model

The documented and source-verified CLI primitives are the baseline interaction model:

- `ubus list`: list objects / namespaces
- `ubus call`: invoke object methods with JSON arguments
- `ubus listen`: observe events
- `ubus send`: emit events
- `ubus subscribe`: subscribe to object notifications
- `ubus wait_for`: wait for objects to appear
- `ubus monitor`: inspect bus traffic
- `ubus -S`: simplified script-oriented output

For daemon-rs OpenWrt integration, adapter design should preserve compatibility with
this mental model. Console/script automation is a first-class use case, not an afterthought.

### HTTP Access To ubus

- The standard web-facing OpenWrt path is `uhttpd-mod-ubus`.
- The default endpoint is `/ubus`.
- The wire contract is JSON-RPC 2.0 over HTTP POST.
- This is the baseline compatibility path for web clients and LuCI-adjacent integration.

### rpcd, ACLs, And Sessions

- Web-facing `/ubus` access is typically mediated by `rpcd`.
- Session and ACL decisions are exposed through the `session.*` ubus namespace.
- ACL role files live under `/usr/share/rpcd/acl.d/*.json`.
- ACL role files are merged by rpcd. Role identity is the top-level JSON key,
  not the ACL filename.
- Session login/access semantics are part of the canonical OpenWrt model and must be
  treated as platform constraints when designing daemon-rs adapters.
- Adapter code may translate these semantics into daemon-facing contracts, but daemon
  policy must not hard-code webserver- or LuCI-specific ACL behavior.
- Session ID `00000000000000000000000000000000` is a special null-session token
  that only carries unauthenticated rights (typically `session.login`).
- ACL denial typically surfaces as ubus status code `6`
  (`UBUS_STATUS_PERMISSION_DENIED`); adapter error mapping should preserve it
  as an authorization failure distinct from transport failures.

### ubus UCI Methods (rpcd)

The `uci` ubus object is provided by rpcd. All methods optionally accept
`ubus_rpc_session` for ACL scoping (set automatically over HTTP).

| Method          | Key Parameters                                                   |
|-----------------|------------------------------------------------------------------|
| `configs`       | `{}`                                                             |
| `get`           | `{config, section?, option?, type?, match?}`                     |
| `state`         | `{config, section?, option?, type?, match?}` (runtime state)     |
| `add`           | `{config, type, name?, values?}`                                 |
| `set`           | `{config, section, type?, match?, values}`                       |
| `delete`        | `{config, section?, type?, option?, options?}`                   |
| `rename`        | `{config, section, option?, name}`                               |
| `order`         | `{config, sections}`                                             |
| `changes`       | `{config}` — show pending staged changes                        |
| `revert`        | `{config}` — discard staged changes                             |
| `commit`        | `{config}` — write staged changes to flash                      |
| `apply`         | `{rollback?, timeout?}` — apply with optional rollback timer    |
| `confirm`       | `{}` — confirm apply (cancels auto-rollback)                    |
| `rollback`      | `{}` — revert an apply                                          |
| `reload_config` | `{}` — trigger service reloads for changed configs              |

### ubus Session Methods (rpcd)

Sessions are in-memory (stored in rpcd process), do not persist across rpcd
restarts, and have a default timeout of 300 s (auto-reset on each use).

| Method    | Key Parameters                                                      |
|-----------|---------------------------------------------------------------------|
| `create`  | `{timeout}` — returns `ubus_rpc_session` ID. Timeout 0 = no expiry |
| `list`    | `{ubus_rpc_session?}` — dump session info (all if no ID)           |
| `grant`   | `{ubus_rpc_session, scope, objects: [["path","func"],...]}`        |
| `revoke`  | `{ubus_rpc_session, scope, objects?}` — revoke all if omitted      |
| `access`  | `{ubus_rpc_session, scope, object, function}` — returns `{access}` |
| `set`     | `{ubus_rpc_session, values: {key: value,...}}`                      |
| `get`     | `{ubus_rpc_session, keys?}`                                        |
| `unset`   | `{ubus_rpc_session, keys?}`                                        |
| `destroy` | `{ubus_rpc_session}`                                                |
| `login`   | `{username, password, timeout?}` — returns session with ACLs       |

### ubus Service Methods (procd)

The `service` ubus object is provided by procd. This is the programmatic
interface used by init scripts to register and manage services.

| Method         | Key Parameters                                                   |
|----------------|------------------------------------------------------------------|
| `set` / `add`  | `{name, script?, instances?, triggers?, validate?, autostart?, data?}` |
| `list`         | `{name?, verbose?}`                                              |
| `delete`       | `{name, instance?}`                                              |
| `update_start` | `{name}` — start update transaction                             |
| `event`        | `{type, data}` — emit service event                             |
| `validate`     | `{package?, type?, service?}`                                    |
| `get_data`     | `{name?, instance?, type?}`                                      |
| `state`        | `{spawn?, name?}`                                                |

### Standard ubus Namespace Registry

These are the standard namespace→owner mappings on a typical OpenWrt installation:

| Namespace   | Owner Package |
|-------------|---------------|
| `dhcp`      | odhcpd        |
| `file`      | rpcd          |
| `hostapd`   | wpad          |
| `iwinfo`    | rpcd          |
| `log`       | procd         |
| `mdns`      | mdnsd         |
| `network`   | netifd        |
| `service`   | procd         |
| `session`   | rpcd          |
| `system`    | procd         |
| `uci`       | rpcd          |

- `network.interface.<name>` objects are dynamic netifd ubus objects exposing
  methods like `up`, `down`, and `status`; adapter object routing must support
  wildcard object paths, not only static namespace names.
- `file.*` methods are provided by `rpcd-mod-file`; they are not guaranteed by
  bare `rpcd` installation and should be capability-checked.

## daemon-rs OpenWrt Adapter Plan

These names reflect the current intended split.

### Storage

- `crates/storage-format-uci`
  - owns UCI parse/dump for OpenWrt config-file syntax (`config`/`option`/`list`)
    and daemon storables except firewall.
- OpenWrt-specific semantic mapping belongs above file syntax (adapter/mapping layer),
  not in a separate file-format crate.
- Firewall is special:
  - OpenWrt already has native firewall ownership/configuration expectations.
  - daemon-rs must align with that authority instead of treating firewall as a normal
    daemon-owned UCI storable.

### Transport / Runtime

- `crates/transport-wire-openwrt-ubus`
  - owns ubus runtime mechanics,
  - owns event publish/subscribe mapping,
  - owns service-scoped RPC command ingress,
  - should support console/script-friendly event watching and method invocation semantics.
- `crates/transport-wire-openwrt-luci`
  - owns LuCI-facing integration,
  - should align with `/ubus` JSON-RPC 2.0 expectations (uhttpd-mod-ubus baseline),
  - must keep request/response/event payloads adapter-local before mapping into daemon contracts.

## Non-Negotiable Boundary Rules

- OpenWrt protocol/storage details must remain adapter-owned.
- daemon `services/`, `flows/`, `workers/`, and core policy logic must not depend on:
  - raw UCI file syntax,
  - ubus TLV/runtime types,
  - rpcd ACL file shapes,
  - LuCI/uhttpd protocol details.
- Domain logic should see canonical models and explicit adapter ports only.
- OpenWrt-facing adapters must preserve the native platform interaction model where possible,
  instead of inventing parallel daemon-specific control conventions.

## Development Expectations For Future Slices

- Prefer fixture-backed development for OpenWrt file/config work.
- Keep fixture intent explicit:
  - `storage-format-uci` fixtures validate text syntax and structural mapping only.
  - Firewall backend behavior (apply/reload/authority semantics) must be covered in
    transport/runtime integration tests, not storage-format fixture tests.
  - Use directory split for fixtures:
    - `daemon-rs/data/*.uci` and `daemon-rs/data/rules/*.uci`: UCI syntax fixtures,
    - `daemon-rs/data/fixtures/firewall/*.json`: firewall backend runtime-semantics fixtures.
- Prefer source-compatible integration with ubus/rpcd/uhttpd conventions over novel APIs.
- Validate scriptability explicitly:
  - event watching,
  - method invocation,
  - auth/session behavior,
  - ACL-denied paths.
- Treat package/install/runtime integration as part of the feature, not post-processing.

#### UCI File Format vs UCI CLI Output

- UCI config files and daemon-rs `storage-format-uci` share the same text file format surface.
- Differences belong to runtime command/output surfaces (`uci` CLI / `ubus uci.*`):
  - command verbs and transactional behavior (`set`/`add`/`delete`/`commit`/`apply`/`rollback`),
  - `uci` CLI output is text-oriented and derived from the UCI file model (for example `show`/`export` style views),
  - `ubus` output is JSON/JSON-RPC shaped by `rpcd` ubus methods, not UCI text output,
  - runtime command output shaping and status/error semantics.
- Those runtime differences must stay in transport/runtime adapters, not storage codecs.
- Parser rule for runtime adapters: `uci` CLI output must be parsed as UCI-derived text
  (key/value and section-path semantics), never as ubus JSON payloads.
- Reference baseline for UCI runtime semantics and key syntax: `rust-uci`
  docs/API (`docs.rs/rust-uci`) and source-level libuci bindings. Use it as a
  libuci behavior reference; do not treat it as a parser for ubus JSON payloads.

## Cross-References

- [daemon-rs/DESIGN_RULES.md](DESIGN_RULES.md)
- [daemon-rs/TODO.md](TODO.md)
- [daemon-rs/COMPATIBILITY.md](COMPATIBILITY.md)
