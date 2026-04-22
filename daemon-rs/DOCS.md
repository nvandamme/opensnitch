# Daemon-RS User Guide

This document provides practical guidance for installing, running, and operating the Rust daemon in `daemon-rs`.

## Scope

This guide covers:

- building from source,
- local runtime management,
- core environment variables,
- optional service-style operation.

It assumes Linux and a local checkout of this repository.

## Prerequisites

- Rust toolchain with Cargo.
- Linux kernel support needed by OpenSnitch runtime features.
- Privileges required for firewall and eBPF paths (typically root/capabilities, depending on deployment).

Optional for eBPF build workflow:

- `rustup` and the configured eBPF target/toolchain used by `scripts/build_ebpf.sh`.

## Build

From `daemon-rs`:

```bash
cargo build -p opensnitchd-rs
```

Release build:

```bash
cargo build --release -p opensnitchd-rs
```

The daemon binary package is `opensnitchd-rs` in `crates/daemon`.

### Feature Flags

| Flag | Default | Description |
|---|---|---|
| `aya-ebpf` | **on** | eBPF backend via [aya](https://github.com/aya-rs/aya). Mutually exclusive with `libbpf-ebpf`. |
| `native-ebpf-ringbuf` | **on** | Use the native eBPF ring-buffer API for kernel event delivery (requires `aya-ebpf`). |
| `libbpf-ebpf` | off | Alternative eBPF backend via libbpf-rs. Pulls in `libbpf-rs` and disables aya. |
| `subscriptions` | off | Subscription management service — remote list download, storage, and rule-layout sync. See [Subscriptions](#subscriptions). |
| `metrics-export` | off | Prometheus scrape endpoint and push exporter. See [Metrics Export](#metrics-export). |

Example — build with both optional features:

```bash
cargo build --release -p opensnitchd-rs --features subscriptions,metrics-export
```

## Run (Foreground)

Default run:

```bash
cargo run -p opensnitchd-rs
```

Run with explicit config and client address:

```bash
OPENSNITCH_CONFIG_FILE=/etc/opensnitchd/default-config.json \
OPENSNITCH_CLIENT_ADDR=http://127.0.0.1:50051 \
RUST_LOG=info \
cargo run -p opensnitchd-rs
```

## Installation From Source

One straightforward approach is to install with Cargo:

```bash
cargo install --path crates/daemon --locked
```

If you need a custom install root:

```bash
cargo install --path crates/daemon --locked --root /usr/local
```

After installation, ensure your runtime config and data paths are available on target host (for example under `/etc/opensnitchd/`).

## Runtime Management

### Live Session Orchestration (Guarded)

Repository-level live session commands are available from workspace root:

```bash
make daemon-rs-live-logs
make daemon-rs-live-stop
make daemon-rs-mock-ui-session
```

Behavior notes:

- These targets run under test-guard semantics and tools-side privilege routing (`direct` / `pkexec` / `sudo`).
- Launch path stores metadata for service cleanup/restart and stop path restores previously stopped services unless explicitly disabled.
- `daemon-rs-mock-ui-session` launches a lightweight mock Python UI endpoint (non-GUI), validates Subscribe/Ping/PingStats/Notifications/NotificationCommandReply(LOG_LEVEL) handshake markers (covering all UI and Subscriptions gRPC endpoints the Python client uses, including stats data flow and notification command round-trip), and shuts down cleanly.

Equivalent tools-only invocation (without Make) is supported:

```bash
cargo run --release --manifest-path daemon-rs/Cargo.toml -p tools -- run-daemon-mock-ui-live-session
```

Optional restart control:

- `OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0` disables post-run service restart behavior.

### Stop

The daemon handles normal termination signals:

- `SIGTERM` for graceful stop,
- `SIGINT` for interrupt stop.

Example:

```bash
kill -TERM <daemon_pid>
```

### Reload

The daemon listens for `SIGHUP` and reloads runtime configuration.

```bash
kill -HUP <daemon_pid>
```

On SIGHUP the daemon reloads:
- `default-config.json` (rules path, firewall backend, logging, etc.)
- Rule files from the configured rules directory
- Firewall rules
- `metrics.json` — Prometheus scrape server is restarted on address change (see
  [Metrics Export → Hot-reload](#metrics-export) below); push exporter config changes
  require a daemon restart.

### Logging

Logging filter is driven by `RUST_LOG`.

Examples:

```bash
RUST_LOG=info cargo run -p opensnitchd-rs
RUST_LOG=debug cargo run -p opensnitchd-rs
```

Notification/session logging includes stable client identity fields:

- `client_id`: session identifier used by daemon runtime.
- `client_origin`: normalized `ClientPrincipal` origin (`local-uid:*`, `unix-abstract:*`, `network:*`, `ip:*`).

Reconnect warning behavior:

- timeout/error/non-stateful disconnect paths remain warn-level,
- repeated reconnect warn logs are throttled to reduce flood noise in multi-user environments.

## Config and Tunables

### Config file resolution

Config is resolved in this order:

1. `OPENSNITCH_CONFIG_FILE` (if set),
2. `/etc/opensnitchd/default-config.json` (if present),
3. repository dev fallback under `daemon/data/default-config.json`.

### Tunables file resolution

Tunables are opt-in and resolved in this order:

1. `OPENSNITCH_TUNABLES_FILE` (if set and exists),
2. `/etc/opensnitchd/tunables.json` (if present),
3. repository dev fallback under `daemon-rs/data/tunables.json`.

Environment overrides use `OPENSNITCH_TUNE_*` keys.

Common examples:

- `OPENSNITCH_TUNE_NETLINK_FALLBACK_RETRY_DELAY_MS`
- `OPENSNITCH_TUNE_NETLINK_RECOVERY_POLL_INTERVAL_MS`
- `OPENSNITCH_TUNE_NFQUEUE_OVERLOAD_POLICY`

### Policy fallback fields

The daemon runtime config includes these policy-related fields:

- `DefaultAction`
- `DefaultDuration`
- `InterceptUnknown`
- `AskTimeoutPolicy`

`AskTimeoutPolicy` values:

- `allow`
- `drop`
- `default` (explicit keyword for daemon default behavior)
- missing/null field: default daemon behavior (same as not specifying `AskTimeoutPolicy`)

Important behavior:

- `AskTimeoutPolicy` is a daemon safeguard for UI-miss conditions only (UI connect failure, AskRule RPC failure, stale/discarded decision).
- If the UI returns a concrete rule, that UI rule remains authoritative.
- In mixed Rust-daemon + Python-UI deployments, Python UI timeout behavior may still default to deny unless UI default action is explicitly changed.

### Multi-user and mutation safety

- Connected-session precedence is deterministic: control session first, otherwise principal-rank ordering.
- Rule/firewall/control mutations run through a shared transactional coordinator with rollback and idempotency dedup.
- Verdict flow uses per-connection decision arbitration and async rule persistence so packet verdict latency stays low while durable policy writes remain transactional.

### default-config.json field reference

All fields are optional; absent fields take the defaults shown below.  Field names are
case-insensitive on the wire.

| Field | Type | Default | Accepted values / notes |
|---|---|---|---|
| `Server.Address` | string | `unix:///tmp/osui.sock` | gRPC listen address for UI connections |
| `Server.LogFile` | string | *(stderr)* | Path for daemon log output |
| `Server.Authentication.Type` | string | `simple` | `simple` · `tls-simple` · `tls-mutual` |
| `Server.Authentication.TLSOptions.CACert` | string | — | CA cert path (TLS modes) |
| `Server.Authentication.TLSOptions.ServerCert` | string | — | Server cert path |
| `Server.Authentication.TLSOptions.ServerKey` | string | — | Server key path |
| `Server.Authentication.TLSOptions.ClientCert` | string | — | Client cert path (mutual TLS) |
| `Server.Authentication.TLSOptions.ClientKey` | string | — | Client key path (mutual TLS) |
| `Server.Authentication.TLSOptions.SkipVerify` | bool | `false` | Skip peer cert verification |
| `Server.Authentication.TLSOptions.ClientAuthType` | string | `no-client-cert` | mTLS requirement level |
| `Server.Loggers` | array | `[]` | Structured log sink array (name / format / protocol / server) |
| `DefaultAction` | string | `allow` | `allow` · `deny` · `reject` |
| `DefaultDuration` | string | `once` | `once` · `always` · `untilrestart` |
| `AskTimeoutPolicy` | string | `default` | `allow` · `deny` · `drop` · `default` — applied when UI misses verdict deadline |
| `InterceptUnknown` | bool | `false` | Intercept connections whose process cannot be resolved |
| `ProcMonitorMethod` | string | `ebpf` | `ebpf` · `proc` · `audit` |
| `LogLevel` | int | `2` | 0 = warn · 1 = info · 2 = debug · 3 = trace |
| `LogUTC` | bool | `true` | Log timestamps in UTC |
| `LogMicro` | bool | `false` | Microsecond resolution in log timestamps |
| `Firewall` | string | `nftables` | `nftables` · `iptables` |
| `FwOptions.ConfigPath` | string | — | Path to `system-fw.json` |
| `FwOptions.MonitorInterval` | string | `10s` | Firewall re-sync interval (Go duration) |
| `FwOptions.QueueNum` | int | `0` | NFQUEUE queue number |
| `FwOptions.QueueBypass` | bool | `true` | Bypass queue when no listener is attached |
| `Ebpf.ModulesPath` | string | `/usr/lib/opensnitchd/ebpf` | Directory containing compiled eBPF objects |
| `Ebpf.EventsWorkers` | int | `8` | eBPF event worker goroutines (Go daemon; ignored by Rust) |
| `Ebpf.QueueEventsSize` | int | `0` | eBPF event queue depth (Go daemon; ignored by Rust) |
| `Audit.AudispSocketPath` | string | `/var/run/audispd_events` | Path to audisp socket (`audit` monitor method) |
| `Rules.Path` | string | — | Directory containing rule JSON files |
| `Rules.EnableChecksums` | bool | `false` | Verify rule file checksums on load |
| `Tasks.ConfigPath` | string | — | Path to `tasks.json` |
| `Stats.MaxEvents` | int | `250` | Maximum events to keep in rolling stats window |
| `Stats.MaxStats` | int | `25` | Maximum per-dimension stat entries |
| `Stats.Workers` | int | `6` | Stats processing worker count |
| `Internal.GCPercent` | int | `100` | Go GC target percentage (Go daemon; unused by Rust) |
| `Internal.FlushConnsOnStart` | bool | `true` | Flush existing connections on daemon start |

### metrics.json field reference

> **Feature gate**: `metrics-export` (off by default — see [Feature Flags](#feature-flags))

`metrics.json` is co-located with the daemon config (e.g. `/etc/opensnitchd/metrics.json`).
The file and all its fields are optional; absent fields disable the corresponding exporter.

#### `prometheus` object

| Field | Type | Default | Notes |
|---|---|---|---|
| `addr` | string | *(disabled)* | TCP `host:port` for the scrape endpoint. Absent or empty string disables the endpoint. |

#### `push` object

| Field | Type | Default | Notes |
|---|---|---|---|
| `url` | string | *(disabled)* | Push target URL. Absent or empty string disables push. |
| `format` | string | `pushgateway` | `pushgateway` · `pushgateway-proto` · `influxdb` — see format descriptions in [Push Exporter](#push-exporter) |
| `job` | string | `opensnitchd` | Job label appended to the push path as `/metrics/job/{job}` (pushgateway formats) |
| `token` | string | — | Auth token. Sent as `Authorization: Bearer <token>` (pushgateway/Mimir) or `Authorization: Token <token>` (InfluxDB) |
| `gzip` | bool | `false` | Compress push body (`Content-Encoding: gzip`) |
| `bucket` | string | `opensnitch` | InfluxDB v2 bucket — appended as `?bucket=…` when not already in the URL. Only used with `format=influxdb`. |
| `org` | string | — | InfluxDB v2 organisation — appended as `?org=…` when not already in the URL. Only used with `format=influxdb`. |

### system-fw.json format

`system-fw.json` is the system firewall configuration file, referenced by
`FwOptions.ConfigPath` in `default-config.json`.  The daemon monitors the file and
reloads it on change.  The top-level structure is:

```
{
  "Enabled": bool,       // master switch — false disables all system rules
  "Version": int,        // schema version (currently 1)
  "SystemRules": [ ... ] // ordered list of firewall rule entries
}
```

Each entry in `SystemRules` carries one or both of:

- **`Rule`** — a single iptables-style command-line rule.
- **`Chains`** — an array of nftables chain definitions.

Leave `Rule` as `{}` (or omit it) when using nftables chains, and leave `Chains` as `[]`
(or omit it) when using an iptables rule.

#### `Rule` object (iptables)

| Field | Type | Notes |
|---|---|---|
| `Table` | string | iptables table, e.g. `mangle`, `filter` |
| `Chain` | string | iptables chain, e.g. `OUTPUT`, `INPUT` |
| `Enabled` | bool | `false` = defined but not applied |
| `Position` | string | Insert position (numeric string) |
| `Description` | string | Human-readable label |
| `Parameters` | string | iptables match parameters, e.g. `-p icmp` |
| `Expressions` | array | Additional match expressions (usually empty for iptables) |
| `Target` | string | iptables target: `ACCEPT`, `DROP`, `REJECT`, … |
| `TargetParameters` | string | Extra target parameters |

#### `Chains` array (nftables)

Each entry defines one nftables chain:

| Field | Type | Notes |
|---|---|---|
| `Name` | string | Chain name, e.g. `filter_output` |
| `Table` | string | nftables table, e.g. `opensnitch` |
| `Family` | string | `inet` · `ip` · `ip6` · `bridge` · `arp` · `netdev` |
| `Priority` | string | nftables priority (empty = kernel default for type/hook) |
| `Type` | string | `filter` · `mangle` · `nat` · `route` |
| `Hook` | string | `input` · `output` · `forward` · `prerouting` · `postrouting` |
| `Policy` | string | Default chain policy: `accept` · `drop` |
| `Rules` | array | Ordered list of nftables rules (see below) |

Each entry in `Rules`:

| Field | Type | Notes |
|---|---|---|
| `Enabled` | bool | `false` = defined but not applied |
| `Position` | string | Rule position (numeric string) |
| `Description` | string | Human-readable label |
| `Parameters` | string | Raw nftables parameters |
| `Expressions` | array | Match expressions — each has a `Statement` with `Op`, `Name`, and `Values` (`Key`/`Value` pairs) |
| `Target` | string | nftables verdict: `accept` · `drop` · `reject` · `continue` · `return` |
| `TargetParameters` | string | Extra verdict parameters |

See [daemon-rs/data/system-fw.example.json](data/system-fw.example.json) for a complete
working example with both iptables and nftables entries.

### tasks.json format

`tasks.json` is the task registry file, referenced by `Tasks.ConfigPath` in
`default-config.example.json` (e.g. `/etc/opensnitchd/tasks/tasks.json`).  It lists the
tasks the daemon should load at start.

```json
{
  "tasks": [
    {
      "name": "downloader",
      "configfile": "/etc/opensnitchd/tasks/downloader/downloader.json",
      "enabled": false
    }
  ]
}
```

Each entry in `tasks`:

| Field | Type | Notes |
|---|---|---|
| `name` | string | Task instance name. Must match a supported task type or be a unique suffix of one (e.g. `downloader`, `downloader-blocklists`). |
| `configfile` | string | Absolute path to the task-specific data file (see below). |
| `enabled` | bool | `false` = registered but not started on load. |

Supported storage task names (loaded from `configfile`): `downloader`, `ioc-scanner`, `looper`.

Runtime-only task names (started on demand via UI command, no `configfile` needed): `pid-monitor`, `node-monitor`, `sockets-monitor`.

#### Task data file format

Each `configfile` is a separate JSON file with this top-level structure:

```json
{
  "parent": "downloader",
  "name": "downloader",
  "data": { ... }
}
```

| Field | Type | Notes |
|---|---|---|
| `parent` | string | Canonical task type: `downloader` · `ioc-scanner` · `looper` |
| `name` | string | Unique instance name (matches the `name` in `tasks.json`) |
| `data` | object | Task-specific configuration (see below) |

#### `downloader` task data

Downloads files at a configured interval, suitable for updating blocklists.

| Field | Type | Notes |
|---|---|---|
| `timeout` | string | Per-download HTTP timeout (Go duration, e.g. `5s`) |
| `urls` | array | List of URLs to download |
| `urls[].name` | string | Unique label for this download entry |
| `urls[].remote` | string | Source URL |
| `urls[].localfile` | string | Destination path on disk |
| `urls[].enabled` | bool | Skip this entry when `false` |
| `notify.enabled` | bool | Send a UI notification on completion |

#### `ioc-scanner` task data

Scans for Indicators Of Compromise on a schedule using external tools.

| Field | Type | Notes |
|---|---|---|
| `timeout` | string | Overall scan timeout (Go duration) |
| `schedule` | array | One or more schedule entries (all are evaluated; any match triggers) |
| `schedule[].time` | string[] | Exact `HH:MM:SS` times to run |
| `schedule[].weekday` | int[] | Days of week to run (0 = Sunday … 6 = Saturday) |
| `schedule[].hour` | int[] | Hours to run (0–23) |
| `schedule[].minute` | int[] | Minutes to run (0–59) |
| `schedule[].second` | int[] | Seconds to run (0–59) |
| `tools` | array | Tools to invoke during a scan |
| `tools[].name` | string | Tool type: `yara` · `debsums` · `dpkg` · `scripts` · `decloacker` |
| `tools[].enabled` | bool | Skip this tool when `false` |
| `tools[].cmd` | string[] | Command and arguments |
| `tools[].options.maxRunningTime` | string | Per-tool timeout (Go duration) |
| `tools[].options.reports` | array | Report output definitions |
| `tools[].options.reports[].type` | string | Report type identifier |
| `tools[].options.reports[].path` | string | Output directory for reports |
| `tools[].options.reports[].format` | string | Output format (tool-specific) |

See [daemon-rs/data/tasks.example.json](data/tasks.example.json) and the Go daemon's
[`daemon/tasks/downloader/README.md`](../daemon/tasks/downloader/README.md) and
[`daemon/tasks/iocscanner/README.md`](../daemon/tasks/iocscanner/README.md) for worked
examples.

### Rule file format

Each rule is a single JSON file stored under the directory configured by `Rules.Path`
(e.g. `/etc/opensnitchd/rules/`).  The daemon watches the directory and reloads rules on
any file change.

#### Top-level fields

| Field | Type | Notes |
|---|---|---|
| `created` | string | RFC 3339 creation timestamp (written by the daemon; leave empty on manual creation) |
| `updated` | string | RFC 3339 last-update timestamp (maintained by the daemon) |
| `name` | string | Unique rule identifier — used as the file stem by convention |
| `description` | string | Human-readable description |
| `enabled` | bool | `false` = rule loaded but never matched |
| `precedence` | bool | When `true` this rule is evaluated before normal rules regardless of load order |
| `nolog` | bool | Suppress audit log entries for connections matched by this rule |
| `action` | string | `allow` · `deny` · `reject` |
| `duration` | string | `always` · `once` · `until restart` |
| `operator` | object | Match condition (see below) |

#### `operator` object

| Field | Type | Notes |
|---|---|---|
| `type` | string | Operator type — see type table below |
| `operand` | string | Attribute of the connection to test — see operand table below |
| `data` | string | Match value; interpretation depends on `type` |
| `sensitive` | bool | Case-sensitive comparison; default `false` |
| `list` | array | Sub-operators when `type=list` (can be `null` or `[]` otherwise) |

#### Operator types

| `type` | `data` format | Description |
|---|---|---|
| `simple` | Exact string | Exact equality match |
| `regexp` | RE2 pattern | Regular expression match |
| `network` | CIDR, e.g. `10.0.0.0/8` | IP address must be within the given CIDR block. Valid operands: `dest.network`, `source.network`, `dest.host`, `dest.ip`, `source.ip` |
| `range` | `min-max`, e.g. `1-1024` or `1 - 5000` | Numeric range (inclusive). Primarily used with `dest.port` or `source.port` |
| `list` | `""` (empty; sub-operators carry the logic) | AND-combination of multiple sub-operators; `operand` must be `"list"` |
| `lists` | Absolute directory path | Match against newline-delimited flat files in the directory. File types (one per line): plain text for `lists.domains` / `lists.ips` / `lists.nets` / `lists.hash.md5`; RE2 patterns for `lists.domains_regexp` |

#### Operands

| `operand` | Matched attribute |
|---|---|
| `true` | Always matches (unconditional rule) |
| `process.id` | Process PID |
| `process.path` | Process executable absolute path |
| `process.parent.path` | Parent process executable path |
| `process.command` | Full command line |
| `process.env.<NAME>` | Value of environment variable `NAME` in the process |
| `process.hash.md5` | MD5 hash of the executable |
| `process.hash.sha1` | SHA-1 hash of the executable |
| `user.id` | User numeric UID |
| `user.name` | Username (resolved to UID at load time) |
| `source.ip` | Source IP address |
| `source.port` | Source port number |
| `source.network` | Source IP CIDR membership (`type=network` only) |
| `dest.ip` | Destination IP address |
| `dest.host` | Destination hostname |
| `dest.port` | Destination port number |
| `dest.network` | Destination IP CIDR membership (`type=network` only) |
| `protocol` | Transport protocol (`tcp`, `udp`, …) |
| `iface.in` | Ingress network interface name |
| `iface.out` | Egress network interface name |
| `list` | AND-list (used only with `type=list`) |
| `lists.domains` | Hostname in newline-delimited domain list file(s). Supported formats per line: plain domain, `0.0.0.0`/`127.0.0.1` hosts-file prefix, AdBlock/AdGuard `\|\|domain^` anchor. Exception rules (`@@`), cosmetic filters (`##`), and `!`/`#` comments are skipped. |
| `lists.domains_regexp` | Hostname matches any RE2 pattern in list file(s) |
| `lists.ips` | IP in newline-delimited IP list file(s) |
| `lists.nets` | IP in newline-delimited CIDR list file(s) |
| `lists.hash.md5` | Executable MD5 in newline-delimited hash list file(s) |

#### Examples

**Simple allow — localhost (precedence, nolog):**
```json
{
  "name": "000-allow-localhost",
  "enabled": true,
  "precedence": true,
  "nolog": true,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "simple",
    "operand": "dest.ip",
    "sensitive": false,
    "data": "127.0.0.1",
    "list": []
  }
}
```

**Regexp deny — block all connections by process path pattern:**
```json
{
  "name": "deny-telemetry-by-path",
  "enabled": true,
  "precedence": false,
  "action": "deny",
  "duration": "always",
  "operator": {
    "type": "regexp",
    "operand": "process.path",
    "sensitive": false,
    "data": "^/opt/(google|microsoft|adobe)/",
    "list": []
  }
}
```

**Network — block connections to a CIDR range:**
```json
{
  "name": "deny-rfc1918-dst",
  "enabled": true,
  "action": "deny",
  "duration": "always",
  "operator": {
    "type": "network",
    "operand": "dest.network",
    "sensitive": false,
    "data": "192.168.0.0/16",
    "list": []
  }
}
```

**Range — allow a port range:**
```json
{
  "name": "allow-ephemeral-ports",
  "enabled": true,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "range",
    "operand": "dest.port",
    "sensitive": false,
    "data": "32768-60999",
    "list": []
  }
}
```

**List — AND multiple conditions (process + port):**
```json
{
  "name": "allow-firefox-dns",
  "enabled": true,
  "precedence": false,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "list",
    "operand": "list",
    "sensitive": false,
    "data": "",
    "list": [
      {
        "type": "simple",
        "operand": "process.path",
        "sensitive": false,
        "data": "/usr/lib/firefox/firefox",
        "list": null
      },
      {
        "type": "simple",
        "operand": "dest.port",
        "sensitive": false,
        "data": "53",
        "list": null
      }
    ]
  }
}
```

**Lists — block by domain blocklist directory:**
```json
{
  "name": "deny-ads-domains",
  "enabled": true,
  "action": "deny",
  "duration": "always",
  "operator": {
    "type": "lists",
    "operand": "lists.domains",
    "sensitive": false,
    "data": "/etc/opensnitchd/tasks/downloader/blocklists/domains",
    "list": []
  }
}
```

See [daemon-rs/data/rules/allow-firefox-dns.example.json](data/rules/allow-firefox-dns.example.json)
for an annotated example file.  The [Go daemon's testdata](../daemon/rule/testdata) directory
contains additional fixtures for all operator types.

## Optional eBPF Build Helper

To build eBPF artifacts via the project helper:

```bash
sudo ./scripts/build_ebpf.sh
```

Important behavior:

- The helper enforces root execution for consistent artifact ownership.
- In repository workflows, prefer the root Make targets (`make daemon-rs-ebpf-build` / `make daemon-rs-ebpf-build-runtime`) so output is normalized under `daemon-rs/target-kernel`.

You can adjust toolchain and target with:

- `DAEMON_RS_EBPF_TOOLCHAIN`
- `DAEMON_RS_EBPF_TARGET`
- `DAEMON_RS_EBPF_PACKAGE`

## Metrics Export

> **Feature gate**: `metrics-export` (off by default — see [Feature Flags](#feature-flags))

Adds two stats export adapters.  Build with:

```bash
cargo build -p opensnitchd-rs --features metrics-export
```

Both adapters are configured through (in precedence order, highest → lowest, DESIGN_RULES §7):

1. **CLI flags** — highest precedence; `--metrics-prometheus-addr`, `--metrics-push-url`, `--metrics-push-format`,
   `--metrics-push-job`, `--metrics-push-token`, `--metrics-push-gzip`.
2. **Env vars** — mid-tier override; typically used for CI/testing (see below).
3. **`metrics.json`** — baseline; co-located with the daemon config file (e.g.
   `/etc/opensnitchd/metrics.json`). Full field reference: [metrics.json field reference](#metricsjson-field-reference).

### Prometheus Scrape Endpoint

#### `metrics.json` (JSON config layer)

```json
{
  "prometheus": {
    "addr": "127.0.0.1:9100"
  }
}
```

#### CLI

```bash
opensnitchd-rs --metrics-prometheus-addr 127.0.0.1:9100
```

#### Env var (CI/testing only)

```bash
OPENSNITCH_PROMETHEUS_ADDR=127.0.0.1:9100 opensnitchd-rs
```

The daemon binds a minimal HTTP/1.1 server on the configured address.  `/metrics` serves
the latest statistics snapshot.  Any other path returns 404.  Bind failure logs a warning
and disables the endpoint without stopping the daemon (fail-open).

**Content negotiation** follows the [Prometheus scrape protocol spec](https://prometheus.io/docs/instrumenting/content_negotiation/).
The richest supported format at the highest `Accept` q-value is selected; ties are broken
by richness (OpenMetrics > Text1.0.0 > Text0.0.4 > Proto).

| Format | Content-Type |
|---|---|
| `PrometheusText0.0.4` | `text/plain; version=0.0.4; charset=utf-8` (default) |
| `PrometheusText1.0.0` | `text/plain; version=1.0.0; charset=utf-8; escaping=allow-utf-8` |
| `OpenMetricsText1.0.0` | `application/openmetrics-text; version=1.0.0; charset=utf-8` |
| `PrometheusProto` | `application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited` |

`PrometheusProto` is selected only when its q-value is strictly higher than all text formats.

**OpenMetrics 1.0.0 specifics**: counter MetricFamily names use the base form (e.g.
`opensnitch_connections`); each counter emits `<base>_total` and `<base>_created` (Unix
float timestamp) samples.  `opensnitch_uptime_seconds` includes a `# UNIT … seconds` line.
The response body terminates with `# EOF\n`.

**Gzip compression**: `Accept-Encoding: gzip` triggers `Content-Encoding: gzip` on the
response body.

**Metric names** (all prefixed `opensnitch_`):

| Name | Type | Description |
|---|---|---|
| `opensnitch_connections_total` | counter | Total connections intercepted |
| `opensnitch_accepted_total` | counter | Connections accepted |
| `opensnitch_dropped_total` | counter | Connections dropped |
| `opensnitch_dns_responses_total` | counter | DNS responses tracked |
| `opensnitch_ignored_total` | counter | Connections ignored |
| `opensnitch_rule_hits_total` | counter | Rule matches |
| `opensnitch_rule_misses_total` | counter | Default action applied |
| `opensnitch_rules` | gauge | Loaded rules count |
| `opensnitch_uptime_seconds` | gauge | Daemon uptime |
| `opensnitch_subscription_total/ready/error` | gauge | Subscription slot counts |
| `opensnitch_connections_by_proto{proto=…}` | gauge | Breakdown by transport protocol |
| `opensnitch_connections_by_address{address=…}` | gauge | Breakdown by remote address |
| `opensnitch_connections_by_host{host=…}` | gauge | Breakdown by remote host |
| `opensnitch_connections_by_port{port=…}` | gauge | Breakdown by remote port |
| `opensnitch_connections_by_uid{uid=…}` | gauge | Breakdown by user UID |
| `opensnitch_connections_by_executable{executable=…}` | gauge | Breakdown by executable |

#### Hot-reload

Sending `SIGHUP` to the daemon re-reads `metrics.json` and reconciles the scrape server:

| Change | Effect |
|---|---|
| `prometheus.addr` unchanged | No-op |
| `prometheus.addr` added or changed | Old server cancelled; new server started on the new address; exporter reused (stats flow uninterrupted) |
| `prometheus.addr` removed | Server cancelled; exporter keeps accumulating snapshots in memory |

The `PrometheusStatsExporter` Arc is always created at startup (even when no address is
configured), so enabling the address for the first time via SIGHUP works without restarting
the daemon.  Push exporter configuration changes still require a daemon restart.

### Push Exporter

Sends a stats snapshot to a remote HTTP endpoint on every `StatsFlow` tick (~1 s when
traffic is active).  Three formats are supported.

#### `metrics.json` (JSON config layer)

Full configuration example:

```json
{
  "push": {
    "url": "http://pushgateway:9091",
    "format": "pushgateway",
    "job": "opensnitchd",
    "token": "optional-bearer-or-api-token",
    "gzip": false,
    "bucket": "opensnitch",
    "org": ""
  }
}
```

`format` accepts: `pushgateway` (default), `pushgateway-proto`, `influxdb`.

#### CLI

```bash
opensnitchd-rs \
  --metrics-push-url http://pushgateway:9091 \
  --metrics-push-format pushgateway \
  --metrics-push-job opensnitchd \
  --metrics-push-token mytoken \
  --metrics-push-gzip
```

#### Env vars (CI/testing only)

| Variable | Description |
|---|---|
| `OPENSNITCH_PUSH_URL` | Push endpoint URL (required to enable push) |
| `OPENSNITCH_PUSH_FORMAT` | `pushgateway` / `pushgateway-proto` / `influxdb` |
| `OPENSNITCH_PUSH_JOB` | Job label (default: `opensnitchd`) |
| `OPENSNITCH_PUSH_TOKEN` | Auth token |
| `OPENSNITCH_PUSH_GZIP` | `1` / `true` / `yes` to enable gzip |
| `OPENSNITCH_PUSH_BUCKET` | InfluxDB bucket (default: `opensnitch`) |
| `OPENSNITCH_PUSH_ORG` | InfluxDB organisation |

#### Formats

**`pushgateway`** — Prometheus text 0.0.4 POSTed to `{url}/metrics/job/{job}`.
Compatible with Prometheus push-gateway, Grafana Mimir, and Grafana Cloud remote-write.
`Authorization: Bearer <token>` when token is set.

**`pushgateway-proto`** — Prometheus protobuf (delimited `MetricFamily`) to the same path.
Preferred by Prometheus-native backends.

**`influxdb`** — InfluxDB line protocol per the
[InfluxDB v2 write API](https://docs.influxdata.com/influxdb/v2/get-started/write/).
The URL is used verbatim; `?precision=s` and `?bucket=…` are appended when not already
present.  Integer fields use the `i` suffix.  Tag values are escaped per the line-protocol
spec (comma, space, equals, backslash).  `Authorization: Token <token>` when token is set.

Example InfluxDB v2 write URL:
```
http://influxdb:8086/api/v2/write?bucket=opensnitch&org=myorg
```

The push background task is fail-open — HTTP errors and non-2xx responses are logged at
`DEBUG` and never stop the daemon.

### Running both adapters simultaneously

When both `prometheus.addr` and `push.url` are configured, a `MultiStatsExporter`
fan-out is created automatically and each snapshot is delivered to both adapters.

## Subscriptions

> **Feature gate**: `subscriptions` (off by default — see [Feature Flags](#feature-flags))

The subscriptions subsystem lets the UI apply, refresh, and delete remote blocklist
subscriptions.  On a successful refresh the daemon downloads the list file and
symlinks it into the active rule-list directories so `lists.*` operators pick it up
automatically.  When the feature is compiled out a no-op stub is used and all
`SubscriptionRequest` RPCs return an accepted-but-empty reply.

Build with the feature enabled:

```bash
cargo build --release -p opensnitchd-rs --features subscriptions
```

### Runtime paths

| Path | Purpose |
|---|---|
| `/etc/opensnitchd/subscriptions/subscriptions.json` | Persistent subscription store (JSON) |
| `/etc/opensnitchd/subscriptions/sources.list.d/` | Downloaded list files (`<filename>.txt`) |
| `<Rules.Path>/<group>/` | Symlinks into `sources.list.d/` consumed by `lists.*` rule operators |

The store file is created automatically on first `Apply`.  Its directory and the
`sources.list.d/` sub-directory are also created on demand.

### gRPC API

All operations go through the `Subscriptions` service defined in
[`proto/subscriptions.proto`](../proto/subscriptions.proto).  Both a multiplexed
`Command` RPC and dedicated per-operation RPCs are available.

| Operation | RPC | Behaviour |
|---|---|---|
| `LIST` | `List` | Return all stored subscriptions |
| `APPLY` | `Apply` | Upsert subscriptions into the store; sync rule-list layout |
| `DELETE` | `Delete` | Remove subscriptions from the store; prune stale rule-list symlinks |
| `REFRESH` | `Refresh` | Download / validate list content; update ETag / Last-Modified cache validators; sync layout on change |
| `DEPLOY` | `Deploy` | Sync rule-list symlinks without downloading (idempotent reconcile) |

### Subscription fields

| Field | Type | Notes |
|---|---|---|
| `id` | string | Stable hex identifier (auto-derived from `url`+`name` when omitted) |
| `name` | string | Human-readable label |
| `url` | string | HTTP/HTTPS source URL |
| `filename` | string | Local filename under `sources.list.d/` (auto-derived from `url` when omitted) |
| `groups` | string[] | Rule-list group names — each group gets its own subdirectory under `Rules.Path` |
| `enabled` | bool | When `false` the file is kept but no symlinks are created for it |
| `format` | string | List format — see format table below |
| `interval_seconds` | uint32 | Minimum seconds between refreshes (default: 86400) |
| `timeout_seconds` | uint32 | Per-download HTTP timeout in seconds (default: 60) |
| `max_bytes` | uint64 | Maximum download size in bytes (default: 20 MiB) |
| `node` | string | Opaque node tag for multi-node setups |

### List formats

| `format` | Feeds rule operand | Content description |
|---|---|---|
| `hosts` (default) | `lists.domains` | `/etc/hosts`-style: `0.0.0.0 hostname` or `127.0.0.1 hostname` lines |
| `domains` | `lists.domains` | One bare domain or glob per line, e.g. `ads.example.com` or `*.tracker.net` |
| `adblock` | `lists.domains` | AdBlock/AdGuard format: `||domain^` entries; `@@` exceptions, `##` cosmetic filters, and `!` comments are skipped automatically; mixed files (hosts + adblock) are also accepted |
| `ips` | `lists.ips` | One IPv4 or IPv6 address per line |
| `nets` | `lists.nets` | One CIDR block per line, e.g. `10.0.0.0/8` |
| `domain_regexps` | `lists.domains_regexp` | One RE2 regular expression per line |

Format is validated against a sample of the downloaded content and the refresh is
aborted with an error if the content shape does not match.

### Refresh behaviour

- Requests carry `If-None-Match` (ETag) and `If-Modified-Since` headers when prior
  cache validators are stored — a `304 Not Modified` response counts as a successful
  no-op refresh.
- A per-subscription async lock prevents concurrent refreshes of the same entry.
- HTTP errors and non-2xx responses increment `consecutive_failures` and schedule
  an exponential back-off via `next_refresh_after`.
- `force=true` in the request bypasses the `next_refresh_after` back-off.
- Refresh is fail-open — errors are logged and surfaced in the reply but never
  stop the daemon.

### Rule wiring

After a successful `APPLY`, `REFRESH`, or `DEPLOY`, the daemon reconciles symlinks
under `<Rules.Path>/<group>/`.  A `lists.*` rule whose `data` field points to one
of those group directories will automatically pick up the subscription's content:

```json
{
  "name": "deny-ads-subscriptions",
  "enabled": true,
  "action": "deny",
  "duration": "always",
  "operator": {
    "type": "lists",
    "operand": "lists.domains",
    "sensitive": false,
    "data": "/etc/opensnitchd/rules/ads",
    "list": []
  }
}
```

Assuming a subscription has `groups: ["ads"]`, its downloaded file will be symlinked
under `/etc/opensnitchd/rules/ads/` and matched by the rule above.

## Performance and Parity Tools

The `tools` crate (`daemon-rs/crates/tools`) provides a CLI for running harness and profiling commands.

```bash
cargo ost <command> [flags...]
# or equivalently:
cargo run --release --manifest-path daemon-rs/Cargo.toml -p tools -- <command> [flags...]
```

Run `cargo ost --help` to print the full reference.

### Commands

| Command | Purpose |
|---|---|
| **Build** | |
| `build` | Build daemon crate (release) |
| `build-all` | Build full daemon-rs workspace (release) |
| `build-ebpf` | Build eBPF crate (root required; privilege via test guard) |
| **Test** | |
| `test` | Run parity test suites (config, firewall, client) |
| `test-kernel-it` | Run kernel integration tests (privileged + strict) |
| `test-filter` | Run tests matching `--filter=PATTERN` |
| **Harness / perf** | |
| `parity-hot-cold-delta` | Hot+cold parity delta N×repeats, median by hot p95 (`OPENSNITCH_PERF_REPEATS`, default 3) |
| `parity-hot-cold-delta-once` | One hot+cold parity delta pass (Go vs Rust) |
| `parity-hot-path-harness-once` | One hot-path parity pass |
| `parity-cold-path-harness` | Cold-path parity pass |
| `parity-hot-path-harness` | Hot-path harness N×repeats (pre-build on pass 1) |
| `parity-gate` | Full parity gate (multi-repeat, gate check) |
| `update-run-perf` | Full perf update cycle; writes PERF.md |
| `quick-pressure-sweep-tunables` | Quick kernel-pressure sweep to calibrate tunables |
| `auto-tune-kernel-pressure-tunables` | Auto-tune kernel pressure tunables |
| `microbench-connect-dispatch` | Microbenchmark connect dispatch |
| **eBPF smoke tests** | |
| `aya-smoke-proc` | aya process eBPF smoke test (root required) |
| `aya-smoke-dns` | aya DNS eBPF smoke test (root required) |
| `aya-smoke-conn` | aya connection eBPF smoke test (root required) |
| `aya-smoke-tunnel` | aya tunnel eBPF smoke test (root required) |
| `kernel-profile-harness` | Rust kernel-pressure + sweep harness (N repeats) |
| **Live daemon** | |
| `launch-daemon-live-logs` | Start daemon with live log streaming |
| `stop-daemon-live-logs` | Stop live daemon session |
| `run-daemon-mock-ui-live-session` | Run daemon with mock Python UI |

### Flags

Flags override their corresponding environment variable (shown in brackets). Env vars remain supported for Makefile and shell compatibility.

**Build:**

| Flag | Environment variable | Default |
|---|---|---|
| `--crate=NAME` | `OPENSNITCH_BUILD_CRATE` | `opensnitchd-rs` |
| `--all-features` | `OPENSNITCH_BUILD_ALL_FEATURES=1` | — |

**Test:**

| Flag | Environment variable | Default |
|---|---|---|
| `--test-log=LEVEL` | `OPENSNITCH_TEST_LOG_LEVEL` | `info,opensnitchd_rs=debug` |
| `--filter=PATTERN` | `OPENSNITCH_TEST_FILTER` | — |
| `--privileged` | `OPENSNITCH_RUN_PRIVILEGED_TESTS=1` | — |
| `--kernel-it-strict` | `OPENSNITCH_KERNEL_IT_STRICT=1` | — |
| `--release` | `OPENSNITCH_TEST_RELEASE=1` | — |
| `--ignored` | `OPENSNITCH_TEST_IGNORED=1` | — |

**Global:**

| Flag | Environment variable(s) | Default |
|---|---|---|
| `--rounds=N` | `OPENSNITCH_PARITY_STRESS_ROUNDS`, `STRESS_ROUNDS` | 500 |
| `--repeats=N` | `OPENSNITCH_PERF_REPEATS` | 3 |
| `--rust-log=LEVEL` | `OPENSNITCH_PERF_RUST_LOG_LEVEL` | warn |
| `--go-log=LEVEL` | `OPENSNITCH_PERF_GO_LOG_LEVEL`, `OPENSNITCH_HARNESS_GO_LOG_LEVEL` | warn |
| `--prebuild` | `OPENSNITCH_PARITY_PREBUILD=1` | — |
| `--no-prebuild` | `OPENSNITCH_PARITY_PREBUILD=skip` | — |
| `--refresh-base` | `OPENSNITCH_PERF_REFRESH_BASE=1` | — |
| `--require-exceed-go` | `OPENSNITCH_PARITY_REQUIRE_EXCEED_GO=1` | — |
| `--skip-regression` | `OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1` | — |

**Pressure/sweep** (`quick-pressure-sweep-tunables`, `auto-tune-kernel-pressure-tunables`):

| Flag | Environment variable(s) | Default |
|---|---|---|
| `--secs=N` | `OPENSNITCH_TUNABLES_SWEEP_SECS`, `OPENSNITCH_AUTOTUNE_PRESSURE_SECS` | 1 |
| `--tasks=N` | `OPENSNITCH_TUNABLES_SWEEP_TASKS`, `OPENSNITCH_AUTOTUNE_PRESSURE_TASKS` | 2 |
| `--sweep-us=LIST` | `OPENSNITCH_TUNABLES_SWEEP_US` | 50,100,200,500,1000 |
| `--timeout-us=N` | `OPENSNITCH_KERNEL_PRESSURE_ENQUEUE_TIMEOUT_US` | 200 |
| `--mode=try\|timeout` | `OPENSNITCH_AUTOTUNE_ENQUEUE_MODE` | timeout |
| `--run-parity-gate` | `OPENSNITCH_AUTOTUNE_RUN_PARITY_GATE=1` | — |

**eBPF smoke** (`aya-smoke-*`):

| Flag | Environment variable | Default |
|---|---|---|
| `--smoke-timeout=N` | `DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS` | 90 |
| `--smoke-kill-after=N` | `DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS` | 3 |

**Output / path:**

| Flag | Environment variable | Default |
|---|---|---|
| `--perf-md=PATH` | `PERF_MD_PATH` | `daemon-rs/PERF.md` |
| `--output=PATH` | `OPENSNITCH_TUNABLES_OUTPUT` | `daemon-rs/data/tunables.json` |
| `--baseline=PATH` | `OPENSNITCH_STRESS_BASELINE_PATH` | `daemon-rs/PERF.md` |
| `--microbench-rounds=N` | `OPENSNITCH_MICROBENCH_ROUNDS` | 4000 |

### Examples

```bash
# Multi-repeat hot+cold delta (3 passes by default, override with PERF_REPEATS)
cargo ost parity-hot-cold-delta

# Override to 5 passes
OPENSNITCH_PERF_REPEATS=5 cargo ost parity-hot-cold-delta

# Single parity delta pass with 200 rounds and quiet logging
cargo ost parity-hot-cold-delta-once --rounds=200 --go-log=err --rust-log=err

# Multi-repeat perf update with 3 repeats, prebuild once
cargo ost update-run-perf --repeats=3 --prebuild

# Quick pressure sweep with longer duration and more tasks
cargo ost quick-pressure-sweep-tunables --secs=3 --tasks=4

# Parity gate requiring Rust to exceed Go
cargo ost parity-gate --repeats=5 --require-exceed-go
```

## Go Tools CLI (gotools)

The `gotools` command runs Go-side harness and profiling commands.

```bash
cd daemon && go run ./cmd/gotools <command> [flags...]
```

Run `cd daemon && go run ./cmd/gotools --help` for the full reference.

### Commands

| Command | Purpose |
|---|---|
| `go-test-full` | Full Go test suite (modprobe, fixture backup, `go test ./...`) |
| `go-stress-profile` | Stress-profile harness (repeats × connect-latency test) |
| `go-kernel-profile-harness` | Kernel-pipeline harness (repeats × pressure + sweep) |

All commands run under the test guard: services are stopped before the run and restored after; when not root, gotools re-execs itself under `sudo`/`pkexec`. Guard behavior is controlled by the same env vars as the Rust tools:

- `OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0` — skip post-run service restart.
- `OPENSNITCH_TEST_GUARD_PRIV_CMD=direct|sudo|pkexec` — override privilege auto-detection.

### Flags

| Flag | Environment variable | Default |
|---|---|---|
| `--repeats=N` | `OPENSNITCH_PERF_REPEATS` | 3 |
| `--go-log=LEVEL` | `OPENSNITCH_HARNESS_GO_LOG_LEVEL` | `error` |
| `--stress-rounds=N` | `OPENSNITCH_STRESS_ROUNDS` | 500 |
| `--pressure-secs=N` | `OPENSNITCH_KERNEL_PRESSURE_SECS` | 1 |
| `--sweep-secs=N` | `OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS` | 1 |
| `--skip-modprobe` | `OPENSNITCH_GOTOOLS_SKIP_MODPROBE=1` | — |

### Examples

```bash
# Full Go test suite
cd daemon && go run ./cmd/gotools go-test-full

# Stress-profile with more repeats and verbose Go logging
cd daemon && go run ./cmd/gotools go-stress-profile --repeats=5 --go-log=warn

# Kernel-pipeline harness with custom pressure duration
cd daemon && go run ./cmd/gotools go-kernel-profile-harness --repeats=3 --pressure-secs=2
```

## Operational Checklist

- Confirm daemon starts without config parse errors.
- Confirm expected client endpoint with `OPENSNITCH_CLIENT_ADDR`.
- Verify reload behavior using `SIGHUP` before production rollout.
- Keep `RUST_LOG` at `info` (or stricter) for normal operation and increase only for troubleshooting.

## Troubleshooting

- If startup fails early, first validate config file path and JSON format.
- If tunables do not apply, verify `OPENSNITCH_TUNABLES_FILE` exists and is readable.
- If firewall/eBPF behavior is missing, verify required host privileges and kernel capabilities for your deployment.
