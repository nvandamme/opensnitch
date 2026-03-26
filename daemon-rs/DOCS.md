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
