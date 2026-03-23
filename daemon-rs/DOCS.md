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

## Optional eBPF Build Helper

To build eBPF artifacts via the project helper:

```bash
./scripts/build_ebpf.sh
```

You can adjust toolchain and target with:

- `DAEMON_RS_EBPF_TOOLCHAIN`
- `DAEMON_RS_EBPF_TARGET`
- `DAEMON_RS_EBPF_PACKAGE`

## Operational Checklist

- Confirm daemon starts without config parse errors.
- Confirm expected client endpoint with `OPENSNITCH_CLIENT_ADDR`.
- Verify reload behavior using `SIGHUP` before production rollout.
- Keep `RUST_LOG` at `info` (or stricter) for normal operation and increase only for troubleshooting.

## Troubleshooting

- If startup fails early, first validate config file path and JSON format.
- If tunables do not apply, verify `OPENSNITCH_TUNABLES_FILE` exists and is readable.
- If firewall/eBPF behavior is missing, verify required host privileges and kernel capabilities for your deployment.
