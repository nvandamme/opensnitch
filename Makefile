all: protocol opensnitch_daemon gui

STRESS_ROUNDS ?= 500
PARITY_STRESS_ROUNDS ?= 500
PERF_REPEATS ?= 3
GO_KERNEL_PRESSURE_SECS ?= 1
GO_KERNEL_PRESSURE_SWEEP_SECS ?= 1
DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS ?= 90
DAEMON_RS_PACKAGE := opensnitchd-rs
DAEMON_RS_EBPF_PACKAGE := opensnitch-ebpf
DAEMON_RS_EBPF_TARGET ?= bpfel-unknown-none
DAEMON_RS_EBPF_TOOLCHAIN ?= nightly
DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS ?= 3
OPENSNITCH_TEST_GUARD_PRIV_CMD ?= sudo
GO_UI_TEST_FIXTURE := daemon/ui/testdata/default-config.json
RUST_TEST_LOG_LEVEL ?= info,opensnitchd_rs=debug
HARNESS_RUST_LOG_LEVEL ?= warn
HARNESS_GO_LOG_LEVEL ?= error
PERF_RUST_LOG_LEVEL ?= warn
PERF_PREBUILD ?= 1
DAEMON_RS_LIVE_RUST_LOG ?= info
GO_PROTO_BOOTSTRAP := ./scripts/bootstrap_go_proto_tools.sh
WORKSPACE_ROOT := $(abspath .)
DAEMON_RS_DIR := $(WORKSPACE_ROOT)/daemon-rs
DAEMON_RS_MANIFEST := $(DAEMON_RS_DIR)/Cargo.toml
DAEMON_RS_KERNEL_TARGET_DIR ?= $(DAEMON_RS_DIR)/target-kernel
DAEMON_RS_CARGO_TARGET_DIR ?= $(DAEMON_RS_KERNEL_TARGET_DIR)
DAEMON_RS_TOOLS_RUN := CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) cargo run --release --manifest-path $(DAEMON_RS_MANIFEST) -p tools --
DAEMON_GOTOOLS_RUN := cd $(WORKSPACE_ROOT)/daemon && go run ./cmd/gotools

# Install layout variables (override for packaging; mirrors daemon/Makefile conventions).
PREFIX        ?= /usr/local
SYSCONFDIR    ?= /etc
BINDIR        ?= bin
# Cargo profile for the installed binary.  Use release-embedded for OpenWrt/constrained targets.
# Short alias: make ... profile=release-embedded  (canonical: CARGO_PROFILE=)
CARGO_PROFILE       ?= $(if $(profile),$(profile),release)
# Target triple for cross-compiled binaries (e.g. aarch64-unknown-linux-musl).
# Short alias: make ... target=aarch64-unknown-linux-musl  (canonical: CARGO_TARGET_TRIPLE=)
# When set, the binary is expected at $(DAEMON_RS_CARGO_TARGET_DIR)/$(CARGO_TARGET_TRIPLE)/$(CARGO_PROFILE)/opensnitchd-rs.
CARGO_TARGET_TRIPLE ?= $(if $(target),$(target),)

# ── Short variable aliases ────────────────────────────────────────────────────
# All canonical names above remain the source of truth and are env-var
# compatible.  These aliases let you use shorter lowercase names on the command
# line without breaking anything that already sets the canonical forms.
#
#   Canonical (env / CI)                  Short alias (interactive)
#   ─────────────────────────────────────────────────────────────────
#   STRESS_ROUNDS=N                        rounds=N
#   PERF_REPEATS=N                         repeats=N
#   PERF_RUST_LOG_LEVEL=LEVEL              rust-log=LEVEL   (note: make uses rust_log=)
#   HARNESS_GO_LOG_LEVEL=LEVEL             go_log=LEVEL
#   DAEMON_RS_LIVE_RUST_LOG=LEVEL          live_log=LEVEL
#   GO_KERNEL_PRESSURE_SECS=N             pressure_secs=N
#   GO_KERNEL_PRESSURE_SWEEP_SECS=N       sweep_secs=N
#   DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS=N   smoke_timeout=N
#   DAEMON_RS_EBPF_TOOLCHAIN=TC           toolchain=TC
#   DAEMON_RS_EBPF_TARGET=TRIPLE          ebpf_target=TRIPLE
#   OPENSNITCH_TEST_GUARD_PRIV_CMD=CMD    priv_cmd=CMD
#   PREFIX=/path                           prefix=/path
#   SYSCONFDIR=/path                       sysconfdir=/path
#   BINDIR=dir                             bindir=dir
#   CARGO_PROFILE=profile                  profile=profile          (already set above)
#   CARGO_TARGET_TRIPLE=triple             target=triple            (already set above)
#
# Make does not allow hyphens in variable names, so rust-log becomes rust_log.
#
ifdef rounds
STRESS_ROUNDS         := $(rounds)
PARITY_STRESS_ROUNDS  := $(rounds)
endif
ifdef repeats
PERF_REPEATS          := $(repeats)
endif
ifdef rust_log
PERF_RUST_LOG_LEVEL   := $(rust_log)
HARNESS_RUST_LOG_LEVEL := $(rust_log)
endif
ifdef go_log
HARNESS_GO_LOG_LEVEL  := $(go_log)
endif
ifdef live_log
DAEMON_RS_LIVE_RUST_LOG := $(live_log)
endif
ifdef pressure_secs
GO_KERNEL_PRESSURE_SECS := $(pressure_secs)
endif
ifdef sweep_secs
GO_KERNEL_PRESSURE_SWEEP_SECS := $(sweep_secs)
endif
ifdef smoke_timeout
DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS := $(smoke_timeout)
endif
ifdef toolchain
DAEMON_RS_EBPF_TOOLCHAIN := $(toolchain)
endif
ifdef ebpf_target
DAEMON_RS_EBPF_TARGET := $(ebpf_target)
endif
ifdef priv_cmd
OPENSNITCH_TEST_GUARD_PRIV_CMD := $(priv_cmd)
endif
ifdef prefix
PREFIX    := $(prefix)
endif
ifdef sysconfdir
SYSCONFDIR := $(sysconfdir)
endif
ifdef bindir
BINDIR    := $(bindir)
endif
# ─────────────────────────────────────────────────────────────────────────────

export OPENSNITCH_TEST_GUARD_PRIV_CMD

# ── Derived env exports ───────────────────────────────────────────────────────
# Bridge Makefile variable names to the OPENSNITCH_* env-var names that cargo
# ost (tools) and go run ./cmd/gotools read.  Exporting once here means recipe
# lines no longer need KEY=$(VAR) prefixes on every target, and short aliases
# (rounds=, repeats=, rust_log=, …) automatically flow through to sub-processes.
export OPENSNITCH_PARITY_STRESS_ROUNDS       = $(PARITY_STRESS_ROUNDS)
export OPENSNITCH_STRESS_ROUNDS              = $(STRESS_ROUNDS)
export OPENSNITCH_PERF_REPEATS               = $(PERF_REPEATS)
export OPENSNITCH_PERF_RUST_LOG_LEVEL        = $(PERF_RUST_LOG_LEVEL)
export OPENSNITCH_PERF_GO_LOG_LEVEL          = $(HARNESS_GO_LOG_LEVEL)
export OPENSNITCH_HARNESS_GO_LOG_LEVEL       = $(HARNESS_GO_LOG_LEVEL)
export OPENSNITCH_PARITY_PREBUILD            = $(PERF_PREBUILD)
export OPENSNITCH_KERNEL_PRESSURE_SECS       = $(GO_KERNEL_PRESSURE_SECS)
export OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS = $(GO_KERNEL_PRESSURE_SWEEP_SECS)
export OPENSNITCH_DAEMON_RS_RUST_LOG         = $(DAEMON_RS_LIVE_RUST_LOG)
# These carry the same name on both sides – just mark them for export.
export RUST_TEST_LOG_LEVEL
export GO_UI_TEST_FIXTURE
export DAEMON_RS_EBPF_PACKAGE
export DAEMON_RS_EBPF_TARGET
export DAEMON_RS_EBPF_TOOLCHAIN
export DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS
export DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: protocol go-protocol go-proto-tools go-test-full go-stress-profile go-kernel-profile-harness rust-parity-tests rust-kernel-it go-rust-parity-full parity-hot-path-harness parity-hot-path-harness-once parity-cold-path-harness parity-hot-cold-delta parity-hot-cold-delta-once daemon-rs-kernel-profile-harness update-run-perf parity-gate quick-pressure-sweep-tunables auto-tune-kernel-pressure-tunables microbench-connect-dispatch daemon-rs-build daemon-rs-live-logs daemon-rs-live-stop daemon-rs-mock-ui-session daemon-rs-async-send-audit daemon-rs-snapshot-clone-audit daemon-rs-design-rule-audit daemon-rs-design-rule-helper-contract-audit daemon-rs-immutable-state-audit daemon-rs-policy-audit daemon-rs-ebpf-build daemon-rs-ebpf-build-runtime daemon-rs-aya-proc-smoke daemon-rs-aya-dns-smoke daemon-rs-aya-conn-smoke daemon-rs-aya-tunnel-smoke daemon-rs-tools daemon-rs-tool-% install install-rs

install:
	@cd daemon && make install
	@cd ui && make install

# Install the Rust daemon binary, config data, and a generated init service unit.
#
# Variables (all overridable for package maintainers):
#   PREFIX        – binary install prefix        (default: /usr/local)
#   DESTDIR       – staging root for pkg builds  (default: empty)
#   SYSCONFDIR    – system config base dir       (default: /etc)
#   BINDIR        – binary sub-directory         (default: bin; OpenWrt uses sbin)
#   CARGO_PROFILE       – Cargo build profile          (default: release; use release-embedded for OpenWrt)
#   CARGO_TARGET_TRIPLE – cross-compile target triple   (default: empty = native; e.g. aarch64-unknown-linux-musl)
#   INIT_SYSTEM         – override init system detection: systemd | openrc | procd | none
#
# Binary lookup path:
#   native:       $(DAEMON_RS_CARGO_TARGET_DIR)/$(CARGO_PROFILE)/opensnitchd-rs
#   cross-compile: $(DAEMON_RS_CARGO_TARGET_DIR)/$(CARGO_TARGET_TRIPLE)/$(CARGO_PROFILE)/opensnitchd-rs
# DAEMON_RS_CARGO_TARGET_DIR defaults to daemon-rs/target-kernel (matches all Makefile builds).
#
# Init system detection order (when INIT_SYSTEM is not set):
#   1. procd    – /etc/openwrt_release or /sbin/procd present  (OpenWrt)
#   2. systemd  – /run/systemd/private present
#   3. openrc   – /run/openrc or openrc-run in PATH
#   4. none     – no unit installed; binary + config only
#
# Templates in daemon-rs/data/init/ use @PREFIX@, @BINDIR@, @SYSCONFDIR@ substituted by sed.
#
# Standard install (binary already built via make daemon-rs-build):
#   make install-rs PREFIX=/usr SYSCONFDIR=/etc DESTDIR=<staging>
#
# OpenWrt cross-compile install:
#   CARGO_TARGET_DIR=daemon-rs/target-kernel \
#     cargo build --profile release-embedded -p opensnitchd-rs \
#       --manifest-path daemon-rs/Cargo.toml --target <arch>-unknown-linux-musl
#   make install-rs PREFIX=/usr BINDIR=sbin CARGO_PROFILE=release-embedded \
#     CARGO_TARGET_TRIPLE=<arch>-unknown-linux-musl INIT_SYSTEM=procd DESTDIR=<staging>
# Resolve binary path: respect DAEMON_RS_CARGO_TARGET_DIR (target-kernel/ by default) and
# an optional cross-compile triple so that `make install-rs` always finds what `make build` built.
_TRIPLE_SEGMENT := $(if $(CARGO_TARGET_TRIPLE),$(CARGO_TARGET_TRIPLE)/,)
DAEMON_RS_INSTALL_BIN := $(DAEMON_RS_CARGO_TARGET_DIR)/$(_TRIPLE_SEGMENT)$(CARGO_PROFILE)/opensnitchd-rs

install-rs:
	@mkdir -p $(DESTDIR)$(PREFIX)/$(BINDIR)
	@mkdir -p $(DESTDIR)$(SYSCONFDIR)/opensnitchd/rules
	@install -Dm755 $(DAEMON_RS_INSTALL_BIN) \
		$(DESTDIR)$(PREFIX)/$(BINDIR)/opensnitchd-rs
	@install -Dm644 daemon/data/default-config.json \
		-t $(DESTDIR)$(SYSCONFDIR)/opensnitchd/
	@install -Dm644 daemon/data/system-fw.json \
		-t $(DESTDIR)$(SYSCONFDIR)/opensnitchd/
	@install -Dm644 daemon/data/network_aliases.json \
		-t $(DESTDIR)$(SYSCONFDIR)/opensnitchd/
	@install -Dm600 daemon/data/rules/* \
		$(DESTDIR)$(SYSCONFDIR)/opensnitchd/rules/
	@_init=$${INIT_SYSTEM:-}; \
	if [ -z "$$_init" ]; then \
		if [ -f /etc/openwrt_release ] || [ -x /sbin/procd ]; then \
			_init=procd; \
		elif [ -d /run/systemd/private ] || command -v systemd-detect-virt >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then \
			_init=systemd; \
		elif [ -d /run/openrc ] || command -v openrc-run >/dev/null 2>&1; then \
			_init=openrc; \
		else \
			_init=none; \
		fi; \
	fi; \
	echo "install-rs: init system = $$_init"; \
	case "$$_init" in \
	systemd) \
		mkdir -p $(DESTDIR)/etc/systemd/system; \
		sed \
			-e 's|@PREFIX@|$(PREFIX)|g' \
			-e 's|@SYSCONFDIR@|$(SYSCONFDIR)|g' \
			daemon-rs/data/init/opensnitchd-rs.service.in \
			> $(DESTDIR)/etc/systemd/system/opensnitchd-rs.service; \
		chmod 644 $(DESTDIR)/etc/systemd/system/opensnitchd-rs.service; \
		echo "  installed: /etc/systemd/system/opensnitchd-rs.service"; \
		if [ -z "$(DESTDIR)" ]; then systemctl daemon-reload 2>/dev/null || true; fi; \
		echo "  enable with: systemctl enable --now opensnitchd-rs"; \
		;; \
	openrc) \
		mkdir -p $(DESTDIR)/etc/init.d; \
		sed \
			-e 's|@PREFIX@|$(PREFIX)|g' \
			-e 's|@SYSCONFDIR@|$(SYSCONFDIR)|g' \
			daemon-rs/data/init/opensnitchd-rs.openrc.in \
			> $(DESTDIR)/etc/init.d/opensnitchd-rs; \
		chmod 755 $(DESTDIR)/etc/init.d/opensnitchd-rs; \
		echo "  installed: /etc/init.d/opensnitchd-rs"; \
		echo "  enable with: rc-update add opensnitchd-rs default"; \
		;; \
	procd) \
		mkdir -p $(DESTDIR)/etc/init.d; \
		sed \
			-e 's|@PREFIX@|$(PREFIX)|g' \
			-e 's|@BINDIR@|$(BINDIR)|g' \
			-e 's|@SYSCONFDIR@|$(SYSCONFDIR)|g' \
			daemon-rs/data/init/opensnitchd-rs.procd.in \
			> $(DESTDIR)/etc/init.d/opensnitchd-rs; \
		chmod 755 $(DESTDIR)/etc/init.d/opensnitchd-rs; \
		echo "  installed: /etc/init.d/opensnitchd-rs (procd)"; \
		echo "  enable with: /etc/init.d/opensnitchd-rs enable && /etc/init.d/opensnitchd-rs start"; \
		;; \
	none) \
		echo "  no init system detected; skipping service unit install"; \
		echo "  binary installed at $(DESTDIR)$(PREFIX)/$(BINDIR)/opensnitchd-rs"; \
		;; \
	*) \
		echo "  unknown INIT_SYSTEM value '$$_init'; skipping service unit install"; \
		;; \
	esac

protocol:
	@cd proto && make

go-proto-tools:
	@$(GO_PROTO_BOOTSTRAP)

go-protocol: go-proto-tools
	@PATH="$(shell go env GOPATH)/bin:$$PATH" cd proto && make

opensnitch_daemon: go-protocol
	@cd daemon && make

gui:
	@cd ui && make

clean:
	@cd daemon && make clean
	@cd proto && make clean
	@cd ui && make clean

run:
	cd ui && pip3 install --upgrade . && cd ..
	opensnitch-ui --socket unix:///tmp/osui.sock &
	./daemon/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket unix:///tmp/osui.sock -cpu-profile cpu.profile -mem-profile mem.profile

test:
	clear
	make clean
	clear
	mkdir -p rules
	make
	clear
	make run

adblocker:
	clear
	make clean
	clear
	make
	clear
	python make_ads_rules.py
	clear
	cd ui && pip3 install --upgrade . && cd ..
	opensnitch-ui --socket unix:///tmp/osui.sock &
	./daemon/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket unix:///tmp/osui.sock

daemon-rs-build:
	@OPENSNITCH_BUILD_PROFILE=$(CARGO_PROFILE) OPENSNITCH_BUILD_TARGET=$(CARGO_TARGET_TRIPLE) \
	  $(DAEMON_RS_TOOLS_RUN) build

daemon-rs-ebpf-build:
	@OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0 $(DAEMON_RS_TOOLS_RUN) build-ebpf

daemon-rs-ebpf-build-runtime:
	@$(MAKE) daemon-rs-ebpf-build

daemon-rs-aya-proc-smoke: daemon-rs-build daemon-rs-ebpf-build
	@$(DAEMON_RS_TOOLS_RUN) aya-smoke-proc

daemon-rs-aya-dns-smoke: daemon-rs-build daemon-rs-ebpf-build
	@$(DAEMON_RS_TOOLS_RUN) aya-smoke-dns

daemon-rs-aya-conn-smoke: daemon-rs-build daemon-rs-ebpf-build
	@$(DAEMON_RS_TOOLS_RUN) aya-smoke-conn

daemon-rs-aya-tunnel-smoke: daemon-rs-build daemon-rs-ebpf-build
	@$(DAEMON_RS_TOOLS_RUN) aya-smoke-tunnel

daemon-rs-kernel-profile-harness:
	@$(DAEMON_RS_TOOLS_RUN) kernel-profile-harness --repeats=$(PERF_REPEATS) --rust-log=$(PERF_RUST_LOG_LEVEL)

go-test-full: go-protocol
	@sh -c '$(DAEMON_GOTOOLS_RUN) go-test-full'

go-stress-profile: go-protocol
	@sh -c '$(DAEMON_GOTOOLS_RUN) go-stress-profile'

go-kernel-profile-harness: go-protocol
	@sh -c '$(DAEMON_GOTOOLS_RUN) go-kernel-profile-harness'

parity-hot-path-harness: go-protocol
	@$(DAEMON_RS_TOOLS_RUN) parity-hot-path-harness

parity-hot-path-harness-once: go-protocol
	@$(DAEMON_RS_TOOLS_RUN) parity-hot-path-harness-once

parity-cold-path-harness: go-protocol
	@$(DAEMON_RS_TOOLS_RUN) parity-cold-path-harness

# parity-hot-cold-delta: multi-pass hot+cold delta (PERF_REPEATS passes, median by hot p95).
# For the PERF.md update workflow use: make update-run-perf
parity-hot-cold-delta: go-protocol
	@$(DAEMON_RS_TOOLS_RUN) parity-hot-cold-delta

parity-hot-cold-delta-once: go-protocol
	@$(DAEMON_RS_TOOLS_RUN) parity-hot-cold-delta-once

rust-parity-tests:
	@$(DAEMON_RS_TOOLS_RUN) test --test-log=$(RUST_TEST_LOG_LEVEL)

rust-kernel-it:
	@$(DAEMON_RS_TOOLS_RUN) test-kernel-it --test-log=$(RUST_TEST_LOG_LEVEL)

go-rust-parity-full:
	@$(MAKE) go-test-full
	@$(MAKE) rust-parity-tests
	@$(MAKE) rust-kernel-it
	@echo "PARITY STATUS: Go full suite + Rust parity tests + Rust strict kernel IT = PASS"

update-run-perf:
	@$(DAEMON_RS_TOOLS_RUN) update-run-perf

parity-gate:
	@$(DAEMON_RS_TOOLS_RUN) parity-gate

quick-pressure-sweep-tunables:
	@$(DAEMON_RS_TOOLS_RUN) quick-pressure-sweep-tunables

auto-tune-kernel-pressure-tunables:
	@$(DAEMON_RS_TOOLS_RUN) auto-tune-kernel-pressure-tunables

microbench-connect-dispatch:
	@$(DAEMON_RS_TOOLS_RUN) microbench-connect-dispatch

daemon-rs-live-logs: daemon-rs-build daemon-rs-ebpf-build-runtime
	@OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0 OPENSNITCH_EBPF_PIN_DOMAIN=aya $(DAEMON_RS_TOOLS_RUN) launch-daemon-live-logs

daemon-rs-live-stop:
	@$(DAEMON_RS_TOOLS_RUN) stop-daemon-live-logs

daemon-rs-mock-ui-session: daemon-rs-build daemon-rs-ebpf-build-runtime
	@OPENSNITCH_EBPF_PIN_DOMAIN=aya $(DAEMON_RS_TOOLS_RUN) run-daemon-mock-ui-live-session

daemon-rs-tool-launch-daemon-live-logs: daemon-rs-ebpf-build-runtime
	@OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0 OPENSNITCH_EBPF_PIN_DOMAIN=aya $(DAEMON_RS_TOOLS_RUN) launch-daemon-live-logs

daemon-rs-tool-stop-daemon-live-logs:
	@$(DAEMON_RS_TOOLS_RUN) stop-daemon-live-logs

daemon-rs-tools:
	@if [ -z "$(TOOL_CMD)" ]; then \
		echo "usage: make daemon-rs-tools TOOL_CMD='<tools-command-and-args>'"; \
		exit 2; \
	fi
	@$(DAEMON_RS_TOOLS_RUN) $(TOOL_CMD)

daemon-rs-tool-%:
	@$(DAEMON_RS_TOOLS_RUN) $*

daemon-rs-async-send-audit:
	@daemon-rs/scripts/check_async_send_policy.sh

daemon-rs-snapshot-clone-audit:
	@daemon-rs/scripts/check_snapshot_clone_policy.sh

daemon-rs-design-rule-audit:
	@daemon-rs/scripts/check_design_rules_policy.sh

daemon-rs-design-rule-helper-contract-audit:
	@daemon-rs/scripts/check_design_rule_helpers_and_contracts.sh

daemon-rs-immutable-state-audit:
	@daemon-rs/scripts/check_immutable_state_access_policy.sh

daemon-rs-policy-audit: daemon-rs-async-send-audit daemon-rs-snapshot-clone-audit daemon-rs-design-rule-audit daemon-rs-design-rule-helper-contract-audit daemon-rs-immutable-state-audit
	@echo "daemon-rs policy audit: pass"
