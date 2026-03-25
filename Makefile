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

export OPENSNITCH_TEST_GUARD_PRIV_CMD

.PHONY: protocol go-protocol go-proto-tools go-test-full go-stress-profile go-kernel-profile-harness rust-parity-tests rust-kernel-it go-rust-parity-full parity-hot-path-harness parity-hot-path-harness-once parity-cold-path-harness parity-hot-cold-delta parity-hot-cold-delta-once daemon-rs-kernel-profile-harness update-run-perf parity-gate quick-pressure-sweep-tunables auto-tune-kernel-pressure-tunables microbench-connect-dispatch daemon-rs-build daemon-rs-live-logs daemon-rs-live-stop daemon-rs-mock-ui-session daemon-rs-async-send-audit daemon-rs-snapshot-clone-audit daemon-rs-design-rule-audit daemon-rs-design-rule-helper-contract-audit daemon-rs-immutable-state-audit daemon-rs-policy-audit daemon-rs-ebpf-build daemon-rs-ebpf-build-runtime daemon-rs-aya-proc-smoke daemon-rs-aya-dns-smoke daemon-rs-aya-conn-smoke daemon-rs-aya-tunnel-smoke daemon-rs-tools daemon-rs-tool-%

install:
	@cd daemon && make install
	@cd ui && make install

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
	@$(DAEMON_RS_TOOLS_RUN) build

daemon-rs-ebpf-build:
	@OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0 CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) DAEMON_RS_EBPF_PACKAGE=$(DAEMON_RS_EBPF_PACKAGE) DAEMON_RS_EBPF_TARGET=$(DAEMON_RS_EBPF_TARGET) DAEMON_RS_EBPF_TOOLCHAIN=$(DAEMON_RS_EBPF_TOOLCHAIN) $(DAEMON_RS_TOOLS_RUN) build-ebpf

daemon-rs-ebpf-build-runtime:
	@$(MAKE) daemon-rs-ebpf-build

daemon-rs-aya-proc-smoke: daemon-rs-build daemon-rs-ebpf-build
	@OPENSNITCH_CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS) DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS) $(DAEMON_RS_TOOLS_RUN) aya-smoke-proc

daemon-rs-aya-dns-smoke: daemon-rs-build daemon-rs-ebpf-build
	@OPENSNITCH_CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS) DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS) $(DAEMON_RS_TOOLS_RUN) aya-smoke-dns

daemon-rs-aya-conn-smoke: daemon-rs-build daemon-rs-ebpf-build
	@OPENSNITCH_CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS) DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS) $(DAEMON_RS_TOOLS_RUN) aya-smoke-conn

daemon-rs-aya-tunnel-smoke: daemon-rs-build daemon-rs-ebpf-build
	@OPENSNITCH_CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS) DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS) $(DAEMON_RS_TOOLS_RUN) aya-smoke-tunnel

daemon-rs-kernel-profile-harness:
	@CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) $(DAEMON_RS_TOOLS_RUN) kernel-profile-harness --repeats=$(PERF_REPEATS) --rust-log=$(PERF_RUST_LOG_LEVEL)

go-test-full: go-protocol
	@OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) GO_UI_TEST_FIXTURE=$(GO_UI_TEST_FIXTURE) sh -c '$(DAEMON_GOTOOLS_RUN) go-test-full'

go-stress-profile: go-protocol
	@OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_REPEATS=$(PERF_REPEATS) sh -c '$(DAEMON_GOTOOLS_RUN) go-stress-profile'

go-kernel-profile-harness: go-protocol
	@OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS) OPENSNITCH_PERF_REPEATS=$(PERF_REPEATS) sh -c '$(DAEMON_GOTOOLS_RUN) go-kernel-profile-harness'

parity-hot-path-harness: go-protocol
	@OPENSNITCH_PARITY_STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) OPENSNITCH_PERF_REPEATS=$(PERF_REPEATS) GO_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) GO_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS) $(DAEMON_RS_TOOLS_RUN) parity-hot-path-harness

parity-hot-path-harness-once: go-protocol
	@OPENSNITCH_PARITY_STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) GO_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) GO_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS) $(DAEMON_RS_TOOLS_RUN) parity-hot-path-harness-once

parity-cold-path-harness: go-protocol
	@OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) $(DAEMON_RS_TOOLS_RUN) parity-cold-path-harness

# parity-hot-cold-delta: multi-pass hot+cold delta (PERF_REPEATS passes, median by hot p95).
# For the PERF.md update workflow use: make update-run-perf
parity-hot-cold-delta: go-protocol
	@OPENSNITCH_PARITY_STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) OPENSNITCH_PERF_REPEATS=$(PERF_REPEATS) GO_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) GO_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS) $(DAEMON_RS_TOOLS_RUN) parity-hot-cold-delta

parity-hot-cold-delta-once: go-protocol
	@OPENSNITCH_PARITY_STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) GO_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) GO_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS) $(DAEMON_RS_TOOLS_RUN) parity-hot-cold-delta-once

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
	@STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_REPEATS=$(PERF_REPEATS) OPENSNITCH_PARITY_STRESS_ROUNDS=$(PARITY_STRESS_ROUNDS) $(DAEMON_RS_TOOLS_RUN) update-run-perf

parity-gate:
	@OPENSNITCH_PERF_REPEATS=$(PERF_REPEATS) OPENSNITCH_PARITY_STRESS_ROUNDS=$(PARITY_STRESS_ROUNDS) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) $(DAEMON_RS_TOOLS_RUN) parity-gate

quick-pressure-sweep-tunables:
	@$(DAEMON_RS_TOOLS_RUN) quick-pressure-sweep-tunables

auto-tune-kernel-pressure-tunables:
	@$(DAEMON_RS_TOOLS_RUN) auto-tune-kernel-pressure-tunables

microbench-connect-dispatch:
	@OPENSNITCH_PERF_REPEATS=$(PERF_REPEATS) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) $(DAEMON_RS_TOOLS_RUN) microbench-connect-dispatch

daemon-rs-live-logs: daemon-rs-build daemon-rs-ebpf-build-runtime
	@OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0 OPENSNITCH_DAEMON_RS_RUST_LOG=$(DAEMON_RS_LIVE_RUST_LOG) OPENSNITCH_EBPF_PIN_DOMAIN=aya $(DAEMON_RS_TOOLS_RUN) launch-daemon-live-logs

daemon-rs-live-stop:
	@$(DAEMON_RS_TOOLS_RUN) stop-daemon-live-logs

daemon-rs-mock-ui-session: daemon-rs-build daemon-rs-ebpf-build-runtime
	@OPENSNITCH_DAEMON_RS_RUST_LOG=$(DAEMON_RS_LIVE_RUST_LOG) OPENSNITCH_EBPF_PIN_DOMAIN=aya $(DAEMON_RS_TOOLS_RUN) run-daemon-mock-ui-live-session

daemon-rs-tool-launch-daemon-live-logs: daemon-rs-ebpf-build-runtime
	@OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0 OPENSNITCH_DAEMON_RS_RUST_LOG=$(DAEMON_RS_LIVE_RUST_LOG) OPENSNITCH_EBPF_PIN_DOMAIN=aya $(DAEMON_RS_TOOLS_RUN) launch-daemon-live-logs

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
