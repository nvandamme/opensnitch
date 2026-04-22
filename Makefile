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
TEST_GUARD := daemon-rs/scripts/with_test_guard.sh
GO_UI_TEST_FIXTURE := daemon/ui/testdata/default-config.json
RUST_TEST_LOG_LEVEL ?= info,opensnitchd_rs=debug
HARNESS_RUST_LOG_LEVEL ?= warn
HARNESS_GO_LOG_LEVEL ?= warn
PERF_RUST_LOG_LEVEL ?= warn
PERF_PREBUILD ?= 1
DAEMON_RS_LIVE_RUST_LOG ?= info
GO_PROTO_BOOTSTRAP := ./scripts/bootstrap_go_proto_tools.sh
WORKSPACE_ROOT := $(abspath .)
DAEMON_RS_DIR := $(WORKSPACE_ROOT)/daemon-rs
DAEMON_RS_MANIFEST := $(DAEMON_RS_DIR)/Cargo.toml
DAEMON_RS_KERNEL_TARGET_DIR ?= $(DAEMON_RS_DIR)/target-kernel
DAEMON_RS_CARGO_TARGET_DIR ?= $(DAEMON_RS_KERNEL_TARGET_DIR)
DAEMON_RS_RUNTIME_TARGET_DIR ?= $(DAEMON_RS_DIR)/target
DAEMON_RS_TOOLS_RUN := CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) cargo run --release --manifest-path $(DAEMON_RS_MANIFEST) -p tools --

export OPENSNITCH_TEST_GUARD_PRIV_CMD

.PHONY: protocol go-protocol go-proto-tools go-test-full go-stress-profile go-kernel-profile-harness rust-parity-tests rust-kernel-it go-rust-parity-full parity-hot-path-harness parity-hot-path-harness-once parity-cold-path-harness parity-hot-cold-matrix parity-hot-cold-delta parity-hot-cold-delta-once daemon-rs-kernel-profile-harness update-run-perf parity-gate quick-pressure-sweep-tunables auto-tune-kernel-pressure-tunables microbench-connect-dispatch daemon-rs-live-logs daemon-rs-live-stop daemon-rs-async-send-audit daemon-rs-snapshot-clone-audit daemon-rs-design-rule-audit daemon-rs-design-rule-helper-contract-audit daemon-rs-immutable-state-audit daemon-rs-policy-audit daemon-rs-ebpf-build daemon-rs-ebpf-build-runtime daemon-rs-aya-proc-smoke daemon-rs-aya-dns-smoke daemon-rs-aya-conn-smoke daemon-rs-aya-tunnel-smoke daemon-rs-tools daemon-rs-tool-%

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
	@CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) cargo build --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE)

daemon-rs-ebpf-build:
	@CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) DAEMON_RS_EBPF_PACKAGE=$(DAEMON_RS_EBPF_PACKAGE) DAEMON_RS_EBPF_TARGET=$(DAEMON_RS_EBPF_TARGET) DAEMON_RS_EBPF_TOOLCHAIN=$(DAEMON_RS_EBPF_TOOLCHAIN) daemon-rs/scripts/build_ebpf.sh --release

daemon-rs-ebpf-build-runtime:
	@CARGO_TARGET_DIR=$(DAEMON_RS_RUNTIME_TARGET_DIR) DAEMON_RS_EBPF_PACKAGE=$(DAEMON_RS_EBPF_PACKAGE) DAEMON_RS_EBPF_TARGET=$(DAEMON_RS_EBPF_TARGET) DAEMON_RS_EBPF_TOOLCHAIN=$(DAEMON_RS_EBPF_TOOLCHAIN) daemon-rs/scripts/build_ebpf.sh --release

daemon-rs-aya-proc-smoke: daemon-rs-build daemon-rs-ebpf-build
	@bash -lc 'set -u; status=0; \
	env OPENSNITCH_RUN_PRIVILEGED_TESTS=1 OPENSNITCH_CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) $(TEST_GUARD) bash -lc '\''cd $(DAEMON_RS_DIR) && timeout --signal=TERM --kill-after=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS)s $(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS)s cargo test -p opensnitchd-rs aya_proc_trace_smoke_reports_explicit_runtime_active -- --ignored --nocapture'\'' || status=$$?; \
	log=$$(ls -1t /tmp/opensnitch-aya-proc-trace-test-*.log 2>/dev/null | head -n1 || true); \
	if [ -n "$$log" ] && grep -q "Verifier output:" "$$log"; then \
		echo "=== Extracted verifier output from $$log ==="; \
		awk '\''/Verifier output:/ { print; in_block=1; next } in_block { if ($$0 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2} /) { in_block=0; next } print }'\'' "$$log"; \
	elif [ -n "$$log" ]; then \
		echo "no verifier stack trace found in $$log"; \
	else \
		echo "no process smoke log found under /tmp/opensnitch-aya-proc-trace-test-*.log"; \
	fi; \
	if [ "$$status" -eq 143 ] || [ "$$status" -eq 124 ] || [ "$$status" -eq 137 ]; then \
		echo "aya process smoke timed out after $(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS)s"; \
		$(TEST_GUARD) bash -lc '\''pkill -KILL -x opensnitchd-rs >/dev/null 2>&1 || true'\'' || true; \
		status=124; \
	fi; \
	exit $$status'

daemon-rs-aya-dns-smoke: daemon-rs-build daemon-rs-ebpf-build
	@bash -lc 'set -u; status=0; log=/tmp/opensnitch-aya-dns-trace-test.log; \
	env OPENSNITCH_RUN_PRIVILEGED_TESTS=1 OPENSNITCH_CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) $(TEST_GUARD) bash -lc '\''cd $(DAEMON_RS_DIR) && timeout --signal=TERM --kill-after=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS)s $(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS)s cargo test -p opensnitchd-rs aya_dns_trace_smoke_reports_explicit_runtime_active -- --ignored --nocapture'\'' || status=$$?; \
	if [ -f "$$log" ] && grep -q "Verifier output:" "$$log"; then \
		echo "=== Extracted verifier output from $$log ==="; \
		awk '\''/Verifier output:/ { print; in_block=1; next } in_block { if ($$0 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2} /) { in_block=0; next } print }'\'' "$$log"; \
	elif [ -f "$$log" ]; then \
		echo "no verifier stack trace found in $$log"; \
	else \
		echo "missing $$log"; \
	fi; \
	if [ "$$status" -eq 143 ] || [ "$$status" -eq 124 ] || [ "$$status" -eq 137 ]; then \
		echo "aya dns smoke timed out after $(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS)s"; \
		$(TEST_GUARD) bash -lc '\''pkill -KILL -x opensnitchd-rs >/dev/null 2>&1 || true'\'' || true; \
		status=124; \
	fi; \
	exit $$status'

daemon-rs-aya-conn-smoke: daemon-rs-build daemon-rs-ebpf-build
	@bash -lc 'set -u; status=0; \
	env OPENSNITCH_RUN_PRIVILEGED_TESTS=1 OPENSNITCH_CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) $(TEST_GUARD) bash -lc '\''cd $(DAEMON_RS_DIR) && timeout --signal=TERM --kill-after=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS)s $(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS)s cargo test -p opensnitchd-rs aya_conn_trace_smoke_reports_explicit_runtime_active -- --ignored --nocapture'\'' || status=$$?; \
	log=$$(ls -1t /tmp/opensnitch-aya-conn-trace-test-*.log 2>/dev/null | head -n1 || true); \
	if [ -n "$$log" ] && grep -q "Verifier output:" "$$log"; then \
		echo "=== Extracted verifier output from $$log ==="; \
		awk '\''/Verifier output:/ { print; in_block=1; next } in_block { if ($$0 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2} /) { in_block=0; next } print }'\'' "$$log"; \
	elif [ -n "$$log" ]; then \
		echo "no verifier stack trace found in $$log"; \
	else \
		echo "no connection smoke log found under /tmp/opensnitch-aya-conn-trace-test-*.log"; \
	fi; \
	if [ "$$status" -eq 143 ] || [ "$$status" -eq 124 ] || [ "$$status" -eq 137 ]; then \
		echo "aya connection smoke timed out after $(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS)s"; \
		$(TEST_GUARD) bash -lc '\''pkill -KILL -x opensnitchd-rs >/dev/null 2>&1 || true'\'' || true; \
		status=124; \
	fi; \
	exit $$status'

daemon-rs-aya-tunnel-smoke: daemon-rs-build daemon-rs-ebpf-build
	@bash -lc 'set -u; status=0; \
	env OPENSNITCH_RUN_PRIVILEGED_TESTS=1 OPENSNITCH_CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) CARGO_TARGET_DIR=$(DAEMON_RS_KERNEL_TARGET_DIR) $(TEST_GUARD) bash -lc '\''cd $(DAEMON_RS_DIR) && timeout --signal=TERM --kill-after=$(DAEMON_RS_EBPF_SMOKE_TIMEOUT_KILL_AFTER_SECS)s $(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS)s cargo test -p opensnitchd-rs aya_tunnel_trace_smoke_reports_tunnel_probe_activity -- --ignored --nocapture'\'' || status=$$?; \
	log=$$(ls -1t /tmp/opensnitch-aya-tunnel-trace-test-*.log 2>/dev/null | head -n1 || true); \
	if [ -n "$$log" ] && grep -q "Verifier output:" "$$log"; then \
		echo "=== Extracted verifier output from $$log ==="; \
		awk '\''/Verifier output:/ { print; in_block=1; next } in_block { if ($$0 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2} /) { in_block=0; next } print }'\'' "$$log"; \
	elif [ -n "$$log" ]; then \
		echo "no verifier stack trace found in $$log"; \
	else \
		echo "no tunnel smoke log found under /tmp/opensnitch-aya-tunnel-trace-test-*.log"; \
	fi; \
	if [ "$$status" -eq 143 ] || [ "$$status" -eq 124 ] || [ "$$status" -eq 137 ]; then \
		echo "aya tunnel smoke timed out after $(DAEMON_RS_EBPF_SMOKE_TIMEOUT_SECS)s"; \
		$(TEST_GUARD) bash -lc '\''pkill -KILL -x opensnitchd-rs >/dev/null 2>&1 || true'\'' || true; \
		status=124; \
	fi; \
	exit $$status'

daemon-rs-profile-test:
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "daemon-rs-profile-test run $$i/$(PERF_REPEATS)"; \
		$(TEST_GUARD) env CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) RUST_LOG=$(HARNESS_RUST_LOG_LEVEL) OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_connect_latency_and_pipeline_drops -- --ignored --nocapture; \
	done

daemon-rs-kernel-profile-harness:
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "daemon-rs-kernel-profile-harness pressure run $$i/$(PERF_REPEATS)"; \
		$(TEST_GUARD) env CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) RUST_LOG=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1 cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_kernel_pipeline_pressure -- --ignored --nocapture; \
	done
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "daemon-rs-kernel-profile-harness sweep run $$i/$(PERF_REPEATS)"; \
		$(TEST_GUARD) env CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) RUST_LOG=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1 cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_kernel_pipeline_timeout_sweep -- --ignored --nocapture; \
	done

profile-backends: daemon-rs-build daemon-rs-profile-test go-protocol
	@echo "Running Rust (release) and Go stress profiles with STRESS_ROUNDS=$(STRESS_ROUNDS)"
	@$(MAKE) go-stress-profile STRESS_ROUNDS=$(STRESS_ROUNDS) PERF_REPEATS=$(PERF_REPEATS)
	@$(MAKE) go-kernel-profile-harness PERF_REPEATS=$(PERF_REPEATS) GO_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) GO_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS)

go-test-full: go-protocol
	@set -e; \
	fixture_backup=$$(mktemp); \
	cp -f $(GO_UI_TEST_FIXTURE) "$$fixture_backup"; \
	trap 'cp -f "$$fixture_backup" $(GO_UI_TEST_FIXTURE) >/dev/null 2>&1 || true; rm -f "$$fixture_backup"' EXIT; \
	OPENSNITCH_RUN_PRIVILEGED_TESTS=1 $(TEST_GUARD) sh -c 'for m in nf_conntrack nfnetlink_queue xt_conntrack xt_mark xt_NFQUEUE; do modprobe "$$m" >/dev/null 2>&1 || { echo "missing kernel module '\''$$m'\'' for kernel $$(uname -r)."; echo "If you recently upgraded kernel/modules, reboot and rerun: sudo make go-test-full"; exit 1; }; done; cd $(WORKSPACE_ROOT)/daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=error go test ./... -count=1' || { \
		echo "go-test-full failed."; \
		echo "If netfilter tests report missing conntrack/NFQUEUE extensions, reboot into the updated kernel and rerun: sudo make go-test-full"; \
		exit 1; \
	}

go-stress-profile: go-protocol
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "go-stress-profile run $$i/$(PERF_REPEATS)"; \
		$(TEST_GUARD) env OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) sh -c 'cd daemon && go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v'; \
	done

go-kernel-profile-harness: go-protocol
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "go-kernel-profile-harness pressure run $$i/$(PERF_REPEATS)"; \
		$(TEST_GUARD) env OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) sh -c 'cd daemon && go test ./runtimeprofile -run TestStressProfileReportsKernelPipelinePressure -count=1 -v'; \
	done
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "go-kernel-profile-harness sweep run $$i/$(PERF_REPEATS)"; \
		$(TEST_GUARD) env OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS) sh -c 'cd daemon && go test ./runtimeprofile -run TestStressProfileReportsKernelPipelineTimeoutSweep -count=1 -v'; \
	done

parity-hot-path-harness: go-protocol
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "parity-hot-path-harness run $$i/$(PERF_REPEATS)"; \
		if [ "$$i" -eq 1 ]; then prebuild=1; else prebuild=0; fi; \
		$(MAKE) parity-hot-path-harness-once STRESS_ROUNDS=$(STRESS_ROUNDS) PERF_REPEATS=1 PERF_PREBUILD=$$prebuild; \
	done

parity-hot-path-harness-once: go-protocol
	@$(TEST_GUARD) env OPENSNITCH_RUN_PRIVILEGED_TESTS=1 OPENSNITCH_PARITY_STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) GO_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) GO_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS) $(DAEMON_RS_TOOLS_RUN) parity-hot-path-harness-once

parity-cold-path-harness: go-protocol
	@$(TEST_GUARD) env OPENSNITCH_RUN_PRIVILEGED_TESTS=1 OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) $(DAEMON_RS_TOOLS_RUN) parity-cold-path-harness

parity-hot-cold-matrix: parity-hot-path-harness parity-cold-path-harness
	@echo "PARITY MATRIX STATUS: hot-path + cold-path = PASS"

parity-hot-cold-delta: go-protocol
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "parity-hot-cold-delta run $$i/$(PERF_REPEATS)"; \
		if [ "$$i" -eq 1 ]; then prebuild=1; else prebuild=0; fi; \
		$(MAKE) parity-hot-cold-delta-once STRESS_ROUNDS=$(STRESS_ROUNDS) PERF_REPEATS=1 PERF_PREBUILD=$$prebuild; \
	done

parity-hot-cold-delta-once: go-protocol
	@$(TEST_GUARD) env OPENSNITCH_RUN_PRIVILEGED_TESTS=1 OPENSNITCH_PARITY_STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) GO_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) GO_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS) $(DAEMON_RS_TOOLS_RUN) parity-hot-cold-delta-once

rust-parity-tests:
	@$(TEST_GUARD) env CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) RUST_LOG=$(RUST_TEST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) tests::config_service:: -- --nocapture
	@$(TEST_GUARD) env CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) RUST_LOG=$(RUST_TEST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) tests::firewall_service:: -- --nocapture
	@$(TEST_GUARD) env CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) RUST_LOG=$(RUST_TEST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) tests::client:: -- --nocapture

rust-kernel-it:
	@$(TEST_GUARD) env CARGO_TARGET_DIR=$(DAEMON_RS_CARGO_TARGET_DIR) RUST_LOG=$(RUST_TEST_LOG_LEVEL) OPENSNITCH_RUN_PRIVILEGED_TESTS=1 OPENSNITCH_KERNEL_IT_STRICT=1 cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) integration_kernel_tests:: -- --nocapture

go-rust-parity-full:
	@$(MAKE) go-test-full
	@$(MAKE) rust-parity-tests
	@$(MAKE) rust-kernel-it
	@echo "PARITY STATUS: Go full suite + Rust parity tests + Rust strict kernel IT = PASS"

update-run-perf:
	@$(TEST_GUARD) env OPENSNITCH_RUN_PRIVILEGED_TESTS=1 STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_REPEATS=$(PERF_REPEATS) OPENSNITCH_PARITY_STRESS_ROUNDS=$(PARITY_STRESS_ROUNDS) $(DAEMON_RS_TOOLS_RUN) update-run-perf

parity-gate:
	@$(TEST_GUARD) env OPENSNITCH_RUN_PRIVILEGED_TESTS=1 OPENSNITCH_PERF_REPEATS=$(PERF_REPEATS) OPENSNITCH_PARITY_STRESS_ROUNDS=$(PARITY_STRESS_ROUNDS) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) $(DAEMON_RS_TOOLS_RUN) parity-gate

quick-pressure-sweep-tunables:
	@$(DAEMON_RS_TOOLS_RUN) quick-pressure-sweep-tunables

auto-tune-kernel-pressure-tunables:
	@$(DAEMON_RS_TOOLS_RUN) auto-tune-kernel-pressure-tunables

microbench-connect-dispatch:
	@OPENSNITCH_PERF_REPEATS=$(PERF_REPEATS) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) $(DAEMON_RS_TOOLS_RUN) microbench-connect-dispatch

daemon-rs-live-logs: daemon-rs-ebpf-build-runtime
	@OPENSNITCH_DAEMON_RS_RUST_LOG=$(DAEMON_RS_LIVE_RUST_LOG) OPENSNITCH_EBPF_PIN_DOMAIN=aya $(DAEMON_RS_TOOLS_RUN) launch-daemon-live-logs

daemon-rs-live-stop:
	@$(DAEMON_RS_TOOLS_RUN) stop-daemon-live-logs

daemon-rs-tool-launch-daemon-live-logs: daemon-rs-ebpf-build-runtime
	@OPENSNITCH_DAEMON_RS_RUST_LOG=$(DAEMON_RS_LIVE_RUST_LOG) OPENSNITCH_EBPF_PIN_DOMAIN=aya $(DAEMON_RS_TOOLS_RUN) launch-daemon-live-logs

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
