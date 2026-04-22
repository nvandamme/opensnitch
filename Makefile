all: protocol opensnitch_daemon gui

STRESS_ROUNDS ?= 1000
PARITY_STRESS_ROUNDS ?= 1000
PERF_REPEATS ?= 5
GO_KERNEL_PRESSURE_SECS ?= 3
GO_KERNEL_PRESSURE_SWEEP_SECS ?= 2
DAEMON_RS_MANIFEST := daemon-rs/Cargo.toml
DAEMON_RS_PACKAGE := opensnitchd-rs
DAEMON_RS_TOOLS_RUN := cargo run --release --manifest-path $(DAEMON_RS_MANIFEST) -p tools --
TEST_GUARD := daemon-rs/scripts/with_test_guard.sh
GO_UI_TEST_FIXTURE := daemon/ui/testdata/default-config.json
RUST_TEST_LOG_LEVEL ?= info,opensnitchd_rs=debug
HARNESS_RUST_LOG_LEVEL ?= error
HARNESS_GO_LOG_LEVEL ?= error
PERF_RUST_LOG_LEVEL ?= error
PERF_PREBUILD ?= 1
DAEMON_RS_LIVE_RUST_LOG ?= info
GO_PROTO_BOOTSTRAP := ./scripts/bootstrap_go_proto_tools.sh

.PHONY: protocol go-protocol go-proto-tools go-test-full go-stress-profile go-kernel-profile-harness rust-parity-tests rust-kernel-it go-rust-parity-full parity-hot-path-harness parity-hot-path-harness-once parity-cold-path-harness parity-hot-cold-matrix parity-hot-cold-delta parity-hot-cold-delta-once daemon-rs-kernel-profile-harness update-run-perf parity-gate quick-pressure-sweep-tunables auto-tune-kernel-pressure-tunables microbench-connect-dispatch daemon-rs-live-logs daemon-rs-live-stop daemon-rs-async-send-audit daemon-rs-snapshot-clone-audit daemon-rs-design-rule-audit daemon-rs-design-rule-helper-contract-audit daemon-rs-immutable-state-audit daemon-rs-policy-audit

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
	@cargo build --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE)

daemon-rs-profile-test:
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "daemon-rs-profile-test run $$i/$(PERF_REPEATS)"; \
		$(TEST_GUARD) env RUST_LOG=$(HARNESS_RUST_LOG_LEVEL) OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_connect_latency_and_pipeline_drops -- --ignored --nocapture; \
	done

daemon-rs-kernel-profile-harness:
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "daemon-rs-kernel-profile-harness pressure run $$i/$(PERF_REPEATS)"; \
		$(TEST_GUARD) env RUST_LOG=error OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1 cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_kernel_pipeline_pressure -- --ignored --nocapture; \
	done
	@set -e; \
	for i in $$(seq 1 $(PERF_REPEATS)); do \
		echo "daemon-rs-kernel-profile-harness sweep run $$i/$(PERF_REPEATS)"; \
		$(TEST_GUARD) env RUST_LOG=error OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1 cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_kernel_pipeline_timeout_sweep -- --ignored --nocapture; \
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
	if [ "$$(id -u)" -ne 0 ]; then \
		echo "go-test-full must run as root (kernel/netfilter test paths require elevated privileges)."; \
		exit 1; \
	fi; \
	for m in nf_conntrack nfnetlink_queue xt_conntrack xt_mark xt_NFQUEUE; do \
		modprobe "$$m" >/dev/null 2>&1 || { \
			echo "missing kernel module '$$m' for kernel $$(uname -r)."; \
			echo "If you recently upgraded kernel/modules, reboot and rerun: sudo make go-test-full"; \
			exit 1; \
		}; \
	done; \
	$(TEST_GUARD) sh -c 'cd daemon && go test ./... -count=1' || { \
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
	@OPENSNITCH_PARITY_STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) GO_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) GO_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS) $(DAEMON_RS_TOOLS_RUN) parity-hot-path-harness-once

parity-cold-path-harness: go-protocol
	@OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) $(DAEMON_RS_TOOLS_RUN) parity-cold-path-harness

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
	@OPENSNITCH_PARITY_STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PERF_RUST_LOG_LEVEL=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_PERF_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_PARITY_PREBUILD=$(PERF_PREBUILD) GO_KERNEL_PRESSURE_SECS=$(GO_KERNEL_PRESSURE_SECS) GO_KERNEL_PRESSURE_SWEEP_SECS=$(GO_KERNEL_PRESSURE_SWEEP_SECS) $(DAEMON_RS_TOOLS_RUN) parity-hot-cold-delta-once

rust-parity-tests:
	@$(TEST_GUARD) env RUST_LOG=$(RUST_TEST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) tests::config_service:: -- --nocapture
	@$(TEST_GUARD) env RUST_LOG=$(RUST_TEST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) tests::firewall_service:: -- --nocapture
	@$(TEST_GUARD) env RUST_LOG=$(RUST_TEST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) tests::client:: -- --nocapture

rust-kernel-it:
	@$(TEST_GUARD) env RUST_LOG=$(RUST_TEST_LOG_LEVEL) OPENSNITCH_RUN_PRIVILEGED_TESTS=1 OPENSNITCH_KERNEL_IT_STRICT=1 cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) integration_kernel_tests:: -- --nocapture

go-rust-parity-full:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "go-rust-parity-full must run as root (includes go-test-full and strict rust kernel integration tests)."; \
		exit 1; \
	fi
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

daemon-rs-live-logs:
	@OPENSNITCH_DAEMON_RS_RUST_LOG=$(DAEMON_RS_LIVE_RUST_LOG) $(DAEMON_RS_TOOLS_RUN) launch-daemon-live-logs

daemon-rs-live-stop:
	@$(DAEMON_RS_TOOLS_RUN) stop-daemon-live-logs

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
