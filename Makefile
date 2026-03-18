all: protocol opensnitch_daemon gui

STRESS_ROUNDS ?= 4000
PARITY_STRESS_ROUNDS ?= 4000
DAEMON_RS_MANIFEST := daemon-rs/Cargo.toml
DAEMON_RS_PACKAGE := opensnitchd-rs
DAEMON_RS_TOOLS_RUN := cargo run --release --manifest-path $(DAEMON_RS_MANIFEST) -p tools --
GO_UI_TEST_FIXTURE := daemon/ui/testdata/default-config.json
RUST_TEST_LOG_LEVEL ?= info,opensnitchd_rs=debug
HARNESS_RUST_LOG_LEVEL ?= error
HARNESS_GO_LOG_LEVEL ?= error
PERF_RUST_LOG_LEVEL ?= error
DAEMON_RS_LIVE_RUST_LOG ?= info

.PHONY: protocol go-protocol go-test-full go-stress-profile rust-parity-tests rust-kernel-it go-rust-parity-full parity-hot-path-harness parity-cold-path-harness parity-hot-cold-matrix parity-hot-cold-delta daemon-rs-kernel-profile-harness update-run-perf parity-gate quick-pressure-sweep-tunables auto-tune-kernel-pressure-tunables microbench-connect-dispatch daemon-rs-live-logs daemon-rs-live-stop

install:
	@cd daemon && make install	
	@cd ui && make install

protocol:
	@cd proto && make

go-protocol: protocol

opensnitch_daemon:
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
	@RUST_LOG=$(HARNESS_RUST_LOG_LEVEL) OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_connect_latency_and_pipeline_drops -- --ignored --nocapture

daemon-rs-kernel-profile-harness:
	@RUST_LOG=error OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1 cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_kernel_pipeline_pressure -- --ignored --nocapture
	@RUST_LOG=error OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK=1 cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_kernel_pipeline_timeout_sweep -- --ignored --nocapture

profile-backends: daemon-rs-build daemon-rs-profile-test go-protocol
	@echo "Running Rust (release) and Go stress profiles with STRESS_ROUNDS=$(STRESS_ROUNDS)"
	@cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v

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
	cd daemon && go test ./... -count=1 || { \
		echo "go-test-full failed."; \
		echo "If netfilter tests report missing conntrack/NFQUEUE extensions, reboot into the updated kernel and rerun: sudo make go-test-full"; \
		exit 1; \
	}

go-stress-profile: go-protocol
	@cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v

parity-hot-path-harness: go-protocol
	@echo "Running hot-path parity harness (Go + Rust) with STRESS_ROUNDS=$(STRESS_ROUNDS)"
	@cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) go test ./runtimeprofile -run TestConnectAttemptProgressesUnderMixedNonConnectSaturation -count=1 -v
	@cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v
	@RUST_LOG=$(HARNESS_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) connect_attempt_progresses_under_mixed_non_connect_saturation -- --nocapture
	@RUST_LOG=$(HARNESS_RUST_LOG_LEVEL) OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_connect_latency_and_pipeline_drops -- --ignored --nocapture
	@echo "PARITY HOT-PATH STATUS: PASS"

parity-cold-path-harness: go-protocol
	@set -e; \
	fixture_backup=$$(mktemp); \
	cp -f $(GO_UI_TEST_FIXTURE) "$$fixture_backup"; \
	trap 'cp -f "$$fixture_backup" $(GO_UI_TEST_FIXTURE) >/dev/null 2>&1 || true; rm -f "$$fixture_backup"' EXIT; \
	echo "Running cold-path parity harness (watch/reload paths, Go + Rust)"; \
	(cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) go test ./rule -run TestLiveReload -count=1 -v); \
	(cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) go test ./ui -run TestClientReloadingConfig -count=1 -v); \
	(cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) go test ./tasks -run TestTaskManager -count=1 -v); \
	RUST_LOG=$(HARNESS_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) tests::watch_service:: -- --nocapture; \
	RUST_LOG=$(HARNESS_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) tests::config_service:: -- --nocapture; \
	RUST_LOG=$(HARNESS_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) tests::notification_flow:: -- --nocapture; \
	RUST_LOG=$(HARNESS_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) tests::process_service:: -- --nocapture; \
	RUST_LOG=$(HARNESS_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) tests::task_runtime:: -- --nocapture; \
	echo "PARITY COLD-PATH STATUS: PASS"

parity-hot-cold-matrix: parity-hot-path-harness parity-cold-path-harness
	@echo "PARITY MATRIX STATUS: hot-path + cold-path = PASS"

parity-hot-cold-delta: go-protocol
	@set -eu; \
	go_hot_log=$$(mktemp); \
	rust_hot_log=$$(mktemp); \
	go_rule_log=$$(mktemp); \
	go_ui_log=$$(mktemp); \
	go_tasks_log=$$(mktemp); \
	rust_watch_log=$$(mktemp); \
	rust_cfg_log=$$(mktemp); \
	rust_notify_log=$$(mktemp); \
	rust_process_log=$$(mktemp); \
	rust_tasks_log=$$(mktemp); \
	fixture_backup=$$(mktemp); \
	cp -f $(GO_UI_TEST_FIXTURE) "$$fixture_backup"; \
	trap 'rm -f "$$go_hot_log" "$$rust_hot_log" "$$go_rule_log" "$$go_ui_log" "$$go_tasks_log" "$$rust_watch_log" "$$rust_cfg_log" "$$rust_notify_log" "$$rust_process_log" "$$rust_tasks_log"; cp -f "$$fixture_backup" $(GO_UI_TEST_FIXTURE) >/dev/null 2>&1 || true; rm -f "$$fixture_backup"' EXIT; \
	echo "Running hot/cold parity delta harness with STRESS_ROUNDS=$(STRESS_ROUNDS)"; \
	s=$$(date +%s%3N); (cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v >"$$go_hot_log" 2>&1); e=$$(date +%s%3N); go_hot_elapsed=$$(awk -v s="$$s" -v e="$$e" 'BEGIN{printf "%.3f", (e-s)/1000}'); \
	cat "$$go_hot_log"; \
	s=$$(date +%s%3N); RUST_LOG=$(PERF_RUST_LOG_LEVEL) OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_connect_latency_and_pipeline_drops -- --ignored --nocapture >"$$rust_hot_log" 2>&1; e=$$(date +%s%3N); rust_hot_elapsed=$$(awk -v s="$$s" -v e="$$e" 'BEGIN{printf "%.3f", (e-s)/1000}'); \
	cat "$$rust_hot_log"; \
	s=$$(date +%s%3N); (cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) go test ./rule -run TestLiveReload -count=1 -v >"$$go_rule_log" 2>&1); e=$$(date +%s%3N); go_rule_elapsed=$$(awk -v s="$$s" -v e="$$e" 'BEGIN{printf "%.3f", (e-s)/1000}'); \
	tail -n 3 "$$go_rule_log"; \
	s=$$(date +%s%3N); (cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) go test ./ui -run TestClientReloadingConfig -count=1 -v >"$$go_ui_log" 2>&1); e=$$(date +%s%3N); go_ui_elapsed=$$(awk -v s="$$s" -v e="$$e" 'BEGIN{printf "%.3f", (e-s)/1000}'); \
	tail -n 5 "$$go_ui_log"; \
	s=$$(date +%s%3N); (cd daemon && OPENSNITCH_HARNESS_GO_LOG_LEVEL=$(HARNESS_GO_LOG_LEVEL) go test ./tasks -run TestTaskManager -count=1 -v >"$$go_tasks_log" 2>&1); e=$$(date +%s%3N); go_tasks_elapsed=$$(awk -v s="$$s" -v e="$$e" 'BEGIN{printf "%.3f", (e-s)/1000}'); \
	tail -n 4 "$$go_tasks_log"; \
	s=$$(date +%s%3N); RUST_LOG=$(PERF_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) tests::watch_service:: -- --nocapture >"$$rust_watch_log" 2>&1; e=$$(date +%s%3N); rust_watch_elapsed=$$(awk -v s="$$s" -v e="$$e" 'BEGIN{printf "%.3f", (e-s)/1000}'); \
	tail -n 3 "$$rust_watch_log"; \
	s=$$(date +%s%3N); RUST_LOG=$(PERF_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) tests::config_service:: -- --nocapture >"$$rust_cfg_log" 2>&1; e=$$(date +%s%3N); rust_cfg_elapsed=$$(awk -v s="$$s" -v e="$$e" 'BEGIN{printf "%.3f", (e-s)/1000}'); \
	tail -n 3 "$$rust_cfg_log"; \
	s=$$(date +%s%3N); RUST_LOG=$(PERF_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) tests::notification_flow:: -- --nocapture >"$$rust_notify_log" 2>&1; e=$$(date +%s%3N); rust_notify_elapsed=$$(awk -v s="$$s" -v e="$$e" 'BEGIN{printf "%.3f", (e-s)/1000}'); \
	tail -n 5 "$$rust_notify_log"; \
	s=$$(date +%s%3N); RUST_LOG=$(PERF_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) tests::process_service:: -- --nocapture >"$$rust_process_log" 2>&1; e=$$(date +%s%3N); rust_process_elapsed=$$(awk -v s="$$s" -v e="$$e" 'BEGIN{printf "%.3f", (e-s)/1000}'); \
	tail -n 3 "$$rust_process_log"; \
	s=$$(date +%s%3N); RUST_LOG=$(PERF_RUST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) tests::task_runtime:: -- --nocapture >"$$rust_tasks_log" 2>&1; e=$$(date +%s%3N); rust_tasks_elapsed=$$(awk -v s="$$s" -v e="$$e" 'BEGIN{printf "%.3f", (e-s)/1000}'); \
	tail -n 3 "$$rust_tasks_log"; \
	go_line=$$(grep 'stress-profile backend=go' "$$go_hot_log" | tail -n1); \
	rust_line=$$(grep '^stress-profile rounds=' "$$rust_hot_log" | tail -n1); \
	if [ -z "$$go_line" ] || [ -z "$$rust_line" ]; then \
		echo "Failed to parse hot-path stress-profile lines from harness output."; \
		exit 1; \
	fi; \
	get_metric() { \
		echo "$$1" | awk -v key="$$2" '{for (i=1;i<=NF;i++) if ($$i ~ ("^" key "=")) {split($$i,a,"="); print a[2]; exit}}'; \
	}; \
	go_p50=$$(get_metric "$$go_line" p50_ms); \
	go_p95=$$(get_metric "$$go_line" p95_ms); \
	go_p99=$$(get_metric "$$go_line" p99_ms); \
	go_max=$$(get_metric "$$go_line" max_ms); \
	go_drop=$$(get_metric "$$go_line" drop_total); \
	rust_p50=$$(get_metric "$$rust_line" p50_ms); \
	rust_p95=$$(get_metric "$$rust_line" p95_ms); \
	rust_p99=$$(get_metric "$$rust_line" p99_ms); \
	rust_max=$$(get_metric "$$rust_line" max_ms); \
	rust_drop=$$(get_metric "$$rust_line" drop_total); \
	delta() { awk -v a="$$1" -v b="$$2" 'BEGIN{printf "%.3f", a-b}'; }; \
	delta_drop() { awk -v a="$$1" -v b="$$2" 'BEGIN{printf "%d", a-b}'; }; \
	go_cold=$$(awk -v a="$$go_rule_elapsed" -v b="$$go_ui_elapsed" -v c="$$go_tasks_elapsed" 'BEGIN{printf "%.3f", a+b+c}'); \
	rust_cold=$$(awk -v a="$$rust_watch_elapsed" -v b="$$rust_cfg_elapsed" -v c="$$rust_notify_elapsed" -v d="$$rust_process_elapsed" -v e="$$rust_tasks_elapsed" 'BEGIN{printf "%.3f", a+b+c+d+e}'); \
	echo "PARITY DELTA COLD COMPONENTS: go_rule_s=$$go_rule_elapsed go_ui_s=$$go_ui_elapsed go_tasks_s=$$go_tasks_elapsed rust_watch_s=$$rust_watch_elapsed rust_config_s=$$rust_cfg_elapsed rust_notification_s=$$rust_notify_elapsed rust_process_s=$$rust_process_elapsed rust_tasks_s=$$rust_tasks_elapsed"; \
	echo "PARITY DELTA HOT COMPONENTS: go_hot_wall_s=$$go_hot_elapsed rust_hot_wall_s=$$rust_hot_elapsed"; \
	echo "PARITY DELTA HOT: vs_go p50=$$(delta "$$rust_p50" "$$go_p50") p95=$$(delta "$$rust_p95" "$$go_p95") p99=$$(delta "$$rust_p99" "$$go_p99") max=$$(delta "$$rust_max" "$$go_max") drop_total=$$(delta_drop "$$rust_drop" "$$go_drop")"; \
	echo "PARITY DELTA COLD: go_total_s=$$go_cold rust_total_s=$$rust_cold delta_s=$$(delta "$$rust_cold" "$$go_cold")"; \
	echo "PARITY DELTA STATUS: PASS"

rust-parity-tests:
	@RUST_LOG=$(RUST_TEST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) config::tests:: -- --nocapture
	@RUST_LOG=$(RUST_TEST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) services::config_service::tests:: -- --nocapture
	@RUST_LOG=$(RUST_TEST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) services::firewall_service::tests:: -- --nocapture
	@RUST_LOG=$(RUST_TEST_LOG_LEVEL) cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) client::client::tests:: -- --nocapture

rust-kernel-it:
	@RUST_LOG=$(RUST_TEST_LOG_LEVEL) OPENSNITCH_RUN_KERNEL_IT=1 OPENSNITCH_KERNEL_IT_STRICT=1 cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) integration_kernel_tests:: -- --nocapture

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
	@STRESS_ROUNDS=$(STRESS_ROUNDS) OPENSNITCH_PARITY_STRESS_ROUNDS=$(PARITY_STRESS_ROUNDS) $(DAEMON_RS_TOOLS_RUN) update-run-perf

parity-gate:
	@OPENSNITCH_PARITY_STRESS_ROUNDS=$(PARITY_STRESS_ROUNDS) $(DAEMON_RS_TOOLS_RUN) parity-gate

quick-pressure-sweep-tunables:
	@$(DAEMON_RS_TOOLS_RUN) quick-pressure-sweep-tunables

auto-tune-kernel-pressure-tunables:
	@$(DAEMON_RS_TOOLS_RUN) auto-tune-kernel-pressure-tunables

microbench-connect-dispatch:
	@$(DAEMON_RS_TOOLS_RUN) microbench-connect-dispatch

daemon-rs-live-logs:
	@OPENSNITCH_DAEMON_RS_RUST_LOG=$(DAEMON_RS_LIVE_RUST_LOG) $(DAEMON_RS_TOOLS_RUN) launch-daemon-live-logs

daemon-rs-live-stop:
	@$(DAEMON_RS_TOOLS_RUN) stop-daemon-live-logs

