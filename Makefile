all: protocol opensnitch_daemon gui

STRESS_ROUNDS ?= 2000
DAEMON_RS_MANIFEST := daemon-rs/Cargo.toml
DAEMON_RS_PACKAGE := opensnitchd-rs

.PHONY: protocol go-protocol go-test-full go-stress-profile rust-parity-tests rust-kernel-it go-rust-parity-full

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
	@OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) cargo test --manifest-path $(DAEMON_RS_MANIFEST) --release -p $(DAEMON_RS_PACKAGE) stress_profile_reports_connect_latency_and_pipeline_drops -- --ignored --nocapture

profile-backends: daemon-rs-build daemon-rs-profile-test go-protocol
	@echo "Running Rust (release) and Go stress profiles with STRESS_ROUNDS=$(STRESS_ROUNDS)"
	@cd daemon && OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v

go-test-full: go-protocol
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "go-test-full must run as root (kernel/netfilter test paths require elevated privileges)."; \
		exit 1; \
	fi
	@for m in nf_conntrack nfnetlink_queue xt_conntrack xt_mark xt_NFQUEUE; do \
		modprobe "$$m" >/dev/null 2>&1 || { \
			echo "missing kernel module '$$m' for kernel $$(uname -r)."; \
			echo "If you recently upgraded kernel/modules, reboot and rerun: sudo make go-test-full"; \
			exit 1; \
		}; \
	done
	@cd daemon && go test ./... -count=1 || { \
		echo "go-test-full failed."; \
		echo "If netfilter tests report missing conntrack/NFQUEUE extensions, reboot into the updated kernel and rerun: sudo make go-test-full"; \
		exit 1; \
	}

go-stress-profile: go-protocol
	@cd daemon && OPENSNITCH_STRESS_PROFILE=1 OPENSNITCH_STRESS_ROUNDS=$(STRESS_ROUNDS) go test ./runtimeprofile -run TestStressProfileReportsConnectLatencyAndPipelineDrops -count=1 -v

rust-parity-tests:
	@cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) config::tests::
	@cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) services::config_service::tests::
	@cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) services::firewall_service::tests::
	@cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) client::client::tests::

rust-kernel-it:
	@OPENSNITCH_RUN_KERNEL_IT=1 OPENSNITCH_KERNEL_IT_STRICT=1 cargo test --manifest-path $(DAEMON_RS_MANIFEST) -p $(DAEMON_RS_PACKAGE) --features integration-kernel-tests integration_kernel_tests::

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
	@STRESS_ROUNDS=$(STRESS_ROUNDS) cargo run --manifest-path $(DAEMON_RS_MANIFEST) -p tools -- update-run-perf


