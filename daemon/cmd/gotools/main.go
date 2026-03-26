package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// ── entry ─────────────────────────────────────────────────────────────────────

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "gotools: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(helpText)
		return nil
	}

	cmd := parseAndApply(args)

	switch cmd {
	case "go-test-full":
		return withGuard("go-test-full", runGoTestFull)
	case "go-stress-profile":
		return withGuard("go-stress-profile", runGoStressProfile)
	case "go-kernel-profile-harness":
		return withGuard("go-kernel-profile-harness", runGoKernelProfileHarness)
	default:
		return fmt.Errorf("unknown command %q\n\n%s", cmd, helpText)
	}
}

// ── privilege routing ──────────────────────────────────────────────────────────

type privCmd int

const (
	privDirect privCmd = iota
	privSudo
	privPkexec
)

func isRoot() bool {
	return os.Getuid() == 0
}

func commandExists(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// pickPrivCmd resolves the privilege command.  Priority:
//  1. OPENSNITCH_TEST_GUARD_PRIV_CMD (compat with Makefile export + with_test_guard.sh)
//  2. OPENSNITCH_TOOLS_PRIV_CMD
//  3. Already root → direct
//  4. Default → sudo
func pickPrivCmd() privCmd {
	if isRoot() {
		return privDirect
	}
	for _, v := range []string{"OPENSNITCH_TEST_GUARD_PRIV_CMD", "OPENSNITCH_TOOLS_PRIV_CMD"} {
		if raw, ok := os.LookupEnv(v); ok {
			switch strings.ToLower(strings.TrimSpace(raw)) {
			case "direct", "none":
				return privDirect
			case "pkexec":
				return privPkexec
			case "sudo":
				return privSudo
			}
		}
	}
	return privSudo
}

func ensurePrivilegedReady(priv privCmd, action string) error {
	switch priv {
	case privDirect:
		return nil
	case privSudo:
		out, err := exec.Command("sudo", "-v").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: sudo auth failed: %w\n%s", action, err, string(out))
		}
		return nil
	case privPkexec:
		if !commandExists("pkexec") {
			return fmt.Errorf("%s requires pkexec but it is not in PATH", action)
		}
		return nil
	}
	return nil
}

// forwardedEnvPairs returns KEY=VAL strings for all env vars that must be
// forwarded when re-executing under sudo/pkexec (mirrors with_test_guard.sh).
var forwardedEnvKeys = []string{
	"OPENSNITCH_RUN_PRIVILEGED_TESTS",
	"OPENSNITCH_RUN_PRIVILEDGED_TESTS",
	"OPENSNITCH_CARGO_TARGET_DIR",
	"CARGO_TARGET_DIR",
	"RUST_LOG",
	"CARGO_HOME",
	"RUSTUP_HOME",
	"HOME",
	"PATH",
	"OPENSNITCH_TEST_GUARD_RESTART_SERVICES",
	"OPENSNITCH_TEST_GUARD_PRIV_CMD",
	"OPENSNITCH_TOOLS_PRIV_CMD",
	"OPENSNITCH_PERF_REPEATS",
	"OPENSNITCH_HARNESS_GO_LOG_LEVEL",
	"OPENSNITCH_STRESS_ROUNDS",
	"OPENSNITCH_KERNEL_PRESSURE_SECS",
	"OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS",
	"GO_UI_TEST_FIXTURE",
	"OPENSNITCH_DAEMON_RULES_PATH",
	"OPENSNITCH_DAEMON_CONFIG_FILE",
	"OPENSNITCH_DAEMON_UI_SOCKET",
	"OPENSNITCH_MOCK_UI_SOCKET",
}

func forwardedEnvPairs() []string {
	var pairs []string
	for _, k := range forwardedEnvKeys {
		if v, ok := os.LookupEnv(k); ok {
			pairs = append(pairs, k+"="+v)
		}
	}
	return pairs
}

// reexecPrivilegedIfNeeded re-executes the gotools binary under sudo/pkexec
// when not root and a privilege escalation command is configured.
// Uses syscall.Exec so the current process is replaced (no double-fork).
func reexecPrivilegedIfNeeded(priv privCmd) error {
	if isRoot() || priv == privDirect {
		return nil
	}
	if err := ensurePrivilegedReady(priv, "gotools"); err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve gotools executable: %w", err)
	}

	pairs := forwardedEnvPairs()
	// Build: [escalator, "env", "KEY=VAL"..., exe, args...]
	var argv []string
	switch priv {
	case privSudo:
		argv = append([]string{"sudo", "env"}, pairs...)
	case privPkexec:
		argv = append([]string{"pkexec", "env"}, pairs...)
	}
	argv = append(argv, exe)
	argv = append(argv, os.Args[1:]...)

	escalator, _ := exec.LookPath(argv[0])
	fmt.Fprintf(os.Stderr, "[gotools] re-execing as root via %s\n", argv[0])
	return syscall.Exec(escalator, argv, os.Environ())
}

// ── service lifecycle ─────────────────────────────────────────────────────────

var opensnitchServices = []string{"opensnitchd-rs", "opensnitchd", "opensnitch-ui"}

func systemctlIsActive(scope, svc string) bool {
	args := []string{"show", "--property=ActiveState", svc}
	if scope == "user" {
		args = append([]string{"--user"}, args...)
	}
	out, err := exec.Command("systemctl", args...).Output()
	return err == nil && strings.Contains(string(out), "ActiveState=active")
}

func stopService(priv privCmd, scope, svc string) bool {
	if !systemctlIsActive(scope, svc) {
		return false
	}
	if scope == "user" {
		exec.Command("systemctl", "--user", "stop", svc).Run() //nolint
	} else {
		runPrivilegedCapture(priv, "systemctl", "stop", svc) //nolint
	}
	return true
}

func startService(priv privCmd, scope, svc string) {
	if scope == "user" {
		exec.Command("systemctl", "--user", "start", svc).Run() //nolint
	} else {
		runPrivilegedCapture(priv, "systemctl", "start", svc) //nolint
	}
}

func killIfRunning(priv privCmd, proc string) {
	if exec.Command("pgrep", "-x", proc).Run() == nil {
		runPrivilegedCapture(priv, "pkill", "-x", proc) //nolint
	}
}

// runPrivilegedCapture runs a short command via sudo/pkexec and discards output.
func runPrivilegedCapture(priv privCmd, args ...string) error {
	var cmd *exec.Cmd
	switch priv {
	case privDirect:
		cmd = exec.Command(args[0], args[1:]...)
	case privSudo:
		cmd = exec.Command("sudo", append([]string{"--"}, args...)...)
	case privPkexec:
		cmd = exec.Command("pkexec", args...)
	}
	return cmd.Run()
}

type stoppedService struct{ scope, name string }

func preflightCleanup(priv privCmd) []stoppedService {
	var stopped []stoppedService
	if commandExists("systemctl") {
		for _, svc := range opensnitchServices {
			if stopService(priv, "system", svc) {
				stopped = append(stopped, stoppedService{"system", svc})
			}
			if stopService(priv, "user", svc) {
				stopped = append(stopped, stoppedService{"user", svc})
			}
		}
	}
	killIfRunning(priv, "opensnitchd-rs")
	killIfRunning(priv, "opensnitchd")
	exec.Command("pkill", "-f", `(^|[[:space:]]|/)opensnitch-ui([[:space:]]|$)`).Run() //nolint
	return stopped
}

func restartStoppedServices(priv privCmd, stopped []stoppedService) {
	if envOr("OPENSNITCH_TEST_GUARD_RESTART_SERVICES", "") == "0" {
		return
	}
	if !commandExists("systemctl") || len(stopped) == 0 {
		return
	}
	for i := len(stopped) - 1; i >= 0; i-- {
		startService(priv, stopped[i].scope, stopped[i].name)
	}
}

// withGuard wraps f() with privilege re-exec, service preflight, and restart.
func withGuard(action string, f func() error) error {
	priv := pickPrivCmd()
	if err := reexecPrivilegedIfNeeded(priv); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	// After reexec we are root (or direct).
	if err := ensurePrivilegedReady(priv, action); err != nil {
		return err
	}
	stopped := preflightCleanup(priv)
	err := f()
	restartStoppedServices(priv, stopped)
	return err
}

// ── flag / env helpers ─────────────────────────────────────────────────────────

// parseAndApply scans args, applies --key=val and --bool-flag pairs as env
// overrides, and returns the first non-flag token (the command name).
func parseAndApply(args []string) string {
	var cmd string
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			if cmd == "" {
				cmd = a
			}
			continue
		}
		body := strings.TrimPrefix(a, "--")
		if idx := strings.Index(body, "="); idx >= 0 {
			applyValueFlag(body[:idx], body[idx+1:])
		} else {
			applyBoolFlag(body)
		}
	}
	return cmd
}

func applyValueFlag(key, val string) {
	switch key {
	case "repeats":
		_ = os.Setenv("OPENSNITCH_PERF_REPEATS", val)
	case "go-log":
		_ = os.Setenv("OPENSNITCH_HARNESS_GO_LOG_LEVEL", val)
	case "stress-rounds":
		_ = os.Setenv("OPENSNITCH_STRESS_ROUNDS", val)
	case "pressure-secs":
		_ = os.Setenv("OPENSNITCH_KERNEL_PRESSURE_SECS", val)
	case "sweep-secs":
		_ = os.Setenv("OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS", val)
	case "rules-path":
		_ = os.Setenv("OPENSNITCH_DAEMON_RULES_PATH", val)
	case "config-file":
		_ = os.Setenv("OPENSNITCH_DAEMON_CONFIG_FILE", val)
	case "ui-socket":
		_ = os.Setenv("OPENSNITCH_DAEMON_UI_SOCKET", val)
		_ = os.Setenv("OPENSNITCH_MOCK_UI_SOCKET", val)
	}
}

func applyBoolFlag(key string) {
	switch key {
	case "skip-modprobe":
		_ = os.Setenv("OPENSNITCH_GOTOOLS_SKIP_MODPROBE", "1")
	}
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func intEnvOr(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func kernelRelease() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// goTestEnv builds an os.Environ() copy extended with the given key=value pairs.
func goTestEnv(extra ...string) []string {
	base := os.Environ()
	return append(base, extra...)
}

// runGoCmd runs a go(1) subcommand with inherited stdio, returning an error on
// non-zero exit.  The command runs in the caller's working directory.
func runGoCmd(env []string, args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// ── commands ───────────────────────────────────────────────────────────────────

// runGoTestFull runs the full Go test suite:
//  1. Backs up the UI test fixture in memory (restored on exit).
//  2. Probes required kernel modules (unless --skip-modprobe).
//  3. Runs `go test ./... -count=1`.
func runGoTestFull() error {
	// 1. Fixture backup.
	fixturePath := envOr("GO_UI_TEST_FIXTURE", "ui/testdata/default-config.json")
	origContent, readErr := os.ReadFile(fixturePath)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("reading fixture %s: %w", fixturePath, readErr)
	}
	defer func() {
		if origContent != nil {
			_ = os.WriteFile(fixturePath, origContent, 0o644)
		}
	}()

	// 2. Kernel module check.
	if envOr("OPENSNITCH_GOTOOLS_SKIP_MODPROBE", "") != "1" {
		modules := []string{"nf_conntrack", "nfnetlink_queue", "xt_conntrack", "xt_mark", "xt_NFQUEUE"}
		for _, mod := range modules {
			out, err := exec.Command("modprobe", mod).CombinedOutput()
			if err != nil {
				return fmt.Errorf(
					"missing kernel module %q for kernel %s.\nIf you recently upgraded kernel/modules, reboot and rerun: sudo make go-test-full\nmodprobe output: %s",
					mod, kernelRelease(), string(out),
				)
			}
		}
	}

	// 3. Run go test ./...
	logLevel := envOr("OPENSNITCH_HARNESS_GO_LOG_LEVEL", "error")
	return runGoCmd(
		goTestEnv(
			"OPENSNITCH_HARNESS_GO_LOG_LEVEL="+logLevel,
			"OPENSNITCH_RUN_PRIVILEGED_TESTS=1",
		),
		"test", "./...", "-count=1",
	)
}

// runGoStressProfile runs TestStressProfileReportsConnectLatencyAndPipelineDrops
// repeats times.
func runGoStressProfile() error {
	repeats := intEnvOr("OPENSNITCH_PERF_REPEATS", 3)
	logLevel := envOr("OPENSNITCH_HARNESS_GO_LOG_LEVEL", "error")
	rounds := envOr("OPENSNITCH_STRESS_ROUNDS", "500")

	for i := 1; i <= repeats; i++ {
		fmt.Printf("[gotools] go-stress-profile run %d/%d\n", i, repeats)
		if err := runGoCmd(
			goTestEnv(
				"OPENSNITCH_HARNESS_GO_LOG_LEVEL="+logLevel,
				"OPENSNITCH_STRESS_PROFILE=1",
				"OPENSNITCH_STRESS_ROUNDS="+rounds,
				"OPENSNITCH_RUN_PRIVILEGED_TESTS=1",
			),
			"test", "./runtimeprofile",
			"-run", "TestStressProfileReportsConnectLatencyAndPipelineDrops",
			"-count=1", "-v",
		); err != nil {
			return fmt.Errorf("go-stress-profile run %d: %w", i, err)
		}
	}
	return nil
}

// runGoKernelProfileHarness runs the kernel-pressure and timeout-sweep tests
// repeats times each.
func runGoKernelProfileHarness() error {
	repeats := intEnvOr("OPENSNITCH_PERF_REPEATS", 3)
	logLevel := envOr("OPENSNITCH_HARNESS_GO_LOG_LEVEL", "error")
	pressureSecs := envOr("OPENSNITCH_KERNEL_PRESSURE_SECS", "1")
	sweepSecs := envOr("OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS", "1")

	for i := 1; i <= repeats; i++ {
		fmt.Printf("[gotools] go-kernel-profile-harness pressure run %d/%d\n", i, repeats)
		if err := runGoCmd(
			goTestEnv(
				"OPENSNITCH_HARNESS_GO_LOG_LEVEL="+logLevel,
				"OPENSNITCH_STRESS_PROFILE=1",
				"OPENSNITCH_KERNEL_PRESSURE_SECS="+pressureSecs,
				"OPENSNITCH_RUN_PRIVILEGED_TESTS=1",
			),
			"test", "./runtimeprofile",
			"-run", "TestStressProfileReportsKernelPipelinePressure",
			"-count=1", "-v",
		); err != nil {
			return fmt.Errorf("pressure run %d: %w", i, err)
		}
	}

	for i := 1; i <= repeats; i++ {
		fmt.Printf("[gotools] go-kernel-profile-harness sweep run %d/%d\n", i, repeats)
		if err := runGoCmd(
			goTestEnv(
				"OPENSNITCH_HARNESS_GO_LOG_LEVEL="+logLevel,
				"OPENSNITCH_STRESS_PROFILE=1",
				"OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS="+sweepSecs,
				"OPENSNITCH_RUN_PRIVILEGED_TESTS=1",
			),
			"test", "./runtimeprofile",
			"-run", "TestStressProfileReportsKernelPipelineTimeoutSweep",
			"-count=1", "-v",
		); err != nil {
			return fmt.Errorf("sweep run %d: %w", i, err)
		}
	}
	return nil
}

// ── help ───────────────────────────────────────────────────────────────────────

const helpText = `Usage:
  go run ./cmd/gotools <command> [flags...]
  go run ./cmd/gotools --help

Commands:
  go-test-full               Full Go test suite (modprobe, fixture backup, go test ./...)
  go-stress-profile          Stress-profile harness (repeats × connect-latency test)
  go-kernel-profile-harness  Kernel-pipeline harness (repeats × pressure + sweep)

Guard behaviour:
  Each command stops opensnitch services before running and restarts them after
  (same as with_test_guard.sh).  When not root, re-execs self under sudo/pkexec.
  Set OPENSNITCH_TEST_GUARD_RESTART_SERVICES=0 to skip restart.
  Set OPENSNITCH_TEST_GUARD_PRIV_CMD=direct|sudo|pkexec to override auto-detection.

Flags (override env vars):
  --repeats=N           Repeat count                      [OPENSNITCH_PERF_REPEATS]        (default: 3)
  --go-log=LEVEL        OPENSNITCH_HARNESS_GO_LOG_LEVEL   (default: error)
  --stress-rounds=N     OPENSNITCH_STRESS_ROUNDS          (default: 500)
  --pressure-secs=N     OPENSNITCH_KERNEL_PRESSURE_SECS   (default: 1)
  --sweep-secs=N        OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS (default: 1)
  --skip-modprobe       Skip kernel module probe step     [OPENSNITCH_GOTOOLS_SKIP_MODPROBE=1]
  --rules-path=PATH     Daemon rules directory override   [OPENSNITCH_DAEMON_RULES_PATH]
  --config-file=PATH    Daemon config file path override  [OPENSNITCH_DAEMON_CONFIG_FILE]
  --ui-socket=PATH      Daemon/mock-UI socket override    [OPENSNITCH_DAEMON_UI_SOCKET, OPENSNITCH_MOCK_UI_SOCKET]

Examples:
  cd daemon && go run ./cmd/gotools go-test-full
  cd daemon && go run ./cmd/gotools go-stress-profile --repeats=5 --go-log=warn
  cd daemon && go run ./cmd/gotools go-kernel-profile-harness --repeats=3 --pressure-secs=2
`
