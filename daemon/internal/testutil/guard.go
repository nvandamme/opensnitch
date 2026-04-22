package testutil

import (
	"os"
	"os/exec"
	"strings"
)

// StopConflictingServices stops any running opensnitchd or opensnitch-ui
// instances (systemd units and standalone processes) before running tests.
//
// Privilege escalation is chosen automatically:
//   - Root: commands run directly.
//   - Desktop session (DISPLAY/WAYLAND_DISPLAY set) + pkexec available:
//     pkexec is used so polkit shows a graphical auth dialog instead of
//     blocking on a terminal sudo prompt.
//   - Otherwise: sudo is used.
//
// Call this at the top of TestMain in any package whose tests can conflict
// with a live daemon or UI client (nfqueue ownership, gRPC Unix socket, etc.).
//
// Example usage:
//
//	func TestMain(m *testing.M) {
//	    testutil.StopConflictingServices()
//	    os.Exit(m.Run())
//	}
func StopConflictingServices() {
	services := []string{"opensnitchd-rs", "opensnitchd", "opensnitch-ui"}

	for _, svc := range services {
		if serviceIsActiveSystem(svc) {
			runPrivileged("systemctl", "stop", svc)
		}
		if serviceIsActiveUser(svc) {
			exec.Command("systemctl", "--user", "stop", svc).Run() //nolint:errcheck
		}
	}

	// Daemons run as root — pgrep is unprivileged; pkill needs privilege.
	for _, name := range []string{"opensnitchd-rs", "opensnitchd"} {
		if exec.Command("pgrep", "-x", name).Run() == nil {
			runPrivileged("pkill", "-x", name)
		}
	}

	// opensnitch-ui runs as the current user — no privilege needed.
	exec.Command("pkill", "-f", `(^|[[:space:]/])opensnitch-ui([[:space:]]|$)`).Run() //nolint:errcheck
}

// serviceIsActiveSystem returns true only when systemd reports exactly
// ActiveState=active for the system-scope unit.  More reliable than
// is-active --quiet which can misbehave on some systemd versions.
func serviceIsActiveSystem(svc string) bool {
	out, err := exec.Command("systemctl", "show", "--property=ActiveState", svc).Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "ActiveState=active" {
			return true
		}
	}
	return false
}

func serviceIsActiveUser(svc string) bool {
	out, err := exec.Command("systemctl", "--user", "show", "--property=ActiveState", svc).Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "ActiveState=active" {
			return true
		}
	}
	return false
}

// desktopPrivTool returns "pkexec" when running in a desktop session and pkexec
// is available, otherwise "" (caller should fall back to sudo -n).
func desktopPrivTool() string {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return ""
	}
	if _, err := exec.LookPath("pkexec"); err == nil {
		return "pkexec"
	}
	return ""
}

// runPrivileged runs name+args silently with the most appropriate privilege
// escalation.  It never blocks on a terminal password prompt.
func runPrivileged(name string, args ...string) {
	if os.Getuid() == 0 {
		exec.Command(name, args...).Run() //nolint:errcheck
		return
	}
	if tool := desktopPrivTool(); tool != "" {
		cmdArgs := append([]string{name}, args...)
		cmd := exec.Command(tool, cmdArgs...)
		err := cmd.Run()
		if err == nil {
			return
		}
		// Only fall back to sudo if pkexec itself could not dispatch:
		// 126 = polkit auth not obtained, 127 = binary not found.
		// Any other exit code means pkexec ran the program — don't retry.
		if exitCode(err) != 126 && exitCode(err) != 127 {
			return
		}
	}
	// -n = non-interactive: fail immediately instead of prompting for a password.
	exec.Command("sudo", append([]string{"-n", "--", name}, args...)...).Run() //nolint:errcheck
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	type exitCoder interface{ ExitCode() int }
	if ee, ok := err.(exitCoder); ok {
		return ee.ExitCode()
	}
	return -1
}
