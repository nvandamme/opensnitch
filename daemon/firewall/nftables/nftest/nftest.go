package nftest

import (
	"os"
	"runtime"
	"testing"

	nftb "github.com/evilsocket/opensnitch/daemon/firewall/nftables"
	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

var (
	conn  *nftables.Conn
	newNS netns.NsHandle

	// Fw represents the nftables Fw object.
	Fw, _ = nftb.Fw()
)

func init() {
	nftb.InitMapsStore()
}

func kernelITEnabled() bool {
	// Elevated runs should automatically enable privileged test paths.
	if os.Geteuid() == 0 {
		return true
	}
	// New canonical shared gate name.
	if os.Getenv("OPENSNITCH_RUN_PRIVILEGED_TESTS") == "1" {
		return true
	}
	// Compatibility aliases.
	if os.Getenv("OPENSNITCH_RUN_PRIVILEDGED_TESTS") == "1" {
		return true
	}
	// Backward-compatible gate used by existing Go nftables tests.
	if os.Getenv("PRIVILEGED_TESTS") == "1" {
		return true
	}
	return false
}

// SkipIfNotPrivileged will skip the test from where it's invoked,
// to skip the test if we don't have root privileges.
// This may occur when executing the tests on restricted environments,
// such as containers, chroots, etc.
func SkipIfNotPrivileged(t *testing.T) {
	if !kernelITEnabled() {
		t.Skip("Set OPENSNITCH_RUN_PRIVILEGED_TESTS=1 (or PRIVILEGED_TESTS=1) to launch privileged nftables tests, or run as root.")
	}
	if os.Geteuid() != 0 {
		t.Skip("privileged nftables tests require root/elevated execution")
	}
}

// OpenSystemConn opens a new connection with the kernel in a new namespace.
// https://github.com/google/nftables/blob/8f2d395e1089dea4966c483fbeae7e336917c095/internal/nftest/system_conn.go#L15
func OpenSystemConn(t *testing.T) (*nftables.Conn, netns.NsHandle) {
	t.Helper()
	// We lock the goroutine into the current thread, as namespace operations
	// such as those invoked by `netns.New()` are thread-local. This is undone
	// in nftest.CleanupSystemConn().
	runtime.LockOSThread()

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New() failed: %v", err)
	}
	t.Log("OpenSystemConn() with NS:", ns)
	c, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatalf("nftables.New() failed: %v", err)
	}
	return c, ns
}

// CleanupSystemConn closes the given namespace.
func CleanupSystemConn(t *testing.T, newNS netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := newNS.Close(); err != nil {
		t.Fatalf("newNS.Close() failed: %v", err)
	}
}
