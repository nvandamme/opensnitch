package runtimeprofile

import (
	"os"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/internal/testutil"
	oslog "github.com/evilsocket/opensnitch/daemon/log"
)

func TestMain(m *testing.M) {
	// Default the harness log level to "err" so that enforceHarnessGoLogLevel
	// does not fatal when running plain `go test ./...` without env.
	// An explicit override (e.g. from CI) is honoured as-is.
	if os.Getenv("OPENSNITCH_HARNESS_GO_LOG_LEVEL") == "" {
		os.Setenv("OPENSNITCH_HARNESS_GO_LOG_LEVEL", "err") //nolint:errcheck
	}
	oslog.SetLogLevel(oslog.ERROR)
	testutil.StopConflictingServices()
	os.Exit(m.Run())
}
