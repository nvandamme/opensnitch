package runtimeprofile

import (
	"os"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.StopConflictingServices()
	os.Exit(m.Run())
}
