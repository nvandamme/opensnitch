package procmon

import (
	"os"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/internal/testutil"
	oslog "github.com/evilsocket/opensnitch/daemon/log"
)

func TestMain(m *testing.M) {
	oslog.SetLogLevel(oslog.ERROR)
	testutil.StopConflictingServices()
	os.Exit(m.Run())
}
