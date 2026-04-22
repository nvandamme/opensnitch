package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/loggers"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/statistics"
	"github.com/evilsocket/opensnitch/daemon/ui/config"
)

var (
	defaultConfig = &config.Config{
		Server: config.ServerConfig{
			Address: "unix:///tmp/osui.sock",
		},
		ProcMonitorMethod: procmon.MethodProc,
		DefaultAction:     "allow",
		DefaultDuration:   "once",
		InterceptUnknown:  false,
		Firewall:          "nftables",
		FwOptions: config.FwOptions{
			ConfigPath:      "../system-fw.json",
			MonitorInterval: "15s",
			QueueNum:        0,
			QueueBypass:     true,
		},
		Rules: config.RulesOptions{
			Path:            "/tmp",
			EnableChecksums: false,
		},
		Stats: statistics.StatsConfig{
			MaxEvents: 150,
			MaxStats:  25,
			Workers:   6,
		},
		Internal: config.InternalOptions{
			GCPercent:         100,
			FlushConnsOnStart: true,
		},
	}
)

func testConfigFile(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("./testdata/default-config.json.orig")
	if err != nil {
		t.Fatalf("error reading default config fixture: %s", err)
	}

	cfgFile := filepath.Join(t.TempDir(), "default-config.json")
	if err := os.WriteFile(cfgFile, raw, 0o644); err != nil {
		t.Fatalf("error creating test config file: %s", err)
	}

	return cfgFile
}

func validateConfig(t *testing.T, uiClient *Client, cfg *config.Config) {
	if uiClient.ProcMonitorMethod() != cfg.ProcMonitorMethod || procmon.GetMonitorMethod() != uiClient.ProcMonitorMethod() {
		t.Errorf("not expected ProcMonitorMethod value: %s, expected: %s, procmon.MonitorMethod: %s", uiClient.ProcMonitorMethod(), cfg.ProcMonitorMethod, procmon.GetMonitorMethod())
	}
	if uiClient.GetFirewallType() != cfg.Firewall {
		t.Errorf("not expected FirewallType value: %s, expected: %s", uiClient.GetFirewallType(), cfg.Firewall)
	}
	if uiClient.InterceptUnknown() != cfg.InterceptUnknown {
		t.Errorf("not expected InterceptUnknown value: %v, expected: %v", uiClient.InterceptUnknown(), cfg.InterceptUnknown)
	}
	if uiClient.DefaultAction() != rule.Action(cfg.DefaultAction) {
		t.Errorf("not expected DefaultAction value: %s, expected: %s", uiClient.DefaultAction(), cfg.DefaultAction)
	}
	if uiClient.DefaultDuration() != rule.Duration(cfg.DefaultDuration) {
		t.Errorf("not expected DefaultDuration value: %s, expected: %s", uiClient.DefaultDuration(), cfg.DefaultDuration)
	}
	if uiClient.config.Server.Address != cfg.Server.Address {
		t.Errorf("not expected Server.Address value: %s, expected: %s", uiClient.config.Server.Address, cfg.Server.Address)
	}
}

func validateInvalidProcMonConfig(t *testing.T, uiClient *Client, cfg *config.Config) {
	if uiClient.ProcMonitorMethod() != procmon.MethodProc {
		t.Errorf("not expected ProcMonitorMethod, using value: %s, cfg value: %s, expected: proc", uiClient.ProcMonitorMethod(), procmon.GetMonitorMethod())
		t.Logf("loaded config: %v", cfg)
		t.Logf("procmon.method: %s", procmon.GetMonitorMethod())
	}
	if uiClient.GetFirewallType() != cfg.Firewall {
		t.Errorf("not expected FirewallType value: %s, expected: %s", uiClient.GetFirewallType(), cfg.Firewall)
	}
	if uiClient.InterceptUnknown() != cfg.InterceptUnknown {
		t.Errorf("not expected InterceptUnknown value: %v, expected: %v", uiClient.InterceptUnknown(), cfg.InterceptUnknown)
	}
	if uiClient.DefaultAction() != rule.Action(cfg.DefaultAction) {
		t.Errorf("not expected DefaultAction value: %s, expected: %s", uiClient.DefaultAction(), cfg.DefaultAction)
	}
	if uiClient.DefaultDuration() != rule.Duration(cfg.DefaultDuration) {
		t.Errorf("not expected DefaultDuration value: %s, expected: %s", uiClient.DefaultDuration(), cfg.DefaultDuration)
	}
	if uiClient.config.Server.Address != cfg.Server.Address {
		t.Errorf("not expected Server.Address value: %s, expected: %s", uiClient.config.Server.Address, cfg.Server.Address)
	}
}

func forceDisconnectedClient(uiClient *Client) {
	// Ensure tests validate disconnected defaults regardless of any running UI service.
	uiClient.setSocketPath("")
	uiClient.disconnect()
}

func cleanupClient(uiClient *Client) {
	uiClient.Close()
	if uiClient.configWatcher != nil {
		_ = uiClient.configWatcher.Close()
	}
}

func saveConfigAtomically(t *testing.T, cfgPath string, raw []byte) {
	t.Helper()

	tmpPath := cfgPath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o644); err != nil {
		t.Fatalf("error writing temp config file: %s", err)
	}
	if err := os.Rename(tmpPath, cfgPath); err != nil {
		t.Fatalf("error replacing config atomically: %s", err)
	}
}

func configMatches(uiClient *Client, cfg *config.Config) bool {
	return uiClient.ProcMonitorMethod() == cfg.ProcMonitorMethod &&
		procmon.GetMonitorMethod() == uiClient.ProcMonitorMethod() &&
		uiClient.GetFirewallType() == cfg.Firewall &&
		uiClient.InterceptUnknown() == cfg.InterceptUnknown &&
		uiClient.DefaultAction() == rule.Action(cfg.DefaultAction) &&
		uiClient.DefaultDuration() == rule.Duration(cfg.DefaultDuration) &&
		uiClient.config.Server.Address == cfg.Server.Address
}

func waitForConfigApplied(t *testing.T, uiClient *Client, cfg *config.Config, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if configMatches(uiClient, cfg) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	validateConfig(t, uiClient, cfg)
}

func TestClientDefaultConfig(t *testing.T) {
	cfgFile := testConfigFile(t)

	rules, err := rule.NewLoader(false)
	if err != nil {
		log.Fatal("")
	}

	stats := statistics.New(rules)
	loggerMgr := loggers.NewLoggerManager()
	uiClient := NewClient("unix:///tmp/osui.sock", cfgFile, stats, rules, loggerMgr)
	t.Cleanup(func() {
		cleanupClient(uiClient)
	})
	forceDisconnectedClient(uiClient)

	t.Run("validate-load-config", func(t *testing.T) {
		validateConfig(t, uiClient, defaultConfig)
	})

}

func TestClientReloadingConfig(t *testing.T) {
	cfgFile := testConfigFile(t)

	rules, err := rule.NewLoader(false)
	if err != nil {
		log.Fatal("")
	}

	stats := statistics.New(rules)
	loggerMgr := loggers.NewLoggerManager()
	uiClient := NewClient("unix:///tmp/osui.sock", cfgFile, stats, rules, loggerMgr)
	t.Cleanup(func() {
		cleanupClient(uiClient)
	})
	forceDisconnectedClient(uiClient)

	t.Run("validate-load-config", func(t *testing.T) {
		validateConfig(t, uiClient, defaultConfig)
	})

	t.Run("validate-reload-config", func(t *testing.T) {
		reloadConfig := *defaultConfig
		//reloadConfig.ProcMonitorMethod = procmon.MethodProc
		reloadConfig.DefaultAction = string(rule.Deny)
		reloadConfig.InterceptUnknown = true
		reloadConfig.FwOptions.QueueBypass = true
		reloadConfig.Server.Address = "unix:///run/user/1000/opensnitch/osui.sock"

		plainJSON, err := json.Marshal(reloadConfig)
		if err != nil {
			t.Errorf("Error marshalling config: %s", err)
		}
		reloadStarted := time.Now()
		saveConfigAtomically(t, configFile, plainJSON)
		// Keep a bounded wait and assert by state rather than sleeping fixed time.
		waitForConfigApplied(t, uiClient, &reloadConfig, 5*time.Second)
		if elapsed := time.Since(reloadStarted); elapsed < 4*time.Second {
			time.Sleep(4*time.Second - elapsed)
		}
		forceDisconnectedClient(uiClient)

		validateConfig(t, uiClient, &reloadConfig)
		fmt.Printf(
			"cold-profile backend=go component=ui elapsed_s=%.3f\n",
			time.Since(reloadStarted).Seconds(),
		)
	})
}

// test a configuration with a Process Monitor which fails to load.
// The configuration must be loaded, but the proc monitor should be "proc".
func TestClientInvalidProcMon(t *testing.T) {
	cfgFile := "./testdata/config-invalid-procmon.json"

	rules, err := rule.NewLoader(false)
	if err != nil {
		log.Fatal("")
	}

	stats := statistics.New(rules)
	loggerMgr := loggers.NewLoggerManager()
	uiClient := NewClient("unix:///tmp/osui.sock", cfgFile, stats, rules, loggerMgr)
	t.Cleanup(func() {
		cleanupClient(uiClient)
	})
	forceDisconnectedClient(uiClient)

	t.Run("validate-invalid-config", func(t *testing.T) {
		validateInvalidProcMonConfig(t, uiClient, &uiClient.config)
	})

}
