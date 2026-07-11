package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	content := `
agent:
  id: "test-agent"
  log_level: "debug"
  ipc_socket: "/tmp/test.sock"
  heartbeat_interval_seconds: 15
telemetry:
  process_monitoring: true
  file_monitoring: false
`
	tmpfile, err := os.CreateTemp("", "aegis_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Agent.ID != "test-agent" {
		t.Errorf("expected ID test-agent, got %s", cfg.Agent.ID)
	}
	if cfg.Agent.LogLevel != "debug" {
		t.Errorf("expected LogLevel debug, got %s", cfg.Agent.LogLevel)
	}
	if cfg.Agent.IPCSocket != "/tmp/test.sock" {
		t.Errorf("expected IPCSocket /tmp/test.sock, got %s", cfg.Agent.IPCSocket)
	}
	if cfg.Agent.HeartbeatIntervalSeconds != 15 {
		t.Errorf("expected HeartbeatIntervalSeconds 15, got %d", cfg.Agent.HeartbeatIntervalSeconds)
	}
	if !cfg.Telemetry.ProcessMonitoring {
		t.Errorf("expected ProcessMonitoring to be true")
	}
	if cfg.Telemetry.FileMonitoring {
		t.Errorf("expected FileMonitoring to be false")
	}
}
