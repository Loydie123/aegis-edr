package platform

import (
	"os"
	"testing"

	"aegis-edr/internal/core"
	"aegis-edr/internal/eventrouter"
	"aegis-edr/internal/logger"
	"aegis-edr/internal/storage"
)

func TestMain(m *testing.M) {
	_ = logger.Init("info")
	os.Exit(m.Run())
}

func TestMonitorsLifecycle(t *testing.T) {
	t.Parallel()

	tmpfile, err := os.CreateTemp("", "aegis_plat_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	store, err := storage.NewStorage(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	router := eventrouter.NewRouter(10, store)
	router.Start()
	defer router.Stop()

	eb := core.NewEventBus()

	monitors := []interface {
		Start(router *eventrouter.Router, eb *core.EventBus) error
		Stop() error
	}{
		NewProcessMonitor(),
		NewFileMonitor(),
		NewNetworkMonitor(),
		NewRegistryMonitor(),
		NewServiceMonitor(),
		NewDriverMonitor(),
		NewUsbMonitor(),
		NewScheduledTaskMonitor(),
		NewStartupMonitor(),
	}

	for i, m := range monitors {
		if err := m.Start(router, eb); err != nil {
			t.Fatalf("monitor %d: expected Start to succeed, got %v", i, err)
		}
		if err := m.Stop(); err != nil {
			t.Fatalf("monitor %d: expected Stop to succeed, got %v", i, err)
		}
	}
}
