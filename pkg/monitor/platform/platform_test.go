package platform

import (
	"os"
	"testing"

	"aegis-edr/pkg/logger"
	"aegis-edr/pkg/monitor/eventrouter"
	"aegis-edr/pkg/storage"
)

func TestProcessMonitorLifecycle(t *testing.T) {
	t.Parallel()
	_ = logger.Init("info")

	tmpfile, err := os.CreateTemp("", "aegis_plat_*.db")
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

	pm := NewProcessMonitor()
	err = pm.Start(router)
	if err != nil {
		t.Fatalf("expected Start to succeed, got %v", err)
	}

	err = pm.Stop()
	if err != nil {
		t.Fatalf("expected Stop to succeed, got %v", err)
	}
}
