package platform

import (
	"os"
	"testing"

	"aegis-edr/pkg/logger"
	"aegis-edr/pkg/monitor/eventrouter"
	"aegis-edr/pkg/storage"
)

func TestMain(m *testing.M) {
	_ = logger.Init("info")
	os.Exit(m.Run())
}

func TestProcessMonitorLifecycle(t *testing.T) {
	t.Parallel()

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

func TestFileMonitorLifecycle(t *testing.T) {
	t.Parallel()

	tmpfile, err := os.CreateTemp("", "aegis_plat_file_*.db")
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

	fm := NewFileMonitor()
	err = fm.Start(router)
	if err != nil {
		t.Fatalf("expected Start to succeed, got %v", err)
	}

	err = fm.Stop()
	if err != nil {
		t.Fatalf("expected Stop to succeed, got %v", err)
	}
}

func TestNetworkMonitorLifecycle(t *testing.T) {
	t.Parallel()

	tmpfile, err := os.CreateTemp("", "aegis_plat_net_*.db")
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

	nm := NewNetworkMonitor()
	err = nm.Start(router)
	if err != nil {
		t.Fatalf("expected Start to succeed, got %v", err)
	}

	err = nm.Stop()
	if err != nil {
		t.Fatalf("expected Stop to succeed, got %v", err)
	}
}

func TestRegistryMonitorLifecycle(t *testing.T) {
	t.Parallel()

	tmpfile, err := os.CreateTemp("", "aegis_plat_reg_*.db")
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

	rm := NewRegistryMonitor()
	err = rm.Start(router)
	if err != nil {
		t.Fatalf("expected Start to succeed, got %v", err)
	}

	err = rm.Stop()
	if err != nil {
		t.Fatalf("expected Stop to succeed, got %v", err)
	}
}
