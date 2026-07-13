package intel

import (
	"context"
	"os"
	"testing"
	"time"

	"aegis-edr/internal/storage"
)

func TestReputationEngine(t *testing.T) {
	engine := NewReputationEngine()
	engine.Load([]Indicator{
		{
			Pattern:     "db29f03225d369f17089b2bbecdd3d80617",
			Type:        IOCHash,
			Label:       "malicious-hash",
			Version:     1,
			LastUpdated: time.Now(),
		},
		{
			Pattern:     "evil.com",
			Type:        IOCDomain,
			Label:       "malicious-domain",
			Version:     1,
			LastUpdated: time.Now(),
		},
	})

	// Lookup hit
	ind, found := engine.Lookup("db29f03225d369f17089b2bbecdd3d80617", IOCHash)
	if !found || ind.Label != "malicious-hash" {
		t.Errorf("expected hash hit, got found=%t, label=%s", found, ind.Label)
	}

	// Lookup miss
	_, found = engine.Lookup("good.com", IOCDomain)
	if found {
		t.Error("expected domain miss, got hit")
	}
}

func TestFeedManagerSyncOffline(t *testing.T) {
	dbPath := "/tmp/aegis_intel_sync_test.db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := storage.NewStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	err = store.InsertIndicator(ctx, "evil.com", "domain", "malicious-domain")
	if err != nil {
		t.Fatalf("failed to insert indicator: %v", err)
	}

	client := NewTAXIIClient(store)
	fm := NewFeedManager(store, client)
	fm.SetOfflineMode(true)

	re := NewReputationEngine()
	if errSync := fm.Sync(ctx, re); errSync != nil {
		t.Fatalf("sync failed: %v", errSync)
	}

	ind, found := re.Lookup("evil.com", IOCDomain)
	if !found || ind.Label != "malicious-domain" {
		t.Errorf("expected offline domain sync match, got found=%t, label=%s", found, ind.Label)
	}
}
