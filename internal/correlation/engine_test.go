package correlation

import (
	"testing"
	"time"

	"aegis-edr/internal/telemetry"
)

func TestCorrelationEngine(t *testing.T) {
	engine := NewEngine(5 * time.Minute)

	t1 := time.Now().Add(-10 * time.Second)
	t2 := time.Now().Add(-8 * time.Second)
	t3 := time.Now().Add(-5 * time.Second)

	// Step 1: Parent Process Launch (PID 100)
	engine.Correlate(&telemetry.Event{
		Type:       "process",
		Timestamp:  t1,
		ProcessID:  100,
		ParentID:   1,
		BinaryPath: "/bin/bash",
		Username:   "root",
	})

	// Step 2: Child Process Launch (PID 101, parent 100)
	engine.Correlate(&telemetry.Event{
		Type:       "process",
		Timestamp:  t2,
		ProcessID:  101,
		ParentID:   100,
		BinaryPath: "/bin/curl",
		Username:   "root",
	})

	// Step 3: Network Connection on Child (PID 101)
	engine.Correlate(&telemetry.Event{
		Type:       "network",
		Timestamp:  t3,
		ProcessID:  101,
		Protocol:   "TCP",
		RemoteIP:   "1.1.1.1",
		RemotePort: 80,
	})

	// Step 4: Record alert on child
	engine.RecordAlert(101, "SUSPICIOUS_CURL", "curl connected to external IP")

	// Verify Timeline Reconstruction for Parent (should include child and network events)
	timeline, err := engine.ReconstructTimeline(100)
	if err != nil {
		t.Fatalf("failed to reconstruct timeline: %v", err)
	}

	if len(timeline) != 4 {
		t.Errorf("expected 4 timeline items, got %d", len(timeline))
	}

	expectedCategories := []string{"PROCESS", "PROCESS", "NETWORK", "ALERT"}
	for i, item := range timeline {
		if item.Category != expectedCategories[i] {
			t.Errorf("at item %d: expected category %s, got %s", i, expectedCategories[i], item.Category)
		}
	}

	// Verify Alert Grouping at Parent Level (should bubble up from child)
	alerts, err := engine.GroupAlerts(100)
	if err != nil {
		t.Fatalf("failed to group alerts: %v", err)
	}

	if len(alerts) != 1 || alerts[0] != "SUSPICIOUS_CURL" {
		t.Errorf("expected alert SUSPICIOUS_CURL, got %v", alerts)
	}
}
