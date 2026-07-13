package nextgen

import (
	"context"
	"testing"
	"time"

	"aegis-edr/internal/telemetry"
)

func TestNextGenEngineSequenceRule(t *testing.T) {
	alertsChan := make(chan Alert, 100)
	engine := NewEngine(8, 5*time.Minute, alertsChan)

	// Register correlation sequence rule: PROCESS -> PROCESS
	engine.AddRule(CorrelationRule{
		ID:          "R001",
		Name:        "Parent Child Spawning Sequence",
		Sequence:    []NodeType{NodeProcess, NodeProcess},
		TimeWindow:  1 * time.Second,
		MITREIDs:    []string{"T1059"},
		Description: "Process spawning child process",
	})

	ctx := context.Background()

	// Ingest parent
	engine.Ingest(ctx, &telemetry.Event{
		Type:      "process",
		Timestamp: time.Now().Add(-500 * time.Millisecond),
		ProcessID: 200,
		ParentID:  1,
	})

	// Ingest child (parent 200)
	engine.Ingest(ctx, &telemetry.Event{
		Type:      "process",
		Timestamp: time.Now(),
		ProcessID: 201,
		ParentID:  200,
	})

	select {
	case alert := <-alertsChan:
		if alert.RuleID != "R001" {
			t.Errorf("expected R001 alert, got %s", alert.RuleID)
		}
		if alert.RiskScore <= 0 {
			t.Errorf("expected aggregated risk score, got %f", alert.RiskScore)
		}
	default:
		t.Error("expected correlation sequence alert to trigger")
	}
}

func TestNextGenEngineSuppression(t *testing.T) {
	alertsChan := make(chan Alert, 100)
	engine := NewEngine(8, 5*time.Minute, alertsChan)

	engine.AddRule(CorrelationRule{
		ID:       "R002",
		Name:     "Parent Child Spawning Sequence",
		Sequence: []NodeType{NodeProcess, NodeProcess},
	})

	engine.SuppressAlert("R002", "300")

	ctx := context.Background()

	engine.Ingest(ctx, &telemetry.Event{
		Type:      "process",
		Timestamp: time.Now().Add(-500 * time.Millisecond),
		ProcessID: 300,
	})

	engine.Ingest(ctx, &telemetry.Event{
		Type:      "process",
		Timestamp: time.Now(),
		ProcessID: 301,
		ParentID:  300,
	})

	select {
	case <-alertsChan:
		t.Error("alert was triggered but should have been suppressed")
	default:
		// Passed
	}
}

func BenchmarkNextGenEngineIngest(b *testing.B) {
	alertsChan := make(chan Alert, 100000)
	engine := NewEngine(16, 1*time.Second, alertsChan)
	ctx := context.Background()

	ev := &telemetry.Event{
		Type:      "process",
		Timestamp: time.Now(),
		ProcessID: 400,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Ingest(ctx, ev)
	}
}
