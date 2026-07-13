package pipeline

import (
	"context"
	"testing"

	"aegis-edr/internal/scoring"
	"aegis-edr/internal/telemetry"
)

func TestDetectionPipeline(t *testing.T) {
	iocList := map[string]string{
		"db29f03225d369f17089b2bbecdd3d80617": "mimikatz",
	}
	rules := map[string]bool{
		"/bin/malware": true,
	}
	patterns := []string{
		"downloadstring",
	}
	indicators := map[string]bool{
		"8.8.8.8": true,
	}

	alertsChan := make(chan scoring.Alert, 10)

	pipeline := NewDetectionPipeline(
		&NormalizerStage{},
		&BehaviorAnalysisStage{},
		NewHeuristicStage(7.2),
		NewIOCMatchingStage(iocList),
		NewYaraStage(rules),
		NewSigmaStage(patterns),
		NewThreatIntelStage(indicators),
		&CorrelationStage{},
		NewRiskScoringStage(0.5),
		NewAlertStage(alertsChan),
	)

	// Test 1: Ingest benign event (Risk should be 0, no Alert)
	ctx := context.Background()
	res1, err := pipeline.Process(ctx, &telemetry.Event{
		Type:       "process",
		BinaryPath: "/bin/ls",
		ParentID:   456,
	})
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}
	if res1.AlertTriggered {
		t.Error("expected no alert for benign event")
	}

	// Test 2: Ingest highly suspicious event (Matches Sigma and Heuristics -> should trigger Alert)
	res2, err := pipeline.Process(ctx, &telemetry.Event{
		Type:        "process",
		BinaryPath:  "/bin/powershell",
		CommandLine: "powershell.exe -nop -enc downloadstring",
		ParentID:    1,
	})
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	if !res2.AlertTriggered {
		t.Error("expected alert to be triggered for malicious event")
	}

	select {
	case alert := <-alertsChan:
		if alert.CompoundScore < 0.5 {
			t.Errorf("expected compound score >= 0.5, got %f", alert.CompoundScore)
		}
	default:
		t.Error("expected alert to be present in channel")
	}
}
