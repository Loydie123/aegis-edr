package purple

import (
	"context"
	"strings"
	"testing"
	"time"

	"aegis-edr/internal/detect/pipeline"
	"aegis-edr/internal/telemetry"
)

func TestPurpleFrameworkSimulation(t *testing.T) {
	framework := NewFramework()

	// Register a mock authorized scenario (T1059.001 Powershell Execution)
	framework.RegisterScenario(&Scenario{
		ID:          "TC001",
		Name:        "Suspicious PowerShell Script Execution",
		MITREIDs:    []string{"T1059.001"},
		Description: "Simulates Powershell spawning with bypass and download directives",
		TriggerEvents: []*telemetry.RawEvent{
			{
				Type:        "Process",
				Timestamp:   time.Now(),
				ProcessID:   102,
				ParentID:    1,
				BinaryPath:  "/bin/powershell",
				CommandLine: "powershell.exe -nop -enc downloadstring",
				Username:    "root",
			},
		},
	})

	dp := pipeline.NewDetectionPipeline(
		&pipeline.NormalizerStage{},
		&pipeline.BehaviorAnalysisStage{},
		pipeline.NewHeuristicStage(5.0),
		pipeline.NewRiskScoringStage(0.5),
	)

	ctx := context.Background()
	res, err := framework.RunSimulation(ctx, "TC001", dp)
	if err != nil {
		t.Fatalf("simulation run failed: %v", err)
	}

	if !res.Detected {
		t.Error("expected scenario TC001 to be successfully detected")
	}

	if res.MITRECoverageScore != 100.0 {
		t.Errorf("expected 100%% MITRE coverage, got %f", res.MITRECoverageScore)
	}

	report := framework.GenerateCoverageReport([]*ValidationResult{res})
	if !strings.Contains(report, "PASS") || !strings.Contains(report, "TC001") {
		t.Errorf("invalid coverage report generated: %s", report)
	}
}
