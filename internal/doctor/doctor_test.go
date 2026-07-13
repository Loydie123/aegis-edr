package doctor

import (
	"context"
	"testing"

	"aegis-edr/internal/logger"
)

func TestDiagnosticsRunner(t *testing.T) {
	_ = logger.Init("info")
	runner := NewDiagnostics()
	ctx := context.Background()

	report, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("diagnostics run failed: %v", err)
	}

	if len(report.Checks) == 0 {
		t.Error("expected component checks in doctor report")
	}

	runner.Print(report)
}
