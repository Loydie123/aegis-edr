package benchmark

import (
	"context"
	"testing"

	"aegis-edr/internal/logger"
)

func TestBenchmarkRunner(t *testing.T) {
	_ = logger.Init("info")
	runner := NewRunner()
	ctx := context.Background()

	results, err := runner.RunAll(ctx)
	if err != nil {
		t.Fatalf("benchmark failed: %v", err)
	}

	if results.HashThroughputMBs <= 0 {
		t.Errorf("invalid hash throughput: %f MB/s", results.HashThroughputMBs)
	}

	if results.DatabaseInsertsPerSec <= 0 {
		t.Errorf("invalid database inserts: %f writes/s", results.DatabaseInsertsPerSec)
	}

	if results.YaraScansPerSec <= 0 {
		t.Errorf("invalid yara scans: %f scans/s", results.YaraScansPerSec)
	}

	if results.TelemetryThroughput <= 0 {
		t.Errorf("invalid telemetry throughput: %f events/s", results.TelemetryThroughput)
	}

	if results.DetectionLatencyUs <= 0 {
		t.Errorf("invalid latency: %f us", results.DetectionLatencyUs)
	}

	runner.PrintResults(results)
}
