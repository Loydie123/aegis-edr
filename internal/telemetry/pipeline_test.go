package telemetry

import (
	"context"
	"os"
	"testing"
	"time"

	"aegis-edr/internal/storage"
)

func TestPipelineIngestAndBuffer(t *testing.T) {
	dbPath := "/tmp/aegis_telemetry_pipeline_test.db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)
	defer os.Remove(dbPath + ".corrupt")

	store, err := storage.NewStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to initialize storage: %v", err)
	}
	defer store.Close()

	pipeline := NewPipeline(100, store, 1*time.Second, []string{"/tmp/excluded"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pipeline.Start(ctx)
	defer pipeline.Stop()

	// Ingest Process Event
	pipeline.Ingest(&RawEvent{
		Type:        "Process",
		Timestamp:   time.Now(),
		ProcessID:   456,
		ParentID:    123,
		BinaryPath:  "/bin/ls",
		CommandLine: "ls -la",
		Username:    "root",
	})

	// Ingest same Process Event (Duplicate -> should be dropped)
	pipeline.Ingest(&RawEvent{
		Type:        "Process",
		Timestamp:   time.Now(),
		ProcessID:   456,
		ParentID:    123,
		BinaryPath:  "/bin/ls",
		CommandLine: "ls -la",
		Username:    "root",
	})

	// Ingest Filtered Event (Filtered -> should be dropped)
	pipeline.Ingest(&RawEvent{
		Type:       "File",
		Timestamp:  time.Now(),
		ProcessID:  456,
		FilePath:   "/tmp/excluded/threat.elf",
		FileAction: "write",
	})

	time.Sleep(300 * time.Millisecond)

	metrics := pipeline.GetMetrics()
	if metrics.IngestedCount != 3 {
		t.Errorf("expected 3 ingested, got %d", metrics.IngestedCount)
	}
	if metrics.Deduplicated != 1 {
		t.Errorf("expected 1 duplicate dropped, got %d", metrics.Deduplicated)
	}
	if metrics.FilteredCount != 1 {
		t.Errorf("expected 1 filtered event, got %d", metrics.FilteredCount)
	}
	if metrics.PersistedCount != 1 {
		t.Errorf("expected 1 event persisted to storage, got %d", metrics.PersistedCount)
	}
}

func TestPipelineReplay(t *testing.T) {
	dbPath := "/tmp/aegis_telemetry_replay_test.db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := storage.NewStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to initialize storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	_, err = store.InsertProcess(ctx, 1, "/bin/sh", "hash-val", "sh", "root")
	if err != nil {
		t.Fatalf("failed to seed process: %v", err)
	}

	pipeline := NewPipeline(100, store, 1*time.Millisecond, nil)
	pipeline.Start(ctx)
	defer pipeline.Stop()

	// Replay history
	start := time.Now().UTC().Add(-5 * time.Minute)
	end := time.Now().UTC().Add(5 * time.Minute)
	if errReplay := pipeline.Replay(ctx, start, end); errReplay != nil {
		t.Fatalf("failed to run replay: %v", errReplay)
	}

	time.Sleep(300 * time.Millisecond)
	metrics := pipeline.GetMetrics()
	if metrics.IngestedCount != 1 {
		t.Errorf("expected 1 replayed event ingested, got %d", metrics.IngestedCount)
	}
}
