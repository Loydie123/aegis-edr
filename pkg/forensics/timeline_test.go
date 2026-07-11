package forensics

import (
	"os"
	"testing"
	"time"

	"aegis-edr/pkg/storage"
)

func TestTimelineBuilder(t *testing.T) {
	t.Parallel()

	tmpfile, err := os.CreateTemp("", "aegis_foren_*.db")
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

	t1 := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	t2 := time.Now().Add(-3 * time.Minute).Truncate(time.Second)
	t3 := time.Now().Add(-1 * time.Minute).Truncate(time.Second)

	_, err = store.DB().Exec("INSERT INTO processes (parent_id, binary_path, sha256, command_line, username, launched_at) VALUES (?, ?, ?, ?, ?, ?)",
		1, "/bin/bash", "hash1", "bash", "root", t1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.DB().Exec("INSERT INTO network_connections (process_id, protocol, local_ip, local_port, remote_ip, remote_port, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		1, "tcp", "10.0.0.2", 45000, "8.8.8.8", 53, t2)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.DB().Exec("INSERT INTO file_modifications (process_id, file_path, action, occurred_at) VALUES (?, ?, ?, ?)",
		1, "/etc/hosts", "write", t3)
	if err != nil {
		t.Fatal(err)
	}

	builder := NewTimelineBuilder(store)
	start := time.Now().Add(-10 * time.Minute)
	end := time.Now()

	events, err := builder.BuildTimeline(start, end)
	if err != nil {
		t.Fatalf("failed to build timeline: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	if events[0].Category != "PROCESS" || !events[0].Timestamp.Equal(t1) {
		t.Errorf("expected first event to be process at t1, got %v", events[0])
	}
	if events[1].Category != "NETWORK" || !events[1].Timestamp.Equal(t2) {
		t.Errorf("expected second event to be network at t2, got %v", events[1])
	}
	if events[2].Category != "FILE" || !events[2].Timestamp.Equal(t3) {
		t.Errorf("expected third event to be file at t3, got %v", events[2])
	}
}
