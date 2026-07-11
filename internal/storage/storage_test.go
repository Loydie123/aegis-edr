package storage

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestStorageLifecycle(t *testing.T) {
	t.Parallel()

	tmpfile, err := os.CreateTemp("", "aegis_db_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	s, err := NewStorage(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var count int
	err = s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('processes', 'file_modifications', 'network_connections', 'alert_logs')").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Errorf("expected 4 tables, got %d", count)
	}

	result, err := s.db.Exec("INSERT INTO processes (binary_path, sha256, command_line, username) VALUES ('/usr/bin/whoami', 'abcd', 'whoami --help', 'root')")
	if err != nil {
		t.Fatal(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Errorf("expected last insert ID to be 1, got %d", id)
	}
}

func TestStoragePruning(t *testing.T) {
	t.Parallel()

	tmpfile, err := os.CreateTemp("", "aegis_prune_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	s, err := NewStorage(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	t1 := time.Now().Add(-10 * 24 * time.Hour)
	t2 := time.Now()

	_, err = s.db.Exec("INSERT INTO processes (process_id, parent_id, binary_path, sha256, command_line, username, launched_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		10, 1, "/bin/old", "hash1", "old", "root", t1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.db.Exec("INSERT INTO processes (process_id, parent_id, binary_path, sha256, command_line, username, launched_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		20, 1, "/bin/alerted", "hash2", "alerted", "root", t1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.db.Exec("INSERT INTO alert_logs (alert_id, rule_name, category, risk_score, description, process_id, triggered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		1, "TEST_RULE", "test", 9.0, "test alert", 20, t2)
	if err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	if err := s.PruneOldTelemetry(ctx, cutoff); err != nil {
		t.Fatalf("pruning failed: %v", err)
	}

	var count int
	_ = s.db.QueryRow("SELECT count(*) FROM processes WHERE process_id = 10").Scan(&count)
	if count != 0 {
		t.Error("expected process 10 to be pruned")
	}

	_ = s.db.QueryRow("SELECT count(*) FROM processes WHERE process_id = 20").Scan(&count)
	if count != 1 {
		t.Error("expected alerted process 20 to NOT be pruned")
	}
}
