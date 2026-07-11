package storage

import (
	"os"
	"testing"
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
