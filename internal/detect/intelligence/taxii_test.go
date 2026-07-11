package intelligence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"aegis-edr/internal/storage"
)

func TestTAXIIClientIngestion(t *testing.T) {
	t.Parallel()

	tmpfile, err := os.CreateTemp("", "aegis_taxii_*.db")
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

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authUsername, authPassword, ok := r.BasicAuth()
		if !ok || authUsername != "user" || authPassword != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Header.Get("Accept") != "application/vnd.oasis.taxii+json; version=2.1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		bundle := `{
			"type": "bundle",
			"id": "bundle--1234",
			"objects": [
				{
					"type": "indicator",
					"id": "indicator--5678",
					"pattern": "[file:hashes.sha256 = 'abcd']",
					"pattern_type": "stix",
					"labels": ["malicious-hash"]
				}
			]
		}`
		w.Header().Set("Content-Type", "application/vnd.oasis.taxii+json; version=2.1")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bundle))
	}))
	defer mockServer.Close()

	client := NewTAXIIClient(store)
	err = client.PollFeed(context.Background(), mockServer.URL, "user", "pass")
	if err != nil {
		t.Fatalf("failed to poll feed: %v", err)
	}

	var pattern, patternType, label string
	err = store.DB().QueryRow("SELECT pattern, pattern_type, threat_label FROM indicators").Scan(&pattern, &patternType, &label)
	if err != nil {
		t.Fatalf("failed to query indicators table: %v", err)
	}

	if pattern != "[file:hashes.sha256 = 'abcd']" {
		t.Errorf("expected pattern [file:hashes.sha256 = 'abcd'], got %s", pattern)
	}
	if patternType != "stix" {
		t.Errorf("expected pattern_type stix, got %s", patternType)
	}
	if label != "malicious-hash" {
		t.Errorf("expected label malicious-hash, got %s", label)
	}
}
